package main

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	mathrand "math/rand"
	"runtime"
	"sort"

	"sync"
	"sync/atomic"
	"time"
)

const (
	adaptiveObservationWindowMinimum        = 5
	adaptiveObservationFallbackLimitDefault = 10
	adaptiveMainCoverage                    = 0.80
	adaptiveLowProbability                  = 0.01
	adaptiveDiffProbability                 = 0.01
	adaptiveDominantProbability             = 0.50
	adaptiveMaxLengths                      = 8
	adaptiveActiveRatio                     = 0.50
	adaptiveFeedbackRecords                 = 20
	adaptiveSimulationErrorLow              = 0.50
	adaptiveSimulationErrorHigh             = 0.80
	adaptiveFeedbackTMinRelaxFactor         = 0.90
	adaptiveFeedbackBudgetRelaxFactor       = 1.10
	adaptiveSaturatedNMinInit               = 2
	adaptiveSaturatedNMinMin                = 1
	adaptiveNonSaturatedNMinInit            = 8
	adaptiveNonSaturatedNMinMin             = 2
	adaptiveFeedbackNMinMax                 = 64
	adaptiveFeedbackTMinMax                 = 2 * time.Second
	adaptiveFeedbackStableWindows           = 3
	adaptiveLongIdleRatioMax                = 0.10
	adaptiveLowActivityFeedbackCycles       = 2
	adaptiveSaturatedAlphaInit              = 0.05
	adaptiveSaturatedAlphaMax               = 0.50
	adaptiveSaturatedBMaxFactor             = 3.0
	adaptiveNonSaturatedAlphaInit           = 0.02
	adaptiveNonSaturatedAlphaMax            = 0.20
	adaptiveUnknownAlphaInit                = 0.02
	adaptiveUnknownAlphaMax                 = 0.20
	adaptiveTimingIATHistoryLimit           = 256
	adaptiveTimingMinimumHistory            = 20
	adaptiveTimingFinalDebtFloor            = 250 * time.Microsecond
	adaptiveTimingMaxDebtRepaymentFraction  = 0.10
	adaptiveTimingFinalDebtIATFraction      = 0.10
	adaptiveTimingIATDisturbanceIndex       = 5

	adaptiveResolvedFlushBatchLimit   = 4
	adaptiveShortRecordIATThreshold   = 64 * time.Microsecond
	adaptiveCandidateDelaySampleLimit = 1
	adaptiveDecisionWorkBudget        = 2 * time.Millisecond
	adaptiveObservedIATBinCount       = 8
	adaptiveObservedIATMinimumSamples = adaptiveObservedIATBinCount * 8
)

var adaptiveFlowID atomic.Uint64

type adaptiveDecision struct {
	Insert    bool
	Length    int
	Delay     time.Duration
	HoldUntil time.Time
}

type adaptiveNormalArrival struct {
	IAT         time.Duration
	ReferenceAt time.Time
	Trusted     bool
	IATValid    bool
}

type adaptiveTimingIATCheck struct {
	CandidateDistance   float64
	NoRepaymentDistance float64
	IncrementalDistance float64
	NaturalThreshold    float64
	AllowedDistance     float64
	Valid               bool
}

type adaptiveLengthCandidate struct {
	Length   int
	Tier     int
	Order    int
	Dominant bool
}

type adaptiveParameters struct {
	NMin   int
	TMin   time.Duration
	Alpha  float64
	BMax   float64
	Budget float64
}

type adaptiveParameterBounds struct {
	NLo, NHi         int
	TLo, THi         time.Duration
	AlphaLo, AlphaHi float64
	BMaxLo, BMaxHi   float64
}

type adaptiveNaturalWaveModel struct {
	observations           []featureWindowResult
	baseline               recordWindowFeatures
	thresholds             []float64
	burstIATReference      float64
	burstIATReferenceValid bool
}

type adaptiveSimulationFeedback struct {
	epochIndex  int
	windowWidth time.Duration
	stableStart time.Duration

	predicted              recordWindowFeatures
	baseline               recordWindowFeatures
	thresholds             []float64
	burstIATReference      float64
	burstIATReferenceValid bool

	embeddedSubmittedAt time.Time
	normalSubmittedAt   time.Time
	embeddedEstimatedAt time.Time
	normalEstimatedAt   time.Time

	embeddedLength    int
	normalLength      int
	embeddedID        uint64
	normalID          uint64
	embeddedResolved  bool
	committed         bool
	timingReferenceAt time.Time
	timingDebt        time.Duration
}

// adaptiveSimulationBadComparison keeps the frozen model and the observed
// feature vector for one BAD simulation result. Comparisons are buffered on
// the hot path and emitted only when the connection closes.

type adaptiveFlowSuitability struct {
	active             bool
	stable             bool
	saturationStable   bool
	recentStable       int
	currentNormalCount int
	minimumActive      int
	longIdleRatio      float64
}

type adaptiveObservationRun struct {
	Start time.Duration
	End   time.Duration
}

// adaptiveObservationCache contains only data from closed feature windows.
// Those records do not change while new records are appended beyond the last
// observed run, so decision-time code can reuse the sorted history and its
// summaries instead of rebuilding them for every candidate.
type adaptiveObservationCache struct {
	valid               bool
	epoch               *recordEpochStream
	epochRecordCount    int
	windows             []featureWindowResult
	runs                []adaptiveObservationRun
	allRecords          []recordSample
	normalRecords       []recordSample
	iats                []time.Duration
	sortedIATs          []time.Duration
	candidateIATs       []time.Duration
	sortedCandidateIATs []time.Duration
	medianNormalCount   float64
	minimumLength       int
	maximumLength       int
	lengthCounts        map[int]int
	pairs               map[[2]int]struct{}
	triples             map[[3]int]struct{}
	diffCounts          map[int]int
	diffTotal           int
	expandedModels      []adaptiveNaturalWaveModel
	expandedModelsReady bool
	expandedWindows     []featureWindowResult
	expandedReference   float64
	expandedRefValid    bool
}

// adaptiveInserter uses the observed egress stream for epoch selection,
// feature extraction, medians, and disturbance distances.
type adaptiveInserter struct {
	mu             sync.Mutex
	forwardWaiters atomic.Int32
	enabled        bool
	stream         *recordFeatureStream
	rng            *mathrand.Rand
	predictor      *recordTimestampPredictor

	pending    map[uint64]recordEgressEvent
	resolved   map[uint64]recordEgressEvent
	droppedIDs map[uint64]struct{}
	// decisionWindowScratch is used only by DecideWithArrival while a.mu is
	// held. Keeping it separate from the general window helpers avoids a fresh
	// roughly-one-window allocation on every eligible decision.
	decisionWindowScratch []recordSample
	// candidateWindowScratch is reused first for the current virtual normal
	// Record and then for each candidate pair. Callers consume the returned
	// local slice before the next simulation overwrites this storage.
	candidateWindowScratch  []recordSample
	currentFeatureScratch   recordWindowFeatureScratch
	candidateFeatureScratch recordWindowFeatureScratch
	candidateDelayScratch   [adaptiveCandidateDelaySampleLimit]time.Duration
	nextID                  uint64
	syntheticID             uint64
	invalidEpoch            int

	// segmentActive identifies the active-epoch-scoped adaptive state. Despite
	// the legacy name, it remains true across startup, transition, tail, and
	// resumed stable_bulk stages inside the same active epoch.
	segmentActive bool
	epochIndex    int
	// observationHistory retains up to observationFallbackLimit complete
	// windows only so a failed five-window precheck can conditionally try a
	// broader natural-wave model. Normal decisions still use observations,
	// which is always the latest adaptiveObservationWindowMinimum windows.
	observationHistory []featureWindowResult
	observations       []featureWindowResult
	// observationFallbackLimit caps conditional fallback history; it does not
	// change the normal five-window baseline.
	observationFallbackLimit int
	baseline                 recordWindowFeatures
	thresholds               []float64
	burstIATReference        float64
	burstIATReferenceValid   bool
	ready                    bool
	initialized              bool
	observationCache         adaptiveObservationCache

	params             adaptiveParameters
	parameterMedianLen float64
	parameterWindow    time.Duration
	safeStreak         int
	lowActivityStreak  int
	feedbackCount      int
	lastFeedbackWindow time.Duration
	// Feedback only tightens parameters when an insertion changes the
	// observed traffic beyond the learned natural-wave envelope.
	feedbackSimulationHold    bool
	feedbackSimulationTighten bool

	saturationKnown                bool
	saturated                      bool
	saturationChangedSinceFeedback bool
	saturatedRelaxationPending     bool
	hasInserted                    bool
	lastInsert                     time.Time
	normalSince                    int
	lastNormalLen                  int
	lastNormalAt                   time.Time
	lastNormalArrivalAt            time.Time
	normalArrivalIATs              []time.Duration
	normalReferenceAt              time.Time
	// timingDebt is the planned absolute offset from the normal RX-derived
	// timeline. It only decreases after an admitted repayment; late TX
	// feedback never increases it.
	timingDebt time.Duration

	timingIATThreshold             float64
	timingIATThresholdValid        bool
	timingFrozen                   bool
	timingCompleteAfterNormalWrite bool

	reservedLength    int
	activeSimulation  *adaptiveSimulationFeedback
	simulationTargets map[uint64]*adaptiveSimulationFeedback
	flowID            uint64
}

func newAdaptiveInserter(enabled bool) *adaptiveInserter {
	return newAdaptiveInserterWithObservationFallbackLimit(enabled, adaptiveObservationFallbackLimitDefault)
}

func newAdaptiveInserterWithObservationFallbackLimit(enabled bool, limit int) *adaptiveInserter {
	var seedBytes [8]byte
	_, _ = cryptorand.Read(seedBytes[:])
	seed := int64(binary.LittleEndian.Uint64(seedBytes[:]))
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	return &adaptiveInserter{
		enabled:           enabled,
		stream:            newSilentRecordFeatureStream(recordFeatureMeta{}),
		rng:               mathrand.New(mathrand.NewSource(seed)),
		pending:           make(map[uint64]recordEgressEvent),
		resolved:          make(map[uint64]recordEgressEvent),
		droppedIDs:        make(map[uint64]struct{}),
		simulationTargets: make(map[uint64]*adaptiveSimulationFeedback),

		nextID:                   1,
		predictor:                newRecordTimestampPredictor(),
		observationFallbackLimit: normalizeAdaptiveObservationFallbackLimit(limit),
		// Saturation classification is intentionally disabled on this branch.
		// Every live flow starts and remains in the non-saturated mode.
		saturationKnown: true,
		flowID:          adaptiveFlowID.Add(1),
	}
}

func normalizeAdaptiveObservationFallbackLimit(limit int) int {
	if limit <= 0 {
		return adaptiveObservationFallbackLimitDefault
	}
	if limit < adaptiveObservationWindowMinimum {
		return adaptiveObservationWindowMinimum
	}
	return limit
}

func (a *adaptiveInserter) Observe(header TLSRecordHeader, at time.Time) {
	if a == nil || header.ContentType != tlsTypeApplicationData {
		return
	}
	a.mu.Lock()
	a.syntheticID++
	event := recordEgressEvent{
		ID:             a.syntheticID,
		Header:         header,
		SubmittedAt:    at,
		ActualEgressAt: at,
	}
	a.processResolvedLocked(event)
	a.mu.Unlock()
}

func (a *adaptiveInserter) AddDropped(count uint64) {
	if a == nil || !a.enabled || count == 0 {
		return
	}
	a.mu.Lock()

	log.Printf("[WARN] adaptive_timestamp_drop flow_id=%d count=%d pending_tx=%d action=use_predicted_egress_time",
		a.flowID,
		count,
		len(a.pending),
	)
	a.mu.Unlock()
}

func (a *adaptiveInserter) ObserveProvisional(event recordEgressEvent) {
	if a == nil || !a.enabled || event.Header.ContentType != tlsTypeApplicationData {
		return
	}

	a.lockForForwardPath()

	defer a.mu.Unlock()

	if event.SubmittedAt.IsZero() {
		event.SubmittedAt = time.Now()
	}
	if event.EstimatedEgressAt.IsZero() {
		event.EstimatedEgressAt = a.predictor.PredictRecord(
			event.ID,
			event.SubmittedAt,
			tlsRecordHeaderLen+int(event.Header.Length),
		)
	}
	a.pending[event.ID] = event

	a.bindSimulationTargetLocked(event)
	featureAt := event.FeatureTime()
	if event.Embedded {
		if featureAt.After(a.lastInsert) {
			a.lastInsert = featureAt
		}
	} else {
		a.lastNormalLen = tlsRecordHeaderLen + int(event.Header.Length)
		if featureAt.After(a.lastNormalAt) {
			a.lastNormalAt = featureAt
		}
	}
}

func (a *adaptiveInserter) ObserveResolved(event recordEgressEvent) {
	a.ObserveResolvedBatch([]recordEgressEvent{event})
}

// ObserveResolvedBatch preserves per-Record ordering and feedback while
// amortizing adaptive-state lock acquisition across a timestamp batch.
func (a *adaptiveInserter) ObserveResolvedBatch(events []recordEgressEvent) {
	if a == nil || !a.enabled || len(events) == 0 {
		return
	}

	a.mu.Lock()

	defer a.mu.Unlock()

	resolved := false
	for _, event := range events {
		if event.Header.ContentType != tlsTypeApplicationData {
			continue
		}
		if provisional, ok := a.pending[event.ID]; ok {
			event.SubmittedAt = provisional.SubmittedAt
			event.EstimatedEgressAt = provisional.EstimatedEgressAt
		}

		delete(a.pending, event.ID)
		a.resolved[event.ID] = event
		resolved = true
	}
	if resolved {
		a.flushResolvedLocked()
	}
}

func (a *adaptiveInserter) ApplyProvisionalEstimates(estimates map[uint64]time.Time) {
	if a == nil || !a.enabled || len(estimates) == 0 {
		return
	}

	a.mu.Lock()

	defer a.mu.Unlock()

	normalTailChanged := false
	embeddedTailChanged := false
	for id, event := range a.pending {
		estimatedAt, ok := estimates[id]
		if !ok || estimatedAt.IsZero() {
			continue
		}
		previousEstimate := event.EstimatedEgressAt
		event.EstimatedEgressAt = estimatedAt
		a.pending[id] = event
		if !event.Embedded && a.lastNormalAt.Equal(previousEstimate) {
			normalTailChanged = true
		}
		if event.Embedded && a.lastInsert.Equal(previousEstimate) {
			embeddedTailChanged = true
		}
	}
	if normalTailChanged {
		var latest time.Time
		for _, event := range a.pending {
			if !event.Embedded && event.FeatureTime().After(latest) {
				latest = event.FeatureTime()
			}
		}
		if !latest.IsZero() {
			a.lastNormalAt = latest
		}
	}
	if embeddedTailChanged {
		var latest time.Time
		for _, event := range a.pending {
			if event.Embedded && event.FeatureTime().After(latest) {
				latest = event.FeatureTime()
			}
		}
		if !latest.IsZero() {
			a.lastInsert = latest
		}
	}
}

func (a *adaptiveInserter) DropProvisional(id uint64) {
	if a == nil || !a.enabled {
		return
	}
	a.mu.Lock()
	a.discardSimulationForEventLocked(id, "provisional_dropped")

	_, wasPending := a.pending[id]
	delete(a.pending, id)
	if !wasPending && id < a.nextID {
		a.mu.Unlock()
		return
	}
	if a.stream.epoch != nil {
		a.invalidEpoch = a.stream.epoch.index
	} else {
		a.invalidEpoch = 1
	}

	log.Printf("[WARN] adaptive_timestamp_drop flow_id=%d invalid_epoch=%d pending_tx=%d action=disable_current_epoch",
		a.flowID,
		a.invalidEpoch,
		len(a.pending),
	)
	a.droppedIDs[id] = struct{}{}
	a.flushResolvedLocked()
	a.mu.Unlock()
}

func (a *adaptiveInserter) flushResolvedLocked() {
	for a.flushResolvedBatchLocked(adaptiveResolvedFlushBatchLimit) {
		// A missing early ID can leave thousands of later timestamps ready at
		// once. Keep their strict ID order, but do not monopolize the adaptive
		// state lock while catching up: normal-write accounting and the next
		// decision only need a short opportunity between batches.
		a.mu.Unlock()
		runtime.Gosched()
		a.mu.Lock()
	}
}

// flushResolvedBatchLocked processes at most limit consecutive lifecycle
// events and reports whether the next ID is already available. The caller
// holds a.mu; flushResolvedLocked may briefly release it between batches but
// always returns with it held.
func (a *adaptiveInserter) flushResolvedBatchLocked(limit int) bool {
	if limit <= 0 {
		limit = 1
	}
	processed := 0
	for processed < limit {
		if _, dropped := a.droppedIDs[a.nextID]; dropped {
			delete(a.droppedIDs, a.nextID)
			a.nextID++
			processed++
			if a.forwardWaiters.Load() > 0 {
				break
			}
			continue
		}
		event, ok := a.resolved[a.nextID]
		if !ok {
			return false
		}
		delete(a.resolved, a.nextID)
		a.nextID++
		a.processResolvedLocked(event)
		processed++
		// Timestamp feedback may already have a large ready backlog. Once a
		// Record's forward path is waiting, finish only the current ordered event
		// and release the lock at flushResolvedLocked's chunk boundary instead of
		// making the write wait behind the rest of the batch.
		if a.forwardWaiters.Load() > 0 {
			break
		}
	}
	if _, dropped := a.droppedIDs[a.nextID]; dropped {
		return true
	}
	_, resolved := a.resolved[a.nextID]
	return resolved
}

func (a *adaptiveInserter) processResolvedLocked(event recordEgressEvent) {
	sample := recordSampleFromEgressEvent(event)
	featureAt := sample.FeatureTime()
	_ = a.stream.Observe(sample)
	a.resolveSimulationTargetLocked(event)
	a.syncSegmentLocked()

	if event.Embedded {
		a.hasInserted = true
		if featureAt.After(a.lastInsert) {
			a.lastInsert = featureAt
		}

		return
	}
	a.lastNormalLen = sample.Length
	if featureAt.After(a.lastNormalAt) {
		a.lastNormalAt = featureAt
	}
	if a.feedbackCount < adaptiveFeedbackRecords &&
		a.initialized && a.ready && a.stream.epoch != nil && a.stream.epoch.inStableSegment {
		// Feedback only needs to know whether a sufficiently populated stable
		// window exists. Computing all Record features here used to hold a.mu
		// for every TX callback, even after the feedback quota was already full.
		if a.feedbackWindowAvailableLocked(featureAt) {
			a.feedbackCount++
		}
	}
}

func (a *adaptiveInserter) syncSegmentLocked() {
	epoch := a.stream.epoch
	if epoch == nil {
		if a.segmentActive {

			a.resetSegmentLocked()
		}
		return
	}
	if !a.segmentActive || a.epochIndex != epoch.index {

		a.resetSegmentLocked()
		a.segmentActive = true
		a.epochIndex = epoch.index

	}
	if !epoch.inStableSegment {
		a.safeStreak = 0
	}
	if !epoch.featureWidthChosen || epoch.featureWidth <= 0 {
		return
	}

	// Feature windows are only produced from stable_bulk stages. Retain the
	// latest windows across short transition/tail interruptions in the same
	// active epoch; the current-stage gate still prevents insertion outside
	// stable_bulk.
	// Inspect the epoch-owned suffix in place first. syncSegmentLocked runs for
	// every resolved egress event, while featureWindows advances only once per
	// window step. Allocating/copying before this equality check therefore did
	// needless work under a.mu on almost every TX timestamp.
	history := epoch.featureWindows
	if len(history) > a.observationFallbackLimit {
		history = history[len(history)-a.observationFallbackLimit:]
	}
	if sameAdaptiveWindows(a.observationHistory, history) {
		return
	}
	primary := history
	if len(primary) > adaptiveObservationWindowMinimum {
		primary = primary[len(primary)-adaptiveObservationWindowMinimum:]
	}
	if !epoch.iatSchemaFrozen && len(primary) >= adaptiveObservationWindowMinimum {
		a.freezeObservedIATSchemaLocked(epoch, primary)
		// Freezing a dynamic schema recomputes the already closed observation
		// windows. Refresh both slices so the baseline never mixes legacy and
		// learned IAT vectors.
		history = epoch.featureWindows
		if len(history) > a.observationFallbackLimit {
			history = history[len(history)-a.observationFallbackLimit:]
		}
		primary = history
		if len(primary) > adaptiveObservationWindowMinimum {
			primary = primary[len(primary)-adaptiveObservationWindowMinimum:]
		}
	}
	a.observationHistory = append(a.observationHistory[:0], history...)
	a.observations = append(a.observations[:0], primary...)
	a.invalidateObservationCacheLocked()
	a.rebuildBaselineLocked()
	// Observation summaries and expanded fallback models are already guarded
	// by lazy ensure helpers at every use site. Rebuilding both here made the TX
	// timestamp callback allocate and recompute them while holding a.mu for
	// every rolling feature window, even when no decision needed either cache.

}

func (a *adaptiveInserter) resetSegmentLocked() {
	if a.timingFrozen {
		a.finishTimingEpisodeLocked()
	}
	a.segmentActive = false
	a.epochIndex = 0
	a.observationHistory = nil
	a.observations = nil
	a.observationCache = adaptiveObservationCache{}
	a.baseline = recordWindowFeatures{}
	a.thresholds = nil
	a.burstIATReference = 0
	a.burstIATReferenceValid = false
	a.ready = false
	a.initialized = false
	a.params = adaptiveParameters{}
	a.parameterMedianLen = 0
	a.parameterWindow = 0
	a.safeStreak = 0
	a.lowActivityStreak = 0
	a.feedbackCount = 0
	a.lastFeedbackWindow = 0
	a.feedbackSimulationHold = false
	a.feedbackSimulationTighten = false
	a.saturationChangedSinceFeedback = false
	a.saturatedRelaxationPending = false
	a.hasInserted = false
	a.lastInsert = time.Time{}
	a.normalSince = 0
	a.lastNormalLen = 0
	a.lastNormalAt = time.Time{}
	a.lastNormalArrivalAt = time.Time{}
	a.normalArrivalIATs = nil
	a.normalReferenceAt = time.Time{}
	a.timingDebt = 0

	a.timingIATThreshold = 0
	a.timingIATThresholdValid = false
	a.timingFrozen = false
	a.timingCompleteAfterNormalWrite = false
	a.reservedLength = 0
	a.activeSimulation = nil
	clear(a.simulationTargets)
}

func sameAdaptiveWindows(a, b []featureWindowResult) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Start != b[i].Start || a[i].End != b[i].End || a[i].RecordCount != b[i].RecordCount {
			return false
		}
	}
	return true
}

func (a *adaptiveInserter) rebuildBaselineLocked() {
	a.ready = false
	a.thresholds = nil
	a.burstIATReference = 0
	a.burstIATReferenceValid = false
	if len(a.observations) < adaptiveObservationWindowMinimum {
		return
	}
	model, valid := a.calibrateAdaptiveNaturalWaveModelLocked(a.observations)
	if !valid {
		log.Printf("[WARN] adaptive_baseline_invalid flow_id=%d epoch=%d reason=non_finite_disturbance", a.flowID, a.epochIndex)
		return
	}
	a.observations = append(a.observations[:0], model.observations...)
	a.baseline = model.baseline
	a.thresholds = model.thresholds
	a.burstIATReference = model.burstIATReference
	a.burstIATReferenceValid = model.burstIATReferenceValid
	a.ready = true

	if !a.initialized {
		a.initializeParametersLocked()
	} else {
		// Observation windows may roll to a different legal length set. Keep
		// the non-saturated budget ceiling payable for the complete observed
		// candidate-length set after every baseline rebuild.
		a.clampParametersLocked()
	}
}

func (a *adaptiveInserter) calibrateAdaptiveNaturalWaveModelLocked(windows []featureWindowResult) (adaptiveNaturalWaveModel, bool) {
	epoch := a.stream.epoch
	if epoch == nil {
		return buildAdaptiveNaturalWaveModel(windows)
	}
	if reference, referenceValid, prepared := a.preparedFeatureWindowBurstReferenceLocked(windows); prepared {
		if !referenceValid {
			return adaptiveNaturalWaveModel{}, false
		}
		model, valid := buildAdaptiveNaturalWaveModel(windows)
		model.burstIATReference = reference
		model.burstIATReferenceValid = true
		return model, valid
	}
	reference, referenceValid := estimateBurstIATReferenceForWindows(epoch.records, windows)
	if !referenceValid {
		return adaptiveNaturalWaveModel{}, false
	}
	return a.buildAdaptiveNaturalWaveModelWithBurstReferenceLocked(windows, reference, true)
}

// preparedFeatureWindowBurstReferenceLocked reports whether windows are a
// suffix of the feature-window timeline most recently recomputed by the
// stream. Production baseline and fallback histories always have this shape.
// Hand-built windows retain the recomputation path as a defensive fallback.
func (a *adaptiveInserter) preparedFeatureWindowBurstReferenceLocked(
	windows []featureWindowResult,
) (reference float64, valid bool, prepared bool) {
	epoch := a.stream.epoch
	if epoch == nil || len(windows) == 0 || len(windows) > len(epoch.featureWindows) ||
		epoch.featureBurstReferenceWindows != len(epoch.featureWindows) {
		return 0, false, false
	}
	start := len(epoch.featureWindows) - len(windows)
	if !sameAdaptiveWindows(epoch.featureWindows[start:], windows) {
		return 0, false, false
	}
	return epoch.featureBurstReference, epoch.featureBurstReferenceValid, true
}

func (a *adaptiveInserter) buildAdaptiveNaturalWaveModelWithBurstReferenceLocked(
	windows []featureWindowResult,
	reference float64,
	referenceValid bool,
) (adaptiveNaturalWaveModel, bool) {
	epoch := a.stream.epoch
	if epoch == nil {
		model, valid := buildAdaptiveNaturalWaveModel(windows)
		model.burstIATReference = reference
		model.burstIATReferenceValid = referenceValid
		return model, valid
	}
	recomputed := a.recomputeAdaptiveFeatureWindowsWithBurstReferenceLocked(
		windows,
		reference,
		referenceValid,
	)
	model, valid := buildAdaptiveNaturalWaveModel(recomputed)
	model.burstIATReference = reference
	model.burstIATReferenceValid = referenceValid
	return model, valid
}

func (a *adaptiveInserter) recomputeAdaptiveFeatureWindowsWithBurstReferenceLocked(
	windows []featureWindowResult,
	reference float64,
	referenceValid bool,
) []featureWindowResult {
	epoch := a.stream.epoch
	if epoch == nil || len(epoch.records) == 0 {
		return recomputeFeatureWindowsWithBurstReferenceAndIATSchema(
			nil,
			windows,
			nil,
			nil,
			reference,
			referenceValid,
			nil,
		)
	}
	for i := 1; i < len(epoch.records); i++ {
		if recordSampleLess(epoch.records[i], epoch.records[i-1]) {
			// Preserve the legacy full-timeline semantics for a pathological
			// regressed epoch; normal TX timelines take the compact path.
			return recomputeFeatureWindowsWithBurstReferenceAndIATSchema(
				epoch.records,
				windows,
				epoch.mainLengths,
				epoch.residualLengthBins,
				reference,
				referenceValid,
				epoch.activeIATSchema(),
			)
		}
	}
	recomputed := make([]featureWindowResult, len(windows))
	for i, window := range windows {
		recomputed[i] = window
		compact := compactDecisionWindowRecords(
			epoch.records,
			epoch.start.Add(window.Start),
			epoch.start.Add(window.End),
			nil,
		)
		recomputed[i].Features = computeRecordWindowFeaturesWithIATSchema(
			compact,
			window.Start,
			window.End,
			window.End-window.Start,
			epoch.mainLengths,
			epoch.residualLengthBins,
			reference,
			referenceValid,
			epoch.activeIATSchema(),
		)
	}
	return recomputed
}

func buildAdaptiveNaturalWaveModel(windows []featureWindowResult) (adaptiveNaturalWaveModel, bool) {
	if len(windows) < adaptiveObservationWindowMinimum {
		return adaptiveNaturalWaveModel{}, false
	}
	baseline := medianRecordWindowFeatures(windows)
	thresholds := make([]float64, len(recordFeatureDisturbanceNames()))
	for _, window := range windows {
		disturbances := recordFeatureDisturbances(window.Features, baseline)
		if !finiteDisturbances(disturbances, len(thresholds)) {
			return adaptiveNaturalWaveModel{}, false
		}
		for i, disturbance := range disturbances {
			if disturbance > thresholds[i] {
				thresholds[i] = disturbance
			}
		}
	}
	lengthQuantizationFloor := adaptiveLengthDistributionQuantizationFloor(windows)
	for _, index := range []int{0, 1} {
		if index < len(thresholds) && thresholds[index] < lengthQuantizationFloor {
			thresholds[index] = lengthQuantizationFloor
		}
	}
	return adaptiveNaturalWaveModel{
		observations: windows,
		baseline:     baseline,
		thresholds:   thresholds,
	}, true
}

func adaptiveLengthDistributionQuantizationFloor(windows []featureWindowResult) float64 {
	counts := make([]float64, 0, len(windows))
	for _, window := range windows {
		if window.RecordCount > 0 {
			counts = append(counts, float64(window.RecordCount))
		}
	}
	medianCount := medianFloat64(counts)
	if medianCount <= 0 {
		return 0
	}
	return 1 / medianCount
}

func (a *adaptiveInserter) initializeParametersLocked() {
	a.ensureObservationCacheLocked()
	history := a.observationCache.normalRecords
	if len(history) == 0 {
		log.Printf("[WARN] adaptive_parameter_init_failed flow_id=%d epoch=%d reason=no_normal_history", a.flowID, a.epochIndex)
		return
	}
	lengths := make([]int, 0, len(history))
	shadowBytes := 0
	for _, sample := range history {
		lengths = append(lengths, sample.Length)
		shadowBytes += sample.Length
	}
	sort.Ints(lengths)
	medianLength := medianSortedInts(lengths)
	if medianLength <= 0 {
		log.Printf("[WARN] adaptive_parameter_init_failed flow_id=%d epoch=%d reason=invalid_median_length", a.flowID, a.epochIndex)
		return
	}
	deltas := a.observationCache.sortedIATs
	if len(deltas) == 0 {
		log.Printf("[WARN] adaptive_parameter_init_failed flow_id=%d epoch=%d reason=no_positive_iat", a.flowID, a.epochIndex)
		return
	}
	medianIAT := nearestDurationQuantile(deltas, 0.50)
	windowWidth := a.stream.epoch.featureWidth
	a.parameterMedianLen = medianLength
	a.parameterWindow = windowWidth
	if a.saturationKnown && a.saturated {
		a.params.NMin = adaptiveSaturatedNMinInit
		a.params.TMin = medianIAT
		a.params.Alpha = adaptiveSaturatedAlphaInit
		a.params.BMax = 2 * medianLength
	} else {
		a.params.NMin = adaptiveNonSaturatedNMinInit
		a.params.TMin = maxDuration(nearestDurationQuantile(deltas, 0.75), windowWidth/8)
		a.params.Alpha = adaptiveUnknownAlphaInit
		if a.saturationKnown {
			a.params.Alpha = adaptiveNonSaturatedAlphaInit
		}
		a.params.BMax = medianLength
	}
	a.initialized = true
	// Credit the normal bytes already observed during the K-window warm-up.
	// This avoids starting a short non-saturated stable opportunity at zero
	// budget while preserving the same alpha-controlled byte ratio.
	a.params.Budget = a.params.Alpha * float64(shadowBytes)
	a.clampParametersLocked()
	if len(a.observations) > 0 {
		a.lastFeedbackWindow = a.observations[len(a.observations)-1].End
	}
	a.saturationChangedSinceFeedback = false

}

func (a *adaptiveInserter) parameterBoundsLocked() adaptiveParameterBounds {
	medianLength := a.parameterMedianLen
	if medianLength <= 0 {
		medianLength = float64(minEmbeddedTLSRecordLen() + 1)
	}
	if a.saturationKnown && a.saturated {
		candidateCeiling := a.maximumObservedCandidateLengthLocked()
		budgetUnit := float64(candidateCeiling)
		if budgetUnit <= 0 {
			budgetUnit = medianLength
		}
		bounds := adaptiveParameterBounds{
			NLo: adaptiveSaturatedNMinMin, NHi: adaptiveFeedbackNMinMax,
			TLo: 0, THi: adaptiveFeedbackTMinMax,
			AlphaLo: 0.005, AlphaHi: adaptiveSaturatedAlphaMax,
			BMaxLo: budgetUnit, BMaxHi: adaptiveSaturatedBMaxFactor * budgetUnit,
		}
		if a.saturatedRelaxationPending {
			minimumCandidate, _ := a.minimumObservedCandidateLengthLocked()
			bounds.AlphaLo = 0.001
			bounds.BMaxLo = float64(minimumCandidate)
		}
		return bounds
	}
	maximumCandidate := a.maximumObservedCandidateLengthLocked()
	budgetFloor := float64(maximumCandidate)
	budgetCeiling := math.Max(2*medianLength, budgetFloor)
	alphaHigh := adaptiveUnknownAlphaMax
	if a.saturationKnown {
		alphaHigh = adaptiveNonSaturatedAlphaMax
	}
	return adaptiveParameterBounds{
		NLo: adaptiveNonSaturatedNMinMin, NHi: adaptiveFeedbackNMinMax,
		TLo: 0, THi: adaptiveFeedbackTMinMax,
		AlphaLo: 0.001, AlphaHi: alphaHigh,
		BMaxLo: budgetFloor, BMaxHi: budgetCeiling,
	}
}

func (a *adaptiveInserter) clampParametersLocked() {
	if !a.initialized {
		return
	}
	bounds := a.parameterBoundsLocked()
	a.params.NMin = clampInt(a.params.NMin, bounds.NLo, bounds.NHi)
	a.params.TMin = clampDuration(a.params.TMin, bounds.TLo, bounds.THi)
	a.params.Alpha = clampFloat(a.params.Alpha, bounds.AlphaLo, bounds.AlphaHi)
	a.params.BMax = clampFloat(a.params.BMax, bounds.BMaxLo, bounds.BMaxHi)
	a.params.Budget = clampFloat(a.params.Budget, 0, a.params.BMax)
	if a.saturatedRelaxationPending && a.saturationKnown && a.saturated {
		candidateCeiling := a.maximumObservedCandidateLengthLocked()
		budgetFloor := float64(candidateCeiling)
		if budgetFloor <= 0 {
			budgetFloor = a.parameterMedianLen
		}
		if a.params.Alpha+scalarEpsilon >= 0.005 &&
			a.params.BMax+scalarEpsilon >= budgetFloor {
			a.saturatedRelaxationPending = false
		}
	}
}

func (a *adaptiveInserter) observeNormalArrivalLocked(
	arrivalAt time.Time,
	trusted bool,
	directNormalAt time.Time,
) adaptiveNormalArrival {
	arrival := adaptiveNormalArrival{
		ReferenceAt: directNormalAt,
		Trusted:     trusted && !arrivalAt.IsZero(),
	}
	if !arrival.Trusted {
		a.lastNormalArrivalAt = time.Time{}
		if a.timingEpisodeActiveLocked() && !a.normalReferenceAt.IsZero() {
			fallback := a.medianNormalArrivalIATLocked()
			if fallback > 0 {
				arrival.IAT = fallback
				arrival.ReferenceAt = a.normalReferenceAt.Add(fallback)
				a.normalReferenceAt = arrival.ReferenceAt
			} else {
				arrival.ReferenceAt = time.Time{}
			}
		}
		return arrival
	}

	if !a.lastNormalArrivalAt.IsZero() {
		delta := arrivalAt.Sub(a.lastNormalArrivalAt)
		if delta >= 0 {
			arrival.IAT = delta
			arrival.IATValid = true
			a.normalArrivalIATs = append(a.normalArrivalIATs, delta)
			if len(a.normalArrivalIATs) > adaptiveTimingIATHistoryLimit {
				a.normalArrivalIATs = append(
					a.normalArrivalIATs[:0],
					a.normalArrivalIATs[len(a.normalArrivalIATs)-adaptiveTimingIATHistoryLimit:]...,
				)
			}
		} else {
			arrival.Trusted = false
			a.lastNormalArrivalAt = time.Time{}
			if a.timingEpisodeActiveLocked() && !a.normalReferenceAt.IsZero() {
				fallback := a.medianNormalArrivalIATLocked()
				if fallback > 0 {
					arrival.IAT = fallback
					arrival.ReferenceAt = a.normalReferenceAt.Add(fallback)
					a.normalReferenceAt = arrival.ReferenceAt
				} else {
					arrival.ReferenceAt = time.Time{}
				}
			}
			return arrival
		}
	}
	a.lastNormalArrivalAt = arrivalAt

	if a.timingEpisodeActiveLocked() && arrival.IATValid && !a.normalReferenceAt.IsZero() {
		arrival.ReferenceAt = a.normalReferenceAt.Add(arrival.IAT)
	}
	a.normalReferenceAt = arrival.ReferenceAt
	return arrival
}

// adaptiveShortRecordIAT is an O(1) admission guard. Prefer the kernel RX IAT
// when it is available, then fall back to the already-computed egress
// prediction. It deliberately performs no clock read, allocation or history
// scan: outside an active timing-debt episode, sub-64us bursts should continue
// through the forwarding path without paying for an insertion simulation.
// Active timing debt is handled before this admission guard, so short-IAT
// Records follow the same hold and repayment policy as every other Record.
func adaptiveShortRecordIAT(
	arrival adaptiveNormalArrival,
	directNormalAt time.Time,
	lastNormalAt time.Time,
) (time.Duration, string, bool) {
	if arrival.IATValid && arrival.IAT >= 0 && arrival.IAT < adaptiveShortRecordIATThreshold {
		return arrival.IAT, "rx", true
	}
	if directNormalAt.IsZero() || lastNormalAt.IsZero() {
		return 0, "", false
	}
	predictedIAT := directNormalAt.Sub(lastNormalAt)
	if predictedIAT >= 0 && predictedIAT < adaptiveShortRecordIATThreshold {
		return predictedIAT, "predicted_egress", true
	}
	return 0, "", false
}

func (a *adaptiveInserter) timingEpisodeActiveLocked() bool {
	if a.saturationKnown && a.saturated {
		return false
	}
	return a.timingFrozen
}

func (a *adaptiveInserter) finishTimingEpisodeLocked() {
	if !a.timingFrozen {
		return
	}
	a.normalReferenceAt = time.Time{}
	a.timingDebt = 0

	a.timingIATThreshold = 0
	a.timingIATThresholdValid = false
	a.timingFrozen = false
	a.timingCompleteAfterNormalWrite = false
}

func (a *adaptiveInserter) medianNormalArrivalIATLocked() time.Duration {
	if len(a.normalArrivalIATs) == 0 {
		return 0
	}
	values := append([]time.Duration(nil), a.normalArrivalIATs...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return nearestDurationQuantile(values, 0.50)
}

func (a *adaptiveInserter) timingFinalDebtThresholdLocked() time.Duration {
	threshold := adaptiveTimingFinalDebtFloor
	fromMedian := time.Duration(
		adaptiveTimingFinalDebtIATFraction * float64(a.medianNormalArrivalIATLocked()),
	)
	if fromMedian > threshold {
		threshold = fromMedian
	}
	return threshold
}

func adaptiveTimingIATThreshold(thresholds []float64) (float64, bool) {
	if adaptiveTimingIATDisturbanceIndex < 0 ||
		adaptiveTimingIATDisturbanceIndex >= len(thresholds) {
		return 0, false
	}
	threshold := thresholds[adaptiveTimingIATDisturbanceIndex]
	return threshold, finiteNonNegative(threshold)
}

func (a *adaptiveInserter) planTimingRepaymentLocked(
	normalLength int,
	plannedAt time.Time,
	directNormalAt time.Time,
	arrival adaptiveNormalArrival,
) adaptiveDecision {
	baselineIAT := arrival.IAT
	if !arrival.IATValid {
		baselineIAT = a.medianNormalArrivalIATLocked()
	}
	if baselineIAT < 0 || arrival.ReferenceAt.IsZero() || directNormalAt.IsZero() {

		return adaptiveDecision{}
	}
	if a.timingDebt <= 0 {

		a.timingCompleteAfterNormalWrite = true
		return adaptiveDecision{}
	}

	debtBefore := a.timingDebt
	noRepaymentTarget := arrival.ReferenceAt.Add(debtBefore)
	// If even an immediate write is already too late for the unchanged-debt
	// target, a sufficiently small final tail has already elapsed naturally:
	// count it as repaid and close the episode after this normal write succeeds.
	// Larger debt is preserved because late execution must not silently erase a
	// material amount of planned delay.
	if !plannedAt.Before(noRepaymentTarget) || !directNormalAt.Before(noRepaymentTarget) {
		if debtBefore <= a.timingFinalDebtThresholdLocked() {
			a.timingDebt = 0
			a.timingCompleteAfterNormalWrite = true

			return adaptiveDecision{}
		}

		return adaptiveDecision{}
	}

	maximumRepayment := time.Duration(
		adaptiveTimingMaxDebtRepaymentFraction * float64(debtBefore),
	)
	if maximumRepayment <= 0 {
		maximumRepayment = time.Nanosecond
	}
	repaymentCandidates := make([]time.Duration, 0, 6)
	if debtBefore <= a.timingFinalDebtThresholdLocked() {
		// A small tail may be closed in one Record, but only if the dynamic IAT
		// comparison accepts the complete contraction.
		repaymentCandidates = append(repaymentCandidates, debtBefore)
	}
	repaymentCandidates = append(repaymentCandidates,
		maximumRepayment,
		3*maximumRepayment/4,
		maximumRepayment/2,
		maximumRepayment/4,
	)
	repaymentCandidates = uniquePositiveDurations(repaymentCandidates)
	// Only a real consecutive RX IAT and a reliable egress model may authorize
	// intentional repayment. The zero candidate below still preserves debt.
	switch {
	case !arrival.IATValid:
		repaymentCandidates = nil
	case baselineIAT <= 0:
		repaymentCandidates = nil
	case !a.predictor.Initialized():
		repaymentCandidates = nil
	}
	repaymentCandidates = append(repaymentCandidates, 0)

	virtualID := uint64(math.MaxUint64)
	noRepaymentSubmitAt := plannedAt.Add(noRepaymentTarget.Sub(directNormalAt))
	noRepaymentPredictedAt := a.predictor.Estimate(noRepaymentSubmitAt, normalLength)
	for _, requestedRepayment := range repaymentCandidates {
		if requestedRepayment > baselineIAT || requestedRepayment > debtBefore {
			continue
		}
		debtAfter := debtBefore - requestedRepayment
		desiredEgressAt := arrival.ReferenceAt.Add(debtAfter)
		if !plannedAt.Before(desiredEgressAt) || !directNormalAt.Before(desiredEgressAt) {
			continue
		}
		submitAt := plannedAt
		submitAt = submitAt.Add(desiredEgressAt.Sub(directNormalAt))
		predictedAt := a.predictor.Estimate(submitAt, normalLength)
		if predictedAt.IsZero() {
			continue
		}
		if !a.lastNormalAt.IsZero() && predictedAt.Before(a.lastNormalAt) {
			continue
		}

		if requestedRepayment > 0 {
			allowed := a.timingRepaymentIATCheckLocked(
				noRepaymentPredictedAt,
				predictedAt,
				virtualID,
			)
			if !allowed {
				continue
			}
		}
		a.timingDebt = debtAfter
		a.timingCompleteAfterNormalWrite = debtAfter == 0

		return adaptiveDecision{HoldUntil: submitAt}
	}

	return adaptiveDecision{}
}

// timingRepaymentIATCheckLocked compares the same current normal Record twice:
// once at the unchanged-debt egress time and once at the candidate repayment
// time. Only IAT distributions participate. The RX distribution is rebuilt
// from recent normal arrivals for every Record, so natural traffic evolution
// cannot leave an episode pinned to an unrelated, insertion-time length model.
func (a *adaptiveInserter) timingRepaymentIATCheckLocked(
	noRepaymentAt time.Time,
	candidateAt time.Time,
	virtualID uint64,
) bool {
	check := adaptiveTimingIATCheck{
		NaturalThreshold: a.timingIATThreshold,
	}
	if !a.timingIATThresholdValid ||
		math.IsNaN(check.NaturalThreshold) ||
		math.IsInf(check.NaturalThreshold, 0) ||
		check.NaturalThreshold < 0 {
		return false
	}
	if noRepaymentAt.IsZero() || candidateAt.IsZero() {
		return false
	}

	referenceSamples := minInt(len(a.normalArrivalIATs), adaptiveTimingIATHistoryLimit)
	if referenceSamples <= 0 {
		return false
	}
	records := a.decisionRecordTailLocked(referenceSamples)
	availableEgressIATs := len(records)
	if availableEgressIATs < referenceSamples {
		referenceSamples = availableEgressIATs
	}
	if referenceSamples <= 0 {
		return false
	}
	var iatSchema *iatDistributionSchema
	if epoch := a.stream.epoch; epoch != nil {
		iatSchema = epoch.activeIATSchema()
	}

	noRepaymentDist, valid := timingRecordIATDistributionWithSchema(
		records,
		recordSample{
			EstimatedEgressAt: noRepaymentAt,
			EgressID:          virtualID,
		},
		referenceSamples,
		iatSchema,
	)
	if !valid {
		return false
	}
	candidateDist, valid := timingRecordIATDistributionWithSchema(
		records,
		recordSample{
			EstimatedEgressAt: candidateAt,
			EgressID:          virtualID,
		},
		referenceSamples,
		iatSchema,
	)
	if !valid {
		return false
	}
	rxDist, valid := durationIATDistributionWithSchema(
		a.normalArrivalIATs[len(a.normalArrivalIATs)-referenceSamples:],
		iatSchema,
	)
	if !valid {
		return false
	}

	iatPositions := iatDistributionPositions(iatSchema)
	check.CandidateDistance = wasserstein1D(candidateDist, rxDist, iatPositions)
	check.NoRepaymentDistance = wasserstein1D(noRepaymentDist, rxDist, iatPositions)
	check.IncrementalDistance = wasserstein1D(candidateDist, noRepaymentDist, iatPositions)
	check.AllowedDistance = math.Max(check.NoRepaymentDistance, check.NaturalThreshold)
	check.Valid = finiteNonNegative(check.CandidateDistance) &&
		finiteNonNegative(check.NoRepaymentDistance) &&
		finiteNonNegative(check.IncrementalDistance) &&
		finiteNonNegative(check.AllowedDistance)
	if !check.Valid {
		return false
	}

	// If the unchanged-debt timeline already differs from RX because of
	// ordinary traffic evolution, repayment may improve it but may not make it
	// worse. While inside the normal envelope, the candidate must remain inside
	// that envelope and its incremental perturbation must also fit the learned
	// natural IAT scale.
	improvesOrPreserves := check.CandidateDistance <= check.NoRepaymentDistance+scalarEpsilon
	withinEnvelope := check.CandidateDistance <= check.AllowedDistance+scalarEpsilon
	incrementWithin := check.IncrementalDistance <= check.NaturalThreshold+scalarEpsilon
	if !withinEnvelope || (!improvesOrPreserves && !incrementWithin) {
		return false
	}
	return true
}

func timingRecordIATDistribution(
	records []recordSample,
	current recordSample,
	sampleCount int,
) ([]float64, bool) {
	return timingRecordIATDistributionWithSchema(records, current, sampleCount, nil)
}

func timingRecordIATDistributionWithSchema(
	records []recordSample,
	current recordSample,
	sampleCount int,
	iatSchema *iatDistributionSchema,
) ([]float64, bool) {
	if current.FeatureTime().IsZero() || current.EgressID == 0 || sampleCount <= 0 {
		return nil, false
	}
	if len(records) == 0 {
		return nil, false
	}
	last := records[len(records)-1]
	lastAt, currentAt := last.FeatureTime(), current.FeatureTime()
	if currentAt.Before(lastAt) || (currentAt.Equal(lastAt) && current.EgressID < last.EgressID) {
		return nil, false
	}
	if sampleCount > len(records) {
		sampleCount = len(records)
	}
	distribution := make([]float64, len(iatDistributionPositions(iatSchema)))
	start := len(records) - sampleCount
	for i := start + 1; i < len(records); i++ {
		delta := records[i].FeatureTime().Sub(records[i-1].FeatureTime())
		if delta < 0 {
			return nil, false
		}
		distribution[iatBinWithSchema(delta, iatSchema)]++
	}
	delta := currentAt.Sub(lastAt)
	if delta < 0 {
		return nil, false
	}
	distribution[iatBinWithSchema(delta, iatSchema)]++
	normalize(distribution, float64(sampleCount))
	return distribution, true
}

func durationIATDistribution(iats []time.Duration) ([]float64, bool) {
	return durationIATDistributionWithSchema(iats, nil)
}

func durationIATDistributionWithSchema(
	iats []time.Duration,
	iatSchema *iatDistributionSchema,
) ([]float64, bool) {
	if len(iats) == 0 {
		return nil, false
	}
	distribution := make([]float64, len(iatDistributionPositions(iatSchema)))
	for _, iat := range iats {
		if iat < 0 {
			return nil, false
		}
		distribution[iatBinWithSchema(iat, iatSchema)]++
	}
	normalize(distribution, float64(len(iats)))
	return distribution, true
}

func finiteNonNegative(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

func uniquePositiveDurations(values []time.Duration) []time.Duration {
	seen := make(map[time.Duration]struct{}, len(values))
	out := make([]time.Duration, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func (a *adaptiveInserter) Decide(normalLength int, plannedAt time.Time, keysReady bool) adaptiveDecision {
	return a.DecideWithArrival(normalLength, plannedAt, plannedAt, true, keysReady)
}

// lockForForwardPath marks a normal or embedded Record's forward path as
// waiting so timestamp-feedback flushing can yield after its current event.
// TryLock also tells decision callers whether they already paid a lock-wait
// penalty and should avoid compounding it with optional simulation work.
func (a *adaptiveInserter) lockForForwardPath() (contended bool) {
	if a.mu.TryLock() {
		return false
	}
	a.forwardWaiters.Add(1)
	a.mu.Lock()
	a.forwardWaiters.Add(-1)
	return true
}

func adaptiveDecisionWorkElapsed(startedAt, now time.Time) (time.Duration, bool) {
	if startedAt.IsZero() || now.Before(startedAt) {
		return 0, false
	}
	elapsed := now.Sub(startedAt)
	return elapsed, elapsed >= adaptiveDecisionWorkBudget
}

func (a *adaptiveInserter) decisionWorkBudgetSkipLocked(startedAt time.Time) (adaptiveDecision, bool) {
	_, exceeded := adaptiveDecisionWorkElapsed(startedAt, time.Now())
	if !exceeded {
		return adaptiveDecision{}, false
	}
	return adaptiveDecision{}, true
}

func (a *adaptiveInserter) DecideWithArrival(
	normalLength int,
	plannedAt time.Time,
	arrivalAt time.Time,
	arrivalTrusted bool,
	keysReady bool,
) adaptiveDecision {
	if a == nil || !a.enabled {
		return adaptiveDecision{}
	}

	lockContended := a.lockForForwardPath()

	defer a.mu.Unlock()

	if normalLength <= 0 {
		return adaptiveDecision{}
	}
	if plannedAt.IsZero() {
		return adaptiveDecision{}
	}

	a.syncSegmentLocked()

	normalAt := a.predictor.Estimate(plannedAt, normalLength)
	arrival := a.observeNormalArrivalLocked(arrivalAt, arrivalTrusted, normalAt)

	if a.timingEpisodeActiveLocked() {

		decision := a.planTimingRepaymentLocked(normalLength, plannedAt, normalAt, arrival)

		return decision
	}
	if lockContended {
		// This Record already waited behind adaptive feedback or another
		// decision. It cannot have an active timing debt (handled above), so
		// conservatively skip the optional insertion instead of extending the
		// pause with window construction and candidate simulation.
		return adaptiveDecision{}
	}
	if _, _, short := adaptiveShortRecordIAT(arrival, normalAt, a.lastNormalAt); short {
		return adaptiveDecision{}
	}
	if !arrival.Trusted && (!a.saturationKnown || !a.saturated) {
		a.safeStreak = 0
		return adaptiveDecision{}
	}
	if !keysReady {
		return adaptiveDecision{}
	}
	predictorStatus := a.predictor.Status()
	if !predictorStatus.Initialized {
		a.safeStreak = 0
		return adaptiveDecision{}
	}
	epoch := a.stream.epoch
	if epoch == nil {
		return adaptiveDecision{}
	}
	if a.invalidEpoch == epoch.index {
		return adaptiveDecision{}
	}
	if !epoch.inStableSegment {
		return adaptiveDecision{}
	}
	if !epoch.featureWidthChosen || epoch.featureWidth <= 0 {
		return adaptiveDecision{}
	}
	if len(epoch.records) == 0 {
		return adaptiveDecision{}
	}
	if !a.segmentActive {
		return adaptiveDecision{}
	}
	if !a.ready {
		return adaptiveDecision{}
	}
	if !a.initialized {
		return adaptiveDecision{}
	}
	if a.reservedLength != 0 {
		return adaptiveDecision{}
	}
	if a.activeSimulation != nil {
		return adaptiveDecision{}
	}

	// These O(1) gates used to run after constructing and evaluating the full
	// feature window. During a burst almost every Record is rejected by one of
	// them, so reject first and leave the expensive path only to real insertion
	// opportunities.
	idleThreshold := a.stream.idleGapThreshold()
	if a.lastNormalAt.IsZero() {
		a.safeStreak = 0
		return adaptiveDecision{}
	}
	idleFor := normalAt.Sub(a.lastNormalAt)
	if idleFor < 0 {
		a.safeStreak = 0
		return adaptiveDecision{}
	}
	if idleFor > idleThreshold {
		return adaptiveDecision{}
	}
	if a.hasInserted && a.normalSince < a.params.NMin {
		return adaptiveDecision{}
	}
	if a.hasInserted {
		sinceInsert := normalAt.Sub(a.lastInsert)
		if sinceInsert < a.params.TMin {
			return adaptiveDecision{}
		}
	}
	if (!a.saturationKnown || !a.saturated) && len(a.normalArrivalIATs) < adaptiveTimingMinimumHistory {
		return adaptiveDecision{}

	}
	minimumLength, historyCount := a.minimumObservedCandidateLengthLocked()
	if historyCount == 0 {
		return adaptiveDecision{}
	}
	if a.lastNormalLen <= 0 {
		return adaptiveDecision{}
	}
	if minimumLength == 0 {
		return adaptiveDecision{}
	}
	// Do not let the current token balance filter the length distribution.
	// Wait for the largest observed legal length before any feature simulation
	// or random draw.
	requiredBudget := a.maximumObservedCandidateLengthLocked()
	if a.params.Budget+scalarEpsilon < float64(requiredBudget) {
		return adaptiveDecision{}
	}

	// From here on every operation is optional insertion work. Bound the time
	// spent while holding adaptive state so an unusually expensive window or
	// candidate set cannot turn one insertion opportunity into a long pause for
	// following normal Records.
	decisionWorkStartedAt := time.Now()
	delays := a.candidateDelaysLocked(idleThreshold)
	if len(delays) == 0 {
		return adaptiveDecision{}
	}
	if decision, stop := a.decisionWorkBudgetSkipLocked(decisionWorkStartedAt); stop {
		return decision
	}

	decisionRecords, latestAt := a.decisionWindowRecordsForDecisionLocked(normalAt, epoch.featureWidth)

	if normalAt.Before(latestAt) {
		return adaptiveDecision{}
	}
	if decision, stop := a.decisionWorkBudgetSkipLocked(decisionWorkStartedAt); stop {
		return decision
	}

	current, currentRecords, ok := a.simulatedWindowFromDecisionRecordsForDecisionLocked(normalAt, decisionRecords, []recordSample{{
		SubmittedAt:       plannedAt,
		EstimatedEgressAt: normalAt,
		Length:            normalLength,
		EgressID:          math.MaxUint64,
	}}, &a.currentFeatureScratch)

	if !ok {

		a.safeStreak = 0
		return adaptiveDecision{}
	}
	if decision, stop := a.decisionWorkBudgetSkipLocked(decisionWorkStartedAt); stop {
		return decision
	}
	currentNormalCount := 0
	for _, sample := range currentRecords {
		if !sample.Embedded {
			currentNormalCount++
		}
	}
	minimumActive := maxInt(2, int(math.Floor(adaptiveActiveRatio*a.medianObservationNormalCountLocked())))
	suitability := a.flowSuitabilityLocked(
		currentRecords,
		idleFor,
		idleThreshold,
		currentNormalCount,
		minimumActive,
	)
	if !suitability.active || !suitability.stable || !suitability.saturationStable {
		a.safeStreak = 0
	}
	a.maybeSuitabilityFeedbackLocked(suitability)
	if currentNormalCount < minimumActive {
		return adaptiveDecision{}
	}
	lengths := a.candidateLengthsLocked(current.Features, normalLength)
	if len(lengths) == 0 {
		return adaptiveDecision{}
	}
	if decision, stop := a.decisionWorkBudgetSkipLocked(decisionWorkStartedAt); stop {
		return decision
	}
	// Natural-wave comparison is the expensive part of the precheck,
	// especially when it falls back to broader observation histories. All
	// gates above make insertion impossible independently of that comparison.

	naturalModel, within, valid, _ := a.selectNaturalWaveModelLocked(current.Features)

	if !valid {

		return adaptiveDecision{}
	}
	if !within {

		return adaptiveDecision{}
	}
	if decision, stop := a.decisionWorkBudgetSkipLocked(decisionWorkStartedAt); stop {
		return decision
	}

	invalidSimulations := 0
	disturbanceRejected := 0
	lastViolation := ""
	for _, candidate := range lengths {
		for _, delay := range delays {
			if decision, stop := a.decisionWorkBudgetSkipLocked(decisionWorkStartedAt); stop {
				return decision
			}
			estimated := a.predictor.EstimateSequence([]timestampPredictionInput{
				{SubmittedAt: plannedAt, Length: candidate.Length},
				{SubmittedAt: plannedAt.Add(delay), Length: normalLength},
			})
			if len(estimated) != 2 || estimated[0].IsZero() || estimated[1].IsZero() {
				invalidSimulations++
				continue
			}
			timingDebt := maxDuration(0, estimated[1].Sub(normalAt))

			embeddedVirtualID := uint64(math.MaxUint64 - 1)
			normalVirtualID := uint64(math.MaxUint64)
			virtual := []recordSample{
				{
					SubmittedAt:       plannedAt,
					EstimatedEgressAt: estimated[0],
					Length:            candidate.Length,
					EgressID:          embeddedVirtualID,
					Embedded:          true,
				},
				{
					SubmittedAt:       plannedAt.Add(delay),
					EstimatedEgressAt: estimated[1],
					Length:            normalLength,
					EgressID:          normalVirtualID,
				},
			}
			var features featureWindowResult
			var local []recordSample
			var valid bool
			if estimated[1].Before(normalAt) {
				// A predictor model should normally move the paired normal Record
				// forward. Preserve full-history semantics if it ever regresses.
				features, local, valid = a.simulatedWindowLocked(estimated[1], virtual)
			} else {
				features, local, valid = a.simulatedWindowFromDecisionRecordsForDecisionLocked(
					estimated[1],
					decisionRecords,
					virtual,
					&a.candidateFeatureScratch,
				)
			}
			if !valid {

				invalidSimulations++
				continue
			}
			if !recordsContainEgressIDs(local, embeddedVirtualID, normalVirtualID) {

				invalidSimulations++
				lastViolation = "candidate_pair_outside_window"
				continue
			}
			disturbances := recordFeatureDisturbances(features.Features, naturalModel.baseline)
			within, valid, violation := naturalWaveCheck(disturbances, naturalModel.thresholds)
			if !valid {

				invalidSimulations++
				lastViolation = violation
				continue
			}
			if !within {

				disturbanceRejected++
				lastViolation = violation
				continue
			}
			if decision, stop := a.decisionWorkBudgetSkipLocked(decisionWorkStartedAt); stop {
				return decision
			}
			a.params.Budget -= float64(candidate.Length)
			a.reservedLength = candidate.Length
			a.activeSimulation = &adaptiveSimulationFeedback{
				epochIndex:  epoch.index,
				windowWidth: epoch.featureWidth,
				stableStart: epoch.stableStart,

				predicted:              cloneRecordWindowFeatures(features.Features),
				baseline:               cloneRecordWindowFeatures(naturalModel.baseline),
				thresholds:             append([]float64(nil), naturalModel.thresholds...),
				burstIATReference:      naturalModel.burstIATReference,
				burstIATReferenceValid: naturalModel.burstIATReferenceValid,

				embeddedLength:    candidate.Length,
				normalLength:      normalLength,
				timingReferenceAt: arrival.ReferenceAt,
				timingDebt:        timingDebt,
			}

			return adaptiveDecision{Insert: true, Length: candidate.Length, Delay: delay}
		}
	}
	detail := fmt.Sprintf("attempted=%d invalid=%d disturbance_rejected=%d", len(lengths)*len(delays), invalidSimulations, disturbanceRejected)
	if lastViolation != "" {
		detail += " last=" + lastViolation
	}
	return adaptiveDecision{}
}

func (a *adaptiveInserter) simulatedWindowLocked(endEventAt time.Time, virtual []recordSample) (featureWindowResult, []recordSample, bool) {
	return a.simulatedWindowWithBurstReferenceLocked(
		endEventAt,
		virtual,
		a.burstIATReference,
		a.burstIATReferenceValid,
	)
}

func (a *adaptiveInserter) feedbackWindowAvailableLocked(endEventAt time.Time) bool {
	epoch := a.stream.epoch
	if epoch == nil || epoch.featureWidth <= 0 || endEventAt.IsZero() {
		return false
	}
	endAt := endEventAt.Add(time.Nanosecond)
	startAt := endAt.Add(-epoch.featureWidth)
	if startAt.Sub(epoch.start) < epoch.stableStart {
		return false
	}
	count := 0
	countSample := func(sample recordSample) {
		featureAt := sample.FeatureTime()
		if sample.Length > 0 && !featureAt.IsZero() && !featureAt.Before(startAt) && featureAt.Before(endAt) {
			count++
		}
	}
	for _, sample := range epoch.records {
		countSample(sample)
	}
	// pending and resolved are disjoint from the already committed epoch and
	// from each other in the live egress lifecycle.
	for _, event := range a.resolved {
		countSample(recordSampleFromEgressEvent(event))
	}
	for _, event := range a.pending {
		countSample(recordSampleFromEgressEvent(event))
	}
	return count >= minFeatureWindowRecords
}

func (a *adaptiveInserter) simulatedWindowWithBurstReferenceLocked(
	endEventAt time.Time,
	virtual []recordSample,
	burstIATReference float64,
	burstIATReferenceValid bool,
) (featureWindowResult, []recordSample, bool) {
	epoch := a.stream.epoch
	if epoch == nil || epoch.featureWidth <= 0 || len(epoch.records) == 0 {
		return featureWindowResult{}, nil, false
	}
	records := a.decisionRecordsLocked()
	return a.simulatedWindowFromDecisionRecordsWithBurstReferenceLocked(
		endEventAt,
		records,
		virtual,
		burstIATReference,
		burstIATReferenceValid,
	)
}

func (a *adaptiveInserter) simulatedWindowFromDecisionRecordsLocked(
	endEventAt time.Time,
	decisionRecords []recordSample,
	virtual []recordSample,
) (featureWindowResult, []recordSample, bool) {
	return a.simulatedWindowFromDecisionRecordsWithBurstReferenceLocked(
		endEventAt,
		decisionRecords,
		virtual,
		a.burstIATReference,
		a.burstIATReferenceValid,
	)
}

func (a *adaptiveInserter) simulatedWindowFromDecisionRecordsForDecisionLocked(
	endEventAt time.Time,
	decisionRecords []recordSample,
	virtual []recordSample,
	featureScratch *recordWindowFeatureScratch,
) (featureWindowResult, []recordSample, bool) {
	epoch := a.stream.epoch
	if epoch == nil || epoch.featureWidth <= 0 || len(decisionRecords) == 0 || endEventAt.IsZero() {
		return featureWindowResult{}, nil, false
	}
	endAt := endEventAt.Add(time.Nanosecond)
	startAt := endAt.Add(-epoch.featureWidth)
	records, ordered := compactDecisionWindowRecordsInto(
		a.candidateWindowScratch[:0],
		decisionRecords,
		startAt,
		endAt,
		virtual,
	)
	a.candidateWindowScratch = records
	if ordered {
		return a.windowFromOrderedRecordsWithBurstReferenceAndScratchLocked(
			endEventAt,
			records,
			epoch.featureWidth,
			epoch.stableStart,
			a.burstIATReference,
			a.burstIATReferenceValid,
			featureScratch,
		)
	}
	return a.windowFromRecordsWithBurstReferenceLocked(
		endEventAt,
		records,
		epoch.featureWidth,
		epoch.stableStart,
		a.burstIATReference,
		a.burstIATReferenceValid,
	)
}

func (a *adaptiveInserter) simulatedWindowFromDecisionRecordsWithBurstReferenceLocked(
	endEventAt time.Time,
	decisionRecords []recordSample,
	virtual []recordSample,
	burstIATReference float64,
	burstIATReferenceValid bool,
) (featureWindowResult, []recordSample, bool) {
	epoch := a.stream.epoch
	if epoch == nil || epoch.featureWidth <= 0 || len(decisionRecords) == 0 || endEventAt.IsZero() {
		return featureWindowResult{}, nil, false
	}
	endAt := endEventAt.Add(time.Nanosecond)
	startAt := endAt.Add(-epoch.featureWidth)
	records := compactDecisionWindowRecords(decisionRecords, startAt, endAt, virtual)
	return a.windowFromRecordsWithBurstReferenceLocked(
		endEventAt,
		records,
		epoch.featureWidth,
		epoch.stableStart,
		burstIATReference,
		burstIATReferenceValid,
	)
}

// compactDecisionWindowRecords retains the epoch anchor required by the
// relative-time feature helpers, the complete feature window, and one Record
// on either side for IAT and burst-boundary semantics. The full decision
// timeline is already sorted, while the much smaller result is re-sorted only
// after virtual candidate Records are added.
func compactDecisionWindowRecords(
	decisionRecords []recordSample,
	startAt time.Time,
	endAt time.Time,
	virtual []recordSample,
) []recordSample {
	records, _ := compactDecisionWindowRecordsInto(nil, decisionRecords, startAt, endAt, virtual)
	return records
}

// compactDecisionWindowRecordsInto is the allocation-reusing form used by the
// forwarding path. When both inputs are ordered it merges the one or two
// virtual Records in O(window records), avoiding a stable sort for every
// candidate while retaining identical timestamp/EgressID ordering.
func compactDecisionWindowRecordsInto(
	dst []recordSample,
	decisionRecords []recordSample,
	startAt time.Time,
	endAt time.Time,
	virtual []recordSample,
) ([]recordSample, bool) {
	if len(decisionRecords) == 0 {
		dst = append(dst[:0], virtual...)
		return dst, recordSamplesOrdered(dst)
	}
	first := sort.Search(len(decisionRecords), func(i int) bool {
		return !decisionRecords[i].FeatureTime().Before(startAt)
	})
	last := sort.Search(len(decisionRecords), func(i int) bool {
		return !decisionRecords[i].FeatureTime().Before(endAt)
	})
	contextStart := first
	if contextStart > 0 {
		contextStart--
	}
	contextEnd := last
	if contextEnd < len(decisionRecords) {
		contextEnd++
	}
	capacity := contextEnd - contextStart + len(virtual)
	if contextStart > 0 {
		capacity++
	}
	if cap(dst) < capacity {
		dst = make([]recordSample, 0, capacity)
	} else {
		dst = dst[:0]
	}
	if contextStart > 0 {
		dst = append(dst, decisionRecords[0])
	}
	dst = append(dst, decisionRecords[contextStart:contextEnd]...)
	if len(virtual) == 0 {
		return dst, recordSamplesOrdered(dst)
	}
	if !recordSamplesOrdered(dst) || !recordSamplesOrdered(virtual) {
		dst = append(dst, virtual...)
		return dst, false
	}

	baseLength := len(dst)
	dst = dst[:baseLength+len(virtual)]
	baseIndex := baseLength - 1
	virtualIndex := len(virtual) - 1
	outputIndex := len(dst) - 1
	for baseIndex >= 0 && virtualIndex >= 0 {
		if recordSampleLess(virtual[virtualIndex], dst[baseIndex]) {
			dst[outputIndex] = dst[baseIndex]
			baseIndex--
		} else {
			dst[outputIndex] = virtual[virtualIndex]
			virtualIndex--
		}
		outputIndex--
	}
	for virtualIndex >= 0 {
		dst[outputIndex] = virtual[virtualIndex]
		virtualIndex--
		outputIndex--
	}
	return dst, true
}

func (a *adaptiveInserter) windowFromRecordsLocked(
	endEventAt time.Time,
	records []recordSample,
	width time.Duration,
	stableStart time.Duration,
) (featureWindowResult, []recordSample, bool) {
	return a.windowFromRecordsWithBurstReferenceLocked(
		endEventAt,
		records,
		width,
		stableStart,
		a.burstIATReference,
		a.burstIATReferenceValid,
	)
}

func (a *adaptiveInserter) windowFromRecordsWithBurstReferenceLocked(
	endEventAt time.Time,
	records []recordSample,
	width time.Duration,
	stableStart time.Duration,
	burstIATReference float64,
	burstIATReferenceValid bool,
) (featureWindowResult, []recordSample, bool) {
	epoch := a.stream.epoch
	if epoch == nil || width <= 0 || len(records) == 0 || endEventAt.IsZero() {
		return featureWindowResult{}, nil, false
	}
	if !recordSamplesOrdered(records) {
		sort.SliceStable(records, func(i, j int) bool { return recordSampleLess(records[i], records[j]) })
	}
	return a.windowFromOrderedRecordsWithBurstReferenceLocked(
		endEventAt,
		records,
		width,
		stableStart,
		burstIATReference,
		burstIATReferenceValid,
	)
}

func (a *adaptiveInserter) windowFromOrderedRecordsWithBurstReferenceLocked(
	endEventAt time.Time,
	records []recordSample,
	width time.Duration,
	stableStart time.Duration,
	burstIATReference float64,
	burstIATReferenceValid bool,
) (featureWindowResult, []recordSample, bool) {
	return a.windowFromOrderedRecordsWithBurstReferenceAndScratchLocked(
		endEventAt,
		records,
		width,
		stableStart,
		burstIATReference,
		burstIATReferenceValid,
		nil,
	)
}

func (a *adaptiveInserter) windowFromOrderedRecordsWithBurstReferenceAndScratchLocked(
	endEventAt time.Time,
	records []recordSample,
	width time.Duration,
	stableStart time.Duration,
	burstIATReference float64,
	burstIATReferenceValid bool,
	featureScratch *recordWindowFeatureScratch,
) (featureWindowResult, []recordSample, bool) {
	epoch := a.stream.epoch
	if epoch == nil || width <= 0 || len(records) == 0 || endEventAt.IsZero() {
		return featureWindowResult{}, nil, false
	}
	endAt := endEventAt.Add(time.Nanosecond)
	startAt := endAt.Add(-width)
	start := startAt.Sub(epoch.start)
	end := endAt.Sub(epoch.start)
	if start < stableStart || end <= start {
		return featureWindowResult{}, nil, false
	}
	count := countRecordsInWindow(records, start, end)
	if count < minFeatureWindowRecords {
		return featureWindowResult{}, nil, false
	}
	features := computeRecordWindowFeaturesWithIATSchemaAndScratch(
		records,
		start,
		end,
		width,
		epoch.mainLengths,
		epoch.residualLengthBins,
		burstIATReference,
		burstIATReferenceValid,
		epoch.activeIATSchema(),
		featureScratch,
	)
	local := recordsInRelativeRange(records, start, end)
	return featureWindowResult{Start: start, End: end, RecordCount: count, Features: features}, local, true
}

func recordsContainEgressIDs(records []recordSample, ids ...uint64) bool {
	if len(ids) == 0 {
		return true
	}
	found := make(map[uint64]struct{}, len(ids))
	for _, sample := range records {
		for _, id := range ids {
			if sample.EgressID == id {
				found[id] = struct{}{}
			}
		}
	}
	return len(found) == len(ids)
}

func cloneRecordWindowFeatures(features recordWindowFeatures) recordWindowFeatures {
	features.MixedLengthDist = append([]float64(nil), features.MixedLengthDist...)
	features.LengthDiffDist = append([]float64(nil), features.LengthDiffDist...)
	features.IATDist = append([]float64(nil), features.IATDist...)
	features.IATPositions = append([]float64(nil), features.IATPositions...)
	return features
}

func recordSampleLess(left, right recordSample) bool {
	leftAt, rightAt := left.FeatureTime(), right.FeatureTime()
	if leftAt.Equal(rightAt) {
		return left.EgressID < right.EgressID
	}
	return leftAt.Before(rightAt)
}

func recordSamplesOrdered(records []recordSample) bool {
	for i := 1; i < len(records); i++ {
		if recordSampleLess(records[i], records[i-1]) {
			return false
		}
	}
	return true
}

type adaptiveWindowRecordSelection struct {
	maxEgressID    uint64
	excludeFirstID uint64
	excludeLastID  uint64
}

func (selection adaptiveWindowRecordSelection) includes(sample recordSample) bool {
	id := sample.EgressID
	if id == 0 {
		return true
	}
	if selection.maxEgressID != 0 && id > selection.maxEgressID {
		return false
	}
	return id != selection.excludeFirstID && id != selection.excludeLastID
}

func (selection adaptiveWindowRecordSelection) empty() bool {
	return selection.maxEgressID == 0 && selection.excludeFirstID == 0 && selection.excludeLastID == 0
}

// windowRecordsLocked retains only one feature window, its epoch anchor and
// the adjacent Records needed by IAT/burst features. Ordered epoch history is
// located with binary search; only a regressed timestamp falls back to a full
// scan. selection and replacements let simulation feedback exclude later IDs
// and replace the embedded pair's actual times with its frozen predictions.
func (a *adaptiveInserter) windowRecordsLocked(
	endEventAt time.Time,
	width time.Duration,
	selection adaptiveWindowRecordSelection,
	replacements []recordSample,
) ([]recordSample, time.Time) {
	return a.windowRecordsIntoLocked(nil, endEventAt, width, selection, replacements)
}

func (a *adaptiveInserter) windowRecordsIntoLocked(
	scratch []recordSample,
	endEventAt time.Time,
	width time.Duration,
	selection adaptiveWindowRecordSelection,
	replacements []recordSample,
) (records []recordSample, latestAt time.Time) {
	epoch := a.stream.epoch
	if epoch == nil || len(epoch.records) == 0 || endEventAt.IsZero() || width <= 0 {
		return nil, time.Time{}
	}
	endAt := endEventAt.Add(time.Nanosecond)
	startAt := endAt.Add(-width)
	orderedFirst, orderedLast := 0, 0
	recordCapacity := minInt(len(epoch.records), 512) + len(replacements) + 3
	if epoch.recordsOrdered {
		orderedFirst, orderedLast = recordTimeRangeIndices(epoch.records, startAt, endAt)
		recordCapacity = orderedLast - orderedFirst + len(replacements) + 3
	}
	// Lifecycle maps are usually small. Reserve a bounded amount so a transient
	// timestamp backlog does not force a full-history-sized allocation.
	recordCapacity += minInt(len(a.resolved)+len(a.pending), 512)
	if cap(scratch) < recordCapacity {
		records = make([]recordSample, 0, recordCapacity)
	} else {
		records = scratch[:0]
	}
	anchor := epoch.records[0]
	records = append(records, anchor)
	latestAt = anchor.FeatureTime()
	var predecessor, following recordSample
	havePredecessor, haveFollowing := false, false
	observe := func(sample recordSample, replacement bool) {
		if !replacement && !selection.includes(sample) {
			return
		}
		featureAt := sample.FeatureTime()
		if sample.Length <= 0 || featureAt.IsZero() || featureAt.Before(epoch.start) {
			return
		}
		if featureAt.After(latestAt) {
			latestAt = featureAt
		}
		switch {
		case featureAt.Before(startAt):
			if !havePredecessor || recordSampleLess(predecessor, sample) {
				predecessor = sample
				havePredecessor = true
			}
		case featureAt.Before(endAt):
			records = append(records, sample)
		default:
			if !haveFollowing || recordSampleLess(sample, following) {
				following = sample
				haveFollowing = true
			}
		}
	}
	if epoch.recordsOrdered && selection.empty() && len(replacements) == 0 && len(a.resolved) == 0 && len(a.pending) == 0 {
		// The common decision path needs no sorting or map scan: the epoch slice
		// is already ordered, so splice its compact range directly.
		latestAt = epoch.records[len(epoch.records)-1].FeatureTime()
		if orderedFirst > 1 {
			records = append(records, epoch.records[orderedFirst-1])
		}
		windowFirst := maxInt(orderedFirst, 1)
		if windowFirst < orderedLast {
			records = append(records, epoch.records[windowFirst:orderedLast]...)
		}
		followingIndex := maxInt(orderedLast, 1)
		if followingIndex < len(epoch.records) {
			records = append(records, epoch.records[followingIndex])
		}
		return records, latestAt
	}
	if epoch.recordsOrdered {
		latestAt = epoch.records[len(epoch.records)-1].FeatureTime()
		for i := orderedFirst - 1; i >= 1; i-- {
			if selection.includes(epoch.records[i]) {
				observe(epoch.records[i], false)
				break
			}
		}
		for i := maxInt(orderedFirst, 1); i < orderedLast; i++ {
			observe(epoch.records[i], false)
		}
		for i := maxInt(orderedLast, 1); i < len(epoch.records); i++ {
			if selection.includes(epoch.records[i]) {
				observe(epoch.records[i], false)
				break
			}
		}
	} else {
		for _, sample := range epoch.records[1:] {
			observe(sample, false)
		}
	}
	appendEvent := func(event recordEgressEvent) {
		// Live lifecycle maps contain only IDs not yet committed to the epoch.
		// Keep the guard used by decisionRecordsLocked for defensive callers.
		if event.ID != 0 && event.ID < a.nextID {
			return
		}
		observe(recordSampleFromEgressEvent(event), false)
	}
	for _, event := range a.resolved {
		appendEvent(event)
	}
	for _, event := range a.pending {
		appendEvent(event)
	}
	for _, replacement := range replacements {
		observe(replacement, true)
	}
	if havePredecessor {
		records = append(records, predecessor)
	}
	if haveFollowing {
		records = append(records, following)
	}
	sort.Slice(records, func(i, j int) bool { return recordSampleLess(records[i], records[j]) })
	return records, latestAt
}

// decisionWindowRecordsLocked returns the compact current decision timeline.
// When latestAt is not after endEventAt, it also contains all history required
// by candidate windows whose end moves forward from endEventAt.
func (a *adaptiveInserter) decisionWindowRecordsLocked(
	endEventAt time.Time,
	width time.Duration,
) ([]recordSample, time.Time) {
	return a.windowRecordsLocked(endEventAt, width, adaptiveWindowRecordSelection{}, nil)
}

func (a *adaptiveInserter) decisionWindowRecordsForDecisionLocked(
	endEventAt time.Time,
	width time.Duration,
) ([]recordSample, time.Time) {
	records, latestAt := a.windowRecordsIntoLocked(
		a.decisionWindowScratch[:0],
		endEventAt,
		width,
		adaptiveWindowRecordSelection{},
		nil,
	)
	a.decisionWindowScratch = records
	return records, latestAt
}

func (a *adaptiveInserter) simulationWindowRecordsLocked(
	endEventAt time.Time,
	width time.Duration,
	maxEgressID uint64,
	replacements []recordSample,
) []recordSample {
	selection := adaptiveWindowRecordSelection{maxEgressID: maxEgressID}
	if len(replacements) > 0 {
		selection.excludeFirstID = replacements[0].EgressID
	}
	if len(replacements) > 1 {
		selection.excludeLastID = replacements[len(replacements)-1].EgressID
	}
	records, _ := a.windowRecordsLocked(endEventAt, width, selection, replacements)
	return records
}

func (a *adaptiveInserter) decisionRecordsLocked() []recordSample {
	epoch := a.stream.epoch
	if epoch == nil {
		return nil
	}
	records := append([]recordSample(nil), epoch.records...)
	seen := make(map[uint64]struct{}, len(records))
	for _, sample := range records {
		if sample.EgressID != 0 {
			seen[sample.EgressID] = struct{}{}
		}
	}
	appendEvent := func(event recordEgressEvent) {
		if event.ID != 0 {
			if _, duplicate := seen[event.ID]; duplicate {
				return
			}
			seen[event.ID] = struct{}{}
		}
		sample := recordSampleFromEgressEvent(event)
		if sample.Length <= 0 || sample.FeatureTime().IsZero() || sample.FeatureTime().Before(epoch.start) {
			return
		}
		records = append(records, sample)
	}
	for _, event := range a.resolved {
		appendEvent(event)
	}
	for _, event := range a.pending {
		appendEvent(event)
	}
	sort.SliceStable(records, func(i, j int) bool {
		left, right := records[i].FeatureTime(), records[j].FeatureTime()
		if left.Equal(right) {
			return records[i].EgressID < records[j].EgressID
		}
		return left.Before(right)
	})
	return records
}

func (a *adaptiveInserter) decisionRecordTailLocked(limit int) []recordSample {
	epoch := a.stream.epoch
	if epoch == nil || limit <= 0 {
		return nil
	}
	ordered := true
	for i := 1; i < len(epoch.records); i++ {
		if recordSampleLess(epoch.records[i], epoch.records[i-1]) {
			ordered = false
			break
		}
	}
	if !ordered {
		records := a.decisionRecordsLocked()
		if len(records) > limit {
			records = records[len(records)-limit:]
		}
		return records
	}
	start := maxInt(0, len(epoch.records)-limit)
	records := append([]recordSample(nil), epoch.records[start:]...)
	appendEvent := func(event recordEgressEvent) {
		if event.ID != 0 && event.ID < a.nextID {
			return
		}
		sample := recordSampleFromEgressEvent(event)
		if sample.Length <= 0 || sample.FeatureTime().IsZero() || sample.FeatureTime().Before(epoch.start) {
			return
		}
		records = append(records, sample)
	}
	for _, event := range a.resolved {
		appendEvent(event)
	}
	for _, event := range a.pending {
		appendEvent(event)
	}
	sort.SliceStable(records, func(i, j int) bool { return recordSampleLess(records[i], records[j]) })
	if len(records) > limit {
		records = records[len(records)-limit:]
	}
	return records
}

func (a *adaptiveInserter) bindSimulationTargetLocked(event recordEgressEvent) {
	simulation := a.activeSimulation
	if simulation == nil || event.ID == 0 {
		return
	}
	if a.simulationTargets == nil {
		a.simulationTargets = make(map[uint64]*adaptiveSimulationFeedback)
	}
	length := tlsRecordHeaderLen + int(event.Header.Length)
	if event.Embedded {
		if simulation.embeddedID != 0 {
			return
		}
		if length != simulation.embeddedLength {
			a.discardSimulationLocked(simulation, "embedded_length_mismatch")
			return
		}
		simulation.embeddedID = event.ID
		simulation.embeddedSubmittedAt = event.SubmittedAt
		simulation.embeddedEstimatedAt = event.EstimatedEgressAt
		a.simulationTargets[event.ID] = simulation
		return
	}
	if !simulation.committed || simulation.embeddedID == 0 || simulation.normalID != 0 {
		return
	}
	if event.ID != simulation.embeddedID+1 || length != simulation.normalLength {
		a.discardSimulationLocked(simulation, "following_normal_mismatch")
		return
	}
	simulation.normalID = event.ID
	a.simulationTargets[event.ID] = simulation
	epoch := a.stream.epoch
	if epoch == nil || epoch.index != simulation.epochIndex {
		a.discardSimulationLocked(simulation, "submission_epoch_changed")
		return
	}
	simulation.normalSubmittedAt = event.SubmittedAt
	simulation.normalEstimatedAt = event.EstimatedEgressAt
	// F_sim must remain a prediction even if the embedded TX timestamp
	// resolved before the following normal Record was submitted. Replace the
	// pair in the compact snapshot instead of rebuilding the full epoch.
	predictedPair := []recordSample{
		{
			SubmittedAt:       simulation.embeddedSubmittedAt,
			EstimatedEgressAt: simulation.embeddedEstimatedAt,
			Length:            simulation.embeddedLength,
			EgressID:          simulation.embeddedID,
			Embedded:          true,
		},
		{
			SubmittedAt:       simulation.normalSubmittedAt,
			EstimatedEgressAt: simulation.normalEstimatedAt,
			Length:            simulation.normalLength,
			EgressID:          simulation.normalID,
		},
	}
	records := a.simulationWindowRecordsLocked(
		event.EstimatedEgressAt,
		simulation.windowWidth,
		simulation.normalID,
		predictedPair,
	)
	rebased, local, valid := a.windowFromRecordsWithBurstReferenceLocked(
		event.EstimatedEgressAt,
		records,
		simulation.windowWidth,
		simulation.stableStart,
		simulation.burstIATReference,
		simulation.burstIATReferenceValid,
	)
	if !valid || !recordsContainEgressIDs(local, simulation.embeddedID, simulation.normalID) {
		a.discardSimulationLocked(simulation, "submission_snapshot_invalid")
		return
	}
	simulation.predicted = cloneRecordWindowFeatures(rebased.Features)

	rebasedDisturbances := recordFeatureDisturbances(rebased.Features, simulation.baseline)
	rebasedWithin, rebasedValid, _ := naturalWaveCheck(rebasedDisturbances, simulation.thresholds)
	if !rebasedValid {
		a.discardSimulationLocked(simulation, "submission_comparison_invalid")
		return
	}
	if !rebasedWithin {
		a.applySimulationFeedbackLocked(true, false)

	}
	a.activeSimulation = nil
}

func (a *adaptiveInserter) resolveSimulationTargetLocked(event recordEgressEvent) {
	simulation := a.simulationTargets[event.ID]
	if simulation == nil {
		return
	}
	if event.ActualEgressAt.IsZero() {
		a.discardSimulationLocked(simulation, "actual_timestamp_unavailable")
		return
	}
	if event.ID == simulation.embeddedID {
		simulation.embeddedResolved = true

		return
	}
	if event.ID != simulation.normalID {
		return
	}
	if !simulation.embeddedResolved {
		a.discardSimulationLocked(simulation, "embedded_timestamp_unresolved")
		return
	}

	epoch := a.stream.epoch
	if epoch == nil || epoch.index != simulation.epochIndex {
		a.discardSimulationLocked(simulation, "active_epoch_changed")
		return
	}

	records := a.simulationWindowRecordsLocked(
		event.ActualEgressAt,
		simulation.windowWidth,
		simulation.normalID,
		nil,
	)
	actual, local, valid := a.windowFromRecordsWithBurstReferenceLocked(
		event.ActualEgressAt,
		records,
		simulation.windowWidth,
		simulation.stableStart,
		simulation.burstIATReference,
		simulation.burstIATReferenceValid,
	)
	if !valid {
		a.discardSimulationLocked(simulation, "actual_window_invalid")
		return
	}
	priorOutside, priorValid, _, _ := a.preEmbeddingWindowOutsideNaturalWaveLocked(simulation)
	if priorValid && priorOutside {
		// The disturbance was already present before the embedded Record. Keep
		// BAD as a predictor/simulation quality signal, but do not attribute the
		// existing natural-wave violation to this insertion.
		a.applySimulationFeedbackLocked(false, false)

		a.removeSimulationLocked(simulation)
		return
	}
	if !recordsContainEgressIDs(local, simulation.embeddedID, simulation.normalID) {

		a.applySimulationFeedbackLocked(false, true)

		a.removeSimulationLocked(simulation)
		return
	}

	actualDisturbances := recordFeatureDisturbances(actual.Features, simulation.baseline)
	actualWithin, actualValid, _ := naturalWaveCheck(actualDisturbances, simulation.thresholds)
	errors := recordFeatureDisturbances(actual.Features, simulation.predicted)
	normalizedError, unscaledMismatch, errorValid := maximumNormalizedFeatureError(errors, simulation.thresholds)
	if !actualValid || !errorValid {
		a.discardSimulationLocked(simulation, "feature_comparison_invalid")
		return
	}

	feedbackHold, feedbackTighten := classifyAdaptiveSimulationFeedback(
		normalizedError,
		unscaledMismatch,
		actualWithin,
	)

	a.applySimulationFeedbackLocked(feedbackHold, feedbackTighten)

	a.removeSimulationLocked(simulation)
}

// preEmbeddingWindowOutsideNaturalWaveLocked rebuilds the actual feature
// window ending at the Record immediately before the embedded Record. Records
// at or after the embedding are excluded by egress ID even if timestamps are
// reordered, so the result is a true pre-embedding observation.
func (a *adaptiveInserter) preEmbeddingWindowOutsideNaturalWaveLocked(
	simulation *adaptiveSimulationFeedback,
) (outside, valid bool, previousID uint64, violation string) {
	if simulation == nil || simulation.embeddedID == 0 || a.stream.epoch == nil {
		return false, false, 0, ""
	}

	var previous recordSample
	records := a.stream.epoch.records
	// Resolved lifecycle events enter the epoch in egress-ID order. Walking
	// backward normally examines only the normal and embedded pair before
	// finding the immediately preceding Record.
	for i := len(records) - 1; i >= 0; i-- {
		sample := records[i]
		if sample.EgressID == 0 || sample.EgressID >= simulation.embeddedID {
			continue
		}
		previous = sample
		previousID = sample.EgressID
		break
	}
	if previousID == 0 || previous.FeatureTime().IsZero() {
		return false, false, 0, ""
	}

	priorRecords := a.simulationWindowRecordsLocked(
		previous.FeatureTime(),
		simulation.windowWidth,
		previousID,
		nil,
	)
	prior, local, windowValid := a.windowFromRecordsWithBurstReferenceLocked(
		previous.FeatureTime(),
		priorRecords,
		simulation.windowWidth,
		simulation.stableStart,
		simulation.burstIATReference,
		simulation.burstIATReferenceValid,
	)
	if !windowValid || !recordsContainEgressIDs(local, previousID) {
		return false, false, previousID, ""
	}

	disturbances := recordFeatureDisturbances(prior.Features, simulation.baseline)
	within, comparisonValid, violation := naturalWaveCheck(disturbances, simulation.thresholds)
	if !comparisonValid {
		return false, false, previousID, violation
	}
	return !within, true, previousID, violation
}

func maximumNormalizedFeatureError(values, thresholds []float64) (maximum float64, unscaledMismatch bool, valid bool) {
	if len(values) == 0 || len(values) != len(thresholds) {
		return 0, false, false
	}
	for i, value := range values {
		threshold := thresholds[i]
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 ||
			math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold < 0 {
			return 0, false, false
		}
		if threshold <= scalarEpsilon {
			if value > scalarEpsilon {
				unscaledMismatch = true
			}
			continue
		}
		normalized := value / threshold
		if normalized > maximum {
			maximum = normalized
		}
	}
	return maximum, unscaledMismatch, true
}

func classifyAdaptiveSimulationFeedback(
	normalizedError float64,
	unscaledMismatch bool,
	actualWithinNaturalWave bool,
) (hold, tighten bool) {
	switch {
	case normalizedError >= adaptiveSimulationErrorHigh:
		return false, !actualWithinNaturalWave
	case !actualWithinNaturalWave || unscaledMismatch || normalizedError > adaptiveSimulationErrorLow:
		return true, false
	default:
		return false, false
	}
}

func (a *adaptiveInserter) applySimulationFeedbackLocked(hold, tighten bool) {
	a.feedbackSimulationHold = a.feedbackSimulationHold || hold
	a.feedbackSimulationTighten = a.feedbackSimulationTighten || tighten
	if hold || tighten {
		a.safeStreak = 0
	}
}

func (a *adaptiveInserter) discardSimulationForEventLocked(id uint64, reason string) {
	if id == 0 {
		return
	}
	if simulation := a.simulationTargets[id]; simulation != nil {
		a.discardSimulationLocked(simulation, reason)
		return
	}
	if a.activeSimulation != nil &&
		(a.activeSimulation.embeddedID == id || a.activeSimulation.normalID == id) {
		a.discardSimulationLocked(a.activeSimulation, reason)
	}
}

func (a *adaptiveInserter) discardAllSimulationFeedbackLocked(reason string) {
	seen := make(map[*adaptiveSimulationFeedback]struct{})
	if a.activeSimulation != nil {
		seen[a.activeSimulation] = struct{}{}
	}
	for _, simulation := range a.simulationTargets {
		seen[simulation] = struct{}{}
	}
	for simulation := range seen {
		a.discardSimulationLocked(simulation, reason)
	}
}

func (a *adaptiveInserter) discardSimulationLocked(simulation *adaptiveSimulationFeedback, reason string) {
	if simulation == nil {
		return
	}

	a.removeSimulationLocked(simulation)
}

func (a *adaptiveInserter) removeSimulationLocked(simulation *adaptiveSimulationFeedback) {
	if simulation == nil {
		return
	}
	if a.activeSimulation == simulation {
		a.activeSimulation = nil
	}
	if simulation.embeddedID != 0 {
		delete(a.simulationTargets, simulation.embeddedID)
	}
	if simulation.normalID != 0 {
		delete(a.simulationTargets, simulation.normalID)
	}
}

func (a *adaptiveInserter) withinNaturalWaveLocked(disturbances []float64) bool {
	within, valid, _ := a.naturalWaveCheckLocked(disturbances)
	return valid && within
}

func (a *adaptiveInserter) naturalWaveCheckLocked(disturbances []float64) (within bool, valid bool, detail string) {
	return naturalWaveCheck(disturbances, a.thresholds)
}

func naturalWaveCheck(disturbances, thresholds []float64) (within bool, valid bool, detail string) {
	if len(thresholds) == 0 || len(disturbances) != len(thresholds) {
		return false, false, fmt.Sprintf("feature_count=%d threshold_count=%d", len(disturbances), len(thresholds))
	}
	names := recordFeatureDisturbanceNames()
	for i, disturbance := range disturbances {
		name := fmt.Sprintf("feature_%d", i)
		if i < len(names) {
			name = names[i]
		}
		if math.IsNaN(disturbance) || math.IsInf(disturbance, 0) || disturbance < 0 {
			return false, false, fmt.Sprintf("feature=%s value=non_finite", name)
		}
		threshold := thresholds[i]
		if math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold < 0 {
			return false, false, fmt.Sprintf("feature=%s threshold=non_finite", name)
		}
		if disturbance > threshold+scalarEpsilon {
			return false, true, fmt.Sprintf("feature=%s disturbance=%.6f threshold=%.6f", name, disturbance, threshold)
		}
	}
	return true, true, ""
}

func (a *adaptiveInserter) primaryNaturalWaveModelLocked() adaptiveNaturalWaveModel {
	return adaptiveNaturalWaveModel{
		observations:           a.observations,
		baseline:               a.baseline,
		thresholds:             a.thresholds,
		burstIATReference:      a.burstIATReference,
		burstIATReferenceValid: a.burstIATReferenceValid,
	}
}

func (a *adaptiveInserter) selectNaturalWaveModelLocked(features recordWindowFeatures) (adaptiveNaturalWaveModel, bool, bool, string) {
	primary := a.primaryNaturalWaveModelLocked()
	disturbances := recordFeatureDisturbances(features, primary.baseline)
	within, valid, violation := naturalWaveCheck(disturbances, primary.thresholds)
	if !valid || within {
		return primary, within, valid, violation
	}
	if expanded, ok := a.expandedNaturalWaveModelLocked(features); ok {
		return expanded, true, true, ""
	}
	if len(a.observationHistory) > adaptiveObservationWindowMinimum {
		violation += fmt.Sprintf(" fallback_windows=%d", len(a.observationHistory))
	}
	return primary, false, true, violation
}

func (a *adaptiveInserter) expandedNaturalWaveModelLocked(features recordWindowFeatures) (adaptiveNaturalWaveModel, bool) {
	if len(a.observationHistory) <= adaptiveObservationWindowMinimum {
		return adaptiveNaturalWaveModel{}, false
	}

	a.ensureExpandedNaturalModelsLocked()
	for _, model := range a.observationCache.expandedModels {
		disturbances := recordFeatureDisturbances(features, model.baseline)
		within, valid, _ := naturalWaveCheck(disturbances, model.thresholds)
		if valid && within {

			return model, true
		}
	}
	return adaptiveNaturalWaveModel{}, false
}

func (a *adaptiveInserter) expandedNaturalModelsMatchLocked() bool {
	cache := &a.observationCache
	return cache.expandedModelsReady &&
		sameAdaptiveWindows(cache.expandedWindows, a.observationHistory) &&
		cache.expandedReference == a.burstIATReference &&
		cache.expandedRefValid == a.burstIATReferenceValid
}

func (a *adaptiveInserter) ensureExpandedNaturalModelsLocked() {
	a.ensureObservationCacheLocked()
	if a.expandedNaturalModelsMatchLocked() {
		return
	}
	cache := &a.observationCache
	cache.expandedModels = nil
	cache.expandedModelsReady = true
	cache.expandedWindows = append(cache.expandedWindows[:0], a.observationHistory...)
	cache.expandedReference = a.burstIATReference
	cache.expandedRefValid = a.burstIATReferenceValid
	recomputed := append([]featureWindowResult(nil), a.observationHistory...)
	_, _, prepared := a.preparedFeatureWindowBurstReferenceLocked(a.observationHistory)
	if epoch := a.stream.epoch; epoch != nil && !prepared {
		// Every fallback suffix uses the same frozen primary burst reference.
		// Recompute each historical window once, then build all suffix models
		// from that shared result instead of rescanning the epoch per suffix.
		recomputed = a.recomputeAdaptiveFeatureWindowsWithBurstReferenceLocked(
			recomputed,
			a.burstIATReference,
			a.burstIATReferenceValid,
		)
	}
	for count := adaptiveObservationWindowMinimum + 1; count <= len(a.observationHistory); count++ {
		windows := recomputed[len(recomputed)-count:]
		// Fallback broadens the natural-wave history but deliberately keeps
		// the primary model's burst segmentation reference frozen.
		model, valid := buildAdaptiveNaturalWaveModel(windows)
		if valid {
			model.burstIATReference = a.burstIATReference
			model.burstIATReferenceValid = a.burstIATReferenceValid
			cache.expandedModels = append(cache.expandedModels, model)
		}
	}
}

func finiteDisturbances(values []float64, want int) bool {
	if len(values) != want || want == 0 {
		return false
	}
	for _, value := range values {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return false
		}
	}
	return true
}

func sampleEmpiricalDurations(
	rng *mathrand.Rand,
	values []time.Duration,
	dst []time.Duration,
	limit int,
) []time.Duration {
	dst = dst[:0]
	if rng == nil || len(values) == 0 || limit <= 0 {
		return dst
	}
	first := rng.Intn(len(values))
	dst = append(dst, values[first])
	if limit == 1 || len(values) == 1 {
		return dst
	}
	// Draw a second empirical sample without replacing the first index. If
	// duplicate observations carry the same duration, one simulation is
	// sufficient; retaining duplicate values would only repeat identical work.
	second := rng.Intn(len(values) - 1)
	if second >= first {
		second++
	}
	if values[second] != values[first] {
		dst = append(dst, values[second])
	}
	return dst
}

func (a *adaptiveInserter) candidateDelaysLocked(idleThreshold time.Duration) []time.Duration {
	a.ensureObservationCacheLocked()
	deltas := a.observationCache.sortedCandidateIATs
	limit := a.stream.epoch.featureWidth
	if idleThreshold < limit {
		limit = idleThreshold
	}
	if limit <= 0 {
		return nil
	}
	// Draw once from the complete observed distribution. Filtering first would
	// renormalize sub-64us and over-limit probability mass into the remaining
	// delays; drawing a second value after a rejection would additionally favor
	// short delays because they pass the simulation more often. An ineligible
	// draw therefore means no insertion for this opportunity.
	draw := sampleEmpiricalDurations(
		a.rng,
		deltas,
		a.candidateDelayScratch[:0],
		adaptiveCandidateDelaySampleLimit,
	)
	if len(draw) != 1 || draw[0] < adaptiveShortRecordIATThreshold || draw[0] >= limit {
		return nil
	}
	return draw
}

func (a *adaptiveInserter) candidateLengthsLocked(current recordWindowFeatures, normalLength int) []adaptiveLengthCandidate {
	a.ensureObservationCacheLocked()
	history := a.observationCache.normalRecords
	if len(history) == 0 || a.lastNormalLen <= 0 {
		return nil
	}
	counts := a.observationCache.lengthCounts
	mainSet := make(map[int]struct{}, len(a.stream.epoch.mainLengths))
	for _, length := range a.stream.epoch.mainLengths {
		mainSet[length] = struct{}{}
	}

	pool := make([]int, 0, len(counts))
	weights := make(map[int]float64, len(counts))
	dominant := make(map[int]bool)
	total := float64(len(history))
	for length, count := range counts {
		if !legalCandidateRecordLength(length) {
			continue
		}
		pool = append(pool, length)
		weights[length] = float64(count) / total
	}
	if len(mainSet) > 0 && current.MainLengthCoverage >= adaptiveMainCoverage {
		mainTotal := 0
		for length, count := range counts {
			if _, ok := mainSet[length]; ok {
				mainTotal += count
			}
		}
		filtered := pool[:0]
		for _, length := range pool {
			if _, ok := mainSet[length]; !ok || mainTotal == 0 {
				continue
			}
			probability := float64(counts[length]) / float64(mainTotal)
			if probability < adaptiveLowProbability {
				continue
			}
			weights[length] = probability
			dominant[length] = probability >= adaptiveDominantProbability
			filtered = append(filtered, length)
		}
		pool = filtered
	} else if len(mainSet) > 0 {
		filtered := pool[:0]
		for _, length := range pool {
			if weights[length] >= adaptiveLowProbability {
				filtered = append(filtered, length)
			}
		}
		pool = filtered
	}
	if len(pool) == 0 {
		return nil
	}
	sampled := a.weightedLengthsLocked(pool, weights, dominant, adaptiveMaxLengths)

	pairs := a.observationCache.pairs
	triples := a.observationCache.triples
	diffCounts := a.observationCache.diffCounts
	diffTotal := maxInt(1, a.observationCache.diffTotal)
	candidates := make([]adaptiveLengthCandidate, 0, len(sampled))
	_, previousIsMain := mainSet[a.lastNormalLen]
	_, currentIsMain := mainSet[normalLength]
	for order, length := range sampled {
		if len(mainSet) > 0 && previousIsMain && currentIsMain {
			if _, candidateIsMain := mainSet[length]; !candidateIsMain {
				continue
			}
		}
		candidate := adaptiveLengthCandidate{Length: length, Order: order, Dominant: dominant[length]}
		if _, ok := triples[[3]int{a.lastNormalLen, length, normalLength}]; ok {
			candidate.Tier = 1
		} else {
			_, left := pairs[[2]int{a.lastNormalLen, length}]
			_, right := pairs[[2]int{length, normalLength}]
			if left && right {
				candidate.Tier = 2
			} else {
				leftBin := lengthDiffBin(absInt(a.lastNormalLen - length))
				rightBin := lengthDiffBin(absInt(length - normalLength))
				leftP := float64(diffCounts[leftBin]) / float64(diffTotal)
				rightP := float64(diffCounts[rightBin]) / float64(diffTotal)
				if leftP >= adaptiveDiffProbability && rightP >= adaptiveDiffProbability {
					candidate.Tier = 3
				}
			}
		}
		if candidate.Tier != 0 {
			candidates = append(candidates, candidate)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Tier != candidates[j].Tier {
			return candidates[i].Tier < candidates[j].Tier
		}
		if candidates[i].Dominant != candidates[j].Dominant {
			return candidates[i].Dominant
		}
		return candidates[i].Order < candidates[j].Order
	})
	return candidates
}

func (a *adaptiveInserter) minimumObservedCandidateLengthLocked() (minimum int, historyCount int) {
	a.ensureObservationCacheLocked()
	return a.observationCache.minimumLength, len(a.observationCache.normalRecords)
}

func (a *adaptiveInserter) maximumObservedCandidateLengthLocked() int {
	a.ensureObservationCacheLocked()
	return a.observationCache.maximumLength
}

func legalCandidateRecordLength(length int) bool {
	return length >= minEmbeddedTLSRecordLen()+1 &&
		length <= tlsRecordHeaderLen+maxTLSRecordPayloadLen &&
		embeddedCovertCapacity(length) > 0
}

func (a *adaptiveInserter) weightedLengthsLocked(pool []int, weights map[int]float64, dominant map[int]bool, limit int) []int {
	remaining := append([]int(nil), pool...)
	sort.Ints(remaining)
	out := make([]int, 0, minInt(limit, len(remaining)))
	for i := 0; i < len(remaining) && len(out) < limit; {
		if dominant[remaining[i]] {
			out = append(out, remaining[i])
			remaining = append(remaining[:i], remaining[i+1:]...)
			continue
		}
		i++
	}
	for len(remaining) > 0 && len(out) < limit {
		total := 0.0
		for _, length := range remaining {
			total += weights[length]
		}
		if total <= 0 {
			out = append(out, remaining[0])
			remaining = remaining[1:]
			continue
		}
		draw := a.rng.Float64() * total
		chosen := len(remaining) - 1
		for i, length := range remaining {
			draw -= weights[length]
			if draw <= 0 {
				chosen = i
				break
			}
		}
		out = append(out, remaining[chosen])
		remaining = append(remaining[:chosen], remaining[chosen+1:]...)
	}
	return out
}

func (a *adaptiveInserter) invalidateObservationCacheLocked() {
	a.observationCache = adaptiveObservationCache{}
}

func adaptiveObservationRuns(windows []featureWindowResult) []adaptiveObservationRun {
	if len(windows) == 0 {
		return nil
	}
	sorted := append([]featureWindowResult(nil), windows...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Start == sorted[j].Start {
			return sorted[i].End < sorted[j].End
		}
		return sorted[i].Start < sorted[j].Start
	})
	runs := make([]adaptiveObservationRun, 0, len(sorted))
	for _, window := range sorted {
		if window.End <= window.Start {
			continue
		}
		if len(runs) == 0 || window.Start > runs[len(runs)-1].End {
			runs = append(runs, adaptiveObservationRun{Start: window.Start, End: window.End})
			continue
		}
		if window.End > runs[len(runs)-1].End {
			runs[len(runs)-1].End = window.End
		}
	}
	return runs
}

func adaptiveObservationRunForRelative(runs []adaptiveObservationRun, relative time.Duration) (int, bool) {
	index := sort.Search(len(runs), func(i int) bool { return runs[i].End > relative })
	if index < len(runs) && relative >= runs[index].Start {
		return index, true
	}
	return 0, false
}

func (a *adaptiveInserter) observationCacheMatchesLocked() bool {
	cache := &a.observationCache
	epoch := a.stream.epoch
	if !cache.valid || epoch == nil || cache.epoch != epoch ||
		!sameAdaptiveWindows(cache.windows, a.observations) || len(epoch.records) < cache.epochRecordCount {
		return false
	}
	// Appending records beyond the closed observation runs does not invalidate
	// their summaries. A rare regressed timestamp that lands inside a run does.
	for _, sample := range epoch.records[cache.epochRecordCount:] {
		relative := sample.FeatureTime().Sub(epoch.start)
		if _, observed := adaptiveObservationRunForRelative(cache.runs, relative); observed {
			return false
		}
	}
	cache.epochRecordCount = len(epoch.records)
	return true
}

func observationRecordsForRuns(epoch *recordEpochStream, runs []adaptiveObservationRun) []recordSample {
	if epoch == nil || len(epoch.records) == 0 || len(runs) == 0 {
		return nil
	}
	records := make([]recordSample, 0)
	if epoch.recordsOrdered {
		for _, run := range runs {
			first, last := recordTimeRangeIndices(
				epoch.records,
				epoch.start.Add(run.Start),
				epoch.start.Add(run.End),
			)
			records = append(records, epoch.records[first:last]...)
		}
		return records
	}

	// Preserve the legacy behavior for a rare regressed timestamp. Normal TX
	// timelines use the binary-search path above and never copy the full epoch.
	for _, sample := range epoch.records {
		relative := sample.FeatureTime().Sub(epoch.start)
		if _, observed := adaptiveObservationRunForRelative(runs, relative); observed {
			records = append(records, sample)
		}
	}
	sort.SliceStable(records, func(i, j int) bool { return recordSampleLess(records[i], records[j]) })
	return records
}

// observedNormalIATsForWindows first merges overlapping observation windows
// into disjoint runs, then visits each Record pair once. This prevents the
// 50%-overlapped feature windows from overweighting their shared IATs when
// quantile boundaries are learned.
func observedNormalIATsForWindows(
	epoch *recordEpochStream,
	windows []featureWindowResult,
) []time.Duration {
	runs := adaptiveObservationRuns(windows)
	records := observationRecordsForRuns(epoch, runs)
	iats := make([]time.Duration, 0, len(records))
	var previous recordSample
	previousRun := -1
	havePrevious := false
	for _, sample := range records {
		run, observed := adaptiveObservationRunForRelative(
			runs,
			sample.FeatureTime().Sub(epoch.start),
		)
		if !observed || run != previousRun {
			havePrevious = false
		}
		if havePrevious && !previous.Embedded && !sample.Embedded {
			if delta := sample.FeatureTime().Sub(previous.FeatureTime()); delta > 0 {
				iats = append(iats, delta)
			}
		}
		previous = sample
		previousRun = run
		havePrevious = observed
	}
	sort.Slice(iats, func(i, j int) bool { return iats[i] < iats[j] })
	return iats
}

func (a *adaptiveInserter) freezeObservedIATSchemaLocked(
	epoch *recordEpochStream,
	windows []featureWindowResult,
) {
	if epoch == nil || epoch.iatSchemaFrozen {
		return
	}
	samples := observedNormalIATsForWindows(epoch, windows)
	schema, dynamic := iatDistributionSchema{}, false
	if len(samples) >= adaptiveObservedIATMinimumSamples {
		schema, dynamic = makeObservedIATDistributionSchema(
			samples,
			adaptiveObservedIATBinCount,
			[]time.Duration{adaptiveShortRecordIATThreshold, shortIATThreshold},
		)
	}
	epoch.iatSchemaFrozen = true
	if dynamic {
		epoch.iatSchema = schema.clone()
		primaryStart := maxInt(0, len(epoch.featureWindows)-adaptiveObservationWindowMinimum)
		reference, referenceValid := estimateBurstIATReferenceForWindows(
			epoch.records,
			epoch.featureWindows[primaryStart:],
		)
		recomputed := recomputeFeatureWindowsWithBurstReferenceAndIATSchema(
			epoch.records,
			epoch.featureWindows,
			epoch.mainLengths,
			epoch.residualLengthBins,
			reference,
			referenceValid,
			epoch.activeIATSchema(),
		)
		copy(epoch.featureWindows, recomputed)

		return
	}

}

func (a *adaptiveInserter) ensureObservationCacheLocked() {
	if a.observationCacheMatchesLocked() {
		return
	}
	epoch := a.stream.epoch
	if epoch == nil || len(a.observations) == 0 {
		a.invalidateObservationCacheLocked()
		return
	}
	runs := adaptiveObservationRuns(a.observations)
	cache := adaptiveObservationCache{
		valid:            true,
		epoch:            epoch,
		epochRecordCount: len(epoch.records),
		windows:          append([]featureWindowResult(nil), a.observations...),
		runs:             runs,
		lengthCounts:     make(map[int]int),
		pairs:            make(map[[2]int]struct{}),
		triples:          make(map[[3]int]struct{}),
		diffCounts:       make(map[int]int),
	}
	records := observationRecordsForRuns(epoch, runs)

	allSeen := make(map[uint64]struct{})
	normalSeen := make(map[uint64]struct{})
	for _, sample := range records {
		if _, duplicate := allSeen[sample.EgressID]; !duplicate {
			allSeen[sample.EgressID] = struct{}{}
			cache.allRecords = append(cache.allRecords, sample)
		}
		if sample.Embedded {
			continue
		}
		if _, duplicate := normalSeen[sample.EgressID]; duplicate {
			continue
		}
		normalSeen[sample.EgressID] = struct{}{}
		cache.normalRecords = append(cache.normalRecords, sample)
	}
	sort.SliceStable(cache.allRecords, func(i, j int) bool {
		left, right := cache.allRecords[i].FeatureTime(), cache.allRecords[j].FeatureTime()
		if left.Equal(right) {
			return cache.allRecords[i].EgressID < cache.allRecords[j].EgressID
		}
		return left.Before(right)
	})
	sort.SliceStable(cache.normalRecords, func(i, j int) bool {
		left, right := cache.normalRecords[i].FeatureTime(), cache.normalRecords[j].FeatureTime()
		if left.Equal(right) {
			return cache.normalRecords[i].EgressID < cache.normalRecords[j].EgressID
		}
		return left.Before(right)
	})
	for _, sample := range cache.normalRecords {
		cache.lengthCounts[sample.Length]++
		if !legalCandidateRecordLength(sample.Length) {
			continue
		}
		if cache.minimumLength == 0 || sample.Length < cache.minimumLength {
			cache.minimumLength = sample.Length
		}
		if sample.Length > cache.maximumLength {
			cache.maximumLength = sample.Length
		}
	}

	var previous recordSample
	previousRun := -1
	havePrevious := false
	for _, sample := range records {
		run, observed := adaptiveObservationRunForRelative(runs, sample.FeatureTime().Sub(epoch.start))
		if !observed {
			havePrevious = false
			previousRun = -1
			continue
		}
		if havePrevious && run == previousRun {
			if delta := sample.FeatureTime().Sub(previous.FeatureTime()); delta > 0 {
				cache.iats = append(cache.iats, delta)
				// Candidate delays model the unmodified Record process. A pair
				// touching an embedded Record contains the scheduler's own delay
				// and must not be fed back into future delay choices.
				if !previous.Embedded && !sample.Embedded {
					cache.candidateIATs = append(cache.candidateIATs, delta)
				}
			}
		}
		previous = sample
		previousRun = run
		havePrevious = true
	}
	cache.sortedIATs = append(cache.sortedIATs, cache.iats...)
	sort.Slice(cache.sortedIATs, func(i, j int) bool { return cache.sortedIATs[i] < cache.sortedIATs[j] })
	cache.sortedCandidateIATs = append(cache.sortedCandidateIATs, cache.candidateIATs...)
	sort.Slice(cache.sortedCandidateIATs, func(i, j int) bool {
		return cache.sortedCandidateIATs[i] < cache.sortedCandidateIATs[j]
	})

	normalRun := make([]recordSample, 0, 3)
	observationRun := -1
	for _, sample := range records {
		// Preserve the original sequence semantics: embedded Records are
		// ignored rather than breaking a normal-length transition.
		if sample.Embedded {
			continue
		}
		run, observed := adaptiveObservationRunForRelative(runs, sample.FeatureTime().Sub(epoch.start))
		if !observed {
			normalRun = normalRun[:0]
			observationRun = -1
			continue
		}
		if run != observationRun {
			normalRun = normalRun[:0]
			observationRun = run
		}
		if len(normalRun) >= 1 {
			previous := normalRun[len(normalRun)-1]
			cache.pairs[[2]int{previous.Length, sample.Length}] = struct{}{}
			cache.diffCounts[lengthDiffBin(absInt(sample.Length-previous.Length))]++
			cache.diffTotal++
		}
		if len(normalRun) >= 2 {
			beforePrevious := normalRun[len(normalRun)-2]
			previous := normalRun[len(normalRun)-1]
			cache.triples[[3]int{beforePrevious.Length, previous.Length, sample.Length}] = struct{}{}
		}
		normalRun = append(normalRun, sample)
		if len(normalRun) > 2 {
			normalRun = normalRun[len(normalRun)-2:]
		}
	}

	counts := make([]float64, 0, len(a.observations))
	for _, window := range a.observations {
		count := 0
		first, last := recordTimeRangeIndices(
			records,
			epoch.start.Add(window.Start),
			epoch.start.Add(window.End),
		)
		for _, sample := range records[first:last] {
			if !sample.Embedded {
				count++
			}
		}
		counts = append(counts, float64(count))
	}
	cache.medianNormalCount = medianFloat64(counts)
	a.observationCache = cache
}

func (a *adaptiveInserter) observedRecordsLocked(includeEmbedded bool) []recordSample {
	a.ensureObservationCacheLocked()
	records := a.observationCache.normalRecords
	if includeEmbedded {
		records = a.observationCache.allRecords
	}
	return append([]recordSample(nil), records...)
}

func (a *adaptiveInserter) sampleInObservationWindowsLocked(sample recordSample) bool {
	_, observed := a.observationRunLocked(sample)
	return observed
}

// observationRunLocked returns the connected component of stable feature
// windows containing sample. Overlapping windows from one stable run share a
// component; a transition/tail gap starts a new one.
func (a *adaptiveInserter) observationRunLocked(sample recordSample) (int, bool) {
	a.ensureObservationCacheLocked()
	epoch := a.stream.epoch
	if epoch == nil {
		return 0, false
	}
	return adaptiveObservationRunForRelative(
		a.observationCache.runs,
		sample.FeatureTime().Sub(epoch.start),
	)
}

func (a *adaptiveInserter) observationIATsLocked() []time.Duration {
	a.ensureObservationCacheLocked()
	return append([]time.Duration(nil), a.observationCache.iats...)
}

func (a *adaptiveInserter) medianObservationNormalCountLocked() float64 {
	a.ensureObservationCacheLocked()
	return a.observationCache.medianNormalCount
}

func (a *adaptiveInserter) flowSuitabilityLocked(
	currentRecords []recordSample,
	idleFor time.Duration,
	idleThreshold time.Duration,
	currentNormalCount int,
	minimumActive int,
) adaptiveFlowSuitability {
	a.ensureObservationCacheLocked()
	var current *recordSample
	for _, sample := range currentRecords {
		if !sample.Embedded && sample.EgressID == math.MaxUint64 {
			copy := sample
			current = &copy
			break
		}
	}
	longIdleRatio := normalLongIdleRatioWithCurrent(
		a.observationCache.normalRecords,
		current,
		idleThreshold,
	)
	recentStable := a.recentStableStageWindowsLocked()
	return adaptiveFlowSuitability{
		active: idleFor <= idleThreshold &&
			currentNormalCount >= minimumActive &&
			longIdleRatio <= adaptiveLongIdleRatioMax,
		stable:             recentStable >= adaptiveFeedbackStableWindows,
		saturationStable:   a.saturationKnown && !a.saturationChangedSinceFeedback,
		recentStable:       recentStable,
		currentNormalCount: currentNormalCount,
		minimumActive:      minimumActive,
		longIdleRatio:      longIdleRatio,
	}
}

func normalLongIdleRatioWithCurrent(records []recordSample, current *recordSample, idleThreshold time.Duration) float64 {
	if idleThreshold <= 0 {
		return 1
	}
	long, total := 0, 0
	var previous recordSample
	havePrevious := false
	observe := func(sample recordSample) {
		if havePrevious {
			gap := sample.FeatureTime().Sub(previous.FeatureTime())
			if gap >= 0 {
				total++
				if gap > idleThreshold {
					long++
				}
			}
		}
		previous = sample
		havePrevious = true
	}
	inserted := current == nil
	for _, sample := range records {
		if !inserted {
			left, right := current.FeatureTime(), sample.FeatureTime()
			if left.Before(right) || (left.Equal(right) && current.EgressID < sample.EgressID) {
				observe(*current)
				inserted = true
			}
		}
		observe(sample)
	}
	if !inserted {
		observe(*current)
	}
	if total == 0 {
		return 1
	}
	return float64(long) / float64(total)
}

func normalLongIdleRatio(records []recordSample, idleThreshold time.Duration) float64 {
	if idleThreshold <= 0 {
		return 1
	}
	normal := make([]recordSample, 0, len(records))
	for _, sample := range records {
		if !sample.Embedded {
			normal = append(normal, sample)
		}
	}
	sort.SliceStable(normal, func(i, j int) bool {
		left, right := normal[i].FeatureTime(), normal[j].FeatureTime()
		if left.Equal(right) {
			return normal[i].EgressID < normal[j].EgressID
		}
		return left.Before(right)
	})
	if len(normal) < 2 {
		return 1
	}
	long, total := 0, 0
	for i := 1; i < len(normal); i++ {
		gap := normal[i].FeatureTime().Sub(normal[i-1].FeatureTime())
		if gap < 0 {
			continue
		}
		total++
		if gap > idleThreshold {
			long++
		}
	}
	if total == 0 {
		return 1
	}
	return float64(long) / float64(total)
}

func (a *adaptiveInserter) recentStableStageWindowsLocked() int {
	epoch := a.stream.epoch
	if epoch == nil {
		return 0
	}
	count := 0
	for i := len(epoch.stageWindows) - 1; i >= 0 && count < adaptiveFeedbackStableWindows; i-- {
		if epoch.stageWindows[i].Label != "stable_bulk" {
			break
		}
		count++
	}
	return count
}

func (a *adaptiveInserter) maybeSuitabilityFeedbackLocked(suitability adaptiveFlowSuitability) {
	if a.feedbackCount < adaptiveFeedbackRecords || !a.ready || !a.predictor.Initialized() || len(a.observations) == 0 {
		return
	}
	latestWindow := a.observations[len(a.observations)-1].End
	if latestWindow <= a.lastFeedbackWindow {
		return
	}
	lowActivityTighten := false
	if suitability.active {
		a.lowActivityStreak = 0
	} else {
		a.lowActivityStreak++
		lowActivityTighten = a.lowActivityStreak >= adaptiveLowActivityFeedbackCycles
	}
	simulationTighten := a.feedbackSimulationTighten
	switch {
	case simulationTighten || lowActivityTighten:
		a.tightenFeedbackParametersLocked()
		a.safeStreak = 0
		if lowActivityTighten {
			a.lowActivityStreak = 0
		}
	case !suitability.active:
		a.safeStreak = 0
	case a.feedbackSimulationHold:
		a.safeStreak = 0
	case !suitability.stable:
		a.safeStreak = 0
	case !suitability.saturationStable:
		a.safeStreak = 0
	default:
		a.safeStreak++
		required := 4
		if a.saturationKnown && a.saturated {
			required = 2
		}
		if a.safeStreak >= required {
			a.relaxFeedbackParametersLocked()
			a.safeStreak = 0
		}
	}
	a.clampParametersLocked()
	a.feedbackCount = 0
	a.lastFeedbackWindow = latestWindow
	a.feedbackSimulationHold = false
	a.feedbackSimulationTighten = false
	a.saturationChangedSinceFeedback = false
}

func (a *adaptiveInserter) relaxFeedbackParametersLocked() {
	a.params.NMin--
	a.params.TMin = time.Duration(adaptiveFeedbackTMinRelaxFactor * float64(a.params.TMin))
	a.params.Alpha *= adaptiveFeedbackBudgetRelaxFactor
	a.params.BMax *= adaptiveFeedbackBudgetRelaxFactor
}

func (a *adaptiveInserter) tightenFeedbackParametersLocked() {
	a.params.NMin++
	a.params.TMin = time.Duration(float64(a.params.TMin) / adaptiveFeedbackTMinRelaxFactor)
	a.params.Alpha /= adaptiveFeedbackBudgetRelaxFactor
	a.params.BMax /= adaptiveFeedbackBudgetRelaxFactor
}

func (a *adaptiveInserter) CancelReservation(length int) {
	a.CancelReservationWithReason(length, "unspecified")
}

func (a *adaptiveInserter) CancelReservationWithReason(length int, reason string) {
	if a == nil || length <= 0 {
		return
	}
	a.lockForForwardPath()
	defer a.mu.Unlock()
	if a.reservedLength != length {

		return
	}
	if a.activeSimulation != nil {
		a.discardSimulationLocked(a.activeSimulation, "reservation_cancelled_"+reason)
	}
	a.params.Budget = math.Min(a.params.BMax, a.params.Budget+float64(length))
	a.reservedLength = 0

}

func (a *adaptiveInserter) ConfirmReservation(decision adaptiveDecision, now time.Time) bool {
	if a == nil || !decision.Insert || decision.Length <= 0 {
		return false
	}
	a.lockForForwardPath()
	defer a.mu.Unlock()
	a.syncSegmentLocked()
	epoch := a.stream.epoch
	if a.reservedLength != decision.Length {

		return false
	}
	if a.activeSimulation == nil || a.activeSimulation.embeddedLength != decision.Length {

		return false
	}
	if epoch == nil {

		return false
	}
	if a.invalidEpoch == epoch.index {

		return false
	}
	if !epoch.inStableSegment || !a.segmentActive {

		return false
	}
	if !a.ready {

		return false
	}
	if !a.initialized {

		return false
	}
	predictorStatus := a.predictor.Status()
	if !predictorStatus.Initialized {

		return false
	}
	if a.hasInserted && a.normalSince < a.params.NMin {

		return false
	}
	proposedAt := a.predictor.Estimate(now, decision.Length)
	if a.hasInserted && proposedAt.Sub(a.lastInsert) < a.params.TMin {

		return false
	}
	if a.params.Budget < -scalarEpsilon {

		return false
	}

	return true
}

func (a *adaptiveInserter) InsertSucceeded(plannedAt time.Time) {
	if a == nil {
		return
	}
	a.lockForForwardPath()
	length := a.reservedLength

	a.reservedLength = 0
	if a.activeSimulation != nil && a.activeSimulation.embeddedLength == length {
		a.activeSimulation.committed = true
		simulation := a.activeSimulation

		if (!a.saturationKnown || !a.saturated) &&
			!a.activeSimulation.timingReferenceAt.IsZero() {
			iatThreshold, iatThresholdValid := adaptiveTimingIATThreshold(simulation.thresholds)
			a.normalReferenceAt = simulation.timingReferenceAt
			a.timingDebt = simulation.timingDebt

			a.timingIATThreshold = iatThreshold
			a.timingIATThresholdValid = iatThresholdValid
			a.timingFrozen = true
			a.timingCompleteAfterNormalWrite = simulation.timingDebt == 0

		}
	}
	a.hasInserted = true
	if plannedAt.After(a.lastInsert) {
		a.lastInsert = plannedAt
	}
	a.normalSince = 0

	a.mu.Unlock()
}

func (a *adaptiveInserter) NormalWriteSucceeded(length int) {
	if a == nil || length <= 0 {
		return
	}

	a.lockForForwardPath()

	defer a.mu.Unlock()

	if a.initialized {
		a.params.Budget = math.Min(a.params.BMax, a.params.Budget+a.params.Alpha*float64(length))
	}
	if a.hasInserted {
		a.normalSince++
	}
	a.lastNormalLen = length
	if a.timingFrozen {
		if a.timingCompleteAfterNormalWrite {
			a.finishTimingEpisodeLocked()
		}
	}
}

func randomCovertMessage(totalRecordLength int) ([]byte, error) {
	capacity := embeddedCovertCapacity(totalRecordLength)
	if capacity <= 0 {
		return nil, nil
	}
	data := make([]byte, capacity)
	if _, err := cryptorand.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

func nearestDurationQuantile(sorted []time.Duration, quantile float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if quantile <= 0 {
		return sorted[0]
	}
	if quantile >= 1 {
		return sorted[len(sorted)-1]
	}
	position := quantile * float64(len(sorted)-1)
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return sorted[lower]
	}
	target := float64(sorted[lower]) + (position-float64(lower))*float64(sorted[upper]-sorted[lower])
	if math.Abs(float64(sorted[lower])-target) <= math.Abs(float64(sorted[upper])-target) {
		return sorted[lower]
	}
	return sorted[upper]
}

func medianSortedInts(sorted []int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return float64(sorted[mid])
	}
	return float64(sorted[mid-1]+sorted[mid]) / 2
}

func clampInt(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func clampFloat(value, low, high float64) float64 {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func clampDuration(value, low, high time.Duration) time.Duration {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
