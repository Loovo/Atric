package main

import (
	"math"
	"sort"
	"sync"
	"time"
)

const (
	timestampPredictorInitialBaseDelay    = 100 * time.Microsecond
	timestampPredictorInitialNanosPerByte = 8.0
	timestampPredictorErrorLearningRate   = 0.20
	timestampPredictorRateLearningRate    = 0.15
	timestampPredictorMinSamples          = 16
	timestampPredictorReadyStreak         = 6
	timestampPredictorIdleRecoveryStreak  = 6
	timestampPredictorReadyError          = 2 * time.Millisecond
	timestampPredictorDegradeError        = 8 * time.Millisecond
	timestampPredictorDegradeStreak       = 3
	timestampPredictorMaxBaseDelay        = 2 * time.Second
	timestampPredictorMinNanosPerByte     = 0.01
	timestampPredictorMaxNanosPerByte     = float64(time.Millisecond)
	timestampPredictorIdleDelayWindow     = 20
	timestampPredictorQueueRateMinSpan    = 50 * time.Millisecond
	timestampPredictorQueueRateMinRecords = 8
	timestampPredictorQueueRateMinBytes   = 32 * 1024
	timestampPredictorRateResultWindow    = 3
	timestampPredictorRateChangeFactor    = 2.0
	timestampPredictorHistoryLimit        = 256
	timestampPredictorHistoryHorizon      = 4 * time.Second
	timestampPredictorBatchIAT            = 2 * time.Millisecond
	timestampPredictorBatchMinRatio       = 0.25
	timestampPredictorBatchMinLongGaps    = 2
	timestampPredictorMaxBatchPeriod      = 500 * time.Millisecond
	timestampPredictorIATProfileMin       = 16
	timestampPredictorIATProfileLimit     = 128
	// Reforecasting publishes one estimate per pending Record and causes two
	// more full pending-map scans in the tracker/adaptive observer. Reforecast
	// less often as the queue grows so the amortized work stays near this many
	// pending Records per consumed timestamp.
	timestampPredictorReforecastWorkLimit = 128
)

type timestampPredictionInput struct {
	SubmittedAt time.Time
	Length      int
}

type timestampPredictorStatus struct {
	Initialized        bool
	EverInitialized    bool
	Degraded           bool
	Samples            int
	CalibrationSamples int
	ErrorEWMA          time.Duration
	BaseDelay          time.Duration
	NanosPerByte       float64
	Batching           bool
	BatchPeriod        time.Duration
	BatchBytes         float64
	ShortIATRatio      float64
	IATProfileSamples  int
	MedianIAT          time.Duration
	NaturalJitter      time.Duration
	BiasEWMA           time.Duration
	JitterEWMA         time.Duration
	ReadyError         time.Duration
	DegradeError       time.Duration
	Pending            int
	ForecastHorizon    time.Duration
}

type trackedTimestampPrediction struct {
	timestampPredictionInput
	EstimatedAt time.Time
	Busy        bool
}

type actualTimestampSample struct {
	At     time.Time
	Length int
}

type timestampPredictionUpdate struct {
	ResolvedEstimate time.Time
	Estimates        map[uint64]time.Time
}

type timestampRecordObservation struct {
	ID          uint64
	SubmittedAt time.Time
	EstimatedAt time.Time
	ActualAt    time.Time
	Length      int
}

type timestampPredictionBatchUpdate struct {
	ResolvedEstimates []time.Time
	Estimates         map[uint64]time.Time
}

type timestampPredictionEstimate struct {
	ID uint64
	At time.Time
}

type timestampForecastState struct {
	serviceTail    time.Time
	estimateTail   time.Time
	batchBoundary  time.Time
	batchBytesUsed float64
	iatIndex       int
}

// recordTimestampPredictor uses a typical submit-to-egress delay while the
// queue is empty and applies a byte rate only to queued Records. The byte rate
// is learned from non-overlapping sustained-queue windows; idle observations
// never modify it. Three windows establish the initial rate. Micro-batch shape
// remains a queued-traffic refinement. Each actual timestamp is always
// resolved; bulk outstanding-estimate refreshes are coalesced under a large
// backlog and resume fully after it drains.
type recordTimestampPredictor struct {
	mu sync.Mutex

	baseDelay     time.Duration
	nanosPerByte  float64
	batching      bool
	batchPeriod   time.Duration
	batchBytes    float64
	shortIATRatio float64
	iatProfile    []float64
	medianIAT     time.Duration
	naturalJitter time.Duration

	lastActual             time.Time
	forecast               timestampForecastState
	outstanding            map[uint64]trackedTimestampPrediction
	outstandingOrder       []uint64
	outstandingOrderSorted bool
	history                []actualTimestampSample
	idleDelays             []time.Duration

	rateReliable          bool
	queueActive           bool
	queueRateStart        time.Time
	queueRateRecords      int
	queueRateBytes        int64
	recentRateResults     []float64
	idleRecoveryGoodCount int

	// observationsSinceReforecast implements load-aware coalescing. It does
	// not delay resolving actual TX timestamps, only bulk provisional updates.
	observationsSinceReforecast int

	samples            int
	calibrationSamples int
	errorEWMA          float64
	biasEWMA           float64
	jitterEWMA         float64
	goodStreak         int
	badStreak          int
	reliable           bool
	everReliable       bool
	degraded           bool
}

func newRecordTimestampPredictor() *recordTimestampPredictor {
	return &recordTimestampPredictor{
		baseDelay:              timestampPredictorInitialBaseDelay,
		nanosPerByte:           timestampPredictorInitialNanosPerByte,
		outstanding:            make(map[uint64]trackedTimestampPrediction),
		outstandingOrderSorted: true,
	}
}

// Predict is retained for callers that do not have an egress ID. Production
// record writes use PredictRecord so outstanding timestamps can be rebuilt.
func (p *recordTimestampPredictor) Predict(submittedAt time.Time, length int) time.Time {
	if p == nil {
		return submittedAt
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	estimated, _, next := p.advanceLocked(p.forecast, submittedAt, length)
	p.forecast = next
	return estimated
}

func (p *recordTimestampPredictor) PredictRecord(id uint64, submittedAt time.Time, length int) time.Time {
	if p == nil {
		return submittedAt
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.outstanding[id]; id != 0 && ok {
		return existing.EstimatedAt
	}
	estimated, busy, next := p.advanceLocked(p.forecast, submittedAt, length)
	p.forecast = next
	if id != 0 {
		p.outstanding[id] = trackedTimestampPrediction{
			timestampPredictionInput: timestampPredictionInput{SubmittedAt: submittedAt, Length: length},
			EstimatedAt:              estimated,
			Busy:                     busy,
		}
		if count := len(p.outstandingOrder); count > 0 && id < p.outstandingOrder[count-1] {
			p.outstandingOrderSorted = false
		}
		p.outstandingOrder = append(p.outstandingOrder, id)
	}
	return estimated
}

func (p *recordTimestampPredictor) Estimate(submittedAt time.Time, length int) time.Time {
	if p == nil {
		return submittedAt
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	estimated, _, _ := p.advanceLocked(p.forecast, submittedAt, length)
	return estimated
}

func (p *recordTimestampPredictor) EstimateSequence(inputs []timestampPredictionInput) []time.Time {
	if len(inputs) == 0 {
		return nil
	}
	if p == nil {
		out := make([]time.Time, len(inputs))
		for i, input := range inputs {
			out[i] = input.SubmittedAt
		}
		return out
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.forecast
	out := make([]time.Time, len(inputs))
	for i, input := range inputs {
		out[i], _, state = p.advanceLocked(state, input.SubmittedAt, input.Length)
	}
	return out
}

func (p *recordTimestampPredictor) advanceLocked(state timestampForecastState, submittedAt time.Time, length int) (time.Time, bool, timestampForecastState) {
	if submittedAt.IsZero() {
		return time.Time{}, false, state
	}
	if length < 0 {
		length = 0
	}
	normalCompletion := submittedAt.Add(p.baseDelay)
	busy := state.serviceTail.After(submittedAt)
	completion := normalCompletion
	if busy {
		serviceNanos := p.nanosPerByte * float64(length)
		if !p.batching && len(p.iatProfile) > 0 {
			profileIndex := state.iatIndex % len(p.iatProfile)
			serviceNanos = p.iatProfile[profileIndex] * float64(length)
			state.iatIndex++
		}
		if serviceNanos < 0 || math.IsNaN(serviceNanos) || math.IsInf(serviceNanos, 0) {
			serviceNanos = 0
		}
		completion = state.serviceTail.Add(time.Duration(serviceNanos))
		if normalCompletion.After(completion) {
			completion = normalCompletion
		}
	}
	estimated := completion

	if busy && p.batching && p.batchPeriod > timestampPredictorBatchIAT && p.batchBytes > 0 && !p.lastActual.IsZero() {
		boundary := state.batchBoundary
		if boundary.IsZero() {
			boundary = p.lastActual
		}
		canUseBatch := state.batchBytesUsed < p.batchBytes
		if boundary.Equal(p.lastActual) && submittedAt.After(p.lastActual) {
			canUseBatch = false
		}
		if !canUseBatch {
			boundary = boundary.Add(p.batchPeriod)
			if !boundary.After(p.lastActual) {
				boundary = p.lastActual.Add(p.batchPeriod)
			}
			state.batchBytesUsed = 0
		}
		estimated = boundary
		state.batchBoundary = boundary
		state.batchBytesUsed += float64(length)
	} else if !busy {
		state.batchBoundary = time.Time{}
		state.batchBytesUsed = 0
	}
	if normalCompletion.After(estimated) {
		estimated = normalCompletion
	}
	if state.estimateTail.After(estimated) {
		estimated = state.estimateTail
	}
	state.serviceTail = completion
	state.estimateTail = estimated
	return estimated, busy, state
}

func (p *recordTimestampPredictor) ObserveRecord(id uint64, submittedAt, estimatedAt, actualAt time.Time, length int) timestampPredictionUpdate {
	update := p.ObserveRecords([]timestampRecordObservation{{
		ID:          id,
		SubmittedAt: submittedAt,
		EstimatedAt: estimatedAt,
		ActualAt:    actualAt,
		Length:      length,
	}})
	if len(update.ResolvedEstimates) == 0 {
		return timestampPredictionUpdate{}
	}
	return timestampPredictionUpdate{
		ResolvedEstimate: update.ResolvedEstimates[0],
		Estimates:        update.Estimates,
	}
}

// ObserveRecords applies every timestamp observation in order while holding
// the predictor lock once. Per-Record learning is retained, but rebuilding the
// queue shape and all outstanding forecasts is deferred until the end of the
// batch. This keeps timestamp consumption linear in the batch size plus one
// outstanding-Record scan, instead of repeating that scan for every timestamp.
func (p *recordTimestampPredictor) ObserveRecords(observations []timestampRecordObservation) timestampPredictionBatchUpdate {
	update := timestampPredictionBatchUpdate{
		ResolvedEstimates: make([]time.Time, len(observations)),
	}
	if p == nil || len(observations) == 0 {
		return update
	}

	p.mu.Lock()
	processed := 0
	queueShapeDirty := false
	for i, observation := range observations {
		resolvedEstimate, shapeDirty, ok := p.observeRecordLocked(observation)
		if !ok {
			continue
		}
		update.ResolvedEstimates[i] = resolvedEstimate
		processed++
		queueShapeDirty = queueShapeDirty || shapeDirty
	}
	if processed == 0 {
		p.mu.Unlock()
		return update
	}
	if queueShapeDirty && p.queueActive {
		p.updateQueueShapeLocked()
	}
	// A batch is one call but represents every valid Record. Credit all of
	// them before the helper accounts for the final observation.
	if processed > 1 {
		p.observationsSinceReforecast += processed - 1
	}
	estimates := p.reforecastOutstandingLocked(false)
	p.mu.Unlock()
	// Building the publication map is independent of predictor state. Keep
	// this allocation and O(P) insertion work outside p.mu so new writes can
	// obtain a forecast as soon as the model update is complete.
	update.Estimates = timestampPredictionEstimateMap(estimates)
	return update
}

func (p *recordTimestampPredictor) observeRecordLocked(observation timestampRecordObservation) (time.Time, bool, bool) {
	id := observation.ID
	submittedAt := observation.SubmittedAt
	estimatedAt := observation.EstimatedAt
	actualAt := observation.ActualAt
	length := observation.Length
	if submittedAt.IsZero() || estimatedAt.IsZero() || actualAt.IsZero() || length <= 0 {
		return time.Time{}, false, false
	}

	tracked, trackedOK := p.outstanding[id]
	if trackedOK {
		submittedAt = tracked.SubmittedAt
		length = tracked.Length
		estimatedAt = tracked.EstimatedAt
		delete(p.outstanding, id)
	}
	errorDuration := actualAt.Sub(estimatedAt)
	errorNanos := float64(errorDuration)
	absError := math.Abs(errorNanos)
	if p.calibrationSamples == 0 {
		p.errorEWMA = absError
		p.biasEWMA = errorNanos
		p.jitterEWMA = 0
	} else {
		previousBias := p.biasEWMA
		p.errorEWMA = (1-timestampPredictorErrorLearningRate)*p.errorEWMA + timestampPredictorErrorLearningRate*absError
		p.biasEWMA = (1-timestampPredictorErrorLearningRate)*p.biasEWMA + timestampPredictorErrorLearningRate*errorNanos
		residual := math.Abs(errorNanos - previousBias)
		p.jitterEWMA = (1-timestampPredictorErrorLearningRate)*p.jitterEWMA + timestampPredictorErrorLearningRate*residual
	}

	previousActual := p.lastActual
	// Only actual ordering confirms a queue. A forecast-time Busy flag may be
	// wrong precisely when the old byte rate is wrong, so it must not authorize
	// rate learning.
	confirmedBusy := !previousActual.IsZero() && !submittedAt.After(previousActual)
	acceptedActual := previousActual.IsZero() || !actualAt.Before(previousActual)
	idleObservation := acceptedActual && !confirmedBusy

	if acceptedActual {
		if !confirmedBusy {
			p.queueActive = false
			p.resetQueueRateMeasurementLocked()
			p.observeIdleDelayLocked(actualAt.Sub(submittedAt))
			// An idle gap starts a new queue-shape history. The last reliable
			// byte rate and its cross-episode confirmation history are retained.
			p.history = []actualTimestampSample{{At: actualAt, Length: length}}
			p.batching = false
			p.batchPeriod = 0
			p.batchBytes = 0
			p.shortIATRatio = 0
			p.iatProfile = nil
			p.medianIAT = 0
			p.naturalJitter = 0
		} else {
			p.queueActive = true
			p.observeQueueRateMeasurementLocked(previousActual, actualAt, length)
			p.history = append(p.history, actualTimestampSample{At: actualAt, Length: length})
		}
		p.trimHistoryLocked(actualAt)
		p.lastActual = actualAt
	}

	p.samples++
	p.calibrationSamples++
	p.updateReliabilityLocked(errorDuration, idleObservation)
	return estimatedAt, acceptedActual && confirmedBusy && actualAt.After(previousActual), true
}

func (p *recordTimestampPredictor) observeIdleDelayLocked(observed time.Duration) {
	if observed < 0 {
		return
	}
	observed = clampDuration(observed, 0, timestampPredictorMaxBaseDelay)
	if len(p.idleDelays) < timestampPredictorIdleDelayWindow {
		p.idleDelays = append(p.idleDelays, observed)
	} else {
		copy(p.idleDelays, p.idleDelays[1:])
		p.idleDelays[len(p.idleDelays)-1] = observed
	}
	values := append([]time.Duration(nil), p.idleDelays...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	middle := len(values) / 2
	if len(values)%2 == 1 {
		p.baseDelay = values[middle]
		return
	}
	p.baseDelay = values[middle-1] + (values[middle]-values[middle-1])/2
}

func (p *recordTimestampPredictor) resetQueueRateMeasurementLocked() {
	p.queueRateStart = time.Time{}
	p.queueRateRecords = 0
	p.queueRateBytes = 0
}

func (p *recordTimestampPredictor) observeQueueRateMeasurementLocked(
	previousActual time.Time,
	actualAt time.Time,
	length int,
) {
	if previousActual.IsZero() || actualAt.Before(previousActual) || length <= 0 {
		return
	}
	if p.queueRateStart.IsZero() {
		p.queueRateStart = previousActual
	}
	if actualAt.Before(p.queueRateStart) {
		p.resetQueueRateMeasurementLocked()
		return
	}
	p.queueRateRecords++
	p.queueRateBytes += int64(length)
	span := actualAt.Sub(p.queueRateStart)
	if span < timestampPredictorQueueRateMinSpan ||
		p.queueRateRecords < timestampPredictorQueueRateMinRecords ||
		p.queueRateBytes < timestampPredictorQueueRateMinBytes {
		return
	}
	observed := clampFloat(
		float64(span)/float64(p.queueRateBytes),
		timestampPredictorMinNanosPerByte,
		timestampPredictorMaxNanosPerByte,
	)
	p.recordQueueRateResultLocked(observed)
	// The next window starts at this exact egress boundary, so no Record or
	// duration is counted twice while a queue remains continuously non-empty.
	p.queueRateStart = actualAt
	p.queueRateRecords = 0
	p.queueRateBytes = 0
}

func (p *recordTimestampPredictor) recordQueueRateResultLocked(observed float64) {
	observed = clampFloat(
		observed,
		timestampPredictorMinNanosPerByte,
		timestampPredictorMaxNanosPerByte,
	)
	p.appendQueueRateResultLocked(observed)
	candidate := medianTimestampPredictorRate(p.recentRateResults)
	if !p.rateReliable {
		if len(p.recentRateResults) < timestampPredictorRateResultWindow {
			return
		}
		p.nanosPerByte = candidate
		p.rateReliable = true
		return
	}
	if timestampPredictorRateRatio(candidate, p.nanosPerByte) <= timestampPredictorRateChangeFactor {
		p.nanosPerByte = candidate
		return
	}

	// A large change needs two consecutive windows pointing in the same
	// direction. The two samples are already part of the three-value median;
	// accepting here avoids waiting for an unnecessary third new window.
	if len(p.recentRateResults) < 2 {
		return
	}
	latest := p.recentRateResults[len(p.recentRateResults)-1]
	previous := p.recentRateResults[len(p.recentRateResults)-2]
	sameDirection := (latest > p.nanosPerByte && previous > p.nanosPerByte) ||
		(latest < p.nanosPerByte && previous < p.nanosPerByte)
	if sameDirection &&
		timestampPredictorRateRatio(latest, previous) <= timestampPredictorRateChangeFactor {
		p.nanosPerByte = candidate
	}
}

func (p *recordTimestampPredictor) appendQueueRateResultLocked(observed float64) {
	if len(p.recentRateResults) < timestampPredictorRateResultWindow {
		p.recentRateResults = append(p.recentRateResults, observed)
	} else {
		copy(p.recentRateResults, p.recentRateResults[1:])
		p.recentRateResults[len(p.recentRateResults)-1] = observed
	}
}

func medianTimestampPredictorRate(values []float64) float64 {
	if len(values) == 0 {
		return timestampPredictorInitialNanosPerByte
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}

func timestampPredictorRateRatio(left, right float64) float64 {
	left = math.Max(left, timestampPredictorMinNanosPerByte)
	right = math.Max(right, timestampPredictorMinNanosPerByte)
	if left < right {
		left, right = right, left
	}
	return left / right
}

func (p *recordTimestampPredictor) trimHistoryLocked(latest time.Time) {
	first := 0
	for len(p.history)-first > timestampPredictorHistoryLimit {
		first++
	}
	for first < len(p.history)-1 && latest.Sub(p.history[first].At) > timestampPredictorHistoryHorizon {
		first++
	}
	if first > 0 {
		p.history = append(p.history[:0], p.history[first:]...)
	}
}

func (p *recordTimestampPredictor) updateQueueShapeLocked() {
	if len(p.history) < 2 {
		return
	}
	shortCount := 0
	longGaps := make([]time.Duration, 0, len(p.history)-1)
	for i := 1; i < len(p.history); i++ {
		delta := p.history[i].At.Sub(p.history[i-1].At)
		if delta <= timestampPredictorBatchIAT {
			shortCount++
		} else if delta <= timestampPredictorMaxBatchPeriod {
			longGaps = append(longGaps, delta)
		}
	}
	p.shortIATRatio = float64(shortCount) / float64(len(p.history)-1)
	p.updateIATProfileLocked()
	p.batching = p.shortIATRatio >= timestampPredictorBatchMinRatio &&
		len(longGaps) >= timestampPredictorBatchMinLongGaps
	if !p.batching {
		p.batchPeriod = 0
		p.batchBytes = 0
		return
	}
	sort.Slice(longGaps, func(i, j int) bool { return longGaps[i] < longGaps[j] })
	median := longGaps[len(longGaps)/2]
	if len(longGaps)%2 == 0 {
		median = (longGaps[len(longGaps)/2-1] + median) / 2
	}
	median = clampDuration(median, timestampPredictorBatchIAT+time.Nanosecond, timestampPredictorMaxBatchPeriod)
	if p.batchPeriod == 0 {
		p.batchPeriod = median
	} else {
		p.batchPeriod = time.Duration((1-timestampPredictorRateLearningRate)*float64(p.batchPeriod) +
			timestampPredictorRateLearningRate*float64(median))
	}

	batchSizes := p.completedBatchSizesLocked()
	if len(batchSizes) == 0 {
		p.batchBytes = float64(p.batchPeriod) / p.nanosPerByte
		return
	}
	sort.Ints(batchSizes)
	batchBytes := float64(batchSizes[len(batchSizes)/2])
	if len(batchSizes)%2 == 0 {
		batchBytes = float64(batchSizes[len(batchSizes)/2-1]+batchSizes[len(batchSizes)/2]) / 2
	}
	if p.batchBytes == 0 {
		p.batchBytes = batchBytes
	} else {
		p.batchBytes = (1-timestampPredictorRateLearningRate)*p.batchBytes +
			timestampPredictorRateLearningRate*batchBytes
	}
}

func (p *recordTimestampPredictor) updateIATProfileLocked() {
	if len(p.history) < timestampPredictorIATProfileMin+1 {
		p.iatProfile = nil
		p.medianIAT = 0
		p.naturalJitter = 0
		return
	}
	start := 1
	if len(p.history)-start > timestampPredictorIATProfileLimit {
		start = len(p.history) - timestampPredictorIATProfileLimit
	}
	normalized := make([]float64, 0, len(p.history)-start)
	durations := make([]time.Duration, 0, len(p.history)-start)
	var totalDuration time.Duration
	totalBytes := 0
	for i := start; i < len(p.history); i++ {
		delta := p.history[i].At.Sub(p.history[i-1].At)
		length := p.history[i].Length
		if delta < 0 || delta > timestampPredictorMaxBatchPeriod || length <= 0 {
			continue
		}
		normalized = append(normalized, float64(delta)/float64(length))
		durations = append(durations, delta)
		totalDuration += delta
		totalBytes += length
	}
	if len(normalized) < timestampPredictorIATProfileMin || totalBytes == 0 || totalDuration <= 0 {
		p.iatProfile = nil
		p.medianIAT = 0
		p.naturalJitter = 0
		return
	}
	observedNanosPerByte := float64(totalDuration) / float64(totalBytes)
	scale := 1.0
	if observedNanosPerByte > 0 {
		scale = p.nanosPerByte / observedNanosPerByte
	}
	p.iatProfile = make([]float64, len(normalized))
	for i, value := range normalized {
		p.iatProfile[i] = clampFloat(
			value*scale,
			0,
			timestampPredictorMaxNanosPerByte,
		)
	}

	sorted := append([]time.Duration(nil), durations...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	p.medianIAT = durationQuantileSorted(sorted, 0.50)
	deviations := make([]time.Duration, len(sorted))
	for i, value := range sorted {
		deviations[i] = absDurationValue(value - p.medianIAT)
	}
	sort.Slice(deviations, func(i, j int) bool { return deviations[i] < deviations[j] })
	p.naturalJitter = durationQuantileSorted(deviations, 0.90)
}

func durationQuantileSorted(values []time.Duration, quantile float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	index := int(math.Ceil(quantile*float64(len(values)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(values) {
		index = len(values) - 1
	}
	return values[index]
}

func absDurationValue(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func (p *recordTimestampPredictor) completedBatchSizesLocked() []int {
	if len(p.history) < 3 {
		return nil
	}
	groups := make([]int, 0)
	bytes := maxInt(0, p.history[0].Length)
	for i := 1; i < len(p.history); i++ {
		if p.history[i].At.Sub(p.history[i-1].At) > timestampPredictorBatchIAT {
			groups = append(groups, bytes)
			bytes = 0
		}
		bytes += maxInt(0, p.history[i].Length)
	}
	groups = append(groups, bytes)
	if len(groups) <= 2 {
		return nil
	}
	// The history edges can contain partial batches after trimming or before
	// the newest batch finishes, so only use fully bounded interior groups.
	return append([]int(nil), groups[1:len(groups)-1]...)
}

func (p *recordTimestampPredictor) currentBatchBytesLocked() float64 {
	if len(p.history) == 0 {
		return 0
	}
	bytes := 0
	for i := len(p.history) - 1; i >= 0; i-- {
		bytes += maxInt(0, p.history[i].Length)
		if i == 0 || p.history[i].At.Sub(p.history[i-1].At) > timestampPredictorBatchIAT {
			break
		}
	}
	return float64(bytes)
}

func (p *recordTimestampPredictor) updateReliabilityLocked(errorDuration time.Duration, idle bool) {
	absError := absDurationValue(errorDuration)
	readyError := p.readyErrorLocked()
	readyBias := p.readyBiasLocked()
	degradeError := p.degradeErrorLocked()
	degradeBias := p.degradeBiasLocked()
	if p.reliable {
		p.idleRecoveryGoodCount = 0
		inaccurate := p.errorEWMA > float64(degradeError) ||
			math.Abs(p.biasEWMA) > float64(degradeBias) ||
			absError > 2*degradeError
		if inaccurate {
			p.badStreak++
		} else {
			p.badStreak = 0
		}
		if p.badStreak >= timestampPredictorDegradeStreak {
			p.reliable = false
			p.degraded = true
			p.calibrationSamples = 0
			p.goodStreak = 0
			p.badStreak = 0
			p.idleRecoveryGoodCount = 0
		}
		return
	}
	if p.degraded {
		if idle && absError <= readyError {
			p.idleRecoveryGoodCount++
		} else {
			p.idleRecoveryGoodCount = 0
		}
		if p.idleRecoveryGoodCount >= timestampPredictorIdleRecoveryStreak {
			p.reliable = true
			p.everReliable = true
			p.degraded = false
			p.errorEWMA = float64(absError)
			p.biasEWMA = float64(errorDuration)
			p.jitterEWMA = 0
			p.goodStreak = 0
			p.badStreak = 0
			p.idleRecoveryGoodCount = 0
			return
		}
	} else {
		p.idleRecoveryGoodCount = 0
	}

	accurate := p.errorEWMA <= float64(readyError) &&
		math.Abs(p.biasEWMA) <= float64(readyBias)
	if accurate {
		p.goodStreak++
	} else if p.goodStreak > 0 {
		// A one-shot queue-rate sample can straddle natural IAT phases. Keep
		// accumulated aggregate accuracy evidence, but decay it on misses.
		p.goodStreak--
	}
	if p.calibrationSamples >= timestampPredictorMinSamples &&
		p.goodStreak >= timestampPredictorReadyStreak && p.trafficModelReadyLocked() {
		p.reliable = true
		p.everReliable = true
		p.degraded = false
		p.badStreak = 0
		p.idleRecoveryGoodCount = 0
	}
}

func (p *recordTimestampPredictor) readyErrorLocked() time.Duration {
	threshold := timestampPredictorReadyError
	if candidate := time.Duration(1.5 * float64(p.naturalJitter)); candidate > threshold {
		threshold = candidate
	}
	return clampDuration(threshold, timestampPredictorReadyError, 100*time.Millisecond)
}

func (p *recordTimestampPredictor) readyBiasLocked() time.Duration {
	threshold := timestampPredictorReadyError
	if candidate := p.naturalJitter / 4; candidate > threshold {
		threshold = candidate
	}
	return clampDuration(threshold, timestampPredictorReadyError, 25*time.Millisecond)
}

func (p *recordTimestampPredictor) degradeErrorLocked() time.Duration {
	return maxDuration(timestampPredictorDegradeError, 2*p.readyErrorLocked())
}

func (p *recordTimestampPredictor) degradeBiasLocked() time.Duration {
	return maxDuration(timestampPredictorDegradeError, 2*p.readyBiasLocked())
}

func (p *recordTimestampPredictor) trafficModelReadyLocked() bool {
	// Reliability is ultimately established by actual prediction error. The
	// traffic history may be short for a genuinely idle flow, where requiring a
	// busy-rate window would prevent initialization forever.
	return p.calibrationSamples >= timestampPredictorMinSamples
}

func (p *recordTimestampPredictor) reforecastOutstandingLocked(force bool) []timestampPredictionEstimate {
	pending := len(p.outstanding)
	if !force {
		p.observationsSinceReforecast++
		if pending > timestampPredictorReforecastWorkLimit {
			interval := (pending + timestampPredictorReforecastWorkLimit - 1) /
				timestampPredictorReforecastWorkLimit
			if p.observationsSinceReforecast < interval {
				return nil
			}
		}
	}
	p.observationsSinceReforecast = 0
	if !p.outstandingOrderSorted {
		sort.Slice(p.outstandingOrder, func(i, j int) bool {
			return p.outstandingOrder[i] < p.outstandingOrder[j]
		})
		p.outstandingOrderSorted = true
	}
	state := timestampForecastState{
		serviceTail:    p.lastActual,
		estimateTail:   p.lastActual,
		batchBoundary:  p.lastActual,
		batchBytesUsed: p.currentBatchBytesLocked(),
	}
	estimates := make([]timestampPredictionEstimate, 0, pending)
	order := p.outstandingOrder[:0]
	for _, id := range p.outstandingOrder {
		tracked, ok := p.outstanding[id]
		if !ok {
			continue
		}
		tracked.EstimatedAt, tracked.Busy, state = p.advanceLocked(state, tracked.SubmittedAt, tracked.Length)
		p.outstanding[id] = tracked
		order = append(order, id)
		estimates = append(estimates, timestampPredictionEstimate{ID: id, At: tracked.EstimatedAt})
	}
	p.outstandingOrder = order
	p.forecast = state
	return estimates
}

func timestampPredictionEstimateMap(estimates []timestampPredictionEstimate) map[uint64]time.Time {
	if len(estimates) == 0 {
		return nil
	}
	out := make(map[uint64]time.Time, len(estimates))
	for _, estimate := range estimates {
		out[estimate.ID] = estimate.At
	}
	return out
}

func (p *recordTimestampPredictor) DropRecord(id uint64) map[uint64]time.Time {
	if p == nil || id == 0 {
		return nil
	}
	return p.DropRecords([]uint64{id})
}

func (p *recordTimestampPredictor) DropRecords(ids []uint64) map[uint64]time.Time {
	if p == nil || len(ids) == 0 {
		return nil
	}
	p.mu.Lock()
	for _, id := range ids {
		if id != 0 {
			delete(p.outstanding, id)
		}
	}
	estimates := p.reforecastOutstandingLocked(true)
	p.mu.Unlock()
	return timestampPredictionEstimateMap(estimates)
}

func (p *recordTimestampPredictor) Invalidate() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reliable || p.everReliable {
		p.degraded = true
	}
	p.reliable = false
	p.calibrationSamples = 0
	p.errorEWMA = 0
	p.biasEWMA = 0
	p.jitterEWMA = 0
	p.goodStreak = 0
	p.badStreak = 0
	p.idleRecoveryGoodCount = 0
	p.queueActive = false
	p.resetQueueRateMeasurementLocked()
	p.history = nil
	p.batching = false
	p.batchPeriod = 0
	p.batchBytes = 0
	p.shortIATRatio = 0
	p.iatProfile = nil
	p.medianIAT = 0
	p.naturalJitter = 0
}

func (p *recordTimestampPredictor) Initialized() bool {
	return p.Status().Initialized
}

func (p *recordTimestampPredictor) Status() timestampPredictorStatus {
	if p == nil {
		return timestampPredictorStatus{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	horizon := time.Duration(0)
	if !p.lastActual.IsZero() && p.forecast.estimateTail.After(p.lastActual) {
		horizon = p.forecast.estimateTail.Sub(p.lastActual)
	}
	queueModelReady := !p.queueActive || p.rateReliable
	return timestampPredictorStatus{
		Initialized:        p.reliable && queueModelReady,
		EverInitialized:    p.everReliable,
		Degraded:           p.degraded && !p.reliable,
		Samples:            p.samples,
		CalibrationSamples: p.calibrationSamples,
		ErrorEWMA:          time.Duration(p.errorEWMA),
		BaseDelay:          p.baseDelay,
		NanosPerByte:       p.nanosPerByte,
		Batching:           p.batching,
		BatchPeriod:        p.batchPeriod,
		BatchBytes:         p.batchBytes,
		ShortIATRatio:      p.shortIATRatio,
		IATProfileSamples:  len(p.iatProfile),
		MedianIAT:          p.medianIAT,
		NaturalJitter:      p.naturalJitter,
		BiasEWMA:           time.Duration(p.biasEWMA),
		JitterEWMA:         time.Duration(p.jitterEWMA),
		ReadyError:         p.readyErrorLocked(),
		DegradeError:       p.degradeErrorLocked(),
		Pending:            len(p.outstanding),
		ForecastHorizon:    horizon,
	}
}
