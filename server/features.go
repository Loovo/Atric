package main

import (
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	minActiveEpochRecords   = 50
	minFeatureWindowRecords = 50

	stageWindowDuration = 500 * time.Millisecond
	stageWindowStep     = 250 * time.Millisecond

	stageWindowTargetRecords       = 20
	stageStableMinimumRecords      = 10
	stageStableCandidateWindows    = 3
	stageStableBaselineWindowLimit = 8

	stageStableSmoothLogThreshold = 0.60
	stageTransitionLogThreshold   = 0.85
	stageTailBaselineRatio        = 0.35

	idleGapFloor            = time.Second
	activeEpochGapFloor     = 3 * time.Second
	idleGapMedianMultiplier = 20.0
	idleGapHistoryLimit     = 256
	idleGapRefreshInterval  = 32

	mainLengthKMax     = 8
	mainLengthMinCount = 3
	mainLengthPiMin    = 0.03
	mainLengthGamma    = 0.80

	residualLengthCentralBinTarget = 8
	residualLengthMinBinWidth      = 4
	residualLengthLowerQuantile    = 0.05
	residualLengthUpperQuantile    = 0.95

	shortIATThreshold = 2 * time.Millisecond

	minBurstRecordCount = 2

	// A Tukey upper fence marks unusually long, length-normalized egress IATs.
	// The actual reference threshold also has a configurable Q3-relative
	// lower bound; see burstIATReferenceQ3Multiplier in config.go.
	burstIATFenceMultiplier = 1.5

	logIATEpsilonSeconds = 1e-6
	scalarEpsilon        = 1e-9
)

var (
	stageWindowDurations = []time.Duration{
		500 * time.Millisecond,
		time.Second,
		2 * time.Second,
	}

	featureWindowDurations = []time.Duration{
		500 * time.Millisecond,
		time.Second,
		2 * time.Second,
		5 * time.Second,
		10 * time.Second,
	}

	defaultResidualLengthBinUpper = []int{128, 256, 320, 384, 448, 512, 1024, 2048, 4096, 8192, 12288, 16384, tlsRecordHeaderLen + maxTLSRecordPayloadLen}
	lengthDiffBinUpper            = []int{0, 16, 64, 256, 1024, 4096, 16384, 65535}
	lengthDiffPositions           = []float64{0, 8, 40, 160, 640, 2560, 10240, 40960}
	logIATPositions               = makeLogIATPositions()
)

// iatDistributionSchema is learned once from the initial observation windows
// of an active epoch and then kept immutable. A zero schema preserves the
// legacy fixed logarithmic bins for offline callers and short observations.
type iatDistributionSchema struct {
	upperBounds []time.Duration
	positions   []float64
}

func (s *iatDistributionSchema) valid() bool {
	if s == nil || len(s.positions) < 2 || len(s.upperBounds)+1 != len(s.positions) {
		return false
	}
	for i, upper := range s.upperBounds {
		if upper <= 0 || (i > 0 && upper <= s.upperBounds[i-1]) {
			return false
		}
	}
	for i, position := range s.positions {
		if math.IsNaN(position) || math.IsInf(position, 0) ||
			(i > 0 && position < s.positions[i-1]) {
			return false
		}
	}
	return true
}

func (s *iatDistributionSchema) clone() iatDistributionSchema {
	if !s.valid() {
		return iatDistributionSchema{}
	}
	return iatDistributionSchema{
		upperBounds: append([]time.Duration(nil), s.upperBounds...),
		positions:   append([]float64(nil), s.positions...),
	}
}

type recordSample struct {
	// At is retained for offline/legacy callers. Live egress records populate
	// the three explicit lifecycle timestamps below.
	At                time.Time
	SubmittedAt       time.Time
	EstimatedEgressAt time.Time
	ActualEgressAt    time.Time
	Length            int
	EgressID          uint64
	Embedded          bool
}

func (r recordSample) FeatureTime() time.Time {
	if !r.ActualEgressAt.IsZero() {
		return r.ActualEgressAt
	}
	if !r.EstimatedEgressAt.IsZero() {
		return r.EstimatedEgressAt
	}
	if !r.At.IsZero() {
		return r.At
	}
	return r.SubmittedAt
}

func recordSampleFromEgressEvent(event recordEgressEvent) recordSample {
	return recordSample{
		SubmittedAt:       event.SubmittedAt,
		EstimatedEgressAt: event.EstimatedEgressAt,
		ActualEgressAt:    event.ActualEgressAt,
		Length:            tlsRecordHeaderLen + int(event.Header.Length),
		EgressID:          event.ID,
		Embedded:          event.Embedded,
	}
}

type recordFeatureMeta struct {
	ClientAddr        string
	UpstreamAddr      string
	UpstreamLocalAddr string
	StartedAt         time.Time
	ConnectionID      uint64
	Direction         string
	EmbeddingEnabled  bool
	DetectionWriter   *detectionDataWriter
}

type recordFeatureSink struct {
	ch                     chan recordSample
	queueDropped           atomic.Uint64
	missingActualTimestamp atomic.Uint64
	meta                   recordFeatureMeta
	closeOnce              sync.Once
	writeErrorOnce         sync.Once
	done                   chan struct{}
}

func newRecordFeatureSink(meta recordFeatureMeta, queueLen int) *recordFeatureSink {
	if meta.DetectionWriter == nil {
		return nil
	}
	if queueLen <= 0 {
		queueLen = recordFeatureQueueLen
	}

	sink := &recordFeatureSink{
		ch:   make(chan recordSample, queueLen),
		meta: meta,
		done: make(chan struct{}),
	}
	if sink.meta.StartedAt.IsZero() {
		sink.meta.StartedAt = time.Now()
	}
	go sink.run()
	return sink
}

func (s *recordFeatureSink) Observe(header TLSRecordHeader, observedAt time.Time) {
	if s == nil || header.ContentType != tlsTypeApplicationData {
		return
	}

	sample := recordSample{
		ActualEgressAt: observedAt,
		Length:         tlsRecordHeaderLen + int(header.Length),
	}
	s.enqueue(sample)
}

func (s *recordFeatureSink) ObserveProvisional(recordEgressEvent) {}

func (s *recordFeatureSink) ObserveResolved(event recordEgressEvent) {
	if s == nil || event.Header.ContentType != tlsTypeApplicationData {
		return
	}
	s.enqueue(recordSampleFromEgressEvent(event))
}

func (s *recordFeatureSink) DropProvisional(uint64) {}

func (s *recordFeatureSink) enqueue(sample recordSample) {
	select {
	case s.ch <- sample:
	default:
		s.queueDropped.Add(1)
	}
}

func (s *recordFeatureSink) AddDropped(count uint64) {
	if s == nil || count == 0 {
		return
	}
	s.missingActualTimestamp.Add(count)
}

func (s *recordFeatureSink) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		close(s.ch)
	})
	<-s.done
}

func (s *recordFeatureSink) run() {
	defer close(s.done)
	s.writeDetectionConnectionStart()

	stream := newSilentRecordFeatureStream(s.meta)
	stream.Start()

	var (
		recordCount         uint64
		actualCount         uint64
		fallbackCount       uint64
		insertedRecordCount uint64
		insertedBytes       uint64
	)
	for sample := range s.ch {
		recordCount++
		if sample.Embedded {
			insertedRecordCount++
			if sample.Length > 0 {
				insertedBytes += uint64(sample.Length)
			}
		}
		recordIndex := sample.EgressID
		if recordIndex == 0 {
			recordIndex = recordCount
		}
		_, source := detectionTimestamp(sample)
		if source == "actual_tx" || source == "observed" {
			actualCount++
		} else {
			fallbackCount++
		}
		if s.meta.DetectionWriter != nil {
			if err := s.meta.DetectionWriter.WriteRecord(
				s.meta.ConnectionID,
				s.meta.Direction,
				s.meta.EmbeddingEnabled,
				recordIndex,
				sample,
			); err != nil {
				s.logWriteError("record detection output", err)
			}
		}
		stream.Observe(sample)
	}
	queueDropped := s.queueDropped.Load()
	missingActual := s.missingActualTimestamp.Load()
	stream.Close(queueDropped + missingActual)
	if s.meta.DetectionWriter != nil {
		if err := s.meta.DetectionWriter.WriteConnectionEnd(
			s.meta.ConnectionID,
			recordCount,
			queueDropped,
			missingActual,
			actualCount,
			fallbackCount,
			insertedRecordCount,
			insertedBytes,
		); err != nil {
			s.logWriteError("record detection connection summary", err)
		}
	}
}

func (s *recordFeatureSink) writeDetectionConnectionStart() {
	if s.meta.DetectionWriter == nil {
		return
	}
	if err := s.meta.DetectionWriter.WriteConnectionStart(
		s.meta.ConnectionID,
		s.meta.Direction,
		s.meta.EmbeddingEnabled,
		s.meta.StartedAt,
		s.meta.UpstreamLocalAddr,
		s.meta.UpstreamAddr,
	); err != nil {
		s.logWriteError("record detection connection start", err)
	}
}

func (s *recordFeatureSink) logWriteError(output string, err error) {
	s.writeErrorOnce.Do(func() {
		log.Printf("[ERROR] write %s failed: %v", output, err)
	})
}

func analyzeRecordFeatures(samples []recordSample, dropped uint64, meta recordFeatureMeta) string {
	if len(samples) == 0 && dropped == 0 {
		return ""
	}

	sort.Slice(samples, func(i, j int) bool {
		return samples[i].FeatureTime().Before(samples[j].FeatureTime())
	})

	var b strings.Builder
	stream := newRecordFeatureStream(meta)
	for _, report := range stream.Start() {
		b.WriteString(report)
	}
	for _, sample := range samples {
		for _, report := range stream.Observe(sample) {
			b.WriteString(report)
		}
	}
	for _, report := range stream.Close(dropped) {
		b.WriteString(report)
	}
	return b.String()
}

type recordFeatureStream struct {
	meta                      recordFeatureMeta
	epoch                     *recordEpochStream
	epochIndex                int
	total                     int
	gaps                      []time.Duration
	cachedIdleGapThreshold    time.Duration
	gapsSinceIdleGapRefresh   int
	idleGapThresholdAvailable bool
	started                   bool
	reportsEnabled            bool
}

func newRecordFeatureStream(meta recordFeatureMeta) *recordFeatureStream {
	return &recordFeatureStream{meta: meta, reportsEnabled: true}
}

func newSilentRecordFeatureStream(meta recordFeatureMeta) *recordFeatureStream {
	stream := newRecordFeatureStream(meta)
	stream.reportsEnabled = false
	return stream
}

func (s *recordFeatureStream) Start() []string {
	if s.started {
		return nil
	}
	s.started = true
	if !s.reportsEnabled {
		return nil
	}
	return []string{
		fmt.Sprintf("connection connection_id=%d direction=%s embedding_enabled=%t client=%s upstream=%s upstream_local=%s started_at=%s realtime=true observation=network_egress timestamp=actual_tx_or_predicted_record_last_byte\n",
			s.meta.ConnectionID,
			s.meta.Direction,
			s.meta.EmbeddingEnabled,
			s.meta.ClientAddr,
			s.meta.UpstreamAddr,
			s.meta.UpstreamLocalAddr,
			s.meta.StartedAt.Format(time.RFC3339Nano),
		),
		fmt.Sprintf("feature_order=%s\n", strings.Join(recordFeatureDisturbanceNames(), ",")),
	}
}

func (s *recordFeatureStream) Observe(sample recordSample) []string {
	if sample.Length <= 0 {
		return nil
	}

	var reports []string
	if !s.started {
		reports = append(reports, s.Start()...)
	}
	s.total++

	if s.epoch == nil {
		reports = append(reports, s.startEpoch(sample)...)
		return reports
	}

	gap := sample.FeatureTime().Sub(s.epoch.LastRecordTime())
	if gap > s.activeEpochGapThreshold() {
		reports = append(reports, s.epoch.Finish("idle_gap")...)
		reports = append(reports, s.startEpoch(sample)...)
		return reports
	}
	if gap > 0 {
		s.gaps = append(s.gaps, gap)
		s.gapsSinceIdleGapRefresh++
		if len(s.gaps) > idleGapHistoryLimit {
			copy(s.gaps, s.gaps[len(s.gaps)-idleGapHistoryLimit:])
			s.gaps = s.gaps[:idleGapHistoryLimit]
		}
	}

	reports = append(reports, s.epoch.Observe(sample)...)
	return reports
}

func (s *recordFeatureStream) Close(dropped uint64) []string {
	var reports []string
	if !s.started {
		reports = append(reports, s.Start()...)
	}
	if s.epoch != nil {
		reports = append(reports, s.epoch.Finish("connection_close")...)
		s.epoch = nil
	}
	if !s.reportsEnabled {
		return nil
	}
	if s.total == 0 {
		reports = append(reports, "no_application_data_records\n")
	}
	reports = append(reports, fmt.Sprintf("connection_closed app_records=%d dropped=%d\n", s.total, dropped))
	return reports
}

func (s *recordFeatureStream) startEpoch(first recordSample) []string {
	s.epochIndex++
	s.epoch = newRecordEpochStream(s.epochIndex, first)
	s.epoch.connectionID = s.meta.ConnectionID
	s.epoch.direction = s.meta.Direction
	s.epoch.embeddingEnabled = s.meta.EmbeddingEnabled
	s.epoch.detectionWriter = s.meta.DetectionWriter
	s.epoch.reportsEnabled = s.reportsEnabled
	if !s.reportsEnabled {
		return nil
	}
	return []string{
		fmt.Sprintf("active_epoch=%d opened first_record_at=%s idle_gap_threshold=%s active_epoch_gap_threshold=%s min_records=%d\n",
			s.epochIndex,
			first.FeatureTime().Format(time.RFC3339Nano),
			s.idleGapThreshold(),
			s.activeEpochGapThreshold(),
			minActiveEpochRecords,
		),
	}
}

func (s *recordFeatureStream) idleGapThreshold() time.Duration {
	if len(s.gaps) == 0 {
		return idleGapFloor
	}
	if s.idleGapThresholdAvailable && s.gapsSinceIdleGapRefresh < idleGapRefreshInterval {
		return s.cachedIdleGapThreshold
	}
	medianGap := medianDuration(s.gaps)
	adaptive := time.Duration(float64(medianGap) * idleGapMedianMultiplier)
	if adaptive < idleGapFloor {
		adaptive = idleGapFloor
	}
	s.cachedIdleGapThreshold = adaptive
	s.gapsSinceIdleGapRefresh = 0
	s.idleGapThresholdAvailable = true
	return s.cachedIdleGapThreshold
}

func (s *recordFeatureStream) activeEpochGapThreshold() time.Duration {
	threshold := s.idleGapThreshold()
	if threshold < activeEpochGapFloor {
		return activeEpochGapFloor
	}
	return threshold
}

type labeledStageWindow struct {
	Window stageWindow
	Label  string
}

type recordEpochStream struct {
	index int
	start time.Time

	connectionID     uint64
	direction        string
	embeddingEnabled bool
	detectionWriter  *detectionDataWriter

	records        []recordSample
	last           recordSample
	recordsOrdered bool
	reportsEnabled bool

	nextStageStart   time.Duration
	stageWidth       time.Duration
	stageStep        time.Duration
	stageWidthChosen bool
	stageWindows     []labeledStageWindow
	stableWindows    []stageWindow
	stableCandidates []stageWindow

	eligibleEmitted       bool
	stableSeen            bool
	inStableSegment       bool
	pendingStableStart    time.Duration
	pendingStableStartSet bool
	stableStart           time.Duration
	stableEnd             time.Duration

	mainLengths        []int
	residualLengthBins []int
	mainLengthsEmitted bool

	featureWidth       time.Duration
	featureWidthChosen bool
	nextFeatureStart   time.Duration
	featureWindows     []featureWindowResult
	// The rolling feature-window builder recomputes the retained windows with
	// one shared burst reference. Remember that reference and the window count
	// it describes so adaptive baseline rebuilds can reuse the already-computed
	// feature vectors instead of scanning the same Records again under a.mu.
	featureBurstReference        float64
	featureBurstReferenceValid   bool
	featureBurstReferenceWindows int
	iatSchema                    iatDistributionSchema
	iatSchemaFrozen              bool
}

func newRecordEpochStream(index int, first recordSample) *recordEpochStream {
	return &recordEpochStream{
		index:            index,
		start:            first.FeatureTime(),
		records:          []recordSample{first},
		last:             first,
		recordsOrdered:   true,
		reportsEnabled:   true,
		nextStageStart:   0,
		nextFeatureStart: 0,
	}
}

func (e *recordEpochStream) LastRecordTime() time.Time {
	return e.last.FeatureTime()
}

func (e *recordEpochStream) activeIATSchema() *iatDistributionSchema {
	if e == nil || !e.iatSchemaFrozen || !e.iatSchema.valid() {
		return nil
	}
	return &e.iatSchema
}

func (e *recordEpochStream) Observe(sample recordSample) []string {
	lastAt, sampleAt := e.last.FeatureTime(), sample.FeatureTime()
	if sampleAt.Before(lastAt) ||
		(sampleAt.Equal(lastAt) && sample.EgressID != 0 && e.last.EgressID != 0 && sample.EgressID < e.last.EgressID) {
		e.recordsOrdered = false
	}
	e.records = append(e.records, sample)
	e.last = sample

	var reports []string
	if len(e.records) >= minActiveEpochRecords && !e.eligibleEmitted {
		e.eligibleEmitted = true
		e.chooseStageWindowGeometry()
		if e.reportsEnabled {
			reports = append(reports, fmt.Sprintf("active_epoch=%d eligible records=%d elapsed=%.3fs\n",
				e.index,
				len(e.records),
				e.last.FeatureTime().Sub(e.start).Seconds(),
			))
			reports = append(reports, fmt.Sprintf("active_epoch=%d stage_window_width=%.3fs stage_window_step=%.3fs target_records=%d\n",
				e.index,
				e.stageWidth.Seconds(),
				e.stageStep.Seconds(),
				stageWindowTargetRecords,
			))
		}
	}
	reports = append(reports, e.processCompletedStageWindows()...)
	return reports
}

func (e *recordEpochStream) Finish(reason string) []string {
	var reports []string
	if len(e.records) < minActiveEpochRecords {
		if e.reportsEnabled {
			reports = append(reports, fmt.Sprintf("active_epoch=%d records=%d skipped=too_few_records reason=%s\n",
				e.index,
				len(e.records),
				reason,
			))
		}
		return reports
	}
	reports = append(reports, e.processCompletedStageWindows()...)
	if e.reportsEnabled {
		reports = append(reports, fmt.Sprintf("active_epoch=%d closed reason=%s records=%d duration=%.3fs stage_windows=%d feature_windows=%d\n",
			e.index,
			reason,
			len(e.records),
			observedDuration(e.records).Seconds(),
			len(e.stageWindows),
			len(e.featureWindows),
		))
	}
	return reports
}

func (e *recordEpochStream) processCompletedStageWindows() []string {
	if len(e.records) < minActiveEpochRecords {
		return nil
	}
	e.chooseStageWindowGeometry()

	var reports []string
	horizon := e.last.FeatureTime().Sub(e.start)
	for e.nextStageStart+e.stageWidth <= horizon {
		window := e.buildStageWindow(e.nextStageStart)
		label := e.classifyStageWindow(window)
		e.stageWindows = append(e.stageWindows, labeledStageWindow{Window: window, Label: label})
		if e.reportsEnabled {
			reports = append(reports, fmt.Sprintf("stage active_epoch=%d range=%.3f-%.3fs label=%s records=%d rate=%.3f throughput=%.3f\n",
				e.index,
				window.Start.Seconds(),
				window.End.Seconds(),
				label,
				window.Count,
				window.Rate,
				window.Throughput,
			))
		}
		reports = append(reports, e.advanceStableFeatureWindows(window, label)...)
		e.nextStageStart += e.stageStep
	}
	return reports
}

func (e *recordEpochStream) chooseStageWindowGeometry() {
	if e.stageWidthChosen {
		return
	}

	e.stageWidth = stageWindowDurations[len(stageWindowDurations)-1]
	sampleCount := minInt(len(e.records), minActiveEpochRecords)
	if sampleCount >= 2 {
		elapsed := e.records[sampleCount-1].FeatureTime().Sub(e.records[0].FeatureTime())
		if elapsed <= 0 {
			e.stageWidth = stageWindowDurations[0]
		} else {
			rate := float64(sampleCount-1) / elapsed.Seconds()
			for _, width := range stageWindowDurations {
				if rate*width.Seconds() >= stageWindowTargetRecords {
					e.stageWidth = width
					break
				}
			}
		}
	} else {
		e.stageWidth = stageWindowDurations[0]
	}
	e.stageStep = e.stageWidth / 2
	e.stageWidthChosen = true
}

func (e *recordEpochStream) buildStageWindow(start time.Duration) stageWindow {
	end := start + e.stageWidth
	count, bytes := countRecordsInRelativeWindow(e.records, e.start, start, end)
	seconds := e.stageWidth.Seconds()
	return stageWindow{
		Start:      start,
		End:        end,
		Count:      count,
		Bytes:      bytes,
		Rate:       float64(count) / seconds,
		Throughput: float64(bytes) / seconds,
	}
}

func (e *recordEpochStream) classifyStageWindow(window stageWindow) string {
	e.pendingStableStartSet = false
	if window.Count == 0 {
		e.stableCandidates = nil
		if e.stableSeen {
			return "tail"
		}
		return "startup"
	}

	var prev *stageWindow
	if len(e.stageWindows) > 0 {
		prev = &e.stageWindows[len(e.stageWindows)-1].Window
	}

	if !e.stableSeen {
		if e.confirmStableRegime(window) {
			return "stable_bulk"
		}
		return "startup"
	}

	baselineCount := medianStageScalar(e.stableWindows, func(w stageWindow) float64 { return float64(w.Count) })
	baselineRate := medianStageScalar(e.stableWindows, func(w stageWindow) float64 { return w.Rate })
	baselineThroughput := medianStageScalar(e.stableWindows, func(w stageWindow) float64 { return w.Throughput })

	label := "stable_bulk"
	if window.Count < stageStableMinimumRecords {
		label = "tail"
	} else if baselineCount > 0 && float64(window.Count) < baselineCount*stageTailBaselineRatio {
		label = "tail"
	} else if baselineThroughput > 0 && window.Throughput < baselineThroughput*stageTailBaselineRatio {
		label = "tail"
	}
	if label == "stable_bulk" && prev != nil && prev.Rate > 0 && prev.Throughput > 0 {
		if absLogRatio(window.Rate, prev.Rate) > stageTransitionLogThreshold ||
			absLogRatio(window.Throughput, prev.Throughput) > stageTransitionLogThreshold {
			label = "transition"
		}
	}
	if label == "stable_bulk" && baselineRate > 0 && baselineThroughput > 0 {
		if absLogRatio(window.Rate, baselineRate) > stageTransitionLogThreshold ||
			absLogRatio(window.Throughput, baselineThroughput) > stageTransitionLogThreshold {
			label = "transition"
		}
	}
	if label == "stable_bulk" {
		e.stableCandidates = nil
		e.appendStableBaselineWindow(window)
		return label
	}
	if e.confirmStableRegime(window) {
		return "stable_bulk"
	}
	return label
}

func (e *recordEpochStream) confirmStableRegime(window stageWindow) bool {
	if window.Count < stageStableMinimumRecords || window.Rate <= 0 || window.Throughput <= 0 {
		e.stableCandidates = nil
		return false
	}

	e.stableCandidates = append(e.stableCandidates, window)
	if len(e.stableCandidates) > stageStableCandidateWindows {
		e.stableCandidates = e.stableCandidates[len(e.stableCandidates)-stageStableCandidateWindows:]
	}
	if len(e.stableCandidates) < stageStableCandidateWindows {
		return false
	}

	a := e.stableCandidates[0]
	b := e.stableCandidates[1]
	c := e.stableCandidates[2]
	if !smoothStageWindows(a, b, c) {
		return false
	}
	if countRecordsInWindow(e.records, a.Start, c.End) < minFeatureWindowRecords {
		return false
	}

	e.stableSeen = true
	e.stableWindows = append(e.stableWindows[:0], e.stableCandidates...)
	e.pendingStableStart = a.Start
	e.pendingStableStartSet = true
	e.stableCandidates = nil
	return true
}

func (e *recordEpochStream) appendStableBaselineWindow(window stageWindow) {
	e.stableWindows = append(e.stableWindows, window)
	if len(e.stableWindows) > stageStableBaselineWindowLimit {
		e.stableWindows = e.stableWindows[len(e.stableWindows)-stageStableBaselineWindowLimit:]
	}
}

func (e *recordEpochStream) advanceStableFeatureWindows(window stageWindow, label string) []string {
	if label != "stable_bulk" {
		e.inStableSegment = false
		return nil
	}

	if !e.inStableSegment {
		e.inStableSegment = true
		e.stableStart = window.Start
		if e.pendingStableStartSet {
			e.stableStart = e.pendingStableStart
		}
		e.stableEnd = window.End
		e.nextFeatureStart = window.Start
		if e.pendingStableStartSet {
			e.nextFeatureStart = e.pendingStableStart
		}
		if !e.featureWidthChosen {
			e.featureWidth = 0
		}
	} else {
		e.stableEnd = window.End
	}
	e.pendingStableStartSet = false

	var reports []string
	if !e.mainLengthsEmitted {
		stableRecords := recordsInRelativeRange(e.records, e.stableStart, e.stableEnd)
		if len(stableRecords) < minFeatureWindowRecords {
			return reports
		}
		selection := selectMainLengths(stableRecords)
		e.mainLengths = selection.Lengths
		e.residualLengthBins = determineResidualLengthBinUpper(stableRecords)
		e.mainLengthsEmitted = true
		if e.reportsEnabled {
			reports = append(reports, fmt.Sprintf("active_epoch=%d stable_bulk_started range=%.3f-%.3fs calibration_records=%d main_lengths=%s main_length_status=%s main_candidate_coverage=%.6f residual_length_bin_upper=%s\n",
				e.index,
				e.stableStart.Seconds(),
				e.stableEnd.Seconds(),
				len(stableRecords),
				formatIntSlice(e.mainLengths),
				mainLengthSelectionStatus(selection),
				selection.CandidateCoverage,
				formatIntSlice(e.residualLengthBins),
			))
		}
	}
	if !e.featureWidthChosen {
		for _, width := range featureWindowDurations {
			if e.stableEnd < e.stableStart+width {
				continue
			}
			// Select the width from the most recent complete interval. The
			// beginning of a connection can contain a short handshake/write
			// burst even when stable throughput is lower; choosing from that
			// first interval can lock the stream to a width whose later windows
			// never reach minFeatureWindowRecords.
			latestStart := e.stableEnd - width
			if countRecordsInWindow(e.records, latestStart, e.stableEnd) >= minFeatureWindowRecords {
				e.featureWidth = width
				e.featureWidthChosen = true
				e.nextFeatureStart = e.stableStart
				if e.reportsEnabled {
					reports = append(reports, fmt.Sprintf("active_epoch=%d feature_window_width=%.3fs feature_window_step=%.3fs\n",
						e.index,
						e.featureWidth.Seconds(),
						featureWindowStepFor(e.featureWidth).Seconds(),
					))
				}
				break
			}
		}
	}
	if !e.featureWidthChosen {
		return reports
	}

	for e.nextFeatureStart+e.featureWidth <= e.stableEnd {
		start := e.nextFeatureStart
		end := start + e.featureWidth
		count := countRecordsInWindow(e.records, start, end)
		if count >= minFeatureWindowRecords {
			result := featureWindowResult{
				Start:       start,
				End:         end,
				RecordCount: count,
			}
			e.featureWindows = append(e.featureWindows, result)
			primaryStart := maxInt(0, len(e.featureWindows)-adaptiveObservationWindowMinimum)
			reference, referenceValid := estimateBurstIATReferenceForWindows(
				e.records,
				e.featureWindows[primaryStart:],
			)
			recomputeStart := maxInt(0, len(e.featureWindows)-adaptiveObservationFallbackLimitDefault)
			recomputed := recomputeFeatureWindowsWithBurstReferenceAndIATSchema(
				e.records,
				e.featureWindows[recomputeStart:],
				e.mainLengths,
				e.residualLengthBins,
				reference,
				referenceValid,
				e.activeIATSchema(),
			)
			copy(e.featureWindows[recomputeStart:], recomputed)
			e.featureBurstReference = reference
			e.featureBurstReferenceValid = referenceValid
			e.featureBurstReferenceWindows = len(e.featureWindows)
			if e.reportsEnabled {
				features := e.featureWindows[len(e.featureWindows)-1].Features
				baseline := medianRecordWindowFeatures(e.featureWindows[primaryStart:])
				disturbances := recordFeatureDisturbances(features, baseline)
				reports = append(reports, fmt.Sprintf("window active_epoch=%d index=%d range=%.3f-%.3fs records=%d disturbances=%s features=%s\n",
					e.index,
					len(e.featureWindows)-1,
					start.Seconds(),
					end.Seconds(),
					count,
					formatFloatSlice(disturbances),
					formatRecordFeatureValues(features),
				))
			}
			if e.detectionWriter != nil {
				localRecords := recordsInRelativeRange(e.records, start, end)
				insertedRecords, insertedBytes := detectionInsertionStats(localRecords)
				if err := e.detectionWriter.WriteWindow(detectionWindowEvent{
					ConnectionID:      e.connectionID,
					Direction:         e.direction,
					EmbeddingEnabled:  e.embeddingEnabled,
					ActiveEpoch:       e.index,
					WindowIndex:       len(e.featureWindows) - 1,
					StartUnixNS:       e.start.Add(start).UnixNano(),
					EndUnixNS:         e.start.Add(end).UnixNano(),
					WidthNS:           int64(e.featureWidth),
					RecordCount:       count,
					IATCount:          countRecordIATsInWindow(e.records, start, end),
					InsertedRecords:   insertedRecords,
					InsertedBytes:     insertedBytes,
					ContainsInsertion: insertedRecords > 0,
				}); err != nil {
					log.Printf("[ERROR] write record detection window: %v", err)
				}
			}
		}
		e.nextFeatureStart += featureWindowStepFor(e.featureWidth)
	}
	return reports
}

func smoothStageWindows(a, b, c stageWindow) bool {
	if a.Count == 0 || b.Count == 0 || c.Count == 0 {
		return false
	}
	if absLogRatio(b.Rate, a.Rate) > stageStableSmoothLogThreshold ||
		absLogRatio(c.Rate, b.Rate) > stageStableSmoothLogThreshold {
		return false
	}
	if absLogRatio(b.Throughput, a.Throughput) > stageStableSmoothLogThreshold ||
		absLogRatio(c.Throughput, b.Throughput) > stageStableSmoothLogThreshold {
		return false
	}
	return true
}

func medianStageScalar(windows []stageWindow, selectValue func(stageWindow) float64) float64 {
	values := make([]float64, 0, len(windows))
	for _, window := range windows {
		values = append(values, selectValue(window))
	}
	return medianFloat64(values)
}

func computeIdleGapThreshold(samples []recordSample) time.Duration {
	if len(samples) < 2 {
		return idleGapFloor
	}

	gaps := make([]time.Duration, 0, len(samples)-1)
	for i := 1; i < len(samples); i++ {
		gap := samples[i].FeatureTime().Sub(samples[i-1].FeatureTime())
		if gap > 0 {
			gaps = append(gaps, gap)
		}
	}
	if len(gaps) == 0 {
		return idleGapFloor
	}

	medianGap := medianDuration(gaps)
	adaptive := time.Duration(float64(medianGap) * idleGapMedianMultiplier)
	if adaptive < idleGapFloor {
		return idleGapFloor
	}
	return adaptive
}

func splitActiveEpochs(samples []recordSample, idleGap time.Duration) [][]recordSample {
	if len(samples) == 0 {
		return nil
	}

	var epochs [][]recordSample
	start := 0
	for i := 1; i < len(samples); i++ {
		if samples[i].FeatureTime().Sub(samples[i-1].FeatureTime()) > idleGap {
			epochs = append(epochs, samples[start:i])
			start = i
		}
	}
	epochs = append(epochs, samples[start:])
	return epochs
}

func analyzeActiveEpoch(b *strings.Builder, epochIndex int, records []recordSample) {
	epochDuration := observedDuration(records)
	stageWindows := buildStageWindows(records)
	stageLabels, stableStart, stableEnd := classifyStageWindows(stageWindows)
	stageSegments := mergeStageSegments(stageWindows, stageLabels)

	calibrationRecords := recordsInRelativeRange(records, stableStart, stableEnd)
	if len(calibrationRecords) == 0 {
		calibrationRecords = records
	}
	selection := selectMainLengths(calibrationRecords)
	mainLengths := selection.Lengths
	residualLengthBins := determineResidualLengthBinUpper(calibrationRecords)

	fmt.Fprintf(b, "active_epoch=%d records=%d duration=%.3fs stable_bulk=%.3f-%.3fs calibration_records=%d main_lengths=%s main_length_status=%s main_candidate_coverage=%.6f residual_length_bin_upper=%s\n",
		epochIndex,
		len(records),
		epochDuration.Seconds(),
		stableStart.Seconds(),
		stableEnd.Seconds(),
		len(calibrationRecords),
		formatIntSlice(mainLengths),
		mainLengthSelectionStatus(selection),
		selection.CandidateCoverage,
		formatIntSlice(residualLengthBins),
	)

	windows, selectedWidth := extractStableFeatureWindows(records, stableStart, stableEnd, mainLengths, residualLengthBins)
	if len(windows) == 0 {
		fmt.Fprintf(b, "active_epoch=%d no_feature_windows min_records_per_window=%d stable_bulk=%.3f-%.3fs\n",
			epochIndex,
			minFeatureWindowRecords,
			stableStart.Seconds(),
			stableEnd.Seconds(),
		)
	} else {
		fmt.Fprintf(b, "active_epoch=%d feature_window_width=%.3fs feature_window_step=%.3fs windows=%d\n",
			epochIndex,
			selectedWidth.Seconds(),
			featureWindowStepFor(selectedWidth).Seconds(),
			len(windows),
		)

		for i, window := range windows {
			baseline := medianRecordWindowFeatures(windows[:i+1])
			disturbances := recordFeatureDisturbances(window.Features, baseline)
			fmt.Fprintf(b, "window active_epoch=%d index=%d range=%.3f-%.3fs records=%d disturbances=%s features=%s\n",
				epochIndex,
				i,
				window.Start.Seconds(),
				window.End.Seconds(),
				window.RecordCount,
				formatFloatSlice(disturbances),
				formatRecordFeatureValues(window.Features),
			)
		}
	}

	for _, segment := range stageSegments {
		fmt.Fprintf(b, "stage active_epoch=%d range=%.3f-%.3fs label=%s\n",
			epochIndex,
			segment.Start.Seconds(),
			segment.End.Seconds(),
			segment.Label,
		)
	}
}

func observedDuration(records []recordSample) time.Duration {
	if len(records) < 2 {
		return 0
	}
	return records[len(records)-1].FeatureTime().Sub(records[0].FeatureTime())
}

type stageWindow struct {
	Start      time.Duration
	End        time.Duration
	Count      int
	Bytes      int
	Rate       float64
	Throughput float64
}

func buildStageWindows(records []recordSample) []stageWindow {
	if len(records) == 0 {
		return nil
	}

	epochStart := records[0].FeatureTime()
	horizon := observedDuration(records)
	if horizon < stageWindowDuration {
		horizon = stageWindowDuration
	}

	var windows []stageWindow
	for start := time.Duration(0); start+stageWindowDuration <= horizon; start += stageWindowStep {
		end := start + stageWindowDuration
		count, bytes := countRecordsInRelativeWindow(records, epochStart, start, end)
		seconds := stageWindowDuration.Seconds()
		windows = append(windows, stageWindow{
			Start:      start,
			End:        end,
			Count:      count,
			Bytes:      bytes,
			Rate:       float64(count) / seconds,
			Throughput: float64(bytes) / seconds,
		})
	}
	if len(windows) == 0 {
		count, bytes := countRecordsInRelativeWindow(records, epochStart, 0, stageWindowDuration)
		seconds := stageWindowDuration.Seconds()
		windows = append(windows, stageWindow{
			Start:      0,
			End:        stageWindowDuration,
			Count:      count,
			Bytes:      bytes,
			Rate:       float64(count) / seconds,
			Throughput: float64(bytes) / seconds,
		})
	}
	return windows
}

func countRecordsInRelativeWindow(records []recordSample, epochStart time.Time, start, end time.Duration) (int, int) {
	first, last := recordTimeRangeIndices(records, epochStart.Add(start), epochStart.Add(end))
	count := last - first
	bytes := 0
	for _, record := range records[first:last] {
		bytes += record.Length
	}
	return count, bytes
}

// Live and offline feature timelines are ordered by FeatureTime. Locate a
// window with binary search so a long epoch does not get rescanned from its
// first Record every time a stage or feature window advances.
func recordTimeRangeIndices(records []recordSample, startAt, endAt time.Time) (int, int) {
	if len(records) == 0 || !endAt.After(startAt) {
		return 0, 0
	}
	first := sort.Search(len(records), func(i int) bool {
		return !records[i].FeatureTime().Before(startAt)
	})
	last := sort.Search(len(records), func(i int) bool {
		return !records[i].FeatureTime().Before(endAt)
	})
	if last < first {
		return 0, 0
	}
	return first, last
}

func recordWindowIndices(records []recordSample, start, end time.Duration) (int, int) {
	if len(records) == 0 {
		return 0, 0
	}
	epochStart := records[0].FeatureTime()
	return recordTimeRangeIndices(records, epochStart.Add(start), epochStart.Add(end))
}

func classifyStageWindows(windows []stageWindow) ([]string, time.Duration, time.Duration) {
	if len(windows) == 0 {
		return nil, 0, 0
	}

	rates := make([]float64, 0, len(windows))
	throughputs := make([]float64, 0, len(windows))
	counts := make([]float64, 0, len(windows))
	for _, window := range windows {
		if window.Count > 0 {
			rates = append(rates, window.Rate)
			throughputs = append(throughputs, window.Throughput)
			counts = append(counts, float64(window.Count))
		}
	}
	if len(rates) == 0 {
		labels := make([]string, len(windows))
		for i := range labels {
			labels[i] = "tail"
		}
		return labels, windows[0].Start, windows[0].End
	}

	medianRate := medianFloat64(rates)
	medianThroughput := medianFloat64(throughputs)
	medianCount := medianFloat64(counts)
	minStableCount := maxInt(5, int(math.Ceil(medianCount*0.35)))

	candidates := make([]bool, len(windows))
	for i, window := range windows {
		if window.Count < minStableCount || window.Rate <= 0 || window.Throughput <= 0 {
			continue
		}
		rateDeviation := absLogRatio(window.Rate, medianRate)
		throughputDeviation := absLogRatio(window.Throughput, medianThroughput)
		if rateDeviation <= 0.60 && throughputDeviation <= 0.60 {
			candidates[i] = true
		}
	}

	runStart, runEnd := longestTrueRun(candidates)
	if runStart < 0 {
		runStart, runEnd = densestWindowRun(windows)
	}

	labels := make([]string, len(windows))
	for i := range labels {
		switch {
		case i < runStart:
			labels[i] = "startup"
		case i > runEnd:
			labels[i] = "tail"
		default:
			labels[i] = "stable_bulk"
		}
	}

	for i := 1; i < len(windows); i++ {
		if labels[i] == "stable_bulk" {
			continue
		}
		prev := windows[i-1]
		cur := windows[i]
		if prev.Rate > 0 && cur.Rate > 0 && prev.Throughput > 0 && cur.Throughput > 0 {
			if absLogRatio(cur.Rate, prev.Rate) > 0.85 || absLogRatio(cur.Throughput, prev.Throughput) > 0.85 {
				labels[i] = "transition"
			}
		}
	}

	return labels, windows[runStart].Start, windows[runEnd].End
}

func longestTrueRun(values []bool) (int, int) {
	bestStart, bestEnd := -1, -1
	curStart := -1
	for i, value := range values {
		if value {
			if curStart < 0 {
				curStart = i
			}
			if bestStart < 0 || i-curStart > bestEnd-bestStart {
				bestStart, bestEnd = curStart, i
			}
			continue
		}
		curStart = -1
	}
	return bestStart, bestEnd
}

func densestWindowRun(windows []stageWindow) (int, int) {
	if len(windows) == 0 {
		return 0, 0
	}
	best := 0
	for i := range windows {
		if windows[i].Bytes > windows[best].Bytes {
			best = i
		}
	}
	return best, best
}

type stageSegment struct {
	Start time.Duration
	End   time.Duration
	Label string
}

func mergeStageSegments(windows []stageWindow, labels []string) []stageSegment {
	if len(windows) == 0 || len(windows) != len(labels) {
		return nil
	}

	segments := []stageSegment{{
		Start: windows[0].Start,
		End:   windows[0].End,
		Label: labels[0],
	}}
	for i := 1; i < len(windows); i++ {
		last := &segments[len(segments)-1]
		if labels[i] == last.Label {
			last.End = windows[i].End
			continue
		}
		segments = append(segments, stageSegment{
			Start: windows[i].Start,
			End:   windows[i].End,
			Label: labels[i],
		})
	}
	return segments
}

func recordsInRelativeRange(records []recordSample, start, end time.Duration) []recordSample {
	first, last := recordWindowIndices(records, start, end)
	return records[first:last]
}

type mainLengthSelection struct {
	Lengths             []int
	CandidateCoverage   float64
	AcceptedAsMainModes bool
}

func determineMainLengths(records []recordSample) []int {
	return selectMainLengths(records).Lengths
}

func selectMainLengths(records []recordSample) mainLengthSelection {
	if len(records) == 0 {
		return mainLengthSelection{}
	}

	counts := make(map[int]int)
	for _, record := range records {
		counts[record.Length]++
	}

	type lengthCount struct {
		Length int
		Count  int
	}
	pairs := make([]lengthCount, 0, len(counts))
	for length, count := range counts {
		pairs = append(pairs, lengthCount{Length: length, Count: count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Count == pairs[j].Count {
			return pairs[i].Length < pairs[j].Length
		}
		return pairs[i].Count > pairs[j].Count
	})

	mainLengths := make([]int, 0, mainLengthKMax)
	cumulative := 0.0
	total := float64(len(records))
	for _, pair := range pairs {
		probability := float64(pair.Count) / total
		if len(mainLengths) >= mainLengthKMax ||
			pair.Count < mainLengthMinCount ||
			probability+scalarEpsilon < mainLengthPiMin ||
			cumulative+scalarEpsilon >= mainLengthGamma {
			break
		}
		mainLengths = append(mainLengths, pair.Length)
		cumulative += probability
	}

	selection := mainLengthSelection{CandidateCoverage: cumulative}
	if cumulative+scalarEpsilon < mainLengthGamma {
		return selection
	}
	selection.Lengths = mainLengths
	selection.AcceptedAsMainModes = true
	return selection
}

func mainLengthSelectionStatus(selection mainLengthSelection) string {
	if selection.AcceptedAsMainModes {
		return "concentrated"
	}
	return "dispersed"
}

// determineResidualLengthBinUpper builds an active-epoch-scoped residual
// length schema from the first confirmed stable calibration interval. The
// central range is robust to a few tail records, while underflow and overflow
// bins still account for every observed TLS record length.
func determineResidualLengthBinUpper(records []recordSample) []int {
	lengths := make([]int, 0, len(records))
	for _, record := range records {
		if record.Length > 0 {
			lengths = append(lengths, record.Length)
		}
	}
	if len(lengths) == 0 {
		return append([]int(nil), defaultResidualLengthBinUpper...)
	}
	sort.Ints(lengths)

	lastIndex := len(lengths) - 1
	lowerIndex := int(math.Floor(float64(lastIndex) * residualLengthLowerQuantile))
	upperIndex := int(math.Ceil(float64(lastIndex) * residualLengthUpperQuantile))
	lower := lengths[lowerIndex]
	upper := lengths[upperIndex]
	maxRecordLength := tlsRecordHeaderLen + maxTLSRecordPayloadLen
	if lower > maxRecordLength {
		lower = maxRecordLength
	}
	if upper > maxRecordLength {
		upper = maxRecordLength
	}
	if upper < lower {
		upper = lower
	}

	span := upper - lower + 1
	width := (span + residualLengthCentralBinTarget - 1) / residualLengthCentralBinTarget
	width = roundedResidualLengthBinWidth(width)

	alignedLower := (lower / width) * width
	if alignedLower < 1 {
		alignedLower = 1
	}

	bins := make([]int, 0, residualLengthCentralBinTarget+2)
	if alignedLower > 1 {
		bins = append(bins, alignedLower-1)
	}
	for binUpper := alignedLower + width - 1; ; binUpper += width {
		if binUpper > maxRecordLength {
			binUpper = maxRecordLength
		}
		if len(bins) == 0 || bins[len(bins)-1] != binUpper {
			bins = append(bins, binUpper)
		}
		if binUpper >= upper || binUpper >= maxRecordLength {
			break
		}
	}
	if bins[len(bins)-1] < maxRecordLength {
		bins = append(bins, maxRecordLength)
	}
	return bins
}

func roundedResidualLengthBinWidth(width int) int {
	if width <= residualLengthMinBinWidth {
		return residualLengthMinBinWidth
	}
	rounded := residualLengthMinBinWidth
	for rounded < width {
		rounded *= 2
	}
	return rounded
}

type featureWindowResult struct {
	Start       time.Duration
	End         time.Duration
	RecordCount int
	Features    recordWindowFeatures
}

func extractStableFeatureWindows(records []recordSample, stableStart, stableEnd time.Duration, mainLengths, residualLengthBins []int) ([]featureWindowResult, time.Duration) {
	for _, width := range featureWindowDurations {
		windows := buildFeatureWindows(records, stableStart, stableEnd, width, mainLengths, residualLengthBins)
		if len(windows) > 0 {
			return windows, width
		}
	}
	return nil, 0
}

func buildFeatureWindows(records []recordSample, stableStart, stableEnd, width time.Duration, mainLengths, residualLengthBins []int) []featureWindowResult {
	if len(records) == 0 || stableEnd <= stableStart || width <= 0 {
		return nil
	}

	step := featureWindowStepFor(width)
	if step <= 0 {
		return nil
	}

	var windows []featureWindowResult
	for start := stableStart; start+width <= stableEnd; start += step {
		end := start + width
		count := countRecordsInWindow(records, start, end)
		if count < minFeatureWindowRecords {
			continue
		}
		windows = append(windows, featureWindowResult{
			Start:       start,
			End:         end,
			RecordCount: count,
		})
	}
	windows, _, _ = calibrateFeatureWindowBursts(records, windows, mainLengths, residualLengthBins)
	return windows
}

// calibrateFeatureWindowBursts estimates one burst reference from the
// historical Record pairs covered by windows, then recomputes every window
// with that same frozen reference. Overlapping windows do not duplicate pairs.
func calibrateFeatureWindowBursts(
	records []recordSample,
	windows []featureWindowResult,
	mainLengths, residualLengthBins []int,
) ([]featureWindowResult, float64, bool) {
	reference, referenceValid := estimateBurstIATReferenceForWindows(records, windows)
	return recomputeFeatureWindowsWithBurstReference(
		records,
		windows,
		mainLengths,
		residualLengthBins,
		reference,
		referenceValid,
	), reference, referenceValid
}

func recomputeFeatureWindowsWithBurstReference(
	records []recordSample,
	windows []featureWindowResult,
	mainLengths, residualLengthBins []int,
	reference float64,
	referenceValid bool,
) []featureWindowResult {
	return recomputeFeatureWindowsWithBurstReferenceAndIATSchema(
		records,
		windows,
		mainLengths,
		residualLengthBins,
		reference,
		referenceValid,
		nil,
	)
}

func recomputeFeatureWindowsWithBurstReferenceAndIATSchema(
	records []recordSample,
	windows []featureWindowResult,
	mainLengths, residualLengthBins []int,
	reference float64,
	referenceValid bool,
	iatSchema *iatDistributionSchema,
) []featureWindowResult {
	recomputed := make([]featureWindowResult, len(windows))
	for i, window := range windows {
		recomputed[i] = window
		recomputed[i].Features = computeRecordWindowFeaturesWithIATSchema(
			records,
			window.Start,
			window.End,
			window.End-window.Start,
			mainLengths,
			residualLengthBins,
			reference,
			referenceValid,
			iatSchema,
		)
	}
	return recomputed
}

func featureWindowStepFor(width time.Duration) time.Duration {
	if width <= 0 {
		return 0
	}
	return width / 2
}

func countRecordsInWindow(records []recordSample, start, end time.Duration) int {
	first, last := recordWindowIndices(records, start, end)
	return last - first
}

func countRecordIATsInWindow(records []recordSample, start, end time.Duration) int {
	first, last := recordWindowIndices(records, start, end)
	if first < 1 {
		first = 1
	}
	return maxInt(0, last-first)
}

func detectionInsertionStats(records []recordSample) (count, bytes int) {
	for _, record := range records {
		if !record.Embedded {
			continue
		}
		count++
		bytes += record.Length
	}
	return count, bytes
}

type recordWindowFeatures struct {
	MainLengthCoverage float64
	MixedLengthDist    []float64
	AvgRecordLength    float64
	LengthCV           float64
	LengthDiffDist     []float64
	IATDist            []float64
	IATPositions       []float64
	RecordRate         float64
	Throughput         float64
	BurstCount         float64
	AvgBurstRecords    float64
	AvgBurstBytes      float64
	BurstRecordRatio   float64
	BurstByteRatio     float64
	MaxBurstRecords    float64
	MaxBurstBytes      float64
}

type recordWindowFeatureScratch struct {
	features recordWindowFeatures
	bursts   []burstSummary
}

func computeRecordWindowFeatures(
	records []recordSample,
	start, end, width time.Duration,
	mainLengths, residualLengthBins []int,
	burstIATReference float64,
	burstIATReferenceValid bool,
) recordWindowFeatures {
	return computeRecordWindowFeaturesWithIATSchemaAndScratch(
		records,
		start,
		end,
		width,
		mainLengths,
		residualLengthBins,
		burstIATReference,
		burstIATReferenceValid,
		nil,
		nil,
	)
}

func computeRecordWindowFeaturesWithIATSchema(
	records []recordSample,
	start, end, width time.Duration,
	mainLengths, residualLengthBins []int,
	burstIATReference float64,
	burstIATReferenceValid bool,
	iatSchema *iatDistributionSchema,
) recordWindowFeatures {
	return computeRecordWindowFeaturesWithIATSchemaAndScratch(
		records,
		start,
		end,
		width,
		mainLengths,
		residualLengthBins,
		burstIATReference,
		burstIATReferenceValid,
		iatSchema,
		nil,
	)
}

func computeRecordWindowFeaturesWithScratch(
	records []recordSample,
	start, end, width time.Duration,
	mainLengths, residualLengthBins []int,
	burstIATReference float64,
	burstIATReferenceValid bool,
	scratch *recordWindowFeatureScratch,
) recordWindowFeatures {
	return computeRecordWindowFeaturesWithIATSchemaAndScratch(
		records,
		start,
		end,
		width,
		mainLengths,
		residualLengthBins,
		burstIATReference,
		burstIATReferenceValid,
		nil,
		scratch,
	)
}

func computeRecordWindowFeaturesWithIATSchemaAndScratch(
	records []recordSample,
	start, end, width time.Duration,
	mainLengths, residualLengthBins []int,
	burstIATReference float64,
	burstIATReferenceValid bool,
	iatSchema *iatDistributionSchema,
	scratch *recordWindowFeatureScratch,
) recordWindowFeatures {
	local := recordsInRelativeRange(records, start, end)
	n := len(local)
	if len(residualLengthBins) == 0 {
		residualLengthBins = defaultResidualLengthBinUpper
	}
	iatPositions := iatDistributionPositions(iatSchema)
	features := recordWindowFeatures{}
	if scratch == nil {
		features.MixedLengthDist = make([]float64, len(mainLengths)+len(residualLengthBins))
		features.LengthDiffDist = make([]float64, len(lengthDiffBinUpper))
		features.IATDist = make([]float64, len(iatPositions))
		features.IATPositions = append([]float64(nil), iatPositions...)
	} else {
		features.MixedLengthDist = resetFloat64Scratch(
			scratch.features.MixedLengthDist,
			len(mainLengths)+len(residualLengthBins),
		)
		features.LengthDiffDist = resetFloat64Scratch(
			scratch.features.LengthDiffDist,
			len(lengthDiffBinUpper),
		)
		features.IATDist = resetFloat64Scratch(
			scratch.features.IATDist,
			len(iatPositions),
		)
		features.IATPositions = resetFloat64Scratch(
			scratch.features.IATPositions,
			len(iatPositions),
		)
		copy(features.IATPositions, iatPositions)
	}
	if n == 0 {
		if scratch != nil {
			scratch.features = features
			scratch.bursts = scratch.bursts[:0]
		}
		return features
	}

	mainLengthIndex := make(map[int]int, len(mainLengths))
	for i, length := range mainLengths {
		mainLengthIndex[length] = i
	}

	totalBytes := 0
	mainCount := 0
	for _, record := range local {
		totalBytes += record.Length
		if idx, ok := mainLengthIndex[record.Length]; ok {
			features.MixedLengthDist[idx]++
			mainCount++
		} else {
			bin := residualLengthBin(record.Length, residualLengthBins)
			features.MixedLengthDist[len(mainLengths)+bin]++
		}
	}
	for i := range features.MixedLengthDist {
		features.MixedLengthDist[i] /= float64(n)
	}

	features.MainLengthCoverage = float64(mainCount) / float64(n)
	features.AvgRecordLength = float64(totalBytes) / float64(n)
	features.LengthCV = lengthCoefficientOfVariation(local, features.AvgRecordLength)

	for i := 1; i < len(local); i++ {
		diff := absInt(local[i].Length - local[i-1].Length)
		features.LengthDiffDist[lengthDiffBin(diff)]++
	}
	if len(local) > 1 {
		normalize(features.LengthDiffDist, float64(len(local)-1))
	}

	fillIATDistributionWithSchema(records, start, end, features.IATDist, iatSchema)

	seconds := width.Seconds()
	features.RecordRate = float64(n) / seconds
	features.Throughput = float64(totalBytes) / seconds

	var burstScratch []burstSummary
	if scratch != nil {
		burstScratch = scratch.bursts[:0]
	}
	bursts := computeWindowBurstsInto(
		burstScratch,
		records,
		start,
		end,
		burstIATReference,
		burstIATReferenceValid,
	)
	features.BurstCount = float64(len(bursts))
	if len(bursts) > 0 {
		var burstRecords, burstBytes float64
		for _, burst := range bursts {
			burstRecords += float64(burst.RecordCount)
			burstBytes += float64(burst.Bytes)
			if float64(burst.RecordCount) > features.MaxBurstRecords {
				features.MaxBurstRecords = float64(burst.RecordCount)
			}
			if float64(burst.Bytes) > features.MaxBurstBytes {
				features.MaxBurstBytes = float64(burst.Bytes)
			}
		}
		features.AvgBurstRecords = burstRecords / float64(len(bursts))
		features.AvgBurstBytes = burstBytes / float64(len(bursts))
		features.BurstRecordRatio = burstRecords / float64(n)
		if totalBytes > 0 {
			features.BurstByteRatio = burstBytes / float64(totalBytes)
		}
	}
	if scratch != nil {
		scratch.features = features
		scratch.bursts = bursts
	}

	return features
}

func resetFloat64Scratch(values []float64, length int) []float64 {
	if cap(values) < length {
		return make([]float64, length)
	}
	values = values[:length]
	clear(values)
	return values
}

func residualLengthBin(length int, binUpper []int) int {
	if len(binUpper) == 0 {
		binUpper = defaultResidualLengthBinUpper
	}
	for i, upper := range binUpper {
		if length <= upper {
			return i
		}
	}
	return len(binUpper) - 1
}

func lengthCoefficientOfVariation(records []recordSample, mean float64) float64 {
	if len(records) < 2 || mean <= 0 {
		return 0
	}
	var sumSquared float64
	for _, record := range records {
		diff := float64(record.Length) - mean
		sumSquared += diff * diff
	}
	stddev := math.Sqrt(sumSquared / float64(len(records)-1))
	return stddev / (mean + scalarEpsilon)
}

func lengthDiffBin(diff int) int {
	if diff == 0 {
		return 0
	}
	for i := 1; i < len(lengthDiffBinUpper); i++ {
		if diff <= lengthDiffBinUpper[i] {
			return i
		}
	}
	return len(lengthDiffBinUpper) - 1
}

func fillIATDistribution(records []recordSample, start, end time.Duration, out []float64) {
	fillIATDistributionWithSchema(records, start, end, out, nil)
}

func fillIATDistributionWithSchema(
	records []recordSample,
	start, end time.Duration,
	out []float64,
	iatSchema *iatDistributionSchema,
) {
	if len(records) < 2 {
		return
	}
	first, last := recordWindowIndices(records, start, end)
	if first < 1 {
		first = 1
	}
	count := 0
	for i := first; i < last; i++ {
		delta := records[i].FeatureTime().Sub(records[i-1].FeatureTime())
		out[iatBinWithSchema(delta, iatSchema)]++
		count++
	}
	if count > 0 {
		normalize(out, float64(count))
	}
}

func iatDistributionPositions(iatSchema *iatDistributionSchema) []float64 {
	if iatSchema.valid() {
		return iatSchema.positions
	}
	return logIATPositions
}

func iatBinWithSchema(delta time.Duration, iatSchema *iatDistributionSchema) int {
	if !iatSchema.valid() {
		return iatBin(delta)
	}
	return sort.Search(len(iatSchema.upperBounds), func(i int) bool {
		return delta <= iatSchema.upperBounds[i]
	})
}

func iatBin(delta time.Duration) int {
	if delta <= shortIATThreshold {
		return 0
	}

	x := math.Log(delta.Seconds() + logIATEpsilonSeconds)
	minLog := logIATMin()
	width := logIATWidth()
	bin := int(math.Floor((x-minLog)/width)) + 1
	if bin < 1 {
		return 1
	}
	if bin >= len(logIATPositions) {
		return len(logIATPositions) - 1
	}
	return bin
}

// makeObservedIATDistributionSchema creates a fixed-size empirical-quantile
// schema. It selects boundaries only at gaps between distinct observations,
// so repeated timer values cannot create duplicate or zero-width bins.
func makeObservedIATDistributionSchema(
	values []time.Duration,
	binCount int,
	anchors []time.Duration,
) (iatDistributionSchema, bool) {
	if binCount < 2 || len(values) < binCount {
		return iatDistributionSchema{}, false
	}
	sorted := make([]time.Duration, 0, len(values))
	for _, value := range values {
		if value > 0 {
			sorted = append(sorted, value)
		}
	}
	if len(sorted) < binCount {
		return iatDistributionSchema{}, false
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	transitions := make([]int, 0, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		if sorted[i] > sorted[i-1] {
			transitions = append(transitions, i)
		}
	}
	if len(transitions) < binCount-1 {
		return iatDistributionSchema{}, false
	}

	upperBounds := make([]time.Duration, 0, binCount-1)
	transitionStart := 0
	for boundary := 1; boundary < binCount; boundary++ {
		remaining := binCount - boundary - 1
		lastCandidate := len(transitions) - remaining - 1
		target := float64(boundary*len(sorted)) / float64(binCount)
		best := transitionStart
		bestDistance := math.Abs(float64(transitions[best]) - target)
		for candidate := transitionStart + 1; candidate <= lastCandidate; candidate++ {
			distance := math.Abs(float64(transitions[candidate]) - target)
			if distance < bestDistance {
				best = candidate
				bestDistance = distance
			}
		}
		cut := transitions[best]
		left, right := sorted[cut-1], sorted[cut]
		upperBounds = append(upperBounds, left+(right-left)/2)
		transitionStart = best + 1
	}

	anchorIATDistributionBounds(upperBounds, sorted[0], sorted[len(sorted)-1], anchors)
	positions := make([]float64, binCount)
	for i := range positions {
		lower := sorted[0]
		if i > 0 {
			lower = upperBounds[i-1]
		}
		upper := sorted[len(sorted)-1]
		if i < len(upperBounds) {
			upper = upperBounds[i]
		}
		positions[i] = (math.Log(lower.Seconds()+logIATEpsilonSeconds) +
			math.Log(upper.Seconds()+logIATEpsilonSeconds)) / 2
	}
	schema := iatDistributionSchema{
		upperBounds: upperBounds,
		positions:   positions,
	}
	return schema, schema.valid()
}

func anchorIATDistributionBounds(
	upperBounds []time.Duration,
	minimum, maximum time.Duration,
	anchors []time.Duration,
) {
	used := make(map[int]struct{}, len(anchors))
	for _, anchor := range anchors {
		if anchor <= minimum || anchor >= maximum {
			continue
		}
		matched := false
		for i, upper := range upperBounds {
			if upper == anchor {
				used[i] = struct{}{}
				matched = true
				break
			}
		}
		if matched {
			continue
		}

		best := -1
		bestDistance := math.Inf(1)
		for i, upper := range upperBounds {
			if _, alreadyUsed := used[i]; alreadyUsed {
				continue
			}
			lowerLimit := minimum
			if i > 0 {
				lowerLimit = upperBounds[i-1]
			}
			upperLimit := maximum
			if i+1 < len(upperBounds) {
				upperLimit = upperBounds[i+1]
			}
			if anchor <= lowerLimit || anchor >= upperLimit {
				continue
			}
			distance := math.Abs(math.Log(
				(float64(upper) + float64(time.Nanosecond)) /
					(float64(anchor) + float64(time.Nanosecond)),
			))
			if distance < bestDistance {
				best = i
				bestDistance = distance
			}
		}
		// An anchor may replace a nearby empirical cut, but it must not pull a
		// distant quantile across a large part of the observed distribution.
		if best >= 0 && bestDistance <= math.Log(2) {
			upperBounds[best] = anchor
			used[best] = struct{}{}
		}
	}
}

type burstSummary struct {
	RecordCount int
	Bytes       int
}

func computeBurstsWithReference(records []recordSample, reference float64) []burstSummary {
	if len(records) < minBurstRecordCount {
		return nil
	}
	var bursts []burstSummary
	start := 0
	for i := 1; i < len(records); i++ {
		if normalizedRecordIAT(records[i-1], records[i]) <= reference {
			continue
		}
		if i-start >= minBurstRecordCount {
			bursts = append(bursts, summarizeBurst(records, start, i))
		}
		start = i
	}
	if len(records)-start >= minBurstRecordCount {
		bursts = append(bursts, summarizeBurst(records, start, len(records)))
	}
	return bursts
}

// computeWindowBursts implements window-clipped intersecting bursts. It uses
// the Record immediately before the window, when present, to decide whether
// the first in-window Record continues an existing burst. When the available
// timeline already contains a following Record, it is also used to recognize
// a parent burst that starts at the last in-window Record. A qualifying parent
// burst is summarized only over its in-window intersection, which may contain
// one Record after clipping.
func computeWindowBursts(
	records []recordSample,
	start, end time.Duration,
	reference float64,
	referenceValid bool,
) []burstSummary {
	return computeWindowBurstsInto(nil, records, start, end, reference, referenceValid)
}

func computeWindowBurstsInto(
	dst []burstSummary,
	records []recordSample,
	start, end time.Duration,
	reference float64,
	referenceValid bool,
) []burstSummary {
	dst = dst[:0]
	if len(records) == 0 || end <= start {
		return dst
	}

	first, last := recordWindowIndices(records, start, end)
	if first >= last {
		return dst
	}

	contextStart := first
	if contextStart > 0 {
		contextStart--
	}
	contextEnd := last
	if contextEnd < len(records) {
		contextEnd++
	}
	segmentStart := contextStart
	bursts := dst
	appendIntersection := func(segmentEnd int) {
		if segmentEnd-segmentStart < minBurstRecordCount {
			return
		}
		clippedStart := maxInt(segmentStart, first)
		clippedEnd := minInt(segmentEnd, last)
		if clippedStart >= clippedEnd {
			return
		}
		bursts = append(bursts, summarizeBurst(records, clippedStart, clippedEnd))
	}

	for i := contextStart + 1; i < contextEnd; i++ {
		connected := !referenceValid || normalizedRecordIAT(records[i-1], records[i]) <= reference
		if connected {
			continue
		}
		appendIntersection(i)
		segmentStart = i
	}
	appendIntersection(contextEnd)
	return bursts
}

func estimateBurstIATReference(records []recordSample) (float64, bool) {
	if len(records) < 2 {
		return 0, false
	}

	normalizedIATs := make([]float64, 0, len(records)-1)
	for i := 1; i < len(records); i++ {
		if records[i].Length > 0 {
			normalizedIATs = append(normalizedIATs, normalizedRecordIAT(records[i-1], records[i]))
		}
	}
	if len(normalizedIATs) == 0 {
		return 0, false
	}

	return estimateBurstIATReferenceFromValues(normalizedIATs)
}

func estimateBurstIATReferenceForWindows(records []recordSample, windows []featureWindowResult) (float64, bool) {
	if len(records) < 2 || len(windows) == 0 {
		return 0, false
	}

	rangeStart := windows[0].Start
	rangeEnd := windows[0].End
	for _, window := range windows[1:] {
		if window.Start < rangeStart {
			rangeStart = window.Start
		}
		if window.End > rangeEnd {
			rangeEnd = window.End
		}
	}
	first, last := recordWindowIndices(records, rangeStart, rangeEnd)
	if first < 1 {
		first = 1
	}
	epochStart := records[0].FeatureTime()
	normalizedIATs := make([]float64, 0, maxInt(0, last-first))
	for i := first; i < last; i++ {
		if records[i].Length <= 0 {
			continue
		}
		previousRelative := records[i-1].FeatureTime().Sub(epochStart)
		currentRelative := records[i].FeatureTime().Sub(epochStart)
		if !recordPairCoveredByFeatureWindow(previousRelative, currentRelative, windows) {
			continue
		}
		normalizedIATs = append(normalizedIATs, normalizedRecordIAT(records[i-1], records[i]))
	}
	return estimateBurstIATReferenceFromValues(normalizedIATs)
}

func recordPairCoveredByFeatureWindow(previous, current time.Duration, windows []featureWindowResult) bool {
	for _, window := range windows {
		if previous >= window.Start && previous < window.End &&
			current >= window.Start && current < window.End {
			return true
		}
	}
	return false
}

func estimateBurstIATReferenceFromValues(normalizedIATs []float64) (float64, bool) {
	if len(normalizedIATs) == 0 {
		return 0, false
	}
	sort.Float64s(normalizedIATs)
	q1 := quantileSortedFloat64(normalizedIATs, 0.25)
	q3 := quantileSortedFloat64(normalizedIATs, 0.75)
	tukeyFence := q3 + burstIATFenceMultiplier*(q3-q1)
	q3Floor := burstIATReferenceQ3Multiplier * q3
	return math.Max(tukeyFence, q3Floor), true
}

func normalizedRecordIAT(previous, current recordSample) float64 {
	if current.Length <= 0 {
		return 0
	}
	gap := current.FeatureTime().Sub(previous.FeatureTime())
	if gap <= 0 {
		return 0
	}
	return gap.Seconds() / float64(current.Length)
}

func quantileSortedFloat64(sortedValues []float64, quantile float64) float64 {
	if len(sortedValues) == 0 {
		return 0
	}
	if quantile <= 0 {
		return sortedValues[0]
	}
	if quantile >= 1 {
		return sortedValues[len(sortedValues)-1]
	}

	position := quantile * float64(len(sortedValues)-1)
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return sortedValues[lower]
	}
	fraction := position - float64(lower)
	return sortedValues[lower] + fraction*(sortedValues[upper]-sortedValues[lower])
}

func summarizeBurst(records []recordSample, start, end int) burstSummary {
	bytes := 0
	for i := start; i < end; i++ {
		bytes += records[i].Length
	}
	return burstSummary{
		RecordCount: end - start,
		Bytes:       bytes,
	}
}

func medianRecordWindowFeatures(windows []featureWindowResult) recordWindowFeatures {
	if len(windows) == 0 {
		return recordWindowFeatures{}
	}
	values := make([]float64, len(windows))

	return recordWindowFeatures{
		MainLengthCoverage: medianFeatureScalarWithScratch(windows, values, func(f recordWindowFeatures) float64 { return f.MainLengthCoverage }),
		MixedLengthDist:    medianFeatureVectorWithScratch(windows, values, func(f recordWindowFeatures) []float64 { return f.MixedLengthDist }),
		AvgRecordLength:    medianFeatureScalarWithScratch(windows, values, func(f recordWindowFeatures) float64 { return f.AvgRecordLength }),
		LengthCV:           medianFeatureScalarWithScratch(windows, values, func(f recordWindowFeatures) float64 { return f.LengthCV }),
		LengthDiffDist:     medianFeatureVectorWithScratch(windows, values, func(f recordWindowFeatures) []float64 { return f.LengthDiffDist }),
		IATDist:            medianFeatureVectorWithScratch(windows, values, func(f recordWindowFeatures) []float64 { return f.IATDist }),
		IATPositions:       append([]float64(nil), windows[0].Features.IATPositions...),
		RecordRate:         medianFeatureScalarWithScratch(windows, values, func(f recordWindowFeatures) float64 { return f.RecordRate }),
		Throughput:         medianFeatureScalarWithScratch(windows, values, func(f recordWindowFeatures) float64 { return f.Throughput }),
		BurstCount:         medianFeatureScalarWithScratch(windows, values, func(f recordWindowFeatures) float64 { return f.BurstCount }),
		AvgBurstRecords:    medianFeatureScalarWithScratch(windows, values, func(f recordWindowFeatures) float64 { return f.AvgBurstRecords }),
		AvgBurstBytes:      medianFeatureScalarWithScratch(windows, values, func(f recordWindowFeatures) float64 { return f.AvgBurstBytes }),
		BurstRecordRatio:   medianFeatureScalarWithScratch(windows, values, func(f recordWindowFeatures) float64 { return f.BurstRecordRatio }),
		BurstByteRatio:     medianFeatureScalarWithScratch(windows, values, func(f recordWindowFeatures) float64 { return f.BurstByteRatio }),
		MaxBurstRecords:    medianFeatureScalarWithScratch(windows, values, func(f recordWindowFeatures) float64 { return f.MaxBurstRecords }),
		MaxBurstBytes:      medianFeatureScalarWithScratch(windows, values, func(f recordWindowFeatures) float64 { return f.MaxBurstBytes }),
	}
}

func medianFeatureScalar(windows []featureWindowResult, selectValue func(recordWindowFeatures) float64) float64 {
	values := make([]float64, 0, len(windows))
	for _, window := range windows {
		values = append(values, selectValue(window.Features))
	}
	return medianFloat64(values)
}

func medianFeatureScalarWithScratch(
	windows []featureWindowResult,
	values []float64,
	selectValue func(recordWindowFeatures) float64,
) float64 {
	values = values[:len(windows)]
	for i, window := range windows {
		values[i] = selectValue(window.Features)
	}
	sort.Float64s(values)
	return medianSortedFloat64(values)
}

func medianFeatureVector(windows []featureWindowResult, selectValue func(recordWindowFeatures) []float64) []float64 {
	first := selectValue(windows[0].Features)
	out := make([]float64, len(first))
	for i := range first {
		values := make([]float64, 0, len(windows))
		for _, window := range windows {
			vector := selectValue(window.Features)
			if i < len(vector) {
				values = append(values, vector[i])
			}
		}
		out[i] = medianFloat64(values)
	}
	return out
}

func medianFeatureVectorWithScratch(
	windows []featureWindowResult,
	values []float64,
	selectValue func(recordWindowFeatures) []float64,
) []float64 {
	first := selectValue(windows[0].Features)
	out := make([]float64, len(first))
	values = values[:len(windows)]
	for i := range first {
		count := 0
		for _, window := range windows {
			vector := selectValue(window.Features)
			if i < len(vector) {
				values[count] = vector[i]
				count++
			}
		}
		sort.Float64s(values[:count])
		out[i] = medianSortedFloat64(values[:count])
	}
	return out
}

func medianSortedFloat64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	mid := len(values) / 2
	if len(values)%2 == 1 {
		return values[mid]
	}
	return (values[mid-1] + values[mid]) / 2
}

func recordFeatureDisturbances(cur, base recordWindowFeatures) []float64 {
	iatPositions := cur.IATPositions
	if len(iatPositions) == 0 {
		iatPositions = base.IATPositions
	}
	if len(iatPositions) == 0 {
		iatPositions = logIATPositions
	}
	return []float64{
		math.Abs(cur.MainLengthCoverage - base.MainLengthCoverage),
		totalVariationDistance(cur.MixedLengthDist, base.MixedLengthDist),
		absLogRatio(cur.AvgRecordLength, base.AvgRecordLength),
		math.Abs(cur.LengthCV - base.LengthCV),
		wasserstein1D(cur.LengthDiffDist, base.LengthDiffDist, lengthDiffPositions),
		wasserstein1D(cur.IATDist, base.IATDist, iatPositions),
		absLogRatio(cur.RecordRate, base.RecordRate),
		absLogRatio(cur.Throughput, base.Throughput),
		math.Abs(cur.BurstCount - base.BurstCount),
		absLogRatio(cur.AvgBurstRecords, base.AvgBurstRecords),
		absLogRatio(cur.AvgBurstBytes, base.AvgBurstBytes),
		math.Abs(cur.BurstRecordRatio - base.BurstRecordRatio),
		math.Abs(cur.BurstByteRatio - base.BurstByteRatio),
		absLogRatio(cur.MaxBurstRecords, base.MaxBurstRecords),
		absLogRatio(cur.MaxBurstBytes, base.MaxBurstBytes),
	}
}

func recordFeatureValues(cur recordWindowFeatures) []string {
	return []string{
		formatFeatureNumber(cur.MainLengthCoverage),
		"-",
		formatFeatureNumber(cur.AvgRecordLength),
		formatFeatureNumber(cur.LengthCV),
		"-",
		"-",
		formatFeatureNumber(cur.RecordRate),
		formatFeatureNumber(cur.Throughput),
		formatFeatureNumber(cur.BurstCount),
		formatFeatureNumber(cur.AvgBurstRecords),
		formatFeatureNumber(cur.AvgBurstBytes),
		formatFeatureNumber(cur.BurstRecordRatio),
		formatFeatureNumber(cur.BurstByteRatio),
		formatFeatureNumber(cur.MaxBurstRecords),
		formatFeatureNumber(cur.MaxBurstBytes),
	}
}

func formatRecordFeatureValues(cur recordWindowFeatures) string {
	return strings.Join(recordFeatureValues(cur), ",")
}

func formatFeatureNumber(value float64) string {
	return fmt.Sprintf("%.6f", value)
}

func recordFeatureDisturbanceNames() []string {
	return []string{
		"main_length_coverage_abs_offset",
		"mixed_length_tvd",
		"avg_record_length_abs_log_ratio",
		"length_cv_abs_offset",
		"adjacent_length_diff_wasserstein",
		"iat_log_wasserstein",
		"record_rate_abs_log_ratio",
		"throughput_abs_log_ratio",
		"burst_count_abs_offset",
		"avg_burst_records_abs_log_ratio",
		"avg_burst_bytes_abs_log_ratio",
		"burst_record_ratio_abs_offset",
		"burst_byte_ratio_abs_offset",
		"max_burst_records_abs_log_ratio",
		"max_burst_bytes_abs_log_ratio",
	}
}

func totalVariationDistance(a, b []float64) float64 {
	n := minInt(len(a), len(b))
	var sum float64
	for i := 0; i < n; i++ {
		sum += math.Abs(a[i] - b[i])
	}
	for i := n; i < len(a); i++ {
		sum += math.Abs(a[i])
	}
	for i := n; i < len(b); i++ {
		sum += math.Abs(b[i])
	}
	return 0.5 * sum
}

func wasserstein1D(a, b, positions []float64) float64 {
	if len(a) == 0 || len(a) != len(b) || len(a) != len(positions) {
		return totalVariationDistance(a, b)
	}

	var distance float64
	var cumulativeDelta float64
	for i := 0; i < len(a)-1; i++ {
		cumulativeDelta += a[i] - b[i]
		width := positions[i+1] - positions[i]
		if width < 0 {
			width = -width
		}
		distance += math.Abs(cumulativeDelta) * width
	}
	return distance
}

func absLogRatio(value, baseline float64) float64 {
	if value <= 0 && baseline <= 0 {
		return 0
	}
	return math.Abs(math.Log((value + scalarEpsilon) / (baseline + scalarEpsilon)))
}

func medianDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	tmp := append([]time.Duration(nil), values...)
	sort.Slice(tmp, func(i, j int) bool {
		return tmp[i] < tmp[j]
	})
	mid := len(tmp) / 2
	if len(tmp)%2 == 1 {
		return tmp[mid]
	}
	return (tmp[mid-1] + tmp[mid]) / 2
}

func medianFloat64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	tmp := append([]float64(nil), values...)
	sort.Float64s(tmp)
	mid := len(tmp) / 2
	if len(tmp)%2 == 1 {
		return tmp[mid]
	}
	return (tmp[mid-1] + tmp[mid]) / 2
}

func normalize(values []float64, denominator float64) {
	if denominator <= 0 {
		return
	}
	for i := range values {
		values[i] /= denominator
	}
}

func logIATMin() float64 {
	return math.Log(shortIATThreshold.Seconds() + logIATEpsilonSeconds)
}

func logIATMax() float64 {
	return math.Log(10 + logIATEpsilonSeconds)
}

func logIATWidth() float64 {
	return (logIATMax() - logIATMin()) / float64(logIATBinCount())
}

func logIATBinCount() int {
	return 12
}

func makeLogIATPositions() []float64 {
	positions := make([]float64, 1+logIATBinCount())
	positions[0] = math.Log(shortIATThreshold.Seconds()/2 + logIATEpsilonSeconds)
	minLog := logIATMin()
	width := logIATWidth()
	for i := 0; i < logIATBinCount(); i++ {
		positions[i+1] = minLog + (float64(i)+0.5)*width
	}
	return positions
}

func formatFloatSlice(values []float64) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = fmt.Sprintf("%.6f", value)
	}
	return strings.Join(parts, ",")
}

func formatIntSlice(values []int) string {
	if len(values) == 0 {
		return "[]"
	}
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = fmt.Sprintf("%d", value)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
