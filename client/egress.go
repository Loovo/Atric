package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"reflect"
	"sort"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	sofTimestampingTXSoftware = 1 << 1
	sofTimestampingSoftware   = 1 << 4
	sofTimestampingOptID      = 1 << 7
	sofTimestampingOptTSOnly  = 1 << 11

	soEEOriginTimestamping = 4
	scmTstampSend          = 0
	ipRecvErr              = 11
	ipv6RecvErr            = 25

	egressTimestampPollInterval = time.Millisecond
	egressReadRetryInterval     = time.Millisecond
	egressTimestampOOBLen       = 256
	txTimestampEventQueueSize   = 16 * 1024
	txTimestampProcessBatchSize = 128

	// TX timestamps are delivered through the socket error queue and are
	// charged against SO_RCVBUF. Long, high-rate Record streams can overflow
	// the small Linux default before the tracker goroutine drains it. Request a
	// connection-local buffer large enough for collection without changing a
	// system-wide sysctl. Linux SO_RCVBUFFORCE is 33; it is attempted only when
	// the ordinary SO_RCVBUF request is capped.
	txTimestampReceiveBufferBytes = 16 << 20
	linuxSOReceiveBufferForce     = 33
)

type recordEgressObserver interface {
	Observe(TLSRecordHeader, time.Time)
	AddDropped(uint64)
}

type recordEgressEvent struct {
	ID                uint64
	Header            TLSRecordHeader
	SubmittedAt       time.Time
	EstimatedEgressAt time.Time
	ActualEgressAt    time.Time
	Embedded          bool
}

func (e recordEgressEvent) FeatureTime() time.Time {
	if !e.ActualEgressAt.IsZero() {
		return e.ActualEgressAt
	}
	if !e.EstimatedEgressAt.IsZero() {
		return e.EstimatedEgressAt
	}
	return e.SubmittedAt
}

type recordEgressLifecycleObserver interface {
	ObserveProvisional(recordEgressEvent)
	ObserveResolved(recordEgressEvent)
	DropProvisional(uint64)
}

type recordEgressPredictionObserver interface {
	ApplyProvisionalEstimates(map[uint64]time.Time)
}

// recordEgressResolvedBatchObserver is an optional fast path for observers
// that can apply a sequence of resolved Records under one lock. Events remain
// ordered exactly as they were read from the socket error queue.
type recordEgressResolvedBatchObserver interface {
	ObserveResolvedBatch([]recordEgressEvent)
}

type combinedEgressObserver struct {
	observers []recordEgressObserver
}

// nilRecordEgressObserver handles typed nil pointers stored in an interface.
// Such an interface is not equal to nil, but invoking one of its methods can
// still dereference a nil receiver.
func nilRecordEgressObserver(observer recordEgressObserver) bool {
	if observer == nil {
		return true
	}
	value := reflect.ValueOf(observer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func combineRecordEgressObservers(observers ...recordEgressObserver) recordEgressObserver {
	combined := &combinedEgressObserver{}
	for _, observer := range observers {
		if !nilRecordEgressObserver(observer) {
			combined.observers = append(combined.observers, observer)
		}
	}
	if len(combined.observers) == 0 {
		return nil
	}
	return combined
}

func (o *combinedEgressObserver) Observe(header TLSRecordHeader, at time.Time) {
	for _, observer := range o.observers {
		observer.Observe(header, at)
	}
}

func (o *combinedEgressObserver) AddDropped(count uint64) {
	for _, observer := range o.observers {
		observer.AddDropped(count)
	}
}

func (o *combinedEgressObserver) ObserveProvisional(event recordEgressEvent) {
	for _, observer := range o.observers {
		if lifecycle, ok := observer.(recordEgressLifecycleObserver); ok {
			lifecycle.ObserveProvisional(event)
		}
	}
}

func (o *combinedEgressObserver) ObserveResolved(event recordEgressEvent) {
	o.ObserveResolvedBatch([]recordEgressEvent{event})
}

func (o *combinedEgressObserver) ObserveResolvedBatch(events []recordEgressEvent) {
	if len(events) == 0 {
		return
	}
	for _, observer := range o.observers {
		if batchObserver, ok := observer.(recordEgressResolvedBatchObserver); ok {
			batchObserver.ObserveResolvedBatch(events)
			continue
		}
		if lifecycle, ok := observer.(recordEgressLifecycleObserver); ok {
			for _, event := range events {
				lifecycle.ObserveResolved(event)
			}
		} else {
			for _, event := range events {
				observer.Observe(event.Header, event.FeatureTime())
			}
		}
	}
}

func (o *combinedEgressObserver) DropProvisional(id uint64) {
	for _, observer := range o.observers {
		if lifecycle, ok := observer.(recordEgressLifecycleObserver); ok {
			lifecycle.DropProvisional(id)
		}
	}
}

func (o *combinedEgressObserver) ApplyProvisionalEstimates(estimates map[uint64]time.Time) {
	for _, observer := range o.observers {
		if predictionObserver, ok := observer.(recordEgressPredictionObserver); ok {
			predictionObserver.ApplyProvisionalEstimates(estimates)
		}
	}
}

type recordEgressWriter struct {
	conn       net.Conn
	raw        syscall.RawConn
	tracker    *txTimestampTracker
	written    uint64
	inserted   uint64
	nextEvent  uint64
	requestOOB []byte
	predictor  *recordTimestampPredictor
}

func newRecordEgressWriter(conn net.Conn, observer recordEgressObserver, predictors ...*recordTimestampPredictor) (*recordEgressWriter, error) {
	predictor := newRecordTimestampPredictor()
	if len(predictors) > 0 && predictors[0] != nil {
		predictor = predictors[0]
	}
	w := &recordEgressWriter{conn: conn, predictor: predictor}
	if observer == nil {
		return w, nil
	}

	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("upstream connection %T does not expose syscall.Conn", conn)
	}
	raw, err := sysConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("get upstream raw connection: %w", err)
	}
	receiveBufferBytes, receiveBufferForced, err := enableTXSoftwareTimestamping(raw)
	if err != nil {
		return nil, fmt.Errorf("enable upstream TX software timestamping: %w", err)
	}
	log.Printf("[INFO] TX timestamp receive buffer requested_bytes=%d actual_bytes=%d forced=%t",
		txTimestampReceiveBufferBytes, receiveBufferBytes, receiveBufferForced)

	w.raw = raw
	w.requestOOB = makeTXTimestampRequestControl()
	w.tracker = newTXTimestampTracker(raw, observer, predictor)
	return w, nil
}

func enableTXSoftwareTimestamping(raw syscall.RawConn) (int, bool, error) {
	flags := sofTimestampingSoftware | sofTimestampingOptID | sofTimestampingOptTSOnly
	var (
		receiveBufferBytes  int
		receiveBufferForced bool
		socketErr           error
	)
	if err := raw.Control(func(fd uintptr) {
		socketErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TIMESTAMPING, flags)
		if socketErr != nil {
			return
		}
		socketErr = syscall.SetsockoptInt(
			int(fd),
			syscall.SOL_SOCKET,
			syscall.SO_RCVBUF,
			txTimestampReceiveBufferBytes,
		)
		if socketErr != nil {
			return
		}
		receiveBufferBytes, socketErr = syscall.GetsockoptInt(
			int(fd),
			syscall.SOL_SOCKET,
			syscall.SO_RCVBUF,
		)
		if socketErr != nil || receiveBufferBytes >= txTimestampReceiveBufferBytes {
			return
		}

		// Raise this socket's receive buffer above net.core.rmem_max when the
		// process has CAP_NET_ADMIN. Otherwise keep the ordinary buffer.
		if forceErr := syscall.SetsockoptInt(
			int(fd),
			syscall.SOL_SOCKET,
			linuxSOReceiveBufferForce,
			txTimestampReceiveBufferBytes,
		); forceErr != nil {
			return
		}
		receiveBufferForced = true
		receiveBufferBytes, socketErr = syscall.GetsockoptInt(
			int(fd),
			syscall.SOL_SOCKET,
			syscall.SO_RCVBUF,
		)
	}); err != nil {
		return 0, false, err
	}
	return receiveBufferBytes, receiveBufferForced, socketErr
}

func makeTXTimestampRequestControl() []byte {
	oob := make([]byte, syscall.CmsgSpace(4))
	header := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = syscall.SOL_SOCKET
	header.Type = syscall.SO_TIMESTAMPING
	header.SetLen(syscall.CmsgLen(4))
	nativeEndian.PutUint32(oob[syscall.CmsgLen(0):], sofTimestampingTXSoftware)
	return oob
}

func (w *recordEgressWriter) WriteRecord(record []byte, header TLSRecordHeader) error {
	return w.writeRecord(record, header, false)
}

func (w *recordEgressWriter) WriteEmbeddedRecord(record []byte, header TLSRecordHeader) error {
	return w.writeRecord(record, header, true)
}

func (w *recordEgressWriter) writeRecord(record []byte, header TLSRecordHeader, embedded bool) error {
	if len(record) == 0 {
		return nil
	}
	if w.tracker == nil || header.ContentType != tlsTypeApplicationData {
		return w.writePlain(record, embedded)
	}
	return w.writeTimestamped(record, header, embedded)
}

// Read bypasses Go's netpoll read path. TX timestamps keep EPOLLERR asserted
// while the socket error queue is non-empty, which net.TCPConn.Read otherwise
// reports as "not pollable" even though the TCP receive queue is healthy.
func (w *recordEgressWriter) Read(p []byte) (int, error) {
	if w.raw == nil {
		return w.conn.Read(p)
	}
	for {
		var (
			n       int
			readErr error
		)
		if err := w.raw.Control(func(fd uintptr) {
			n, readErr = syscall.Read(int(fd), p)
		}); err != nil {
			return 0, err
		}
		switch {
		case n > 0:
			return n, nil
		case readErr == nil:
			return 0, io.EOF
		case errors.Is(readErr, syscall.EINTR):
			continue
		case errors.Is(readErr, syscall.EAGAIN) || errors.Is(readErr, syscall.EWOULDBLOCK):
			time.Sleep(egressReadRetryInterval)
			continue
		default:
			return n, readErr
		}
	}
}

func (w *recordEgressWriter) writePlain(record []byte, embedded bool) error {
	for len(record) > 0 {
		n, err := w.conn.Write(record)
		if n > 0 {
			w.written += uint64(n)
			if embedded {
				w.inserted += uint64(n)
			}
			record = record[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (w *recordEgressWriter) writeTimestamped(record []byte, header TLSRecordHeader, embedded bool) error {
	w.nextEvent++
	submittedAt := time.Now()
	event := recordEgressEvent{
		ID:          w.nextEvent,
		Header:      header,
		SubmittedAt: submittedAt,
		Embedded:    embedded,
	}
	provisionalObserved := false
	predictionDropped := false
	dropProvisional := func() {
		if !predictionDropped {
			w.tracker.DropPrediction(event.ID)
			predictionDropped = true
		}
		if provisionalObserved {
			lifecycle, ok := w.tracker.observer.(recordEgressLifecycleObserver)
			if !ok {
				return
			}
			lifecycle.DropProvisional(event.ID)
		}
	}

	for len(record) > 0 {
		requestedID := uint32(w.written + uint64(len(record)) - 1)
		var err error
		event, err = w.tracker.Add(requestedID, event)
		if err != nil {
			dropProvisional()
			return err
		}
		if !provisionalObserved {
			if lifecycle, ok := w.tracker.observer.(recordEgressLifecycleObserver); ok {
				lifecycle.ObserveProvisional(event)
				provisionalObserved = true
			}
		}

		n, err := sendmsgWithTXTimestamp(w.raw, record, w.requestOOB)
		if n > 0 {
			w.written += uint64(n)
			if embedded {
				w.inserted += uint64(n)
			}
			record = record[n:]
		}
		if err != nil || n == 0 || len(record) > 0 {
			w.tracker.Remove(requestedID)
		}
		if err != nil {
			dropProvisional()
			return err
		}
		if n == 0 {
			dropProvisional()
			return io.ErrShortWrite
		}
	}
	w.tracker.Wake()
	return nil
}

func (w *recordEgressWriter) Stats() (insertedBytes, totalSentBytes uint64) {
	if w == nil {
		return 0, 0
	}
	return w.inserted, w.written
}

// WaitUntilEgressIdle waits until every timestamped Record submitted before
// the call has passed the TX software timestamp point. Linux places that point
// near the device driver, after ordinary packet scheduling, so a subsequent
// userspace sleep cannot be hidden behind an already queued saturated stream.
// The boolean is false only when the bounded wait timed out.
func (w *recordEgressWriter) WaitUntilEgressIdle(ctx context.Context, timeout time.Duration) (bool, error) {
	if w == nil || w.tracker == nil {
		return false, errors.New("TX egress tracking is unavailable")
	}
	return w.tracker.WaitUntilIdle(ctx, timeout)
}

func sendmsgWithTXTimestamp(raw syscall.RawConn, payload, oob []byte) (int, error) {
	var (
		n       int
		sendErr error
	)
	err := raw.Write(func(fd uintptr) bool {
		n, sendErr = syscall.SendmsgN(
			int(fd),
			payload,
			oob,
			nil,
			syscall.MSG_EOR|syscall.MSG_NOSIGNAL,
		)
		if errors.Is(sendErr, syscall.EAGAIN) || errors.Is(sendErr, syscall.EWOULDBLOCK) {
			sendErr = nil
			return false
		}
		return true
	})
	if err != nil {
		return n, err
	}
	return n, sendErr
}

func (w *recordEgressWriter) Close() {
	if w == nil || w.tracker == nil {
		return
	}
	w.tracker.Close()
}

type txTimestampRequest struct {
	event recordEgressEvent
}

type txTimestampTracker struct {
	raw       syscall.RawConn
	observer  recordEgressObserver
	predictor *recordTimestampPredictor

	mu         sync.Mutex
	pending    map[uint32]txTimestampRequest
	processing int
	failed     error
	closing    bool

	wake      chan struct{}
	changed   chan struct{}
	stop      chan struct{}
	events    chan txTimestampEvent
	done      chan struct{}
	closeOnce sync.Once
}

func newTXTimestampTracker(raw syscall.RawConn, observer recordEgressObserver, predictor *recordTimestampPredictor) *txTimestampTracker {
	t := &txTimestampTracker{
		raw:       raw,
		observer:  observer,
		predictor: predictor,
		pending:   make(map[uint32]txTimestampRequest),
		wake:      make(chan struct{}, 1),
		changed:   make(chan struct{}, 1),
		stop:      make(chan struct{}),
		events:    make(chan txTimestampEvent, txTimestampEventQueueSize),
		done:      make(chan struct{}),
	}
	go t.processLoop()
	go t.readLoop()
	return t
}

func (t *txTimestampTracker) Add(id uint32, event recordEgressEvent) (recordEgressEvent, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failed != nil {
		return event, fmt.Errorf("TX timestamp tracker stopped: %w", t.failed)
	}
	if t.closing {
		return event, errors.New("TX timestamp tracker is closing")
	}
	if _, exists := t.pending[id]; exists {
		return event, fmt.Errorf("duplicate TX timestamp byte id %d", id)
	}
	if event.EstimatedEgressAt.IsZero() {
		event.EstimatedEgressAt = t.predictor.PredictRecord(
			event.ID,
			event.SubmittedAt,
			tlsRecordHeaderLen+int(event.Header.Length),
		)
	}
	t.pending[id] = txTimestampRequest{event: event}
	return event, nil
}

func (t *txTimestampTracker) Remove(id uint32) {
	t.mu.Lock()
	delete(t.pending, id)
	t.mu.Unlock()
	t.notifyChanged()
}

func (t *txTimestampTracker) DropPrediction(id uint64) {
	if t == nil || t.predictor == nil || id == 0 {
		return
	}
	t.mu.Lock()
	estimates := t.predictor.DropRecord(id)
	t.applyPendingEstimatesLocked(estimates)
	t.mu.Unlock()
	t.notifyPredictionUpdate(estimates)
}

func (t *txTimestampTracker) Wake() {
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (t *txTimestampTracker) notifyChanged() {
	select {
	case t.changed <- struct{}{}:
	default:
	}
}

func (t *txTimestampTracker) WaitUntilIdle(ctx context.Context, timeout time.Duration) (bool, error) {
	if t == nil {
		return false, errors.New("TX timestamp tracker is unavailable")
	}
	if timeout <= 0 {
		return false, nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		t.mu.Lock()
		pending := len(t.pending) + t.processing
		failed := t.failed
		t.mu.Unlock()
		if pending == 0 {
			return true, nil
		}
		if failed != nil {
			return false, fmt.Errorf("TX timestamp tracker stopped: %w", failed)
		}
		t.Wake()
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-timer.C:
			return false, nil
		case <-t.changed:
		}
	}
}

func (t *txTimestampTracker) Close() {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closing = true
		t.mu.Unlock()
		close(t.stop)
		<-t.done
	})
}

func (t *txTimestampTracker) readLoop() {
	defer close(t.events)
	ticker := time.NewTicker(egressTimestampPollInterval)
	defer ticker.Stop()

	for {
		if err := t.drainToQueue(); err != nil {
			if !isExpectedClose(err) {
				log.Printf("[ERROR] receive TX software timestamp: %v", err)
			}
			t.setFailed(err)
			return
		}
		select {
		case <-t.stop:
			t.readUntilComplete()
			return
		case <-t.wake:
		case <-ticker.C:
		}
	}
}

func (t *txTimestampTracker) processLoop() {
	defer close(t.done)
	batch := make([]txTimestampEvent, 0, txTimestampProcessBatchSize)
	for {
		first, ok := <-t.events
		if !ok {
			break
		}
		batch = append(batch[:0], first)
		eventsOpen := true
	collectBatch:
		for len(batch) < cap(batch) {
			select {
			case event, ok := <-t.events:
				if !ok {
					eventsOpen = false
					break collectBatch
				}
				batch = append(batch, event)
			default:
				break collectBatch
			}
		}
		t.emitBatch(batch)
		if !eventsOpen {
			break
		}
	}
	if t.failure() != nil {
		t.dropPending()
	}
}

func (t *txTimestampTracker) setFailed(err error) {
	t.mu.Lock()
	t.failed = err
	t.mu.Unlock()
	t.notifyChanged()
}

func (t *txTimestampTracker) failure() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.failed
}

func (t *txTimestampTracker) readUntilComplete() {
	for t.pendingCount() > 0 {
		if err := t.drainToQueue(); err != nil {
			if !isExpectedClose(err) {
				log.Printf("[ERROR] receive TX software timestamp while closing: %v", err)
			}
			t.setFailed(err)
			return
		}
		if t.pendingCount() > 0 {
			time.Sleep(egressTimestampPollInterval)
		}
	}
}

func (t *txTimestampTracker) dropPending() {
	requests := t.takePendingForProcessing()
	if len(requests) > 0 {
		defer t.finishProcessing(len(requests))
		seen := make(map[uint64]struct{}, len(requests))
		events := make([]recordEgressEvent, 0, len(requests))
		ids := make([]uint64, 0, len(requests))
		for _, request := range requests {
			if _, duplicate := seen[request.event.ID]; duplicate {
				continue
			}
			seen[request.event.ID] = struct{}{}
			ids = append(ids, request.event.ID)
			events = append(events, request.event)
		}
		sort.Slice(events, func(i, j int) bool { return events[i].ID < events[j].ID })
		if t.predictor != nil {
			t.predictor.DropRecords(ids)
		}
		// The Records were submitted successfully. Resolve them with their
		// estimates so feature processing can retain them.
		t.observeResolvedBatch(events)
		t.observer.AddDropped(uint64(len(seen)))
		log.Printf("[WARN] missing TX software timestamps for %d TLS records; using predicted egress times", len(seen))
	}
}

func (t *txTimestampTracker) pendingCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pending)
}

func (t *txTimestampTracker) takePendingForProcessing() []txTimestampRequest {
	t.mu.Lock()
	requests := make([]txTimestampRequest, 0, len(t.pending))
	for _, request := range t.pending {
		requests = append(requests, request)
	}
	clear(t.pending)
	t.processing += len(requests)
	t.mu.Unlock()
	t.notifyChanged()
	return requests
}

func (t *txTimestampTracker) drainToQueue() error {
	for {
		event, ok, err := receiveTXTimestamp(t.raw)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		t.events <- event
	}
}

func (t *txTimestampTracker) emit(event txTimestampEvent) {
	t.emitBatch([]txTimestampEvent{event})
}

func (t *txTimestampTracker) emitBatch(events []txTimestampEvent) {
	if len(events) == 0 {
		return
	}
	resolved := make([]recordEgressEvent, 0, len(events))
	observations := make([]timestampRecordObservation, 0, len(events))
	t.mu.Lock()
	for _, event := range events {
		request, ok := t.pending[event.ID]
		if !ok {
			continue
		}
		delete(t.pending, event.ID)
		record := request.event
		record.ActualEgressAt = event.At
		resolved = append(resolved, record)
		observations = append(observations, timestampRecordObservation{
			ID:          record.ID,
			SubmittedAt: record.SubmittedAt,
			EstimatedAt: record.EstimatedEgressAt,
			ActualAt:    record.ActualEgressAt,
			Length:      tlsRecordHeaderLen + int(record.Header.Length),
		})
	}
	t.processing += len(resolved)
	t.mu.Unlock()
	if len(resolved) == 0 {
		t.notifyChanged()
		return
	}
	defer t.finishProcessing(len(resolved))

	update := t.predictor.ObserveRecords(observations)
	for i, estimate := range update.ResolvedEstimates {
		if !estimate.IsZero() {
			resolved[i].EstimatedEgressAt = estimate
		}
	}
	t.mu.Lock()
	t.applyPendingEstimatesLocked(update.Estimates)
	t.mu.Unlock()
	t.notifyPredictionUpdate(update.Estimates)
	t.observeResolvedBatch(resolved)
}

func (t *txTimestampTracker) finishProcessing(count int) {
	if count <= 0 {
		return
	}
	t.mu.Lock()
	t.processing -= count
	if t.processing < 0 {
		t.processing = 0
	}
	t.mu.Unlock()
	t.notifyChanged()
}

func (t *txTimestampTracker) observeResolvedBatch(events []recordEgressEvent) {
	if len(events) == 0 || t.observer == nil {
		return
	}
	if batchObserver, ok := t.observer.(recordEgressResolvedBatchObserver); ok {
		batchObserver.ObserveResolvedBatch(events)
		return
	}
	if lifecycle, ok := t.observer.(recordEgressLifecycleObserver); ok {
		for _, event := range events {
			lifecycle.ObserveResolved(event)
		}
		return
	}
	for _, event := range events {
		t.observer.Observe(event.Header, event.FeatureTime())
	}
}

func (t *txTimestampTracker) applyPendingEstimatesLocked(estimates map[uint64]time.Time) {
	if len(estimates) == 0 {
		return
	}
	for byteID, request := range t.pending {
		estimatedAt, ok := estimates[request.event.ID]
		if !ok || estimatedAt.IsZero() {
			continue
		}
		request.event.EstimatedEgressAt = estimatedAt
		t.pending[byteID] = request
	}
}

func (t *txTimestampTracker) notifyPredictionUpdate(estimates map[uint64]time.Time) {
	if len(estimates) == 0 {
		return
	}
	if predictionObserver, adjusts := t.observer.(recordEgressPredictionObserver); adjusts {
		predictionObserver.ApplyProvisionalEstimates(estimates)
	}
}

type txTimestampEvent struct {
	ID uint32
	At time.Time
}

func receiveTXTimestamp(raw syscall.RawConn) (txTimestampEvent, bool, error) {
	var (
		payload [1]byte
		oob     [egressTimestampOOBLen]byte
		oobLen  int
		flags   int
		recvErr error
	)
	if err := raw.Control(func(fd uintptr) {
		_, oobLen, flags, _, recvErr = syscall.Recvmsg(
			int(fd),
			payload[:],
			oob[:],
			syscall.MSG_ERRQUEUE|syscall.MSG_DONTWAIT,
		)
	}); err != nil {
		return txTimestampEvent{}, false, err
	}
	if errors.Is(recvErr, syscall.EAGAIN) || errors.Is(recvErr, syscall.EWOULDBLOCK) {
		return txTimestampEvent{}, false, nil
	}
	if recvErr != nil {
		return txTimestampEvent{}, false, recvErr
	}
	if flags&syscall.MSG_CTRUNC != 0 {
		return txTimestampEvent{}, false, errors.New("TX timestamp control message truncated")
	}

	event, ok, err := parseTXTimestampControl(oob[:oobLen])
	return event, ok, err
}

func parseTXTimestampControl(oob []byte) (txTimestampEvent, bool, error) {
	messages, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return txTimestampEvent{}, false, err
	}

	var (
		event        txTimestampEvent
		hasTimestamp bool
		hasID        bool
	)
	for _, message := range messages {
		switch {
		case message.Header.Level == syscall.SOL_SOCKET && message.Header.Type == syscall.SCM_TIMESTAMPING:
			if len(message.Data) < 16 {
				continue
			}
			seconds := int64(nativeEndian.Uint64(message.Data[0:8]))
			nanoseconds := int64(nativeEndian.Uint64(message.Data[8:16]))
			if seconds != 0 || nanoseconds != 0 {
				event.At = time.Unix(seconds, nanoseconds)
				hasTimestamp = true
			}
		case isTimestampExtendedError(message):
			if len(message.Data) < 16 || message.Data[4] != soEEOriginTimestamping {
				continue
			}
			if nativeEndian.Uint32(message.Data[8:12]) != scmTstampSend {
				continue
			}
			event.ID = nativeEndian.Uint32(message.Data[12:16])
			hasID = true
		}
	}
	return event, hasTimestamp && hasID, nil
}

func isTimestampExtendedError(message syscall.SocketControlMessage) bool {
	return (message.Header.Level == syscall.SOL_IP && message.Header.Type == ipRecvErr) ||
		(message.Header.Level == syscall.SOL_IPV6 && message.Header.Type == ipv6RecvErr)
}
