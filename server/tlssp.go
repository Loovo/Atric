package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func runTLSProxy(ctx context.Context, cfg TLSProxyConfig) error {

	if cfg.ListenAddr == "" {
		return errors.New("listen address is empty")
	}
	if cfg.UpstreamAddr == "" {
		return errors.New("upstream address is empty")
	}
	if cfg.DownlinkSocketMark < 0 {
		return fmt.Errorf("downlink socket mark must be non-negative, got %d", cfg.DownlinkSocketMark)
	}
	if len(cfg.PSK) < minPSKLen {
		return fmt.Errorf("psk length must be at least %d bytes, got %d", minPSKLen, len(cfg.PSK))
	}
	if cfg.ExtractQueueLen <= 0 {
		cfg.ExtractQueueLen = extractQueueLen
	}
	if cfg.AdaptiveObservationFallbackLimit <= 0 {
		cfg.AdaptiveObservationFallbackLimit = adaptiveObservationFallbackLimitDefault
	}
	if cfg.AdaptiveObservationFallbackLimit < adaptiveObservationWindowMinimum {
		return fmt.Errorf("adaptive observation fallback limit must be at least %d, got %d",
			adaptiveObservationWindowMinimum, cfg.AdaptiveObservationFallbackLimit)
	}
	collectionEnabled := cfg.DownlinkObservation
	if collectionEnabled && cfg.DetectionRecordOutputPath != "" &&
		cfg.DetectionRecordOutputPath == cfg.DetectionWindowOutputPath {
		return errors.New("record and window detection output paths must differ")
	}
	var detectionWriter *detectionDataWriter
	if collectionEnabled {
		var err error
		detectionWriter, err = newDetectionDataWriter(
			cfg.DetectionRecordOutputPath,
			cfg.DetectionWindowOutputPath,
		)
		if err != nil {
			return err
		}
	}
	var connectionWG sync.WaitGroup
	defer func() {
		connectionWG.Wait()
		if err := detectionWriter.Close(); err != nil {
			log.Printf("[ERROR] close detection data output: %v", err)
		}
	}()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("[INFO] tls reverse proxy listening on %s", ln.Addr())
	log.Printf("[INFO] upstream server: %s", cfg.UpstreamAddr)
	log.Printf("[INFO] adaptive downlink embedding enabled: %t", cfg.DownlinkEmbedding)
	log.Printf("[INFO] downlink record observation enabled: %t", cfg.DownlinkObservation)
	if cfg.DownlinkObservation {
		log.Printf("[INFO] detection record output: %q", cfg.DetectionRecordOutputPath)
		log.Printf("[INFO] detection window output: %q", cfg.DetectionWindowOutputPath)
	}
	if cfg.DownlinkEmbedding {
		log.Printf("[INFO] downlink socket mark: %d", cfg.DownlinkSocketMark)
		log.Printf("[INFO] adaptive observation windows primary=%d conditional_fallback_limit=%d",
			adaptiveObservationWindowMinimum, cfg.AdaptiveObservationFallbackLimit)
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var connectionSequence atomic.Uint64
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Println("[ERROR] accept failed:", err)
			continue
		}

		connectionID := connectionSequence.Add(1)
		connectionWG.Add(1)
		go func() {
			defer connectionWG.Done()
			handleTLSProxyConn(ctx, conn, cfg, connectionID, detectionWriter)
		}()
	}
}

func handleTLSProxyConn(
	parent context.Context,
	client net.Conn,
	cfg TLSProxyConfig,
	connectionID uint64,
	detectionWriter *detectionDataWriter,
) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer client.Close()
	egressTrackingEnabled := cfg.DownlinkObservation || cfg.DownlinkEmbedding
	if egressTrackingEnabled && cfg.DownlinkSocketMark != 0 {
		if err := setConnectionSocketMark(client, cfg.DownlinkSocketMark); err != nil {
			log.Printf("[ERROR] set downlink socket mark %d for %s failed: %v", cfg.DownlinkSocketMark, client.RemoteAddr(), err)
			return
		}
		log.Printf("[INFO] applied downlink socket mark=%d client=%s", cfg.DownlinkSocketMark, client.RemoteAddr())
	}

	dialer := net.Dialer{}
	server, err := dialer.DialContext(ctx, "tcp", cfg.UpstreamAddr)
	if err != nil {
		log.Printf("[ERROR] dial upstream %s failed: %v", cfg.UpstreamAddr, err)
		return
	}
	defer server.Close()
	go func() {
		<-ctx.Done()
		_ = client.Close()
		_ = server.Close()
	}()

	log.Printf("[INFO] proxy %s -> %s", client.RemoteAddr(), cfg.UpstreamAddr)

	state := newConnectionState(cfg.PSK)
	decryptCh := make(chan decryptRequest, cfg.ExtractQueueLen)
	extractedCh := make(chan ExtractedRecord, cfg.ExtractQueueLen)

	go embeddedRecordWorker(ctx, decryptCh)
	go consumeExtractedRecords(ctx, extractedCh)

	var (
		clientReader io.Reader = client
		serverReader io.Reader = server
		adaptive     *adaptiveInserter
		egressWriter *recordEgressWriter
		featureSink  *recordFeatureSink
	)
	if cfg.DownlinkEmbedding {
		adaptive = newAdaptiveInserterWithObservationFallbackLimit(true, cfg.AdaptiveObservationFallbackLimit)

		rxReader, rxErr := newRecordRXTimestampReader(server)
		if rxErr != nil {
			log.Printf("[WARN] initialize downlink RX timestamp reader for %s failed: %v; non-saturated adaptive insertion is disabled for this connection", server.RemoteAddr(), rxErr)
		} else {
			serverReader = rxReader
		}
	}
	if cfg.DownlinkObservation {
		featureSink = newRecordFeatureSink(recordFeatureMeta{
			ClientAddr:        client.RemoteAddr().String(),
			UpstreamAddr:      client.RemoteAddr().String(),
			UpstreamLocalAddr: client.LocalAddr().String(),
			StartedAt:         time.Now(),
			ConnectionID:      connectionID,
			Direction:         detectionDirectionServerToClient,
			EmbeddingEnabled:  cfg.DownlinkEmbedding,
			DetectionWriter:   detectionWriter,
		}, cfg.FeatureQueueLen)
	}

	if adaptive != nil || featureSink != nil {
		observers := []recordEgressObserver{featureSink, adaptive}

		egressObserver := combineRecordEgressObservers(observers...)
		var predictors []*recordTimestampPredictor
		if adaptive != nil {
			predictors = append(predictors, adaptive.predictor)
		}
		egressWriter, err = newRecordEgressWriter(client, egressObserver, predictors...)
		if err != nil {
			if featureSink != nil {
				featureSink.Close()
			}
			log.Printf("[ERROR] initialize downlink record observer for %s failed: %v", client.RemoteAddr(), err)
			return
		}
		clientReader = egressWriter

	}

	type pipeResult struct {
		direction proxyDirection
		err       error
	}
	errCh := make(chan pipeResult, 2)
	go func() {
		errCh <- pipeResult{
			direction: clientToServer,
			err:       pipeTLSRecords(ctx, clientReader, server, state, clientToServer, decryptCh, extractedCh, nil, nil),
		}
	}()
	go func() {
		err := pipeTLSRecords(ctx, serverReader, client, state, serverToClient, nil, nil, adaptive, egressWriter)
		if egressWriter != nil {
			egressWriter.Close()

			insertedBytes, totalSentBytes := egressWriter.Stats()
			log.Printf("[INFO] downlink_egress_summary connection_id=%d inserted_bytes=%d total_sent_bytes=%d",
				connectionID, insertedBytes, totalSentBytes)
			if featureSink != nil {
				featureSink.Close()
			}
		}
		errCh <- pipeResult{direction: serverToClient, err: err}
	}()

	first := <-errCh
	if egressTrackingEnabled &&
		first.direction == clientToServer && isExpectedClose(first.err) {
		// A normal client-side EOF can race with the last downlink TX timestamp.
		// Half-close only the upstream write side and keep the marked client
		// socket open until the downlink goroutine drains every timestamp.
		if tcpServer, ok := server.(*net.TCPConn); ok {
			_ = tcpServer.CloseWrite()
		}
		second := <-errCh
		cancel()
		_ = client.Close()
		_ = server.Close()
		logProxyPipeErrors(client.RemoteAddr(), cfg.UpstreamAddr, first.err, second.err)
		return
	}

	cancel()
	_ = client.Close()
	_ = server.Close()
	second := <-errCh
	logProxyPipeErrors(client.RemoteAddr(), cfg.UpstreamAddr, first.err, second.err)
}

func logProxyPipeErrors(clientAddr net.Addr, upstreamAddr string, firstErr, secondErr error) {
	if firstErr != nil && !isExpectedClose(firstErr) {
		log.Printf("[ERROR] proxy %s -> %s stopped: %v", clientAddr, upstreamAddr, firstErr)
		return
	}
	if secondErr != nil && !isExpectedClose(secondErr) {
		log.Printf("[ERROR] proxy %s -> %s stopped: %v", clientAddr, upstreamAddr, secondErr)
	}
}

func setConnectionSocketMark(conn net.Conn, mark int) error {
	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		return fmt.Errorf("connection %T does not expose syscall.Conn", conn)
	}
	raw, err := sysConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw connection: %w", err)
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		socketErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
	}); err != nil {
		return err
	}
	return socketErr
}

type proxyDirection int

const (
	clientToServer proxyDirection = iota
	serverToClient
)

func pipeTLSRecords(ctx context.Context, src io.Reader, dst io.Writer, state *connectionState, direction proxyDirection, decryptCh chan<- decryptRequest, extractedCh chan<- ExtractedRecord, adaptive *adaptiveInserter, egressWriter *recordEgressWriter) error {
	for {

		record, header, arrivedAt, arrivalTrusted, err := readTLSRecordWithArrival(src)

		if err != nil {
			return err
		}

		switch direction {
		case clientToServer:
			state.observeClientRecord(record)
			extracted, err := state.tryExtractEmbeddedRecord(ctx, record, decryptCh, extractedCh)
			if err != nil {
				return err
			}
			if extracted {
				continue
			}
			if err := writeAll(dst, record); err != nil {
				return err
			}
		case serverToClient:

			state.observeServerRecord(record)

			if egressWriter == nil {

				writeErr := writeAll(dst, record)

				if writeErr != nil {
					return writeErr
				}
				continue
			}
			var decisionStartedAt time.Time
			if adaptive != nil && header.ContentType == tlsTypeApplicationData {
				decisionStartedAt = time.Now()
				decision := adaptive.DecideWithArrival(
					len(record),
					decisionStartedAt,
					arrivedAt,
					arrivalTrusted,
					state.embeddingReady(),
				)

				if decision.Insert {

					covertData, randomErr := randomCovertMessage(decision.Length)

					if randomErr != nil {
						adaptive.CancelReservationWithReason(decision.Length, "random_generation_failed")
						log.Printf("[ERROR] generate random covert message failed: %v", randomErr)
					} else {

						confirmed := adaptive.ConfirmReservation(decision, time.Now())

						if !confirmed {
							adaptive.CancelReservationWithReason(decision.Length, "confirmation_rejected")
						} else {

							embedded, ready, buildErr := state.buildEmbeddedRecordSized(header, covertData, decision.Length)

							if buildErr != nil {
								adaptive.CancelReservationWithReason(decision.Length, "record_build_failed")
								log.Printf("[ERROR] build adaptive embedded record failed: %v", buildErr)
							} else if !ready {
								adaptive.CancelReservationWithReason(decision.Length, "record_builder_not_ready")
							} else {
								embeddedHeader, parseErr := parseTLSRecordHeader(embedded[:tlsRecordHeaderLen])
								if parseErr != nil {
									adaptive.CancelReservationWithReason(decision.Length, "embedded_header_invalid")
									return parseErr
								}
								embeddedSubmitStart := time.Now()

								writeErr := egressWriter.WriteEmbeddedRecord(embedded, embeddedHeader)

								if writeErr != nil {
									adaptive.CancelReservationWithReason(decision.Length, "embedded_write_failed")
									return writeErr
								}

								adaptive.InsertSucceeded(time.Now())

								if time.Now().Before(embeddedSubmitStart.Add(decision.Delay)) {

									if waitErr := waitUntilContext(ctx, embeddedSubmitStart.Add(decision.Delay)); waitErr != nil {
										return waitErr
									}

								}
							}
						}
					}
				}
				if !decision.Insert && !decision.HoldUntil.IsZero() {

					waitErr := waitUntilContext(ctx, decision.HoldUntil)

					if waitErr != nil {
						return waitErr
					}
				}
			}

			writeErr := egressWriter.WriteRecord(record, header)

			if writeErr != nil {
				return writeErr
			}
			if adaptive != nil && header.ContentType == tlsTypeApplicationData {

				adaptive.NormalWriteSucceeded(len(record))

			}

		}
	}
}

func readTLSRecord(r io.Reader) ([]byte, TLSRecordHeader, error) {
	record, header, _, _, err := readTLSRecordWithArrival(r)
	return record, header, err
}

func readTLSRecordWithArrival(r io.Reader) ([]byte, TLSRecordHeader, time.Time, bool, error) {
	headerBytes := make([]byte, tlsRecordHeaderLen)
	headerAt, headerTrusted, err := readFullWithRXTimestamp(r, headerBytes)
	if err != nil {
		return nil, TLSRecordHeader{}, time.Time{}, false, err
	}

	header, err := parseTLSRecordHeader(headerBytes)
	if err != nil {
		return nil, TLSRecordHeader{}, time.Time{}, false, err
	}

	record := make([]byte, tlsRecordHeaderLen+int(header.Length))
	copy(record, headerBytes)
	if header.Length == 0 {
		return record, header, headerAt, headerTrusted, nil
	}
	bodyAt, bodyTrusted, err := readFullWithRXTimestamp(r, record[tlsRecordHeaderLen:])
	if err != nil {
		return nil, TLSRecordHeader{}, time.Time{}, false, err
	}
	return record, header, bodyAt, bodyTrusted, nil
}

func waitUntilContext(ctx context.Context, at time.Time) error {
	const finalSpinWindow = 250 * time.Microsecond

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		remaining := time.Until(at)
		if remaining <= 0 {
			return nil
		}
		if remaining > finalSpinWindow {
			request := syscall.NsecToTimespec((remaining - finalSpinWindow).Nanoseconds())
			var leftover syscall.Timespec
			if err := syscall.Nanosleep(&request, &leftover); err != nil && err != syscall.EINTR {
				return err
			}
			continue
		}

		for iteration := uint32(0); time.Now().Before(at); iteration++ {
			if iteration&255 != 0 {
				continue
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}
		return nil
	}
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

type connectionState struct {
	mu sync.Mutex

	psk            []byte
	clientRandom   []byte
	serverRandom   []byte
	keys           *ConnKeys
	embedKeys      *ConnKeys
	nextExtractSeq uint64
	nextEmbedSeq   uint64

	clientHandshake handshakeExtractor
	serverHandshake handshakeExtractor
}

func newConnectionState(psk []byte) *connectionState {
	return &connectionState{psk: append([]byte(nil), psk...)}
}

func (s *connectionState) observeClientRecord(record []byte) {
	s.observeRecord(record, true)
}

func (s *connectionState) observeServerRecord(record []byte) {
	s.observeRecord(record, false)
}

func (s *connectionState) observeRecord(record []byte, fromClient bool) {
	if len(record) < tlsRecordHeaderLen {
		return
	}

	header, err := parseTLSRecordHeader(record[:tlsRecordHeaderLen])
	if err != nil || header.ContentType != tlsTypeHandshake {
		return
	}
	payload := record[tlsRecordHeaderLen:]

	s.mu.Lock()
	defer s.mu.Unlock()

	var clientRandom, serverRandom []byte
	if fromClient {
		clientRandom, _ = s.clientHandshake.feed(payload)
	} else {
		_, serverRandom = s.serverHandshake.feed(payload)
	}

	if clientRandom != nil && s.clientRandom == nil {
		s.clientRandom = clientRandom
		log.Println("[INFO] captured TLS client_random")
	}
	if serverRandom != nil && s.serverRandom == nil {
		s.serverRandom = serverRandom
		log.Println("[INFO] captured TLS server_random")
	}
	if s.keys != nil || s.clientRandom == nil || s.serverRandom == nil {
		return
	}

	keys, err := deriveConnKeys(s.psk, s.clientRandom, s.serverRandom)
	if err != nil {
		log.Printf("[ERROR] derive connection keys failed: %v", err)
		return
	}
	embedKeys, err := deriveDownlinkConnKeys(s.psk, s.clientRandom, s.serverRandom)
	if err != nil {
		log.Printf("[ERROR] derive downlink connection keys failed: %v", err)
		return
	}
	s.keys = keys
	s.embedKeys = embedKeys
	log.Println("[INFO] derived per-connection covert-record keys")
}

func (s *connectionState) buildEmbeddedRecord(template TLSRecordHeader, data []byte) ([]byte, bool, error) {
	return s.buildEmbeddedRecordSized(template, data, tlsRecordHeaderLen+embeddedPayloadLen)
}

func (s *connectionState) buildEmbeddedRecordSized(template TLSRecordHeader, data []byte, totalLen int) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.embedKeys == nil {
		return nil, false, nil
	}
	keys := s.embedKeys
	seq := s.nextEmbedSeq

	record, err := buildEmbeddedTLSRecordSized(template, keys, seq, data, totalLen)
	if err != nil {
		return nil, false, err
	}
	s.nextEmbedSeq++
	return record, true, nil
}

func (s *connectionState) embeddingReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.embedKeys != nil
}

func (s *connectionState) tryExtractEmbeddedRecord(ctx context.Context, record []byte, decryptCh chan<- decryptRequest, extractedCh chan<- ExtractedRecord) (bool, error) {
	if decryptCh == nil || extractedCh == nil {
		return false, nil
	}

	s.mu.Lock()
	keys := s.keys
	seq := s.nextExtractSeq
	s.mu.Unlock()

	if keys == nil || !recordHasMarker(record, keys, seq) {
		return false, nil
	}

	resultCh := make(chan decryptResult, 1)
	req := decryptRequest{
		record: append([]byte(nil), record...),
		keys:   keys,
		seq:    seq,
		result: resultCh,
	}

	select {
	case decryptCh <- req:
	case <-ctx.Done():
		return false, ctx.Err()
	}

	var result decryptResult
	select {
	case result = <-resultCh:
	case <-ctx.Done():
		return false, ctx.Err()
	}

	if result.err != nil {
		if result.authenticated {
			s.advanceExtractSeq(seq)
			log.Printf("[ERROR] embedded tls record seq=%d authenticated but malformed: %v", seq, result.err)
			return true, nil
		}
		log.Printf("[WARN] embedded marker matched seq=%d but authentication failed: %v", seq, result.err)
		return false, nil
	}
	if !result.markerMatched || result.record == nil {
		return false, nil
	}

	s.advanceExtractSeq(seq)
	select {
	case extractedCh <- *result.record:
		return true, nil
	case <-ctx.Done():
		return true, ctx.Err()
	}
}

func (s *connectionState) advanceExtractSeq(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextExtractSeq == seq {
		s.nextExtractSeq++
	}
}

type decryptRequest struct {
	record []byte
	keys   *ConnKeys
	seq    uint64
	result chan<- decryptResult
}

type decryptResult struct {
	record        *ExtractedRecord
	markerMatched bool
	authenticated bool
	err           error
}

func embeddedRecordWorker(ctx context.Context, requests <-chan decryptRequest) {
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-requests:
			if !ok {
				return
			}
			record, markerMatched, authenticated, err := decryptEmbeddedTLSRecord(req.record, req.keys, req.seq)
			result := decryptResult{
				record:        record,
				markerMatched: markerMatched,
				authenticated: authenticated,
				err:           err,
			}
			select {
			case req.result <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

func consumeExtractedRecords(ctx context.Context, records <-chan ExtractedRecord) {
	var count int
	var covertBytes int
	defer func() {
		if count > 0 {
			log.Printf("[INFO] extracted_record_summary records=%d covert_bytes=%d", count, covertBytes)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case record, ok := <-records:
			if !ok {
				return
			}
			count++
			covertBytes += len(record.Data)

		}
	}
}

type handshakeExtractor struct {
	buf []byte
}

func (h *handshakeExtractor) feed(payload []byte) (clientRandom []byte, serverRandom []byte) {
	h.buf = append(h.buf, payload...)
	if len(h.buf) > 1<<20 {
		h.buf = nil
		return nil, nil
	}

	for {
		if len(h.buf) < 4 {
			return clientRandom, serverRandom
		}

		msgLen := int(h.buf[1])<<16 | int(h.buf[2])<<8 | int(h.buf[3])
		totalLen := 4 + msgLen
		if msgLen < 0 || totalLen < 4 {
			h.buf = nil
			return clientRandom, serverRandom
		}
		if len(h.buf) < totalLen {
			return clientRandom, serverRandom
		}

		msgType := h.buf[0]
		body := h.buf[4:totalLen]
		switch msgType {
		case 1:
			if r := handshakeRandom(body); r != nil {
				clientRandom = r
			}
		case 2:
			if r := handshakeRandom(body); r != nil {
				serverRandom = r
			}
		}

		copy(h.buf, h.buf[totalLen:])
		h.buf = h.buf[:len(h.buf)-totalLen]
	}
}

func handshakeRandom(body []byte) []byte {
	if len(body) < 34 {
		return nil
	}
	return append([]byte(nil), body[2:34]...)
}

func isExpectedClose(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}
