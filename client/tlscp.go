package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	soOriginalDst = 80
)

type TLSProxyConfig struct {
	ListenAddr          string
	UpstreamAddr        string
	SocketMark          int
	PSK                 []byte
	ExtractQueueLen     int
	UpstreamObservation bool
	UpstreamEmbedding   bool

	AdaptiveObservationFallbackLimit int
	FeatureQueueLen                  int
	DetectionRecordOutputPath        string
	DetectionWindowOutputPath        string
}

func upstreamEmbeddingModeName(enabled bool) string {
	if enabled {
		return "adaptive"
	}
	return "none"
}

func runTLSProxy(ctx context.Context, cfg TLSProxyConfig) error {

	if cfg.ListenAddr == "" {
		return errors.New("listen address is empty")
	}
	if cfg.SocketMark < 0 {
		return fmt.Errorf("socket mark must be non-negative, got %d", cfg.SocketMark)
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
	collectionEnabled := cfg.UpstreamObservation
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

	lc := net.ListenConfig{Control: listenControl}
	ln, err := lc.Listen(ctx, "tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("[INFO] tls proxy listening on %s", ln.Addr())
	if cfg.UpstreamAddr != "" {
		log.Printf("[INFO] upstream override enabled: %s", cfg.UpstreamAddr)
	}
	log.Printf("[INFO] upstream embedding mode: %s", upstreamEmbeddingModeName(cfg.UpstreamEmbedding))
	log.Printf("[INFO] upstream record observation enabled: %t", cfg.UpstreamObservation)
	if cfg.UpstreamObservation {
		log.Printf("[INFO] detection record output: %q", cfg.DetectionRecordOutputPath)
		log.Printf("[INFO] detection window output: %q", cfg.DetectionWindowOutputPath)
	}
	if cfg.UpstreamEmbedding {
		log.Printf("[INFO] adaptive observation windows primary=%d conditional_fallback_limit=%d",
			adaptiveObservationWindowMinimum, cfg.AdaptiveObservationFallbackLimit)
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	listenPort := parsePort(cfg.ListenAddr)
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

		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			_ = conn.Close()
			log.Printf("[ERROR] accepted non-TCP connection from %s", conn.RemoteAddr())
			continue
		}

		connectionID := connectionSequence.Add(1)
		connectionWG.Add(1)
		go func() {
			defer connectionWG.Done()
			handleTLSProxyConn(ctx, tcpConn, cfg, listenPort, connectionID, detectionWriter)
		}()
	}
}

func handleTLSProxyConn(
	parent context.Context,
	client *net.TCPConn,
	cfg TLSProxyConfig,
	listenPort int,
	connectionID uint64,
	detectionWriter *detectionDataWriter,
) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer client.Close()

	upstreamAddr, err := resolveUpstreamAddr(client, cfg.UpstreamAddr, listenPort)
	if err != nil {
		log.Printf("[ERROR] resolve upstream for %s failed: %v", client.RemoteAddr(), err)
		return
	}

	server, err := dialUpstream(upstreamAddr, cfg.SocketMark)
	if err != nil {
		log.Printf("[ERROR] dial upstream %s failed: %v", upstreamAddr, err)
		return
	}
	defer server.Close()
	go func() {
		<-ctx.Done()
		_ = client.Close()
		_ = server.Close()
	}()

	log.Printf("[INFO] proxy %s -> %s", client.RemoteAddr(), upstreamAddr)
	state := newConnectionState(cfg.PSK)
	var (
		clientReader io.Reader = client
		serverReader io.Reader = server
		adaptive     *adaptiveInserter
		egressWriter *recordEgressWriter
		featureSink  *recordFeatureSink
	)
	if cfg.UpstreamEmbedding {
		adaptive = newAdaptiveInserterWithObservationFallbackLimit(true, cfg.AdaptiveObservationFallbackLimit)

		rxReader, rxErr := newRecordRXTimestampReader(client)
		if rxErr != nil {
			log.Printf("[WARN] initialize upstream RX timestamp reader for %s failed: %v; non-saturated adaptive insertion is disabled for this connection", client.RemoteAddr(), rxErr)
		} else {
			clientReader = rxReader
		}
	}
	if cfg.UpstreamObservation {
		featureSink = newRecordFeatureSink(recordFeatureMeta{
			ClientAddr:        client.RemoteAddr().String(),
			UpstreamAddr:      server.RemoteAddr().String(),
			UpstreamLocalAddr: server.LocalAddr().String(),
			StartedAt:         time.Now(),
			ConnectionID:      connectionID,
			Direction:         detectionDirectionClientToServer,
			EmbeddingEnabled:  cfg.UpstreamEmbedding,
			EmbeddingMode:     upstreamEmbeddingModeName(cfg.UpstreamEmbedding),
			DetectionWriter:   detectionWriter,
		}, cfg.FeatureQueueLen)
	}
	if adaptive != nil || featureSink != nil {
		egressObserver := combineRecordEgressObservers(featureSink, adaptive)
		var predictors []*recordTimestampPredictor
		if adaptive != nil {
			predictors = append(predictors, adaptive.predictor)
		}
		egressWriter, err = newRecordEgressWriter(server, egressObserver, predictors...)
		if err != nil {
			if featureSink != nil {
				featureSink.Close()
			}
			log.Printf("[ERROR] initialize network-egress record observer for %s failed: %v", upstreamAddr, err)
			return
		}
		serverReader = egressWriter

	}
	decryptCh := make(chan decryptRequest, cfg.ExtractQueueLen)
	extractedCh := make(chan ExtractedRecord, cfg.ExtractQueueLen)
	extractedDone := make(chan struct{})
	go embeddedRecordWorker(ctx, decryptCh)
	go func() {
		defer close(extractedDone)
		consumeExtractedRecords(extractedCh)
	}()

	errCh := make(chan error, 2)
	go func() {
		err := pipeTLSRecords(ctx, clientReader, server, state, clientToServer, adaptive, egressWriter, nil, nil)
		if egressWriter != nil {
			egressWriter.Close()

			insertedBytes, totalSentBytes := egressWriter.Stats()
			fmt.Printf("egress_summary connection_id=%d embedding_mode=%s inserted_bytes=%d total_sent_bytes=%d\n",
				connectionID, upstreamEmbeddingModeName(cfg.UpstreamEmbedding), insertedBytes, totalSentBytes)
			if featureSink != nil {
				featureSink.Close()
			}
		}
		errCh <- err
	}()
	go func() {
		err := pipeTLSRecords(ctx, serverReader, client, state, serverToClient, nil, nil, decryptCh, extractedCh)
		close(extractedCh)
		<-extractedDone
		errCh <- err
	}()

	firstErr := <-errCh
	cancel()
	_ = client.Close()
	_ = server.Close()
	secondErr := <-errCh

	if firstErr != nil && !isExpectedClose(firstErr) {
		log.Printf("[ERROR] proxy %s -> %s stopped: %v", client.RemoteAddr(), upstreamAddr, firstErr)
		return
	}
	if secondErr != nil && !isExpectedClose(secondErr) {
		log.Printf("[ERROR] proxy %s -> %s stopped: %v", client.RemoteAddr(), upstreamAddr, secondErr)
	}
}

type proxyDirection int

const (
	clientToServer proxyDirection = iota
	serverToClient
)

func pipeTLSRecords(ctx context.Context, src io.Reader, dst io.Writer, state *connectionState, direction proxyDirection, adaptive *adaptiveInserter, egressWriter *recordEgressWriter, decryptCh chan<- decryptRequest, extractedCh chan<- ExtractedRecord) error {
	for {
		record, header, arrivedAt, arrivalTrusted, err := readTLSRecordWithArrival(src)
		if err != nil {
			return err
		}

		switch direction {
		case clientToServer:
			state.observeClientRecord(record)
			if egressWriter == nil {
				if err := writeAll(dst, record); err != nil {
					return err
				}
				continue
			}
			if adaptive != nil && header.ContentType == tlsTypeApplicationData {
				decision := adaptive.DecideWithArrival(
					len(record),
					time.Now(),
					arrivedAt,
					arrivalTrusted,
					state.embeddingReady(),
				)
				if decision.Insert {
					covertData, randomErr := randomCovertMessage(decision.Length)
					if randomErr != nil {
						adaptive.CancelReservationWithReason(decision.Length, "random_generation_failed")
						log.Printf("[ERROR] generate random covert message failed: %v", randomErr)
					} else if !adaptive.ConfirmReservation(decision, time.Now()) {
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
							if writeErr := egressWriter.WriteEmbeddedRecord(embedded, embeddedHeader); writeErr != nil {
								adaptive.CancelReservationWithReason(decision.Length, "embedded_write_failed")
								return writeErr
							}
							adaptive.InsertSucceeded(time.Now())

							if waitErr := waitUntilContext(ctx, embeddedSubmitStart.Add(decision.Delay)); waitErr != nil {
								return waitErr
							}
						}
					}
				}
				if !decision.Insert && !decision.HoldUntil.IsZero() {
					if err := waitUntilContext(ctx, decision.HoldUntil); err != nil {
						return err
					}
				}
			}
			if err := egressWriter.WriteRecord(record, header); err != nil {
				return err
			}
			if adaptive != nil && header.ContentType == tlsTypeApplicationData {
				adaptive.NormalWriteSucceeded(len(record))
			}
		case serverToClient:
			state.observeServerRecord(record)
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
	nextSeq        uint64
	extractKeys    *ConnKeys
	nextExtractSeq uint64

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
	extractKeys, err := deriveDownlinkConnKeys(s.psk, s.clientRandom, s.serverRandom)
	if err != nil {
		log.Printf("[ERROR] derive downlink extraction keys failed: %v", err)
		return
	}
	s.keys = keys
	s.extractKeys = extractKeys
	log.Println("[INFO] derived per-connection embedding and downlink extraction keys")
}

func (s *connectionState) buildEmbeddedRecord(template TLSRecordHeader, data []byte) ([]byte, bool, error) {
	return s.buildEmbeddedRecordSized(template, data, tlsRecordHeaderLen+embeddedPayloadLen)
}

func (s *connectionState) buildEmbeddedRecordSized(template TLSRecordHeader, data []byte, totalLen int) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys == nil {
		return nil, false, nil
	}
	keys := s.keys
	seq := s.nextSeq

	record, err := buildEmbeddedTLSRecordSized(template, keys, seq, data, totalLen)
	if err != nil {
		return nil, false, err
	}
	s.nextSeq++
	return record, true, nil
}

func (s *connectionState) embeddingReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys != nil
}

func (s *connectionState) tryExtractEmbeddedRecord(ctx context.Context, record []byte, decryptCh chan<- decryptRequest, extractedCh chan<- ExtractedRecord) (bool, error) {
	if decryptCh == nil || extractedCh == nil {
		return false, nil
	}

	s.mu.Lock()
	keys := s.extractKeys
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
			log.Printf("[ERROR] downlink embedded tls record seq=%d authenticated but malformed: %v", seq, result.err)
			return true, nil
		}
		log.Printf("[WARN] downlink embedded marker matched seq=%d but authentication failed: %v", seq, result.err)
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

func consumeExtractedRecords(records <-chan ExtractedRecord) {
	var count int
	var covertBytes int
	for record := range records {
		count++
		covertBytes += len(record.Data)

	}
	if count > 0 {
		log.Printf("[INFO] extracted_record_summary records=%d covert_bytes=%d", count, covertBytes)
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

func listenControl(_, _ string, c syscall.RawConn) error {
	var ctrlErr error
	if err := c.Control(func(fd uintptr) {
		ctrlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	}); err != nil {
		return err
	}
	return ctrlErr
}

func resolveUpstreamAddr(conn *net.TCPConn, override string, listenPort int) (string, error) {
	if override != "" {
		return override, nil
	}

	if local, ok := conn.LocalAddr().(*net.TCPAddr); ok && (listenPort == 0 || local.Port != listenPort) {
		return local.String(), nil
	}

	original, err := originalDst(conn)
	if err != nil {
		return "", err
	}
	return original.String(), nil
}

func dialUpstream(addr string, mark int) (net.Conn, error) {
	if mark == 0 {
		return net.Dial("tcp", addr)
	}
	return dialTCPWithMark(addr, mark)
}

func originalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var (
		addr    syscall.RawSockaddrInet4
		addrLen = uint32(unsafe.Sizeof(addr))
		sysErr  error
	)

	if err := raw.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.SOL_IP),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if errno != 0 {
			sysErr = errno
		}
	}); err != nil {
		return nil, err
	}
	if sysErr != nil {
		return nil, sysErr
	}

	port := int(ntohs(addr.Port))
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	return &net.TCPAddr{IP: ip, Port: port}, nil
}

func ntohs(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func parsePort(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return n
}

func isExpectedClose(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

func dialTCPWithMark(remoteAddr string, mark int) (net.Conn, error) {
	dialer := &net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				err := setSocketMark(int(fd), mark)
				if err != nil {
					log.Println("[ERROR] net dialer set mark error:", err)
				}
			})
		},
	}

	conn, err := dialer.Dial("tcp", remoteAddr)
	if err != nil {
		log.Println("[ERROR] Error dialing:", err)
		return nil, err
	}

	return conn, nil
}

func setSocketMark(fd int, value int) (e error) {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, value)
}
