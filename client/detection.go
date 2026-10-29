package main

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"
)

const detectionDirectionClientToServer = "c2s"

type detectionDataWriter struct {
	mu         sync.Mutex
	recordFile *os.File
	windowFile *os.File
	recordJSON *json.Encoder
	windowJSON *json.Encoder
	closed     bool
}

type detectionConnectionStartEvent struct {
	Kind               string `json:"kind"`
	ConnectionID       uint64 `json:"connection_id"`
	Direction          string `json:"direction"`
	EmbeddingEnabled   bool   `json:"embedding_enabled"`
	EmbeddingMode      string `json:"embedding_mode"`
	StartedAtUnixNS    int64  `json:"started_at_unix_ns"`
	UpstreamLocalAddr  string `json:"upstream_local_addr"`
	UpstreamRemoteAddr string `json:"upstream_remote_addr"`
}

type detectionConnectionEndEvent struct {
	Kind                    string `json:"kind"`
	ConnectionID            uint64 `json:"connection_id"`
	EmbeddingMode           string `json:"embedding_mode"`
	RecordCount             uint64 `json:"record_count"`
	QueueDroppedRecords     uint64 `json:"queue_dropped_records"`
	MissingActualTimestamps uint64 `json:"missing_actual_timestamps"`
	ActualTimestamps        uint64 `json:"actual_timestamps"`
	FallbackTimestamps      uint64 `json:"fallback_timestamps"`
	InsertedRecords         uint64 `json:"inserted_records"`
	InsertedBytes           uint64 `json:"inserted_bytes"`
}

type detectionRecordEvent struct {
	Kind             string `json:"kind"`
	ConnectionID     uint64 `json:"connection_id"`
	Direction        string `json:"direction"`
	EmbeddingEnabled bool   `json:"embedding_enabled"`
	EmbeddingMode    string `json:"embedding_mode"`
	RecordIndex      uint64 `json:"record_index"`
	EgressID         uint64 `json:"egress_id"`
	TimestampUnixNS  int64  `json:"timestamp_unix_ns"`
	TimestampSource  string `json:"timestamp_source"`
	Length           int    `json:"length"`
	Embedded         bool   `json:"embedded"`
}

type detectionWindowEvent struct {
	Kind              string `json:"kind"`
	ConnectionID      uint64 `json:"connection_id"`
	Direction         string `json:"direction"`
	EmbeddingEnabled  bool   `json:"embedding_enabled"`
	EmbeddingMode     string `json:"embedding_mode"`
	ActiveEpoch       int    `json:"active_epoch"`
	WindowIndex       int    `json:"window_index"`
	StartUnixNS       int64  `json:"start_unix_ns"`
	EndUnixNS         int64  `json:"end_unix_ns"`
	WidthNS           int64  `json:"width_ns"`
	RecordCount       int    `json:"record_count"`
	IATCount          int    `json:"iat_count"`
	InsertedRecords   int    `json:"inserted_records"`
	InsertedBytes     int    `json:"inserted_bytes"`
	ContainsInsertion bool   `json:"contains_insertion"`
}

func newDetectionDataWriter(recordPath, windowPath string) (*detectionDataWriter, error) {
	if recordPath == "" && windowPath == "" {
		return nil, nil
	}
	if recordPath != "" && recordPath == windowPath {
		return nil, errors.New("record and window detection output paths must differ")
	}

	writer := &detectionDataWriter{}
	var err error
	if recordPath != "" {
		writer.recordFile, err = os.OpenFile(recordPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		writer.recordJSON = json.NewEncoder(writer.recordFile)
		writer.recordJSON.SetEscapeHTML(false)
	}
	if windowPath != "" {
		writer.windowFile, err = os.OpenFile(windowPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			if writer.recordFile != nil {
				_ = writer.recordFile.Close()
			}
			return nil, err
		}
		writer.windowJSON = json.NewEncoder(writer.windowFile)
		writer.windowJSON.SetEscapeHTML(false)
	}
	return writer, nil
}

func (w *detectionDataWriter) WriteConnectionStart(
	connectionID uint64,
	direction string,
	embeddingEnabled bool,
	startedAt time.Time,
	localAddr string,
	remoteAddr string,
	embeddingModes ...string,
) error {
	if w == nil || w.recordJSON == nil {
		return nil
	}
	return w.writeRecordJSON(detectionConnectionStartEvent{
		Kind:               "connection_start",
		ConnectionID:       connectionID,
		Direction:          direction,
		EmbeddingEnabled:   embeddingEnabled,
		EmbeddingMode:      detectionEmbeddingMode(embeddingEnabled, embeddingModes...),
		StartedAtUnixNS:    startedAt.UnixNano(),
		UpstreamLocalAddr:  localAddr,
		UpstreamRemoteAddr: remoteAddr,
	})
}

func (w *detectionDataWriter) WriteRecord(
	connectionID uint64,
	direction string,
	embeddingEnabled bool,
	recordIndex uint64,
	sample recordSample,
	embeddingModes ...string,
) error {
	if w == nil || w.recordJSON == nil {
		return nil
	}
	timestamp, source := detectionTimestamp(sample)
	var timestampUnixNS int64
	if !timestamp.IsZero() {
		timestampUnixNS = timestamp.UnixNano()
	}
	return w.writeRecordJSON(detectionRecordEvent{
		Kind:             "record",
		ConnectionID:     connectionID,
		Direction:        direction,
		EmbeddingEnabled: embeddingEnabled,
		EmbeddingMode:    detectionEmbeddingMode(embeddingEnabled, embeddingModes...),
		RecordIndex:      recordIndex,
		EgressID:         sample.EgressID,
		TimestampUnixNS:  timestampUnixNS,
		TimestampSource:  source,
		Length:           sample.Length,
		Embedded:         sample.Embedded,
	})
}

func (w *detectionDataWriter) WriteConnectionEnd(
	connectionID uint64,
	recordCount uint64,
	queueDropped uint64,
	missingActual uint64,
	actualTimestamps uint64,
	fallbackTimestamps uint64,
	insertedRecords uint64,
	insertedBytes uint64,
	embeddingModes ...string,
) error {
	if w == nil || w.recordJSON == nil {
		return nil
	}
	return w.writeRecordJSON(detectionConnectionEndEvent{
		Kind:                    "connection_end",
		ConnectionID:            connectionID,
		EmbeddingMode:           detectionEmbeddingMode(insertedRecords > 0, embeddingModes...),
		RecordCount:             recordCount,
		QueueDroppedRecords:     queueDropped,
		MissingActualTimestamps: missingActual,
		ActualTimestamps:        actualTimestamps,
		FallbackTimestamps:      fallbackTimestamps,
		InsertedRecords:         insertedRecords,
		InsertedBytes:           insertedBytes,
	})
}

func detectionEmbeddingMode(enabled bool, configured ...string) string {
	if len(configured) > 0 {
		if mode := strings.TrimSpace(configured[0]); mode != "" {
			return mode
		}
	}
	return upstreamEmbeddingModeName(enabled)
}

func (w *detectionDataWriter) WriteWindow(event detectionWindowEvent) error {
	if w == nil || w.windowJSON == nil {
		return nil
	}
	if event.Kind == "" {
		event.Kind = "window"
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}
	return w.windowJSON.Encode(event)
}

func (w *detectionDataWriter) writeRecordJSON(value any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}
	return w.recordJSON.Encode(value)
}

func (w *detectionDataWriter) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true

	var errs []error
	if w.recordFile != nil {
		if err := w.recordFile.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if w.windowFile != nil {
		if err := w.windowFile.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func detectionTimestamp(sample recordSample) (time.Time, string) {
	switch {
	case !sample.ActualEgressAt.IsZero():
		return sample.ActualEgressAt, "actual_tx"
	case !sample.EstimatedEgressAt.IsZero():
		return sample.EstimatedEgressAt, "predicted_tx"
	case !sample.At.IsZero():
		return sample.At, "observed"
	case !sample.SubmittedAt.IsZero():
		return sample.SubmittedAt, "submitted"
	default:
		return time.Time{}, "unavailable"
	}
}
