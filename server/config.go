package main

const (
	proxyListenAddr    = "0.0.0.0:8443"
	proxyUpstreamAddr  = "127.0.0.1:8003"
	downlinkSocketMark = 3
	extractQueueLen    = 8

	// Observation and embedding are independent. Keep observation enabled for
	// both normal and embedded detection runs so they use the same TX timestamp
	// instrumentation. Toggle only downlinkEmbeddingEnabled between the pair.
	downlinkObservationEnabled = true
	downlinkEmbeddingEnabled   = true
	recordFeatureQueueLen      = 65536

	// Raw Record events preserve length and ordered egress time for offline
	// shared-bin feature extraction, K-S, and CCE. Window events preserve the
	// current stable-bulk segmentation without freezing per-connection bins.
	recordDetectionOutputPath = "detection_records.jsonl"
	windowDetectionOutputPath = "detection_windows.jsonl"

	// burstIATReferenceQ3Multiplier is the dimensionless lower-bound
	// coefficient kappa in:
	//
	//	tau_ref = max(Q3 + 1.5*IQR, kappa*Q3)
	//
	// tau_ref itself has units of seconds/byte because burst IATs are
	// normalized by the current TLS Record length.
	burstIATReferenceQ3Multiplier = 2.0
)

// K0 is the PSK shared between the tunnel client proxy and this reverse proxy.
// It is independent from the original TLS connection.
var pskK0 = []byte("tls-cp-demo-pre-shared-master-key")

type TLSProxyConfig struct {
	ListenAddr          string
	UpstreamAddr        string
	PSK                 []byte
	ExtractQueueLen     int
	DownlinkObservation bool
	DownlinkEmbedding   bool

	DownlinkSocketMark               int
	AdaptiveObservationFallbackLimit int
	FeatureQueueLen                  int
	DetectionRecordOutputPath        string
	DetectionWindowOutputPath        string
}

func defaultTLSProxyConfig() TLSProxyConfig {
	return TLSProxyConfig{
		ListenAddr:          proxyListenAddr,
		UpstreamAddr:        proxyUpstreamAddr,
		PSK:                 append([]byte(nil), pskK0...),
		ExtractQueueLen:     extractQueueLen,
		DownlinkObservation: downlinkObservationEnabled,
		DownlinkEmbedding:   downlinkEmbeddingEnabled,

		DownlinkSocketMark:               downlinkSocketMark,
		AdaptiveObservationFallbackLimit: adaptiveObservationFallbackLimitDefault,
		FeatureQueueLen:                  recordFeatureQueueLen,
		DetectionRecordOutputPath:        recordDetectionOutputPath,
		DetectionWindowOutputPath:        windowDetectionOutputPath,
	}
}
