package main

const (
	proxyListenAddr = "127.0.0.1:1234"

	// Leave empty when running behind NAT REDIRECT so the proxy uses SO_ORIGINAL_DST.
	proxyUpstreamAddr = ""

	// Upstream dials use mark 2 to bypass the transparent redirect rule.
	proxySocketMark = 2

	// Observation and embedding are independent. Keep observation enabled for
	// both normal and embedded runs so they use the same TX timestamp path.
	upstreamObservationEnabled = true
	upstreamEmbeddingEnabled   = false
	extractQueueLen            = 8
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

// K0 is the PSK shared between the client proxy and reverse proxy.
// It is not a TLS PSK and is never used by the original TLS connection.
var pskK0 = []byte("tls-cp-demo-pre-shared-master-key")

func defaultTLSProxyConfig() TLSProxyConfig {
	return TLSProxyConfig{
		ListenAddr:          proxyListenAddr,
		UpstreamAddr:        proxyUpstreamAddr,
		SocketMark:          proxySocketMark,
		PSK:                 append([]byte(nil), pskK0...),
		ExtractQueueLen:     extractQueueLen,
		UpstreamObservation: upstreamObservationEnabled,
		UpstreamEmbedding:   upstreamEmbeddingEnabled,

		AdaptiveObservationFallbackLimit: adaptiveObservationFallbackLimitDefault,
		FeatureQueueLen:                  recordFeatureQueueLen,
		DetectionRecordOutputPath:        recordDetectionOutputPath,
		DetectionWindowOutputPath:        windowDetectionOutputPath,
	}
}
