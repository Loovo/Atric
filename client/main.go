package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"
)

func main() {
	cfg := defaultTLSProxyConfig()
	flag.BoolVar(
		&cfg.UpstreamEmbedding,
		"embed",
		cfg.UpstreamEmbedding,
		"enable adaptive upstream embedding",
	)
	flag.BoolVar(
		&cfg.UpstreamObservation,
		"observe",
		cfg.UpstreamObservation,
		"collect upstream TLS record detection data",
	)
	flag.StringVar(
		&cfg.DetectionRecordOutputPath,
		"detection-record-output",
		cfg.DetectionRecordOutputPath,
		"raw TLS record JSONL output path (empty disables it)",
	)
	flag.StringVar(
		&cfg.DetectionWindowOutputPath,
		"detection-window-output",
		cfg.DetectionWindowOutputPath,
		"online stable-window JSONL output path (empty disables it)",
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := runTLSProxy(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}
