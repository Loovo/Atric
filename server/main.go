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
		&cfg.DownlinkEmbedding,
		"embed",
		cfg.DownlinkEmbedding,
		"insert covert TLS records on the downstream direction",
	)
	flag.BoolVar(
		&cfg.DownlinkObservation,
		"observe",
		cfg.DownlinkObservation,
		"collect downstream TLS record detection data",
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
