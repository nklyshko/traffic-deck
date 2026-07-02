// Package logging configures the gateway's standard-library log output: by default it
// tees to stderr and a size-rolling file, so logs persist and rotate without any external
// setup. Set GATEWAY_LOG_FILE=off (config.LogFile) for stderr only.
package logging

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/config"
)

// Setup points the standard logger at the configured destination. On any error preparing
// the log file it falls back to stderr (logging must never take the process down).
func Setup(cfg config.Config) {
	w, err := writer(cfg)
	if err != nil {
		log.SetOutput(os.Stderr)
		log.Printf("logging: file logging disabled: %v", err)
		return
	}
	log.SetOutput(w)
	if cfg.LogFile != "" && !disabled(cfg.LogFile) {
		log.Printf("logging to %s (rolling: %d MiB x %d backups, %d days, compress=%v)",
			cfg.LogFile, cfg.LogMaxSizeMB, cfg.LogMaxBackups, cfg.LogMaxAgeDays, cfg.LogCompress)
	}
}

func disabled(path string) bool {
	return strings.EqualFold(path, "off") || strings.EqualFold(path, "none")
}

// writer returns the log destination: stderr alone when file logging is disabled, else
// stderr teed with a rolling file logger.
func writer(cfg config.Config) (io.Writer, error) {
	if cfg.LogFile == "" || disabled(cfg.LogFile) {
		return os.Stderr, nil
	}
	if err := os.MkdirAll(filepath.Dir(cfg.LogFile), 0o755); err != nil {
		return nil, err
	}
	lj := &lumberjack.Logger{
		Filename:   cfg.LogFile,
		MaxSize:    cfg.LogMaxSizeMB,
		MaxBackups: cfg.LogMaxBackups,
		MaxAge:     cfg.LogMaxAgeDays,
		Compress:   cfg.LogCompress,
	}
	return io.MultiWriter(os.Stderr, lj), nil
}
