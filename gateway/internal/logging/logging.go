// Package logging configures the gateway's standard-library log output: by default it
// tees to stderr and a size-rolling file, so logs persist and rotate without any external
// setup. Set GATEWAY_LOG_FILE=off (config.LogFile) for stderr only.
//
// It also owns ChildLog, the sink spawned children (capture sources, the MCP server) are
// given — each gets its own rolling file, and the terminal only when the terminal is ours.
// In one-command mode it belongs to the TUI, and anything written there scribbles over the
// viewer. See SetupFused and child.go.
package logging

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"

	"github.com/nklyshko/traffic-deck/gateway/internal/config"
)

// The active configuration, as ChildLog needs it to open a child's own file, and whether
// the terminal is ours to write to (it isn't once the TUI has it).
var (
	mu          sync.Mutex
	current     config.Config
	hasTerminal = true
)

// Setup points the standard logger at the configured destination. On any error preparing
// the log file it falls back to stderr (logging must never take the process down).
func Setup(cfg config.Config) { setup(cfg, true) }

// SetupFused is Setup for one-command mode, where the TUI has the terminal: logs and child
// output go to the rolling file only. With file logging off they are dropped — a corrupted
// viewer is worse than lost logs, and `trafficdeck serve` is there when you need to watch.
func SetupFused(cfg config.Config) { setup(cfg, false) }

func setup(cfg config.Config, terminal bool) {
	mu.Lock()
	current, hasTerminal = cfg, terminal
	mu.Unlock()

	w, err := writer(cfg, terminal)
	if err != nil {
		// File logging failed. Fall back to the terminal only when it's ours; in fused mode
		// it belongs to the TUI, so drop the logs rather than scribble over the viewer — the
		// same invariant writer() keeps on its success paths. The failure resurfaces once the
		// viewer exits and Setup restores terminal ownership.
		fallback := io.Writer(io.Discard)
		if terminal {
			fallback = os.Stderr
		}
		log.SetOutput(fallback)
		mu.Lock()
		current.LogFile = "off" // no usable file: children fall back the same way (tee or nothing)
		mu.Unlock()
		log.Printf("logging: file logging disabled: %v", err)
		return
	}
	log.SetOutput(w)
	if terminal && cfg.LogFile != "" && !disabled(cfg.LogFile) {
		log.Printf("logging to %s (rolling: %d MiB x %d backups, %d days, compress=%v)",
			cfg.LogFile, cfg.LogMaxSizeMB, cfg.LogMaxBackups, cfg.LogMaxAgeDays, cfg.LogCompress)
	}
}

func disabled(path string) bool {
	return strings.EqualFold(path, "off") || strings.EqualFold(path, "none")
}

// writer returns the log destination: the rolling file, teed with stderr when the terminal
// is ours to write to. With file logging disabled it degrades to stderr alone, or to
// io.Discard when we may not touch the terminal either.
func writer(cfg config.Config, terminal bool) (io.Writer, error) {
	if cfg.LogFile == "" || disabled(cfg.LogFile) {
		if !terminal {
			return io.Discard, nil
		}
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
	if !terminal {
		return lj, nil
	}
	return io.MultiWriter(os.Stderr, lj), nil
}
