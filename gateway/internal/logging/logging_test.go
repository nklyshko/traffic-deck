package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/config"
)

func TestWriterRollingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "logs", "gateway.log") // nested dir must be created
	w, err := writer(config.Config{LogFile: p, LogMaxSizeMB: 1, LogMaxBackups: 1}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("hello world\n")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("log file not written: %v", err)
	}
	if !strings.Contains(string(b), "hello world") {
		t.Fatalf("log file = %q, want it to contain the written line", b)
	}
}

func TestWriterDisabled(t *testing.T) {
	for _, v := range []string{"off", "OFF", "none", ""} {
		w, err := writer(config.Config{LogFile: v}, true)
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if w != os.Stderr {
			t.Errorf("LogFile=%q: expected stderr-only writer", v)
		}
	}
}

// Under one-command mode the TUI owns the terminal, so no destination may be stderr —
// anything written there overwrites the top of the viewer.
func TestWriterFusedNeverTouchesTerminal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "logs", "gateway.log")
	for _, logFile := range []string{p, "off", ""} {
		w, err := writer(config.Config{LogFile: logFile, LogMaxSizeMB: 1}, false)
		if err != nil {
			t.Fatalf("%q: %v", logFile, err)
		}
		if w == os.Stderr {
			t.Errorf("LogFile=%q: fused writer is stderr, would corrupt the TUI", logFile)
		}
	}
}

// SetupFused must also redirect spawned children (the MCP server, capture sources) — MCP's
// startup banner on stderr is what corrupts the viewer.
func TestSetupFusedSendsChildOutputToItsOwnFile(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{LogFile: filepath.Join(dir, "gateway.log"), LogMaxSizeMB: 1}
	SetupFused(cfg)
	t.Cleanup(func() { Setup(config.Config{LogFile: "off"}) })

	w := ChildLog("mcp")
	if c, ok := w.(*childLog); !ok || c.tee != nil {
		t.Fatal("fused child log tees to the terminal; it would write over the TUI")
	}
	if _, err := w.Write([]byte("INFO: Uvicorn running\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "mcp.log"))
	if err != nil {
		t.Fatalf("no per-child log file: %v", err)
	}
	if !strings.Contains(string(b), "Uvicorn running") {
		t.Fatalf("mcp.log = %q, want the child's output", b)
	}
	if g, err := os.ReadFile(cfg.LogFile); err == nil && strings.Contains(string(g), "Uvicorn") {
		t.Error("child output leaked into the shared gateway log; it has its own file")
	}
}
