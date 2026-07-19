package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/config"
)

// fused points logging at a temp dir with the terminal not ours, and returns the log dir.
func fused(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	SetupFused(config.Config{LogFile: filepath.Join(dir, "gateway.log"), LogMaxSizeMB: 1})
	t.Cleanup(func() { Setup(config.Config{LogFile: "off"}) })
	return dir
}

// Each child gets its own file, so a misbehaving source can be read on its own.
func TestChildLogsAreSeparateFiles(t *testing.T) {
	dir := fused(t)
	for _, name := range []string{"chrome", "mitmproxy"} {
		w := ChildLog(name)
		if _, err := w.Write([]byte(name + " speaking\n")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"chrome", "mitmproxy"} {
		b, err := os.ReadFile(filepath.Join(dir, name+".log"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(string(b), name+" speaking") {
			t.Errorf("%s.log = %q", name, b)
		}
		if other := map[string]string{"chrome": "mitmproxy", "mitmproxy": "chrome"}[name]; strings.Contains(string(b), other) {
			t.Errorf("%s.log contains %s's output; the files are not isolated", name, other)
		}
	}
}

// os/exec hands over arbitrary chunks, so a line can arrive in pieces. The terminal tee
// must hold a partial line rather than emit it — otherwise two children splice together.
func TestChildLogTeeHoldsPartialLines(t *testing.T) {
	var term bytes.Buffer
	a := &childLog{name: "chrome", tee: &term}
	b := &childLog{name: "mcp", tee: &term}

	a.Write([]byte("starting cap"))
	b.Write([]byte("mcp up\n"))
	a.Write([]byte("ture on eth0\n"))

	got := term.String()
	want := "[mcp] mcp up\n[chrome] starting capture on eth0\n"
	if got != want {
		t.Errorf("tee =\n%q\nwant\n%q", got, want)
	}
}

// A child that exits mid-line should still have that line surfaced — it is often the
// interesting one (a truncated traceback).
func TestChildLogCloseFlushesPartialLine(t *testing.T) {
	var term bytes.Buffer
	c := &childLog{name: "chrome", tee: &term}
	c.Write([]byte("died without a newline"))
	if term.Len() != 0 {
		t.Fatalf("partial line emitted before Close: %q", term.String())
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := term.String(), "[chrome] died without a newline\n"; got != want {
		t.Errorf("tee = %q, want %q", got, want)
	}
}

// A child spewing without newlines must not grow the buffer unboundedly.
func TestChildLogBoundsUnterminatedOutput(t *testing.T) {
	var term bytes.Buffer
	c := &childLog{name: "noisy", tee: &term}
	c.Write(bytes.Repeat([]byte("x"), 100<<10))
	if term.Len() == 0 {
		t.Error("nothing emitted; an unterminated flood buffers without bound")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.buf) > 64<<10 {
		t.Errorf("buffer grew to %d bytes", len(c.buf))
	}
}

// Writes come from os/exec copy goroutines, one per stream, so a source's stdout and
// stderr land on the same sink concurrently.
func TestChildLogConcurrentWrites(t *testing.T) {
	dir := fused(t)
	w := ChildLog("chrome")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				w.Write([]byte("line\n"))
			}
		}()
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "chrome.log"))
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(b, []byte("line\n")); n != 400 {
		t.Errorf("got %d lines, want 400", n)
	}
}

// Source names are free-form — a module's is "module:<mod>:<NN>-<proc>" — and must never
// escape the log directory or collide with the gateway's own log.
func TestSafeName(t *testing.T) {
	cases := map[string]string{
		"chrome":              "chrome",
		"module:acme:01-web":  "module-acme-01-web",
		"../../etc/passwd":    "etc-passwd",
		"..":                  "child",
		"":                    "child",
		"weird name/with sep": "weird-name-with-sep",
	}
	for in, want := range cases {
		if got := safeName(in); got != want {
			t.Errorf("safeName(%q) = %q, want %q", in, got, want)
		}
		if strings.ContainsAny(safeName(in), `/\`) {
			t.Errorf("safeName(%q) = %q escapes the log dir", in, safeName(in))
		}
	}
}

// With file logging off there is no per-child file, but a child must still start.
func TestChildLogWithFileLoggingOff(t *testing.T) {
	SetupFused(config.Config{LogFile: "off"})
	t.Cleanup(func() { Setup(config.Config{LogFile: "off"}) })
	if p := ChildLogPath("chrome"); p != "" {
		t.Errorf("ChildLogPath = %q, want empty", p)
	}
	w := ChildLog("chrome")
	if _, err := w.Write([]byte("dropped\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
