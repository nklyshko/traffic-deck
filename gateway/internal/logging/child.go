package logging

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// Every spawned child gets its own rolling file next to the gateway log — logs/chrome.log,
// logs/mcp.log — so one misbehaving source can be read on its own instead of picked out of
// an interleaved stream. When the terminal is ours it is also teed there, tagged with the
// child's name, so `trafficdeck serve` still shows everything in one place.

// ChildLog returns the sink for a named child's stdout/stderr. Close it once the child has
// exited. Never hand a child os.Stderr directly: under one-command mode that is the TUI's
// terminal. A child whose file cannot be opened still logs to the tee (or is dropped).
func ChildLog(name string) io.WriteCloser {
	mu.Lock()
	cfg, terminal := current, hasTerminal
	mu.Unlock()

	c := &childLog{name: name}
	if terminal {
		c.tee = os.Stderr
	}
	if cfg.LogFile == "" || disabled(cfg.LogFile) {
		return c
	}
	dir := filepath.Dir(cfg.LogFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return c // the tee, or nothing — a child must never fail to start over its log
	}
	c.file = &lumberjack.Logger{
		Filename:   filepath.Join(dir, safeName(name)+".log"),
		MaxSize:    cfg.LogMaxSizeMB,
		MaxBackups: cfg.LogMaxBackups,
		MaxAge:     cfg.LogMaxAgeDays,
		Compress:   cfg.LogCompress,
	}
	// Mark the run: it creates the file up front, so a quiet child can still be tailed and
	// `ls` shows what has run, and it separates one run from the last in an appended file.
	fmt.Fprintf(c.file, "=== %s started %s ===\n", name, time.Now().Format(time.RFC3339))
	return c
}

// ChildLogPath is where ChildLog writes a given child's file, for pointing an operator at
// it. Empty when file logging is off.
func ChildLogPath(name string) string {
	mu.Lock()
	cfg := current
	mu.Unlock()
	if cfg.LogFile == "" || disabled(cfg.LogFile) {
		return ""
	}
	return filepath.Join(filepath.Dir(cfg.LogFile), safeName(name)+".log")
}

var unsafeName = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

// safeName turns a child name into one path segment. Source names are free-form — a module
// is "module:<mod>:<NN>-<proc>" — so anything that could escape the log dir is folded away.
func safeName(name string) string {
	s := unsafeName.ReplaceAllString(name, "-")
	s = strings.Trim(s, "-.")
	if s == "" {
		return "child"
	}
	return s
}

// childLog fans one child's output into its own file and, when we own the terminal, the
// terminal with a name tag. os/exec copies a child's output in arbitrary chunks, so writes
// arrive split mid-line; childLog buffers until a newline. Without that, two children
// writing at once splice into each other's lines.
type childLog struct {
	name string
	file io.WriteCloser // nil when file logging is off
	tee  io.Writer      // nil when the terminal isn't ours

	mu     sync.Mutex
	buf    []byte
	closed bool
}

func (c *childLog) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return len(p), nil
	}
	if c.file != nil {
		_, _ = c.file.Write(p) // the file is this child's alone: no splicing to guard against
	}
	if c.tee == nil {
		return len(p), nil
	}
	c.buf = append(c.buf, p...)
	for {
		i := bytes.IndexByte(c.buf, '\n')
		if i < 0 {
			break
		}
		c.emit(c.buf[:i])
		c.buf = c.buf[i+1:]
	}
	// A child that floods without newlines must not grow the buffer without bound.
	if len(c.buf) > 64<<10 {
		c.emit(c.buf)
		c.buf = c.buf[:0]
	}
	return len(p), nil
}

// emit writes one complete line to the tee, tagged, in a single Write so it cannot
// interleave with another child's line.
func (c *childLog) emit(line []byte) {
	line = trimCR(line)
	out := make([]byte, 0, len(c.name)+len(line)+4)
	out = append(out, '[')
	out = append(out, c.name...)
	out = append(out, ']', ' ')
	out = append(out, line...)
	out = append(out, '\n')
	_, _ = c.tee.Write(out)
}

// Close flushes a trailing partial line and releases the child's file handle.
func (c *childLog) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if len(c.buf) > 0 && c.tee != nil {
		c.emit(c.buf)
		c.buf = nil
	}
	if c.file != nil {
		return c.file.Close()
	}
	return nil
}

func trimCR(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\r' {
		return b[:len(b)-1]
	}
	return b
}
