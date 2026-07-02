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
	w, err := writer(config.Config{LogFile: p, LogMaxSizeMB: 1, LogMaxBackups: 1})
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
		w, err := writer(config.Config{LogFile: v})
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if w != os.Stderr {
			t.Errorf("LogFile=%q: expected stderr-only writer", v)
		}
	}
}
