package decode

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestDecodeNativeFromFile covers the tshark-free import path: DecodeNative reads a stored
// pcap off disk and runs the in-process Go pipeline over it, returning fully-decoded flows
// (final state, not the mid-flight isNew emission).
func TestDecodeNativeFromFile(t *testing.T) {
	req := []byte("GET /hello?x=1 HTTP/1.1\r\nHost: plain.example.com\r\n" +
		"User-Agent: probe/1\r\n\r\n")
	resp := []byte("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n" +
		"Content-Length: 9\r\n\r\nnot found")

	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(path, buildPcap(t, req, resp), 0o644); err != nil {
		t.Fatal(err)
	}

	ds, err := DecodeNative(context.Background(), path, "")
	if err != nil {
		t.Fatalf("DecodeNative: %v", err)
	}
	if ds.Engine != EngineNative {
		t.Errorf("engine = %q, want %q", ds.Engine, EngineNative)
	}
	if len(ds.Flows) != 1 {
		t.Fatalf("got %d flows, want 1", len(ds.Flows))
	}
	f := ds.Flows[0]
	if f.Method != "GET" || f.Path != "/hello" || f.Authority != "plain.example.com" {
		t.Errorf("req: method=%q path=%q authority=%q", f.Method, f.Path, f.Authority)
	}
	// The response must be reflected even though the flow was appended on its isNew emission
	// (the retained pointer's final state is read after EOF).
	if f.Status != 404 || string(f.ResponseBody) != "not found" {
		t.Errorf("resp: status=%d body=%q", f.Status, f.ResponseBody)
	}
}

// TestDecodeNativeMissingFile checks the open error surfaces rather than panicking.
func TestDecodeNativeMissingFile(t *testing.T) {
	if _, err := DecodeNative(context.Background(), filepath.Join(t.TempDir(), "nope.pcap"), ""); err == nil {
		t.Fatal("expected an error for a missing pcap, got nil")
	}
}
