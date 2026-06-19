package decode

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// tsharkPath resolves tshark or skips the test if it is unavailable.
func tsharkPath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("tshark")
	if err != nil {
		t.Skip("tshark not found on PATH")
	}
	return p
}

func TestDecodeSample(t *testing.T) {
	ts := tsharkPath(t)
	pcap := filepath.Join("testdata", "sample.pcap")
	keylog := filepath.Join("testdata", "sample.key.log")
	if _, err := os.Stat(pcap); err != nil {
		t.Skipf("fixture missing: %v", err)
	}

	ds, err := Decode(context.Background(), ts, pcap, keylog)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if ds.Engine != "tshark" || !ds.TLSKeyLogUsed {
		t.Fatalf("engine=%q keylog=%v", ds.Engine, ds.TLSKeyLogUsed)
	}
	if len(ds.Flows) == 0 {
		t.Fatal("no flows decoded")
	}

	var withReq, withResp, decrypted, withHdrs int
	for _, f := range ds.Flows {
		if f.Method != "" {
			withReq++
		}
		if f.Status != 0 {
			withResp++
		}
		if f.TLSDecrypted {
			decrypted++
		}
		if len(f.RequestHeaders) > 0 {
			withHdrs++
		}
	}
	t.Logf("flows=%d withReq=%d withResp=%d decrypted=%d withReqHdrs=%d",
		len(ds.Flows), withReq, withResp, decrypted, withHdrs)

	if withReq == 0 {
		t.Error("no flows with a request method")
	}
	if withResp == 0 {
		t.Error("no flows with a response status")
	}
	if decrypted == 0 {
		t.Error("no TLS-decrypted flows (keylog not applied?)")
	}

	// Spot-check a known TikTok request from the sample (tcp.stream 5, h2 stream 1).
	// The fixture is truncated at frame 2000, so not every request has its
	// response captured — require that at least one tiktok.com GET is fully stitched.
	var found, stitched bool
	for _, f := range ds.Flows {
		if f.Authority == "www.tiktok.com" && f.Method == "GET" {
			found = true
			if f.Protocol != "HTTP/2" {
				t.Errorf("protocol = %q, want HTTP/2", f.Protocol)
			}
			if f.Status != 0 {
				stitched = true
			}
		}
	}
	if !found {
		t.Error("expected a GET to www.tiktok.com in the sample")
	}
	if !stitched {
		t.Error("expected at least one tiktok.com GET stitched with its response")
	}
}
