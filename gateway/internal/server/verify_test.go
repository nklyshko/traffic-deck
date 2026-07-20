package server

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/objstore"
)

func f(proto, method, authority, path string) *trafficv1.Flow {
	return &trafficv1.Flow{Protocol: proto, Method: method, Authority: authority, Path: path}
}

func TestVerifyLiveVsTshark(t *testing.T) {
	tshark := []*trafficv1.Flow{
		f("HTTP/2", "GET", "example.com", "/a"),
		f("HTTP/2", "GET", "httpbin.org", "/get"),
		f("HTTP/2", "GET", "httpbin.org", "/get"), // two identical requests
		f("HTTP/2", "POST", "httpbin.org", "/post"),
	}

	// Live matches tshark exactly → no diffs.
	if diffs := verifyLiveVsTshark("s", tshark, tshark); len(diffs) != 0 {
		t.Fatalf("expected no diffs, got %v", diffs)
	}

	// Live missed one httpbin GET and produced an extra example.com flow.
	live := []*trafficv1.Flow{
		f("HTTP/2", "GET", "example.com", "/a"),
		f("HTTP/2", "GET", "example.com", "/a"), // extra (live-only count)
		f("HTTP/2", "GET", "httpbin.org", "/get"),
		f("HTTP/2", "POST", "httpbin.org", "/post"),
	}
	diffs := verifyLiveVsTshark("s", live, tshark)
	joined := strings.Join(diffs, "\n")
	if !strings.Contains(joined, "httpbin.org/get: live=1 tshark=2") {
		t.Errorf("expected missing httpbin GET diff, got:\n%s", joined)
	}
	if !strings.Contains(joined, "example.com/a: live=2 tshark=1") {
		t.Errorf("expected extra example.com diff, got:\n%s", joined)
	}
}

// TestVerifyRecordedLiveLogsDecodeFailure checks the record-live verification pass:
// a failing batch decode is logged and swallowed — it must never fail the close, since
// the live flows are already persisted by then.
func TestVerifyRecordedLiveLogsDecodeFailure(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	obj, err := objstore.NewFSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sid := "verify-rec"
	if _, err := obj.Put(pcapKey(sid), strings.NewReader("not a pcap")); err != nil {
		t.Fatal(err)
	}

	ing := &Ingest{obj: obj, tshark: "/nonexistent/tshark"}
	ls := &liveSession{flows: map[string]*trafficv1.Flow{}}
	ing.verifyRecordedLive(context.Background(), sid, ls, "")

	if !strings.Contains(buf.String(), "tshark decode failed") {
		t.Errorf("expected decode failure to be logged, got:\n%s", buf.String())
	}
}
