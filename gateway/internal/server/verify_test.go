package server

import (
	"strings"
	"testing"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
)

func f(proto, method, authority, path string) *trafficv1.Flow {
	return &trafficv1.Flow{Protocol: proto, Method: method, Authority: authority, Path: path}
}

func TestVerifyLiveVsBatch(t *testing.T) {
	batch := []*trafficv1.Flow{
		f("HTTP/2", "GET", "example.com", "/a"),
		f("HTTP/2", "GET", "httpbin.org", "/get"),
		f("HTTP/2", "GET", "httpbin.org", "/get"), // two identical requests
		f("HTTP/2", "POST", "httpbin.org", "/post"),
	}

	// Live matches batch exactly → no diffs.
	if diffs := verifyLiveVsBatch("s", batch, batch); len(diffs) != 0 {
		t.Fatalf("expected no diffs, got %v", diffs)
	}

	// Live missed one httpbin GET and produced an extra example.com flow.
	live := []*trafficv1.Flow{
		f("HTTP/2", "GET", "example.com", "/a"),
		f("HTTP/2", "GET", "example.com", "/a"), // extra (live-only count)
		f("HTTP/2", "GET", "httpbin.org", "/get"),
		f("HTTP/2", "POST", "httpbin.org", "/post"),
	}
	diffs := verifyLiveVsBatch("s", live, batch)
	joined := strings.Join(diffs, "\n")
	if !strings.Contains(joined, "httpbin.org/get: live=1 batch=2") {
		t.Errorf("expected missing httpbin GET diff, got:\n%s", joined)
	}
	if !strings.Contains(joined, "example.com/a: live=2 batch=1") {
		t.Errorf("expected extra example.com diff, got:\n%s", joined)
	}
}
