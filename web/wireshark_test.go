package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
)

func TestDisplayFilter(t *testing.T) {
	for _, c := range []struct {
		flow *trafficv1.Flow
		want string
	}{
		{&trafficv1.Flow{SrcAddr: "10.0.0.1:43894", DstAddr: "74.125.128.188:5228", Protocol: "HTTP/1.1"},
			"ip.addr eq 10.0.0.1 and tcp.port eq 43894 and ip.addr eq 74.125.128.188 and tcp.port eq 5228"},
		{&trafficv1.Flow{SrcAddr: "[2001:db8::1]:50000", DstAddr: "[2606:4700::6810:84e5]:443", Protocol: "HTTP/2", StreamId: "5"},
			"ipv6.addr eq 2001:db8::1 and tcp.port eq 50000 and ipv6.addr eq 2606:4700::6810:84e5 and tcp.port eq 443 and (http2.streamid eq 5 or not http2)"},
		// The PDML path's bare IPv6 with the port as the last group; a bare "::1" has none.
		{&trafficv1.Flow{SrcAddr: "2001:db8::1:50000", DstAddr: "::1"}, "ipv6.addr eq 2001:db8::1 and tcp.port eq 50000 and ipv6.addr eq ::1"},
		{&trafficv1.Flow{SrcAddr: "192.168.0.19:55384", DstAddr: "142.250.1.1:443", Protocol: "HTTP/3"},
			"ip.addr eq 192.168.0.19 and udp.port eq 55384 and ip.addr eq 142.250.1.1 and udp.port eq 443"},
		{&trafficv1.Flow{SrcAddr: "[::ffff:10.0.0.1]:1", ConnectionId: "quic:ab"}, "ip.addr eq 10.0.0.1 and udp.port eq 1"},
		// A stream id outside HTTP/2, or an HTTP/2 flow that doesn't know its stream, doesn't narrow the filter.
		{&trafficv1.Flow{SrcAddr: "10.0.0.1:1", Protocol: "HTTP/1.1", StreamId: "5"}, "ip.addr eq 10.0.0.1 and tcp.port eq 1"},
		{&trafficv1.Flow{SrcAddr: "10.0.0.1:1", Protocol: "HTTP/2"}, "ip.addr eq 10.0.0.1 and tcp.port eq 1"},
		{&trafficv1.Flow{}, ""},
	} {
		got, err := displayFilter(c.flow)
		if err != nil || got != c.want {
			t.Errorf("%v:\n got %q, %v\nwant %q", c.flow, got, err, c.want)
		}
	}
	// An HTTP/2 stream id that isn't one is refused rather than widened to the connection.
	for _, sid := range []string{"5 or 1==1", "-1", "x", "2147483648"} {
		if got, err := displayFilter(&trafficv1.Flow{SrcAddr: "10.0.0.1:1", Protocol: "HTTP/2", StreamId: sid}); err == nil {
			t.Errorf("stream id %q accepted as %q", sid, got)
		}
	}
	// Anything that isn't an address and a port is refused, never written into the filter.
	for _, a := range []string{"example.com:443", "10.0.0.1:0", "10.0.0.1:70000", "[fe80::1%eth0]:443", "10.0.0.1 or 1:443", "10.0.0.1\":443"} {
		if got, err := displayFilter(&trafficv1.Flow{SrcAddr: a}); err == nil {
			t.Errorf("%q accepted as %q", a, got)
		}
	}
}

func sessionDir(t *testing.T, sid string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sessions", sid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"capture.pcap", "key.log"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestSessionFile(t *testing.T) {
	const sid = "084e7620-1a99-4c70-85f8-4b7fe50d1fdd"
	dir := sessionDir(t, sid)
	good := filepath.Join(dir, "capture.pcap")
	if p, err := sessionFile(good, sid, "capture.pcap"); err != nil || p != good {
		t.Fatalf("good path: %q, %v", p, err)
	}
	other := sessionDir(t, "other")
	for _, p := range []string{
		filepath.Join(dir, "key.log"),              // another file of the session
		filepath.Join(other, "capture.pcap"),       // another session
		"sessions/" + sid + "/capture.pcap",        // relative
		dir + "/../" + sid + "/capture.pcap",       // not clean
		good + "\n-o\nx",                           // control characters
		filepath.Join(dir, "nope", "capture.pcap"), // wrong layout
	} {
		if _, err := sessionFile(p, sid, "capture.pcap"); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
	// A symlink or a directory under the right name is refused too.
	if err := os.Remove(good); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "capture.pcap"), good); err != nil {
		t.Fatal(err)
	}
	if _, err := sessionFile(good, sid, "capture.pcap"); err == nil {
		t.Error("symlink accepted")
	}
	if err := os.Remove(good); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(good, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := sessionFile(good, sid, "capture.pcap"); err == nil {
		t.Error("directory accepted")
	}
}

type wsControl struct {
	trafficv1.ControlServiceClient
	arts *trafficv1.SessionArtifacts
}

func (c *wsControl) GetSessionArtifacts(context.Context, *trafficv1.GetSessionArtifactsRequest, ...grpc.CallOption) (*trafficv1.SessionArtifacts, error) {
	return c.arts, nil
}

type wsViewer struct {
	trafficv1.ViewerServiceClient
	flow *trafficv1.Flow
}

func (v *wsViewer) GetFlow(context.Context, *trafficv1.GetFlowRequest, ...grpc.CallOption) (*trafficv1.Flow, error) {
	return v.flow, nil
}

func TestOpenInWireshark(t *testing.T) {
	const sid = "084e7620-1a99-4c70-85f8-4b7fe50d1fdd"
	dir := sessionDir(t, sid)
	pcap, keylog := filepath.Join(dir, "capture.pcap"), filepath.Join(dir, "key.log")
	setup := func() (*server, *trafficv1.SessionArtifacts, *[][]string, *time.Time) {
		arts := &trafficv1.SessionArtifacts{PcapPath: pcap, KeylogPath: keylog, Hostname: "this-host"}
		flow := &trafficv1.Flow{Id: "f1", SrcAddr: "10.0.0.1:43894", DstAddr: "74.125.128.188:443", Protocol: "HTTP/2", StreamId: "3", FrameNumber: 1243}
		// The embedded clients only answer the method-value lookups routes() makes.
		s := newServer(backend{
			viewer:  &wsViewer{ViewerServiceClient: trafficv1.NewViewerServiceClient(nil), flow: flow},
			control: &wsControl{ControlServiceClient: trafficv1.NewControlServiceClient(nil), arts: arts},
			ingest:  trafficv1.NewIngestServiceClient(nil),
		}, "127.0.0.1:18890")
		var started [][]string
		now := time.Unix(1000, 0)
		s.wireshark = &wiresharkLauncher{
			binary: "/usr/bin/wireshark", local: true, hostname: "this-host", lastStart: map[string]time.Time{},
			start: func(argv []string) (func(), error) { started = append(started, argv); return func() { select {} }, nil },
			now:   func() time.Time { return now },
		}
		return s, arts, &started, &now
	}
	call := func(h http.Handler, mutate func(*http.Request), body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/wireshark", strings.NewReader(body))
		r.Host = "127.0.0.1:18890"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://127.0.0.1:18890")
		r.Header.Set(actionHeader, "wireshark")
		if mutate != nil {
			mutate(r)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	ok := `{"sessionId":"` + sid + `","flowId":"f1"}`

	s, _, started, now := setup()
	h := s.routes()
	if w := call(h, nil, ok); w.Code != http.StatusNoContent {
		t.Fatalf("launch: %d %s", w.Code, w.Body)
	}
	want := []string{"/usr/bin/wireshark", "-r", pcap, "-o", "tls.keylog_file:" + keylog,
		"-Y", "ip.addr eq 10.0.0.1 and tcp.port eq 43894 and ip.addr eq 74.125.128.188 and tcp.port eq 443 and (http2.streamid eq 3 or not http2)",
		"-g", "1243"}
	if len(*started) != 1 || !reflect.DeepEqual((*started)[0], want) {
		t.Fatalf("argv = %q", *started)
	}
	if w := call(h, nil, ok); w.Code != http.StatusTooManyRequests {
		t.Errorf("repeat within the cooldown: %d", w.Code)
	}
	*now = now.Add(wiresharkCooldown)
	if w := call(h, nil, ok); w.Code != http.StatusNoContent {
		t.Errorf("after the cooldown: %d %s", w.Code, w.Body)
	}
	for i := 2; i < wiresharkMaxRunning; i++ {
		*now = now.Add(wiresharkCooldown)
		call(h, nil, ok)
	}
	*now = now.Add(wiresharkCooldown)
	if w := call(h, nil, ok); w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "close one") {
		t.Errorf("past the window cap: %d %s", w.Code, w.Body)
	}

	for name, c := range map[string]struct {
		mutate func(*http.Request)
		body   string
		code   int
	}{
		"text/plain":        {func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, ok, http.StatusUnsupportedMediaType},
		"no action header":  {func(r *http.Request) { r.Header.Del(actionHeader) }, ok, http.StatusForbidden},
		"other origin":      {func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }, ok, http.StatusForbidden},
		"no origin":         {func(r *http.Request) { r.Header.Del("Origin") }, ok, http.StatusForbidden},
		"unknown field":     {nil, `{"sessionId":"` + sid + `","flowId":"f1","binary":"/bin/sh"}`, http.StatusBadRequest},
		"bad session id":    {nil, `{"sessionId":"../x","flowId":"f1"}`, http.StatusBadRequest},
		"option as flow id": {nil, `{"sessionId":"` + sid + `","flowId":"-o"}`, http.StatusBadRequest},
		"too large":         {nil, `{"sessionId":"` + strings.Repeat("a", 2000) + `"}`, http.StatusBadRequest},
		"trailing object":   {nil, ok + `{"flowId":"f2"}`, http.StatusBadRequest},
		"trailing garbage":  {nil, ok + ` x`, http.StatusBadRequest},
	} {
		s, _, started, _ := setup()
		if w := call(s.routes(), c.mutate, c.body); w.Code != c.code || len(*started) != 0 {
			t.Errorf("%s: %d %s, started %d", name, w.Code, w.Body, len(*started))
		}
	}

	for name, c := range map[string]struct {
		change func(*server, *trafficv1.SessionArtifacts)
		code   int
		says   string
	}{
		"not local":        {func(s *server, _ *trafficv1.SessionArtifacts) { s.wireshark.local = false }, http.StatusForbidden, "this machine"},
		"no launcher":      {func(s *server, _ *trafficv1.SessionArtifacts) { s.wireshark = nil }, http.StatusForbidden, "this machine"},
		"not installed":    {func(s *server, _ *trafficv1.SessionArtifacts) { s.wireshark.binary = "" }, http.StatusServiceUnavailable, "TRAFFICDECK_WIRESHARK"},
		"other host":       {func(_ *server, a *trafficv1.SessionArtifacts) { a.Hostname = "elsewhere" }, http.StatusForbidden, "elsewhere"},
		"no pcap":          {func(_ *server, a *trafficv1.SessionArtifacts) { a.PcapPath = "" }, http.StatusConflict, "no pcap"},
		"pcap elsewhere":   {func(_ *server, a *trafficv1.SessionArtifacts) { a.PcapPath = "/etc/passwd" }, http.StatusUnprocessableEntity, "capture.pcap"},
		"keylog elsewhere": {func(_ *server, a *trafficv1.SessionArtifacts) { a.KeylogPath = pcap }, http.StatusUnprocessableEntity, "key.log"},
	} {
		s, arts, started, _ := setup()
		c.change(s, arts)
		if w := call(s.routes(), nil, ok); w.Code != c.code || !strings.Contains(w.Body.String(), c.says) || len(*started) != 0 {
			t.Errorf("%s: %d %s, started %d", name, w.Code, w.Body, len(*started))
		}
	}
}

func TestLoopbackAddr(t *testing.T) {
	for a, want := range map[string]bool{"127.0.0.1:18890": true, "[::1]:7331": true, "localhost:7331": true, "0.0.0.0:18890": false, "192.168.0.19:7331": false, "gateway.lan:7331": false} {
		if got := loopbackAddr(a); got != want {
			t.Errorf("%s = %v", a, got)
		}
	}
}
