package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
)

func TestParseCursor(t *testing.T) {
	for in, want := range map[string][2]uint64{"12:34": {12, 34}, ":34": {0, 34}, "12:": {12, 0}, ":": {0, 0}} {
		c, err := parseCursor(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if uint64(c.TsMicros) != want[0] || c.FrameNumber != want[1] {
			t.Errorf("%q = %v", in, c)
		}
	}
	if c, err := parseCursor(""); c != nil || err != nil {
		t.Errorf("empty = %v, %v", c, err)
	}
	for _, in := range []string{"abc", "12", "a:1", "1:b", "1:-2", "99999999999999999999:1"} {
		if _, err := parseCursor(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestBannerAlignsMultibyte(t *testing.T) {
	var b strings.Builder
	writeBanner(&b, "http://127.0.0.1:18890/é→", "127.0.0.1:7331", true)
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(b.String(), "\x1b[1;36m", ""), "\x1b[0m", "")), "\n")
	want := len([]rune(lines[0]))
	for _, l := range lines {
		if len([]rune(l)) != want {
			t.Errorf("width %d != %d: %q", len([]rune(l)), want, l)
		}
	}
}

func TestSanitizeFilename(t *testing.T) {
	for in, want := range map[string]string{"ab-1_C": "ab-1_C", `a"b/../c`: "abc", "///": "session", "": "session"} {
		if got := sanitizeFilename(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}

type fakeControl struct {
	trafficv1.ControlServiceClient
	label string
}

func (f *fakeControl) SetSessionLabel(_ context.Context, in *trafficv1.SetSessionLabelRequest, _ ...grpc.CallOption) (*trafficv1.Empty, error) {
	f.label = in.Label
	return &trafficv1.Empty{}, nil
}

func (f *fakeControl) DeleteSession(context.Context, *trafficv1.DeleteSessionRequest, ...grpc.CallOption) (*trafficv1.Empty, error) {
	return nil, status.Error(codes.Internal, "boom")
}

type fakeBodyStream struct {
	grpc.ServerStreamingClient[trafficv1.BodyChunk]
	chunks []string
	err    error
}

func (f *fakeBodyStream) Recv() (*trafficv1.BodyChunk, error) {
	if len(f.chunks) == 0 {
		return nil, f.err
	}
	c := f.chunks[0]
	f.chunks = f.chunks[1:]
	return &trafficv1.BodyChunk{Payload: []byte(c)}, nil
}

type fakeViewer struct {
	trafficv1.ViewerServiceClient
	stream *fakeBodyStream
}

func (f *fakeViewer) GetBody(context.Context, *trafficv1.GetBodyRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[trafficv1.BodyChunk], error) {
	return f.stream, nil
}

func post(h http.Handler, path, contentType, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Host = "127.0.0.1:18890"
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func testServer(c *fakeControl, v *fakeViewer) http.Handler {
	return newServer(backend{viewer: v, control: c, ingest: trafficv1.NewIngestServiceClient(nil)}, "127.0.0.1:18890").routes()
}

func TestContentTypeGate(t *testing.T) {
	c := &fakeControl{}
	h := testServer(c, &fakeViewer{})
	const path, body = "/api/rpc/SetSessionLabel", `{"sessionId":"s","label":"x","unknownField":1}`
	for _, ct := range []string{"text/plain", "", "application/x-www-form-urlencoded", "multipart/form-data"} {
		if w := post(h, path, ct, body); w.Code != http.StatusUnsupportedMediaType {
			t.Errorf("%q: %d", ct, w.Code)
		}
	}
	if c.label != "" {
		t.Fatal("rejected request reached the gateway")
	}
	if w := post(h, path, "application/json; charset=utf-8", body); w.Code != 200 {
		t.Fatalf("json: %d %s", w.Code, w.Body)
	}
	if c.label != "x" {
		t.Errorf("label = %q", c.label)
	}
	if w := post(h, "/api/session/import", "application/json", ""); w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("import as json: %d", w.Code)
	}
}

func TestRPCAllowListAndErrors(t *testing.T) {
	h := testServer(&fakeControl{}, &fakeViewer{})
	if w := post(h, "/api/rpc/StartService", "application/json", ""); w.Code != http.StatusNotFound {
		t.Errorf("unlisted method: %d", w.Code)
	}
	if w := post(h, "/api/rpc/DeleteSession", "application/json", "{"); w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", w.Code)
	}
	w := post(h, "/api/rpc/DeleteSession", "application/json", "")
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "DeleteSession: boom") {
		t.Errorf("gateway failure: %d %q", w.Code, w.Body)
	}
	if w := post(h, "/api/rpc/SetSessionLabel", "application/json", strings.Repeat(" ", maxUnaryBody+1)); w.Code != http.StatusBadRequest {
		t.Errorf("oversized body: %d", w.Code)
	}
}

func get(h http.Handler, host, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	r.Host = host
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestCapturedBytesNeverKeepTheirType(t *testing.T) {
	v := &fakeViewer{stream: &fakeBodyStream{chunks: []string{"<script>", "x"}, err: io.EOF}}
	w := get(testServer(&fakeControl{}, v), "127.0.0.1:18890", "/api/body?session=s&id=f&response=1")
	if w.Code != 200 || w.Body.String() != "<script>x" {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("content type %q", ct)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("no nosniff")
	}
}

func TestBodyNotFoundIsAnAnswer(t *testing.T) {
	v := &fakeViewer{stream: &fakeBodyStream{err: status.Error(codes.NotFound, "no body")}}
	if w := get(testServer(&fakeControl{}, v), "localhost:18890", "/api/body"); w.Code != http.StatusNotFound {
		t.Errorf("%d", w.Code)
	}
}

func TestHostGuard(t *testing.T) {
	h := testServer(&fakeControl{}, &fakeViewer{})
	for _, host := range []string{"127.0.0.1:18890", "localhost:18890", "[::1]:18890", "127.0.0.1"} {
		if w := get(h, host, "/"); w.Code != 200 {
			t.Errorf("%s: %d", host, w.Code)
		}
	}
	for _, host := range []string{"evil.example:18890", "127.0.0.1.example.com"} {
		if w := get(h, host, "/"); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", host, w.Code)
		}
	}
}

func TestNoCORSHeaders(t *testing.T) {
	r := httptest.NewRequest("OPTIONS", "/api/rpc/SetSessionLabel", nil)
	r.Host = "127.0.0.1:18890"
	r.Header.Set("Origin", "http://evil.example")
	r.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	testServer(&fakeControl{}, &fakeViewer{}).ServeHTTP(w, r)
	for name := range w.Header() {
		if strings.HasPrefix(name, "Access-Control-") {
			t.Errorf("CORS header %s", name)
		}
	}
}

func TestSSEFraming(t *testing.T) {
	events := []proto.Message{&trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_FlowUnmatched{FlowUnmatched: "f1"}}}
	w := httptest.NewRecorder()
	serveSSE(w, func() (proto.Message, error) {
		if len(events) == 0 {
			return nil, status.Error(codes.Internal, "line one\nline two")
		}
		ev := events[0]
		events = nil
		return ev, nil
	})
	got := strings.ReplaceAll(w.Body.String(), ": ", ":")
	if !strings.Contains(got, `"flowUnmatched":"f1"`) {
		t.Errorf("event missing: %q", got)
	}
	if !strings.Contains(w.Body.String(), "line one line two") || !strings.HasSuffix(got, "event:end\ndata:{}\n\n") {
		t.Errorf("tail: %q", got)
	}
}

func TestStatic(t *testing.T) {
	files := fstest.MapFS{"index.html": {Data: []byte("spa")}, "assets/a.js": {Data: []byte("js")}}
	h := staticHandler(files)
	for path, want := range map[string]string{"/": "spa", "/assets/a.js": "js", "/no/such/page": "spa"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Body.String() != want {
			t.Errorf("%s = %q", path, w.Body)
		}
	}
	w := httptest.NewRecorder()
	staticHandler(fstest.MapFS{}).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(w.Body.String(), "was not built") {
		t.Errorf("stub: %q", w.Body)
	}
}
