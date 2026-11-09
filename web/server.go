package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
)

const (
	maxUnaryBody = 1 << 20
	uploadChunk  = 1 << 20
)

// backend is the gateway as the bridge sees it; an interface each, so tests can stand in
// for the parts they exercise.
type backend struct {
	viewer  trafficv1.ViewerServiceClient
	control trafficv1.ControlServiceClient
	ingest  trafficv1.IngestServiceClient
}

type server struct {
	backend
	listenHost string
	wireshark  *wiresharkLauncher // nil: opening Wireshark is refused
}

func newServer(b backend, listenAddr string) *server {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		host = listenAddr
	}
	return &server{backend: b, listenHost: host}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/sessions", s.sessions)
	mux.HandleFunc("GET /api/flows", s.flows)
	mux.HandleFunc("GET /api/stream", s.streamFlows)
	mux.HandleFunc("GET /api/flow", s.flow)
	mux.HandleFunc("GET /api/body", s.body)
	mux.HandleFunc("GET /api/messages", s.messages)
	mux.HandleFunc("GET /api/messages/stream", s.streamMessages)
	mux.HandleFunc("GET /api/message", s.message)
	mux.HandleFunc("GET /api/message/body", s.messageBody)
	mux.HandleFunc("GET /api/log", s.log)
	mux.HandleFunc("GET /api/session/export", s.exportSession)
	mux.HandleFunc("POST /api/session/import", s.importSession)
	mux.HandleFunc("POST /api/wireshark", s.openInWireshark)
	for name, h := range s.rpcMethods() {
		mux.Handle("POST /api/rpc/"+name, h)
	}
	mux.HandleFunc("/api/", http.NotFound)
	mux.Handle("/", staticHandler(bundle()))
	return s.guardHost(mux)
}

// guardHost refuses a Host that isn't this server's. The same-origin policy keys on the
// name, so without this a site could rebind its own domain to 127.0.0.1 and read captured
// traffic as a same-origin page, past every other defence here.
func (s *server) guardHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			http.Error(w, "unexpected Host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) hostAllowed(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = strings.Trim(hostport, "[]")
	}
	if strings.EqualFold(host, "localhost") || host == s.listenHost {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// --- errors ---

// rpcError maps a gateway failure. NotFound is an ordinary answer (a flow with no stored
// body); 502 keeps "the gateway failed" distinct from a bad request.
func rpcError(w http.ResponseWriter, what string, err error) {
	if status.Code(err) == codes.NotFound {
		http.Error(w, status.Convert(err).Message(), http.StatusNotFound)
		return
	}
	msg := what + ": " + status.Convert(err).Message()
	log.Print(msg)
	http.Error(w, msg, http.StatusBadGateway)
}

// --- request parsing ---

var cursorRe = regexp.MustCompile(`^(-?\d*):(\d*)$`)

// parseCursor reads "<tsMicros>:<frameNumber>"; protojson omits a zero, so either half may
// be missing. "" means no cursor.
func parseCursor(s string) (*trafficv1.FlowCursor, error) {
	if s == "" {
		return nil, nil
	}
	m := cursorRe.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("bad cursor %q", s)
	}
	c := &trafficv1.FlowCursor{}
	var err error
	if m[1] != "" {
		if c.TsMicros, err = strconv.ParseInt(m[1], 10, 64); err != nil {
			return nil, fmt.Errorf("bad cursor %q", s)
		}
	}
	if m[2] != "" {
		if c.FrameNumber, err = strconv.ParseUint(m[2], 10, 64); err != nil {
			return nil, fmt.Errorf("bad cursor %q", s)
		}
	}
	return c, nil
}

func queryUint(r *http.Request, key string, fallback uint32) (uint32, error) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("bad %s %q", key, v)
	}
	return uint32(n), nil
}

func queryInt(r *http.Request, key string) (int64, error) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad %s %q", key, v)
	}
	return n, nil
}

// contentTypeIs is the CSRF defence: both accepted types are non-"simple", so a cross-origin
// page's request is preflighted and dies there because no CORS headers ever come back.
// Accepting text/plain or a form encoding would silently disable that.
func contentTypeIs(r *http.Request, want string) bool {
	got, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && got == want
}

// --- responses ---

func writeProto(w http.ResponseWriter, what string, msg proto.Message, err error) {
	if err != nil {
		rpcError(w, what, err)
		return
	}
	data, err := protojson.Marshal(msg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

var unsafeFilename = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func sanitizeFilename(id string) string {
	if s := unsafeFilename.ReplaceAllString(id, ""); s != "" {
		return s
	}
	return "session"
}

// streamBytes copies a chunked gRPC stream to the response. Headers wait for the first
// chunk, so a failure there can still be a proper status; after it, the headers are gone
// and a truncated download is the only possible signal.
func streamBytes(w http.ResponseWriter, what string, setHeaders func(http.Header), recv func() ([]byte, error)) {
	first, err := recv()
	if err != nil && !errors.Is(err, io.EOF) {
		rpcError(w, what, err)
		return
	}
	setHeaders(w.Header())
	w.WriteHeader(http.StatusOK)
	flusher := http.NewResponseController(w)
	for chunk := first; err == nil; chunk, err = recv() {
		if _, werr := w.Write(chunk); werr != nil {
			return
		}
		_ = flusher.Flush()
	}
}

// capturedBytes marks a response as data. Captured content is never served under its own
// content type, or a captured HTML page would run on this origin with the API in reach.
func capturedBytes(h http.Header) {
	h.Set("Content-Type", "application/octet-stream")
	h.Set("X-Content-Type-Options", "nosniff")
}

// --- control path ---

// unary adapts one gRPC method to POST + protojson. The Content-Type gate lives here so a
// method in the allow-list cannot forget it.
func unary[Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](name string, call func(context.Context, PReq, ...grpc.CallOption) (Resp, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !contentTypeIs(r, "application/json") {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxUnaryBody))
		if err != nil {
			http.Error(w, "unreadable body: "+err.Error(), http.StatusBadRequest)
			return
		}
		req := PReq(new(Req))
		if len(data) > 0 {
			if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, req); err != nil {
				http.Error(w, "unreadable JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		resp, err := call(r.Context(), req)
		writeProto(w, name, resp, err)
	})
}

// rpcMethods is the allow-list: a method not named here is unreachable from a browser.
func (s *server) rpcMethods() map[string]http.Handler {
	c := s.control
	return map[string]http.Handler{
		"ListCaptureSources":    unary("ListCaptureSources", c.ListCaptureSources),
		"DescribeCaptureSource": unary("DescribeCaptureSource", c.DescribeCaptureSource),
		"StartCapture":          unary("StartCapture", c.StartCapture),
		"StopCapture":           unary("StopCapture", c.StopCapture),
		"ForceCloseSession":     unary("ForceCloseSession", s.ingest.ForceCloseSession),

		"ListTags":       unary("ListTags", c.ListTags),
		"CreateTag":      unary("CreateTag", c.CreateTag),
		"DeleteTag":      unary("DeleteTag", c.DeleteTag),
		"SetTags":        unary("SetTags", c.SetTags),
		"ToggleFavorite": unary("ToggleFavorite", c.ToggleFavorite),
		"SetMark":        unary("SetMark", c.SetMark),
		"ClearMark":      unary("ClearMark", c.ClearMark),
		"AddComment":     unary("AddComment", c.AddComment),
		"EditComment":    unary("EditComment", c.EditComment),
		"DeleteComment":  unary("DeleteComment", c.DeleteComment),
		"ListGroups":     unary("ListGroups", c.ListGroups),
		"CreateGroup":    unary("CreateGroup", c.CreateGroup),
		"UpdateGroup":    unary("UpdateGroup", c.UpdateGroup),
		"DeleteGroup":    unary("DeleteGroup", c.DeleteGroup),
		"SetGroups":      unary("SetGroups", c.SetGroups),

		"SetSessionLabel":     unary("SetSessionLabel", c.SetSessionLabel),
		"SetSessionGroup":     unary("SetSessionGroup", c.SetSessionGroup),
		"DeleteSession":       unary("DeleteSession", c.DeleteSession),
		"ImportCapture":       unary("ImportCapture", c.ImportCapture),
		"GetSessionArtifacts": unary("GetSessionArtifacts", c.GetSessionArtifacts),

		"CheckUpdates": unary("CheckUpdates", c.CheckUpdates),

		"ListServices": unary("ListServices", c.ListServices),
		"StartService": unary("StartService", c.StartService),
		"StopService":  unary("StopService", c.StopService),
		"ListLogs":     unary("ListLogs", c.ListLogs),
	}
}
