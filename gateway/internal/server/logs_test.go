package server

import (
	"context"
	"log"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/metadata"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/config"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/logging"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/sourcemgr"
)

// fakeLogStream is a minimal grpc.ServerStreamingServer[LogChunk] that accumulates the
// payloads GetLog sends.
type fakeLogStream struct {
	ctx  context.Context
	data []byte
}

func (f *fakeLogStream) Send(c *trafficv1.LogChunk) error {
	f.data = append(f.data, c.GetPayload()...)
	return nil
}
func (f *fakeLogStream) Context() context.Context     { return f.ctx }
func (f *fakeLogStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeLogStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeLogStream) SetTrailer(metadata.MD)       {}
func (f *fakeLogStream) SendMsg(any) error            { return nil }
func (f *fakeLogStream) RecvMsg(any) error            { return nil }

// TestListAndGetLog covers the log RPCs end to end: a child writes to its own file, the
// gateway writes to its own, ListLogs reports both, and GetLog streams a log's tail back.
func TestListAndGetLog(t *testing.T) {
	dir := t.TempDir()
	logging.SetupFused(config.Config{LogFile: filepath.Join(dir, "gateway.log"), LogMaxSizeMB: 1})
	t.Cleanup(func() { logging.Setup(config.Config{LogFile: "off"}) })

	log.Print("gateway is up") // → the gateway's own log
	child := logging.ChildLog("chrome")
	_, _ = child.Write([]byte("[chrome] capturing\n"))
	_ = child.Close()

	// A manager that knows a "chrome" source, so the catalog can label and locate its log.
	mgr := sourcemgr.New("127.0.0.1:0", map[string]sourcemgr.Spec{"chrome": {Label: "Chrome"}})
	c := NewControl(nil, nil, dir, "", mgr, sourcemgr.NewServices("127.0.0.1:0", nil))

	list, err := c.ListLogs(context.Background(), &trafficv1.Empty{})
	if err != nil {
		t.Fatalf("list logs: %v", err)
	}
	got := map[string]*trafficv1.LogInfo{}
	for _, l := range list.GetLogs() {
		got[l.GetName()] = l
	}
	if got["gateway"] == nil || got["chrome"] == nil {
		t.Fatalf("want gateway + chrome logs, got %v", got)
	}
	if got["chrome"].GetLabel() != "Chrome" || got["chrome"].GetSizeBytes() == 0 {
		t.Errorf("chrome log info = %+v, want label Chrome and a non-zero size", got["chrome"])
	}

	stream := &fakeLogStream{ctx: context.Background()}
	if err := c.GetLog(&trafficv1.GetLogRequest{Name: "chrome"}, stream); err != nil {
		t.Fatalf("get log: %v", err)
	}
	if s := string(stream.data); !contains(s, "[chrome] capturing") {
		t.Errorf("chrome log tail = %q, want it to contain the written line", s)
	}

	// A log the catalog doesn't list is NotFound (and never a path the client can name).
	if err := c.GetLog(&trafficv1.GetLogRequest{Name: "../etc/passwd"}, stream); err == nil {
		t.Error("GetLog for an uncatalogued name should error")
	}
}

// TestModuleProcessLogIsListed confirms a third-party module's processes are covered: they
// register as services keyed "module:<mod>:<NN>-<proc>" (ApplyManifests), so their per-child
// files show up in ListLogs under that name and GetLog streams them like any other.
func TestModuleProcessLogIsListed(t *testing.T) {
	dir := t.TempDir()
	logging.SetupFused(config.Config{LogFile: filepath.Join(dir, "gateway.log"), LogMaxSizeMB: 1})
	t.Cleanup(func() { logging.Setup(config.Config{LogFile: "off"}) })

	const key = "module:acme:00-adapter"
	child := logging.ChildLog(key) // written under the same name the service is spawned with
	_, _ = child.Write([]byte("[" + key + "] adapter listening\n"))
	_ = child.Close()

	// The service registry as ApplyManifests builds it for a module process.
	svcs := sourcemgr.NewServices("127.0.0.1:0", map[string]sourcemgr.ServiceSpec{
		key: {Module: "acme", Label: "acme / adapter"},
	})
	c := NewControl(nil, nil, dir, "", sourcemgr.New("127.0.0.1:0", nil), svcs)

	list, err := c.ListLogs(context.Background(), &trafficv1.Empty{})
	if err != nil {
		t.Fatalf("list logs: %v", err)
	}
	var info *trafficv1.LogInfo
	for _, l := range list.GetLogs() {
		if l.GetName() == key {
			info = l
		}
	}
	if info == nil {
		t.Fatalf("module process log %q not listed: %+v", key, list.GetLogs())
	}
	if info.GetLabel() != "acme / adapter" {
		t.Errorf("label = %q, want %q", info.GetLabel(), "acme / adapter")
	}

	stream := &fakeLogStream{ctx: context.Background()}
	if err := c.GetLog(&trafficv1.GetLogRequest{Name: key}, stream); err != nil {
		t.Fatalf("get log: %v", err)
	}
	if !contains(string(stream.data), "adapter listening") {
		t.Errorf("module log tail = %q, want the written line", stream.data)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
