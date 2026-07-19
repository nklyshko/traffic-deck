package sourcemgr

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/config"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/logging"
)

// TestRealSpawnChromeDescribe exercises the whole env-free path against the actual chrome
// tool: DefaultSpecs discovers it, realSpawn spawns its `serve`, reads the ready line,
// dials, Describes. Describe needs no browser, so it's safe headless. Skipped only where
// the tool can't be discovered (no repo layout + no console script).
func TestRealSpawnChromeDescribe(t *testing.T) {
	specs := DefaultSpecs()
	if _, ok := specs["chrome"]; !ok {
		t.Skip("chrome tool not discoverable in this environment")
	}
	m := New("127.0.0.1:8080", specs)
	t.Cleanup(m.Close)
	d, err := m.Describe(context.Background(), "chrome", nil)
	if err != nil {
		t.Fatalf("describe via real spawn: %v", err)
	}
	if len(d.GetParams()) == 0 || d.GetParams()[0].GetKey() != "chrome" {
		t.Fatalf("descriptor lacks a chrome param: %+v", d.GetParams())
	}
}

// A spawned source's output goes to its own file, so one tool can be read on its own
// rather than picked out of an interleaved stream. Real spawn, as the file only appears
// once a child actually writes.
func TestRealSpawnWritesPerSourceLog(t *testing.T) {
	specs := DefaultSpecs()
	if _, ok := specs["chrome"]; !ok {
		t.Skip("chrome tool not discoverable in this environment")
	}
	dir := t.TempDir()
	logging.SetupFused(config.Config{LogFile: filepath.Join(dir, "gateway.log"), LogMaxSizeMB: 1})
	t.Cleanup(func() { logging.Setup(config.Config{LogFile: "off"}) })

	m := New("127.0.0.1:8080", specs)
	if _, err := m.Describe(context.Background(), "chrome", nil); err != nil {
		t.Fatalf("describe via real spawn: %v", err)
	}
	m.Close() // flushes and closes the source's log

	if want := filepath.Join(dir, "chrome.log"); want != logging.ChildLogPath("chrome") {
		t.Errorf("ChildLogPath = %q, want %q", logging.ChildLogPath("chrome"), want)
	}
	b, err := os.ReadFile(filepath.Join(dir, "chrome.log"))
	if err != nil {
		t.Fatalf("no per-source log for chrome: %v", err)
	}
	if len(b) == 0 {
		t.Error("chrome.log is empty")
	}
}

func TestFindCaptureDirWalksUp(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "capture", "capture_chrome"), 0o755); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := findCaptureDirFrom([]string{deep}); got != filepath.Join(root, "capture") {
		t.Errorf("findCaptureDirFrom = %q, want %q", got, filepath.Join(root, "capture"))
	}
	if got := findCaptureDirFrom([]string{t.TempDir()}); got != "" {
		t.Errorf("no capture dir should yield \"\", got %q", got)
	}
}

func TestResolveLauncherPrefersEnvThenRepo(t *testing.T) {
	// Explicit override wins.
	t.Setenv("TRAFFICDECK_SOURCE_CHROME", "my launcher here")
	if got := resolveLauncher("chrome", "/whatever"); !equal(got, []string{"my", "launcher", "here"}) {
		t.Errorf("env override = %v", got)
	}
	// Repo layout: a capture_<name> dir under capDir → a uv run launcher (uv is on PATH here).
	capDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(capDir, "capture_demo"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := resolveLauncher("demo", capDir)
	if len(got) < 4 || got[1] != "run" || got[len(got)-1] != "trafficdeck-capture-demo" {
		t.Errorf("repo launcher = %v, want a uv run … trafficdeck-capture-demo", got)
	}
	// Nothing found → nil.
	if got := resolveLauncher("nonesuch-xyz", ""); got != nil {
		t.Errorf("unknown tool should be nil, got %v", got)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// fakeSource is an in-process CaptureSourceService: canned Describe/StartCapture, records
// what it was asked to stop, so the manager's dispatch and routing can be checked.
type fakeSource struct {
	trafficv1.UnimplementedCaptureSourceServiceServer
	name    string
	mu      sync.Mutex
	n       int
	started []*trafficv1.StartCaptureRequest
	stopped []string
}

func (f *fakeSource) Describe(_ context.Context, _ *trafficv1.DescribeRequest) (*trafficv1.SourceDescriptor, error) {
	return &trafficv1.SourceDescriptor{Message: f.name}, nil
}

func (f *fakeSource) StartCapture(_ context.Context, req *trafficv1.StartCaptureRequest) (*trafficv1.StartCaptureResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	f.started = append(f.started, req)
	return &trafficv1.StartCaptureResponse{SessionId: fmt.Sprintf("%s-sess-%d", f.name, f.n)}, nil
}

func (f *fakeSource) StopCapture(_ context.Context, req *trafficv1.StopCaptureRequest) (*trafficv1.Empty, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = append(f.stopped, req.GetSessionId())
	return &trafficv1.Empty{}, nil
}

func serveFake(t *testing.T, f *fakeSource) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	trafficv1.RegisterCaptureSourceServiceServer(s, f)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return lis.Addr().String()
}

// managerWithFakes wires a manager whose spawn dials in-process fakes (no real processes),
// counting spawns so caching can be asserted.
func managerWithFakes(t *testing.T, names ...string) (*Manager, map[string]*fakeSource, map[string]*int) {
	specs := map[string]Spec{}
	fakes := map[string]*fakeSource{}
	addrs := map[string]string{}
	counts := map[string]*int{}
	for _, n := range names {
		specs[n] = Spec{}
		f := &fakeSource{name: n}
		fakes[n] = f
		addrs[n] = serveFake(t, f)
		c := 0
		counts[n] = &c
	}
	m := New("127.0.0.1:8080", specs)
	m.spawn = func(_ context.Context, name string, _ Spec) (*conn, error) {
		*counts[name]++
		cc, err := grpc.NewClient(addrs[name], grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, err
		}
		return &conn{client: trafficv1.NewCaptureSourceServiceClient(cc), cc: cc}, nil
	}
	return m, fakes, counts
}

func TestStartRoutesStopToTheOwningSource(t *testing.T) {
	m, fakes, _ := managerWithFakes(t, "chrome", "android")
	ctx := context.Background()

	csid, err := m.StartCapture(ctx, "chrome", "run", map[string]string{"k": "v"})
	if err != nil || csid != "chrome-sess-1" {
		t.Fatalf("chrome start: sid=%q err=%v", csid, err)
	}
	asid, err := m.StartCapture(ctx, "android", "run", nil)
	if err != nil || asid != "android-sess-1" {
		t.Fatalf("android start: sid=%q err=%v", asid, err)
	}
	// The chrome source saw the request, with its name filled in for dispatch.
	if got := fakes["chrome"].started[0].GetSource(); got != "chrome" {
		t.Errorf("start request source=%q, want chrome", got)
	}

	// Stopping chrome's session must reach chrome, not android.
	if err := m.StopCapture(ctx, csid); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if len(fakes["chrome"].stopped) != 1 || fakes["chrome"].stopped[0] != csid {
		t.Errorf("chrome stopped=%v, want [%s]", fakes["chrome"].stopped, csid)
	}
	if len(fakes["android"].stopped) != 0 {
		t.Errorf("android should not have been stopped, got %v", fakes["android"].stopped)
	}
}

func TestStopUnknownSessionErrors(t *testing.T) {
	m, _, _ := managerWithFakes(t, "chrome")
	if err := m.StopCapture(context.Background(), "ghost"); err == nil {
		t.Fatal("stopping an unknown session should error")
	}
}

func TestSourceSpawnedOncePerName(t *testing.T) {
	m, _, counts := managerWithFakes(t, "chrome")
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := m.StartCapture(ctx, "chrome", "run", nil); err != nil {
			t.Fatal(err)
		}
	}
	if *counts["chrome"] != 1 {
		t.Errorf("chrome spawned %d times, want 1 (reused across captures)", *counts["chrome"])
	}
}

func TestDescribeDispatches(t *testing.T) {
	m, _, _ := managerWithFakes(t, "chrome")
	d, err := m.Describe(context.Background(), "chrome", map[string]string{"x": "1"})
	if err != nil {
		t.Fatal(err)
	}
	if d.GetMessage() != "chrome" {
		t.Errorf("describe routed to %q, want chrome", d.GetMessage())
	}
}

func TestUnknownSourceErrors(t *testing.T) {
	m, _, _ := managerWithFakes(t, "chrome")
	if _, err := m.StartCapture(context.Background(), "nope", "run", nil); err == nil {
		t.Fatal("unknown source should error")
	}
}

func TestCloseDropsConnections(t *testing.T) {
	m, _, counts := managerWithFakes(t, "chrome")
	ctx := context.Background()
	if _, err := m.StartCapture(ctx, "chrome", "run", nil); err != nil {
		t.Fatal(err)
	}
	m.Close()
	// After Close the source is gone; the next use spawns afresh.
	if _, err := m.StartCapture(ctx, "chrome", "run", nil); err != nil {
		t.Fatal(err)
	}
	if *counts["chrome"] != 2 {
		t.Errorf("spawned %d times, want 2 (Close forces a respawn)", *counts["chrome"])
	}
}
