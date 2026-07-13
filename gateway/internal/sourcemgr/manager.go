// Package sourcemgr supervises capture-source processes on behalf of viewers. Each source
// (a built-in like chrome, or a third-party module) is a CaptureSourceService server; the
// manager spawns one on demand, dials it, dispatches Describe/StartCapture/StopCapture to
// it, and owns its lifecycle — reaping the whole process group on shutdown. See ADR-0010.
package sourcemgr

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
)

// readyPrefix mirrors capture_sdk.source.READY_PREFIX: the line a source prints on stdout
// once its server is bound, carrying the address to dial.
const readyPrefix = "traffic-deck source ready "

// Spec is how to launch a source: the argv of its `serve` command. The manager appends
// --gateway and --control and injects GATEWAY_ADDR.
type Spec struct {
	Argv     []string
	Label    string
	KeepWarm bool
}

// SourceInfo names a registered source for the viewer-facing list.
type SourceInfo struct {
	Name     string
	Label    string
	KeepWarm bool
}

// conn is one running source: its dialed client, and (for a spawned one) the process to reap.
type conn struct {
	client trafficv1.CaptureSourceServiceClient
	cc     *grpc.ClientConn
	proc   *exec.Cmd // nil for an injected/pre-dialed conn (tests)
}

// Manager holds the source registry, the running sources, and which source owns each live
// session (so StopCapture can route by session id).
type Manager struct {
	gatewayAddr string
	spawn       func(ctx context.Context, name string, spec Spec) (*conn, error)

	mu      sync.Mutex
	specs   map[string]Spec
	conns   map[string]*conn
	session map[string]string // session id -> source name
}

// builtinSources are the sources the gateway registers by default, no configuration
// needed. A source appears here once it has a `serve` mode; android (keep_warm, for its
// emulator) and mitmproxy join as those land.
var builtinSources = []struct {
	name     string
	label    string
	keepWarm bool
}{
	{name: "chrome", label: "Chrome", keepWarm: false},
}

// DefaultSpecs builds the built-in source registry by locating each tool itself — no env
// vars required. For each built-in it resolves a launcher (see resolveLauncher) and, if the
// tool is found, registers it. A tool that can't be located is logged and simply omitted,
// so capture control lists what actually works.
func DefaultSpecs() map[string]Spec {
	capDir := findCaptureDir()
	specs := map[string]Spec{}
	for _, b := range builtinSources {
		argv := resolveLauncher(b.name, capDir)
		if argv == nil {
			log.Printf("capture source %q: tool not found — set TRAFFICDECK_SOURCE_%s to enable",
				b.name, strings.ToUpper(b.name))
			continue
		}
		specs[b.name] = Spec{Argv: append(argv, "serve"), Label: b.label, KeepWarm: b.keepWarm}
		log.Printf("capture source %q: %s", b.name, strings.Join(argv, " "))
	}
	return specs
}

// resolveLauncher finds how to launch a built-in tool, most-specific first: an explicit
// TRAFFICDECK_SOURCE_<NAME> override; else the dev repo (uv run against capture/capture_<name>);
// else an installed console script on PATH. Returns nil when none is found.
func resolveLauncher(name, capDir string) []string {
	if env := os.Getenv("TRAFFICDECK_SOURCE_" + strings.ToUpper(name)); env != "" {
		return strings.Fields(env)
	}
	if capDir != "" {
		proj := filepath.Join(capDir, "capture_"+name)
		if fi, err := os.Stat(proj); err == nil && fi.IsDir() {
			if uv, err := exec.LookPath("uv"); err == nil {
				return []string{uv, "run", "--project", proj, "trafficdeck-capture-" + name}
			}
		}
	}
	if p, err := exec.LookPath("trafficdeck-capture-" + name); err == nil {
		return []string{p}
	}
	return nil
}

// findCaptureDir locates the repo's capture/ directory (holding capture_chrome, …) by
// walking up from the working directory, then from the executable's directory. Returns ""
// if not found — the installed-console-script path then applies.
func findCaptureDir() string {
	var starts []string
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	if exe, err := os.Executable(); err == nil {
		starts = append(starts, filepath.Dir(exe))
	}
	return findCaptureDirFrom(starts)
}

func findCaptureDirFrom(starts []string) string {
	for _, start := range starts {
		for dir := start; ; {
			cand := filepath.Join(dir, "capture", "capture_chrome")
			if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
				return filepath.Join(dir, "capture")
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break // reached the filesystem root
			}
			dir = parent
		}
	}
	return ""
}

// New returns a manager over the given registry. gatewayAddr is where spawned sources
// connect back for IngestService (OpenSession/UploadCapture).
func New(gatewayAddr string, specs map[string]Spec) *Manager {
	m := &Manager{
		gatewayAddr: gatewayAddr,
		specs:       specs,
		conns:       map[string]*conn{},
		session:     map[string]string{},
	}
	m.spawn = m.realSpawn
	return m
}

// Sources lists the registered source names and whether each keeps a warm resource.
func (m *Manager) Sources() []SourceInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SourceInfo, 0, len(m.specs))
	for name, spec := range m.specs {
		out = append(out, SourceInfo{Name: name, Label: spec.Label, KeepWarm: spec.KeepWarm})
	}
	return out
}

func (m *Manager) ensure(ctx context.Context, name string) (*conn, error) {
	m.mu.Lock()
	if c := m.conns[name]; c != nil {
		m.mu.Unlock()
		return c, nil
	}
	spec, ok := m.specs[name]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown capture source %q", name)
	}
	c, err := m.spawn(ctx, name, spec)
	if err != nil {
		return nil, fmt.Errorf("start source %q: %w", name, err)
	}
	m.mu.Lock()
	// Another caller may have raced us; keep theirs and drop ours.
	if existing := m.conns[name]; existing != nil {
		m.mu.Unlock()
		c.close()
		return existing, nil
	}
	m.conns[name] = c
	m.mu.Unlock()
	return c, nil
}

// Describe returns the source's current option form for the partial params so far.
func (m *Manager) Describe(ctx context.Context, name string, params map[string]string) (*trafficv1.SourceDescriptor, error) {
	c, err := m.ensure(ctx, name)
	if err != nil {
		return nil, err
	}
	return c.client.Describe(ctx, &trafficv1.DescribeRequest{Params: params})
}

// StartCapture asks the source to begin a capture and records which source owns the
// resulting session, so StopCapture can route to it later.
func (m *Manager) StartCapture(ctx context.Context, name, label string, params map[string]string) (string, error) {
	c, err := m.ensure(ctx, name)
	if err != nil {
		return "", err
	}
	resp, err := c.client.StartCapture(ctx, &trafficv1.StartCaptureRequest{
		Source: name, Label: label, Params: params})
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.session[resp.GetSessionId()] = name
	m.mu.Unlock()
	return resp.GetSessionId(), nil
}

// StopCapture ends a session by routing to the source that started it.
func (m *Manager) StopCapture(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	name := m.session[sessionID]
	m.mu.Unlock()
	if name == "" {
		return fmt.Errorf("no running capture for session %q", sessionID)
	}
	c, err := m.ensure(ctx, name)
	if err != nil {
		return err
	}
	_, err = c.client.StopCapture(ctx, &trafficv1.StopCaptureRequest{SessionId: sessionID})
	m.mu.Lock()
	delete(m.session, sessionID)
	m.mu.Unlock()
	return err
}

// Close reaps every running source (whole process group) and drops the connections.
func (m *Manager) Close() {
	m.mu.Lock()
	conns := m.conns
	m.conns = map[string]*conn{}
	m.mu.Unlock()
	for _, c := range conns {
		c.close()
	}
}

func (c *conn) close() {
	if c.cc != nil {
		_ = c.cc.Close()
	}
	if c.proc != nil && c.proc.Process != nil {
		// Kill the whole group so the source's own children (dumpcap, a browser, an
		// emulator) go too — a plain kill of the parent would strand them.
		_ = syscall.Kill(-c.proc.Process.Pid, syscall.SIGTERM)
	}
}

// realSpawn launches a source's `serve` command, reads the ready line for its address, and
// dials it. The process gets its own group (Setpgid) so Close can group-kill it.
func (m *Manager) realSpawn(ctx context.Context, name string, spec Spec) (*conn, error) {
	if len(spec.Argv) == 0 {
		return nil, fmt.Errorf("source %q has no command", name)
	}
	argv := append([]string{}, spec.Argv...)
	argv = append(argv, "--gateway", m.gatewayAddr, "--control", "127.0.0.1:0")
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "GATEWAY_ADDR="+m.gatewayAddr)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	addr, err := readReady(stdout, 20*time.Second)
	if err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		return nil, err
	}
	// Keep draining stdout so the child never blocks on a full pipe; tee to the log.
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			log.Printf("source %s: %s", name, sc.Text())
		}
	}()

	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		return nil, err
	}
	return &conn{client: trafficv1.NewCaptureSourceServiceClient(cc), cc: cc, proc: cmd}, nil
}

// readReady scans lines until the source prints its ready line, returning the address to
// dial. Fails if the stream ends (the source died) or the deadline passes.
func readReady(r io.Reader, timeout time.Duration) (string, error) {
	type res struct {
		addr string
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, readyPrefix) {
				ch <- res{addr: strings.TrimSpace(strings.TrimPrefix(line, readyPrefix))}
				return
			}
		}
		if err := sc.Err(); err != nil {
			ch <- res{err: err}
			return
		}
		ch <- res{err: fmt.Errorf("source exited before signalling ready")}
	}()
	select {
	case r := <-ch:
		return r.addr, r.err
	case <-time.After(timeout):
		return "", fmt.Errorf("source not ready within %s", timeout)
	}
}
