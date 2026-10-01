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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/logging"
)

// readyPrefix mirrors capture_sdk.source.READY_PREFIX: the line a source prints on stdout
// once its server is bound, carrying the address to dial.
const readyPrefix = "traffic-deck source ready "

// Spec is how the manager reaches a source. A built-in is spawned: Argv is its `serve`
// command, to which the manager appends --gateway/--control and injects GATEWAY_ADDR. A
// third-party module is already running (its manifest launched it), so Addr is set and the
// manager dials it directly instead of spawning.
type Spec struct {
	Argv     []string
	Addr     string // dial-only: a module's already-running CaptureSourceService
	Module   string // owning module, whose processes are started before this source is dialed
	Label    string
	KeepWarm bool
	// External marks a dial-only source with nothing for the gateway to start: its module
	// declares no processes, so whatever serves Addr is the user's to run (ApplyManifests).
	// Such a source is offered only while it is actually listening — see Available.
	External bool
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
	proc   *exec.Cmd      // nil for an injected/pre-dialed conn (tests)
	log    io.WriteCloser // this source's own log sink; nil when not spawned by us
}

// Manager holds the source registry, the running sources, and which source owns each live
// session (so StopCapture can route by session id).
type Manager struct {
	gatewayAddr string
	spawn       func(ctx context.Context, name string, spec Spec) (*conn, error)
	startModule func(module string) error // start a module's processes before its source is dialed

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
	{name: "firefox", label: "Firefox", keepWarm: false},
	{name: "android", label: "Android", keepWarm: true},
	{name: "mitmproxy", label: "mitmproxy", keepWarm: false},
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

// SetModuleStarter wires the callback the manager uses to bring a module's processes up
// before its capture source is dialed (see ApplyManifests / Services.StartModule). Left
// unset for built-in sources, which have no module processes.
func (m *Manager) SetModuleStarter(fn func(module string) error) { m.startModule = fn }

// Sources lists the registered source names and whether each keeps a warm resource. This
// is the whole registry, including sources that cannot run right now — the log catalogue
// wants them, so a source that was never reachable still has a log to read.
//
// Sorted by the label a viewer shows, because the registry is a map and iterating it handed
// the picker a different order on every open — unusable for something a user builds muscle
// memory on. Case-insensitive, so "mitmproxy" sits among the capitalised ones rather than
// after them, and the name breaks ties so the order is total.
func (m *Manager) Sources() []SourceInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SourceInfo, 0, len(m.specs))
	for name, spec := range m.specs {
		out = append(out, SourceInfo{Name: name, Label: spec.Label, KeepWarm: spec.KeepWarm})
	}
	slices.SortFunc(out, func(a, b SourceInfo) int {
		if c := strings.Compare(strings.ToLower(orName(a)), strings.ToLower(orName(b))); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

// orName is what the viewer actually displays: the label, or the name when there is none.
func orName(s SourceInfo) string {
	if s.Label == "" {
		return s.Name
	}
	return s.Label
}

// Available is Sources minus the externally-started ones that are not listening — the list
// to offer a viewer.
//
// Everything else is offered unconditionally, because the gateway can bring it up: a
// built-in is spawned on demand, and a module with processes has them started before its
// source is dialed. An external source is the one case where "registered" and "usable" come
// apart, and offering it anyway is what made every viewer sit on "starting …" for two
// minutes before failing.
//
// The probe is a TCP connect, not an RPC: the question is whether the user's daemon is
// running at all, and a dial answers it in a millisecond on loopback without waking the
// source up. It races, of course — the daemon can stop between this and the capture — so
// the start path still has to fail cleanly, and does.
func (m *Manager) Available(ctx context.Context) []SourceInfo {
	m.mu.Lock()
	ext := map[string]string{}
	for name, spec := range m.specs {
		if spec.External && spec.Addr != "" {
			ext[name] = spec.Addr
		}
	}
	m.mu.Unlock()

	all := m.Sources()
	if len(ext) == 0 {
		return all
	}
	var mu sync.Mutex
	live := map[string]bool{}
	var wg sync.WaitGroup
	for name, addr := range ext {
		wg.Go(func() {
			if !listening(ctx, addr) {
				return
			}
			mu.Lock()
			live[name] = true
			mu.Unlock()
		})
	}
	wg.Wait()

	out := make([]SourceInfo, 0, len(all))
	for _, s := range all {
		if _, isExt := ext[s.Name]; isExt && !live[s.Name] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// probeTimeout bounds one availability probe. A loopback connect either succeeds at once or
// is refused at once; this only covers a listener that accepted the SYN and then stalled.
const probeTimeout = 500 * time.Millisecond

func listening(ctx context.Context, addr string) bool {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
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
	// Bring the module's processes up first: the adapter that serves spec.Addr is one of
	// them, so it must be running before we dial. Idempotent, so racing callers are fine.
	if spec.Module != "" && m.startModule != nil {
		if err := m.startModule(spec.Module); err != nil {
			return nil, fmt.Errorf("start module %q for source %q: %w", spec.Module, name, err)
		}
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

// sourceShutdownGrace bounds how long conn.close waits for a signalled source to exit on
// its own. A source's SIGTERM handler stops each live capture — which closes that session
// on the still-running Ingest server — before it exits, so the gateway must let that finish
// before it tears Ingest down (otherwise the close races GracefulStop and the session is
// stranded open). Larger than a source's own stop timeout so a normal teardown never hits
// it; escalates to SIGKILL past it so a wedged source can't hang the gateway's shutdown.
const sourceShutdownGrace = 30 * time.Second

// Close reaps every running source (whole process group) and drops the connections. Sources
// are closed concurrently so the total wait is one grace period, not one per source.
func (m *Manager) Close() {
	m.mu.Lock()
	conns := m.conns
	m.conns = map[string]*conn{}
	m.mu.Unlock()
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func(c *conn) { defer wg.Done(); c.close() }(c)
	}
	wg.Wait()
}

func (c *conn) close() { c.closeWithGrace(sourceShutdownGrace) }

func (c *conn) closeWithGrace(grace time.Duration) {
	if c.cc != nil {
		_ = c.cc.Close()
	}
	if c.proc != nil && c.proc.Process != nil {
		// Kill the whole group so the source's own children (dumpcap, a browser, an
		// emulator) go too — a plain kill of the parent would strand them. Then wait for the
		// source to finish its graceful shutdown (it closes its open sessions on the still-up
		// Ingest server before exiting); SIGKILL the group if it overruns the grace, so a
		// wedged source can't block teardown.
		_ = syscall.Kill(-c.proc.Process.Pid, syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = c.proc.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(grace):
			_ = syscall.Kill(-c.proc.Process.Pid, syscall.SIGKILL)
			<-done
		}
	}
	if c.log != nil { // flush its last partial line and release the file
		_ = c.log.Close()
	}
}

// realSpawn reaches a source. A module (Addr set) is already running — just dial it. A
// built-in is launched: run its `serve` command, read the ready line for its address, and
// dial that. The process gets its own group (Setpgid) so Close can group-kill it.
func (m *Manager) realSpawn(ctx context.Context, name string, spec Spec) (*conn, error) {
	if spec.Addr != "" {
		cc, err := grpc.NewClient(spec.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, err
		}
		// The module's adapter serves this address and may have just been launched (its
		// processes now start lazily), so wait for it to accept connections before handing
		// back a client — otherwise the first Describe would race the adapter's bind.
		//
		// An external source had nothing launched for it, so there is nothing to wait for:
		// either the user's daemon is listening or it is not, and waiting two minutes to say
		// so is what made a viewer look hung rather than wrong.
		timeout := moduleReadyTimeout
		if spec.External {
			timeout = externalReadyTimeout
		}
		if err := waitReady(ctx, cc, timeout); err != nil {
			_ = cc.Close()
			if spec.External {
				return nil, fmt.Errorf("nothing is serving source %q at %s — it is started by "+
					"you, not by the gateway (it needs privileges the gateway cannot ask for); "+
					"start it and try again", name, spec.Addr)
			}
			return nil, fmt.Errorf("source %q at %s: %w", name, spec.Addr, err)
		}
		return &conn{client: trafficv1.NewCaptureSourceServiceClient(cc), cc: cc}, nil
	}
	if len(spec.Argv) == 0 {
		return nil, fmt.Errorf("source %q has no command", name)
	}
	argv := append([]string{}, spec.Argv...)
	argv = append(argv, "--gateway", m.gatewayAddr, "--control", "127.0.0.1:0")
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "GATEWAY_ADDR="+m.gatewayAddr)
	// Setsid: a new session with no controlling terminal, so a source (or a grandchild it
	// spawns — dumpcap, a browser) can't write to the TUI's /dev/tty behind our redirect.
	// pgid still equals the leader's pid, so the group-kill in conn.close reaps it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	srcLog := logging.ChildLog(name)
	cmd.Stderr = srcLog
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = srcLog.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = srcLog.Close()
		return nil, err
	}

	addr, err := readReady(stdout, readyTimeout)
	if err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		_ = srcLog.Close()
		return nil, err
	}
	// Keep draining stdout so the child never blocks on a full pipe; into its own log
	// alongside its stderr, so one source reads as one stream.
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			_, _ = srcLog.Write(append([]byte(sc.Text()), '\n'))
		}
	}()

	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		return nil, err
	}
	if p := logging.ChildLogPath(name); p != "" {
		log.Printf("source %s: logging to %s", name, p)
	}
	return &conn{client: trafficv1.NewCaptureSourceServiceClient(cc), cc: cc, proc: cmd, log: srcLog}, nil
}

// readyTimeout bounds how long we wait for a freshly spawned source (or a module's dialed
// adapter) to come up. It has to cover a cold start: the built-in sources launch via
// `uv run`, which on a cold cache resolves and builds the project environment (grpcio, and
// frida for android) before the tool even executes — tens of seconds, well past the old 20s.
// The child dying still fails fast (readReady sees the closed stream; the dial sees the
// connection refused), so this only bounds a genuinely hung-but-alive start.
const readyTimeout = 120 * time.Second

// moduleReadyTimeout is readyTimeout for a module's dial-only adapter, whose process the
// gateway just launched (npm/uv, also cold-slow) and now waits to bind.
const moduleReadyTimeout = readyTimeout

// externalReadyTimeout is the same wait for a source the gateway did not launch. Nothing is
// starting up, so this covers only the handshake with a listener already accepting — long
// enough that a loaded machine is not called unavailable, short enough that a viewer gets
// an answer rather than a spinner.
const externalReadyTimeout = 3 * time.Second

// waitReady blocks until the channel reaches Ready, or the timeout / ctx expires. Used on a
// module's dial-only connection, whose adapter may still be binding after a lazy start.
func waitReady(ctx context.Context, cc *grpc.ClientConn, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cc.Connect()
	for {
		switch s := cc.GetState(); s {
		case connectivity.Ready:
			return nil
		default:
			if !cc.WaitForStateChange(ctx, s) { // deadline or ctx cancelled
				return fmt.Errorf("not ready: %w", context.Cause(ctx))
			}
		}
	}
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
