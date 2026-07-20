package sourcemgr

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/logging"
)

// Auxiliary services are gateway-owned processes that are not capture sources — the MCP
// server, a module's web UI. The gateway spawns/reaps them (group-kill, GATEWAY_ADDR
// injected) but never dials them: they're opaque, with only start/stop/status. A viewer
// toggles them; because the gateway owns them they outlive the viewer. See ADR-0010.

// ServiceSpec is how to launch an auxiliary service, plus what to tell the viewer about it.
type ServiceSpec struct {
	Argv      []string
	Cwd       string            // working dir (a module process runs in its own dir)
	Env       map[string]string // extra env (a module declares e.g. VITE_ADAPTER_URL)
	Label     string
	URL       string // where it's reachable when up
	Detail    string // note for the viewer (e.g. exposure warning)
	AutoStart bool   // start at gateway launch vs toggled (MCP) or module-gated
	Module    string // owning module: started with its capture source, not at launch ("" = neither)
}

// ServiceInfo is a service's state for the viewer-facing list.
type ServiceInfo struct {
	Name    string
	Label   string
	Running bool
	URL     string
	Detail  string
}

// Services manages the auxiliary-service registry and the running processes.
type Services struct {
	gatewayAddr string
	spawn       func(name string, spec ServiceSpec) (*exec.Cmd, error)

	mu      sync.Mutex
	specs   map[string]ServiceSpec
	running map[string]*exec.Cmd
	logs    map[string]io.WriteCloser // per-service log sink, closed when it exits
}

// NewServices returns a manager over the given registry. gatewayAddr is injected as
// GATEWAY_ADDR so a service (MCP) connects back to the gateway.
func NewServices(gatewayAddr string, specs map[string]ServiceSpec) *Services {
	s := &Services{
		gatewayAddr: gatewayAddr,
		specs:       specs,
		running:     map[string]*exec.Cmd{},
		logs:        map[string]io.WriteCloser{},
	}
	s.spawn = s.realSpawn
	return s
}

// DefaultServices builds the built-in auxiliary registry — the MCP server — located the
// same way the capture tools are (the repo's mcp/ dir), env-overridable, else the installed
// console entry. An unlocatable service is omitted.
func DefaultServices() map[string]ServiceSpec {
	specs := map[string]ServiceSpec{}
	if argv := resolveMCP(); argv != nil {
		specs["mcp"] = ServiceSpec{
			Argv:   argv,
			Label:  "MCP server",
			URL:    mcpURL(),
			Detail: "serves recorded sessions to MCP/agent clients (loopback, read-only by default)",
		}
	}
	return specs
}

func resolveMCP() []string {
	if env := os.Getenv("TRAFFICDECK_SERVICE_MCP"); env != "" {
		return strings.Fields(env)
	}
	if capDir := findCaptureDir(); capDir != "" {
		mcpDir := filepath.Join(filepath.Dir(capDir), "mcp")
		if fi, err := os.Stat(filepath.Join(mcpDir, "traffic_mcp")); err == nil && fi.IsDir() {
			if uv, err := exec.LookPath("uv"); err == nil {
				return []string{uv, "run", "--directory", mcpDir, "python", "-m", "traffic_mcp.server"}
			}
		}
	}
	if p, err := exec.LookPath("trafficdeck-mcp"); err == nil {
		return []string{p}
	}
	return nil
}

func mcpURL() string {
	host := os.Getenv("MCP_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	port := os.Getenv("MCP_PORT")
	if port == "" {
		port = "8765"
	}
	return "http://" + host + ":" + port + "/mcp"
}

// List reports every registered service and whether it's currently running.
func (s *Services) List() []ServiceInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ServiceInfo, 0, len(s.specs))
	for name, spec := range s.specs {
		out = append(out, s.infoLocked(name, spec))
	}
	return out
}

func (s *Services) infoLocked(name string, spec ServiceSpec) ServiceInfo {
	return ServiceInfo{
		Name: name, Label: spec.Label, URL: spec.URL, Detail: spec.Detail,
		Running: s.running[name] != nil,
	}
}

// Start launches a service if it isn't already running, returning its state.
func (s *Services) Start(name string) (ServiceInfo, error) {
	s.mu.Lock()
	spec, ok := s.specs[name]
	if !ok {
		s.mu.Unlock()
		return ServiceInfo{}, &notFoundError{name}
	}
	if s.running[name] != nil {
		info := s.infoLocked(name, spec)
		s.mu.Unlock()
		return info, nil
	}
	s.mu.Unlock()

	cmd, err := s.spawn(name, spec)
	if err != nil {
		return ServiceInfo{}, err
	}
	s.mu.Lock()
	s.running[name] = cmd
	info := s.infoLocked(name, spec)
	s.mu.Unlock()

	go func() { // drop it from the running set when it exits on its own
		_ = cmd.Wait()
		s.mu.Lock()
		if s.running[name] == cmd {
			delete(s.running, name)
		}
		out := s.logs[name]
		delete(s.logs, name)
		s.mu.Unlock()
		if out != nil { // flush its last partial line and release the file
			_ = out.Close()
		}
	}()
	return info, nil
}

// Stop group-kills a running service; a no-op if it isn't running.
func (s *Services) Stop(name string) error {
	s.mu.Lock()
	cmd := s.running[name]
	delete(s.running, name)
	s.mu.Unlock()
	if cmd != nil {
		killGroup(cmd)
	}
	return nil
}

// Close reaps every running service (whole process group).
func (s *Services) Close() {
	s.mu.Lock()
	running := s.running
	s.running = map[string]*exec.Cmd{}
	s.mu.Unlock()
	for _, cmd := range running {
		killGroup(cmd)
	}
}

func (s *Services) realSpawn(name string, spec ServiceSpec) (*exec.Cmd, error) {
	cmd := exec.Command(spec.Argv[0], spec.Argv[1:]...)
	cmd.Dir = spec.Cwd
	cmd.Env = append(os.Environ(), "GATEWAY_ADDR="+s.gatewayAddr)
	for k, v := range spec.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	// Setsid, not just Setpgid: a new session with no controlling terminal. We already
	// redirect stdout/stderr to the child's log, but under one-command mode the terminal is
	// the TUI's, and a child (or a grandchild) that writes straight to /dev/tty would scribble
	// over the viewer regardless. No controlling terminal means /dev/tty can't be opened.
	// The session leader's pid is still the process-group id, so killGroup(-pid) reaps it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out := logging.ChildLog(name)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		_ = out.Close()
		return nil, err
	}
	s.mu.Lock()
	s.logs[name] = out
	s.mu.Unlock()
	if p := logging.ChildLogPath(name); p != "" {
		log.Printf("service %q started: %s (log: %s)", name, spec.URL, p)
	} else {
		log.Printf("service %q started: %s", name, spec.URL)
	}
	return cmd, nil
}

// StartAuto launches every service marked AutoStart, in registry order — called once at
// gateway launch. A module's processes are no longer auto-started unless the module has no
// capture source (module-gated processes come up on first use; see StartModule).
func (s *Services) StartAuto() {
	s.mu.Lock()
	names := make([]string, 0, len(s.specs))
	for name, spec := range s.specs {
		if spec.AutoStart {
			names = append(names, name)
		}
	}
	s.mu.Unlock()
	sort.Strings(names) // module:<name>:<NN>-<proc> keys sort into declared order
	for _, name := range names {
		if _, err := s.Start(name); err != nil {
			log.Printf("auto-start service %q: %v", name, err)
		}
	}
}

// StartModule launches every process belonging to a module (its adapter, its web UI), in
// registry order — called by the source manager the first time the module's capture source
// is requested, so a module's processes come up only when its capture type is used. Already
// running processes are left as-is (Start is idempotent), and it's a no-op for a module with
// no processes. The first process that fails to start aborts and is returned.
func (s *Services) StartModule(module string) error {
	if module == "" {
		return nil
	}
	s.mu.Lock()
	var names []string
	for name, spec := range s.specs {
		if spec.Module == module {
			names = append(names, name)
		}
	}
	s.mu.Unlock()
	sort.Strings(names) // module:<name>:<NN>-<proc> keys sort into declared order
	for _, name := range names {
		if _, err := s.Start(name); err != nil {
			return fmt.Errorf("start %s: %w", name, err)
		}
	}
	return nil
}

func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
}

type notFoundError struct{ name string }

func (e *notFoundError) Error() string { return "unknown service " + e.name }
