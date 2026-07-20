package sourcemgr

import (
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// servicesWithSleeps wires a Services whose spawn launches a real `sleep`, so Stop can
// group-kill it and status reflects a live process — without needing the real MCP server.
func servicesWithSleeps(t *testing.T, seconds string) *Services {
	svcs := NewServices("127.0.0.1:8080", map[string]ServiceSpec{
		"mcp": {Label: "MCP server", URL: "http://127.0.0.1:8765/mcp"},
	})
	svcs.spawn = func(name string, spec ServiceSpec) (*exec.Cmd, error) {
		cmd := exec.Command("sleep", seconds)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		return cmd, cmd.Start()
	}
	return svcs
}

func eventually(t *testing.T, cond func() bool) bool {
	t.Helper()
	for i := 0; i < 50; i++ {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func TestServiceStartStopStatus(t *testing.T) {
	svcs := servicesWithSleeps(t, "30")
	t.Cleanup(svcs.Close)

	if got := svcs.List(); len(got) != 1 || got[0].Running {
		t.Fatalf("initial: %+v, want one not-running service", got)
	}
	info, err := svcs.Start("mcp")
	if err != nil || !info.Running || info.URL != "http://127.0.0.1:8765/mcp" {
		t.Fatalf("start: info=%+v err=%v", info, err)
	}
	if !svcs.List()[0].Running {
		t.Error("service should read running after Start")
	}
	if err := svcs.Stop("mcp"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if !eventually(t, func() bool { return !svcs.List()[0].Running }) {
		t.Error("service should read not-running after Stop")
	}
}

func TestServiceReapsWhenItExits(t *testing.T) {
	svcs := servicesWithSleeps(t, "0.2") // exits on its own
	t.Cleanup(svcs.Close)
	if _, err := svcs.Start("mcp"); err != nil {
		t.Fatal(err)
	}
	if !eventually(t, func() bool { return !svcs.List()[0].Running }) {
		t.Error("a service that exits on its own should drop from running")
	}
}

// A spawned service must run in its own session, not the gateway's: under one-command mode
// the gateway shares the TUI's controlling terminal, and only a session with no controlling
// terminal keeps a child (or grandchild) from writing over the viewer via /dev/tty. Uses the
// real realSpawn (not the sleep-stub) so it exercises the SysProcAttr the code sets.
func TestSpawnedServiceRunsInOwnSession(t *testing.T) {
	svcs := NewServices("127.0.0.1:0", map[string]ServiceSpec{
		"sleeper": {Argv: []string{"sleep", "30"}},
	})
	t.Cleanup(svcs.Close)
	if _, err := svcs.Start("sleeper"); err != nil {
		t.Fatal(err)
	}
	svcs.mu.Lock()
	pid := svcs.running["sleeper"].Process.Pid
	svcs.mu.Unlock()

	sid, err := unix.Getsid(pid)
	if err != nil {
		t.Fatalf("getsid(%d): %v", pid, err)
	}
	if sid != pid {
		t.Errorf("service sid=%d, want it to lead its own session (== pid %d)", sid, pid)
	}
	if own, _ := unix.Getsid(0); sid == own {
		t.Errorf("service shares the gateway's session %d — it can still reach the terminal", own)
	}
}

func TestStartUnknownService(t *testing.T) {
	svcs := NewServices("addr", map[string]ServiceSpec{})
	if _, err := svcs.Start("nope"); err == nil {
		t.Fatal("starting an unknown service should error")
	}
}

func TestResolveMCPEnvOverride(t *testing.T) {
	t.Setenv("TRAFFICDECK_SERVICE_MCP", "my mcp launcher")
	if got := resolveMCP(); !equal(got, []string{"my", "mcp", "launcher"}) {
		t.Errorf("env override = %v", got)
	}
}
