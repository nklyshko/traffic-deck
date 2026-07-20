package sourcemgr

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// startGroupProc launches a shell in its own process group (as realSpawn does), running
// `body` after it has installed its signal traps and touched a readiness file. It returns
// once that file appears, so a test can signal the group without racing the trap install.
func startGroupProc(t *testing.T, traps, body string) *exec.Cmd {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command("sh", "-c", traps+"; : > "+ready+"; "+body)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			return cmd
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("process never signalled readiness")
	return nil
}

// TestCloseWaitsForGracefulExit: a source that exits on SIGTERM is waited for, so its
// session-closing shutdown finishes before the gateway tears Ingest down — close must not
// return before the process is gone, and must not need the SIGKILL escalation.
func TestCloseWaitsForGracefulExit(t *testing.T) {
	cmd := startGroupProc(t, "trap 'exit 0' TERM", "sleep 30")
	c := &conn{proc: cmd}

	start := time.Now()
	c.closeWithGrace(5 * time.Second)
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("close took %v — it hit the grace instead of the process's prompt SIGTERM exit", elapsed)
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
		t.Fatal("process not reaped after close")
	}
}

// TestCloseForceKillsWedgedSource: a source that ignores SIGTERM is SIGKILLed past the
// grace, so a wedged source can't hang shutdown — close still returns, having reaped it.
func TestCloseForceKillsWedgedSource(t *testing.T) {
	cmd := startGroupProc(t, "trap '' TERM", "sleep 30")
	c := &conn{proc: cmd}

	start := time.Now()
	c.closeWithGrace(200 * time.Millisecond)
	elapsed := time.Since(start)
	if elapsed < 200*time.Millisecond {
		t.Fatalf("close returned in %v — it did not wait out the grace before force-killing", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("close took %v — the SIGKILL escalation did not bound the wait", elapsed)
	}
	if cmd.ProcessState == nil {
		t.Fatal("process not reaped after close")
	}
}
