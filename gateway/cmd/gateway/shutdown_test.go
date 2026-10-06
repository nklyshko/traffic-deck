package main

import (
	"errors"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// captureLog redirects the standard logger for the duration of a test.
func captureLog(t *testing.T) *strings.Builder {
	t.Helper()
	var buf strings.Builder
	old := logOutput()
	setLogOutput(&buf)
	t.Cleanup(func() { setLogOutput(old) })
	return &buf
}

func TestShutdownStepReportsCompletion(t *testing.T) {
	buf := captureLog(t)
	ok := shutdownStep("stopping things", time.Now().Add(time.Minute), func() {})
	if !ok {
		t.Fatal("a step that returns promptly should report success")
	}
	out := buf.String()
	if !strings.Contains(out, "stopping things…") || !strings.Contains(out, "done in") {
		t.Fatalf("a step must narrate its start and finish, got:\n%s", out)
	}
}

// TestShutdownStepGivesUpAtTheDeadline is the point of the bound: quitting must not be
// able to hang on something that will not finish.
func TestShutdownStepGivesUpAtTheDeadline(t *testing.T) {
	buf := captureLog(t)
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })

	start := time.Now()
	ok := shutdownStep("waiting forever", time.Now().Add(150*time.Millisecond), func() { <-block })
	if ok {
		t.Fatal("a step that never finishes must report failure")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %s to give up; the deadline was not honoured", elapsed)
	}
	if !strings.Contains(buf.String(), "did not finish in time") {
		t.Fatalf("giving up must say so, got:\n%s", buf.String())
	}
}

func TestShutdownStepSkipsWhenOutOfTime(t *testing.T) {
	buf := captureLog(t)
	ran := false
	if shutdownStep("too late", time.Now().Add(-time.Second), func() { ran = true }) {
		t.Fatal("a step past the deadline should report failure")
	}
	if ran {
		t.Fatal("a step past the deadline should not start")
	}
	if !strings.Contains(buf.String(), "out of time") {
		t.Fatalf("skipping must say why, got:\n%s", buf.String())
	}
}

// A signal with no handler installed takes the runtime's default action and kills the
// process where it stands — skipping every teardown step above, which is how one-command
// mode used to leave its capture sources, module processes and MCP server running with no
// parent. They outlive it: spawned with Setsid, nothing the shell sends reaches them, so
// the gateway's own teardown is the only thing that ever stops them.
func TestShutdownSignalsCoverTheWaysTrafficDeckIsStopped(t *testing.T) {
	for _, s := range []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		if !slices.Contains(shutdownSignals, s) {
			t.Errorf("%s is not handled — stopping that way would orphan every child", s)
		}
	}
}

func TestStopViewerOnSignalForwardsAndNarrates(t *testing.T) {
	buf := captureLog(t)
	sig := make(chan os.Signal, 1)
	sig <- syscall.SIGHUP
	stopped := make(chan struct{})

	go stopViewerOnSignal(sig, func() error { close(stopped); return nil })

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the viewer was never asked to stop, so the teardown would never be released")
	}
	// Under a full-screen viewer this goes to the log file, which is where someone looks
	// afterwards to find out why it stopped.
	if out := buf.String(); !strings.Contains(out, "hangup") || !strings.Contains(out, "again to force") {
		t.Errorf("the signal and the escape hatch must both be named, got:\n%s", out)
	}
}

// A viewer that has already exited is the normal case for Ctrl-C, which reached it too.
func TestStopViewerOnSignalSurvivesAnAlreadyDeadViewer(t *testing.T) {
	buf := captureLog(t)
	sig := make(chan os.Signal, 1)
	sig <- syscall.SIGINT

	stopViewerOnSignal(sig, func() error { return errors.New("os: process already finished") })

	if !strings.Contains(buf.String(), "already finished") {
		t.Errorf("the failure is worth one line, not a panic, got:\n%s", buf.String())
	}
}
