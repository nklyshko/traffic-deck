package main

import (
	"strings"
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
