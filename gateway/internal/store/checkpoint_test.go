package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// TestFinishSessionCheckpointsWAL: a finalized bundle's write-ahead log is folded back in
// rather than left beside it for the life of the process (one per session captured).
func TestFinishSessionCheckpointsWAL(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	st, err := Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	sid := "s1"
	if err := st.CreateSession(ctx, NewSession{ID: sid}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAnalysis(ctx, NewAnalysis{ID: "a1", SessionID: sid, Engine: "live"}); err != nil {
		t.Fatal(err)
	}
	flows := make([]*decode.Flow, 0, 400)
	for i := range 400 {
		f := &decode.Flow{ID: fmt.Sprintf("f-%d", i), Method: "GET", Authority: "example.com",
			Path: fmt.Sprintf("/r/%d", i), Status: 200, ResponseBody: make([]byte, 2048)}
		copy(f.ResponseBody, fmt.Sprintf("body-%d", i))
		for h := range 10 {
			f.RequestHeaders = append(f.RequestHeaders,
				decode.Header{Name: fmt.Sprintf("x-%d", h), Value: "some-header-value"})
		}
		flows = append(flows, f)
	}
	if _, err := st.InsertFlows(ctx, sid, "a1", flows); err != nil {
		t.Fatal(err)
	}

	wal := filepath.Join(root, "sessions", sid, "flows.sqlite-wal")
	before, err := os.Stat(wal)
	if err != nil {
		t.Skipf("no WAL to checkpoint (%v)", err)
	}
	if before.Size() == 0 {
		t.Skip("WAL already empty; nothing to prove")
	}

	if err := st.FinishSession(ctx, sid, trafficv1.SessionStatus_SESSION_STATUS_CLOSED, len(flows)); err != nil {
		t.Fatal(err)
	}

	after, err := os.Stat(wal)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err == nil && after.Size() >= before.Size() {
		t.Fatalf("WAL not checkpointed: %d bytes before, %d after", before.Size(), after.Size())
	}

	// The bundle must still be readable, and complete, after the checkpoint.
	n, err := st.CountFlows(ctx, sid)
	if err != nil || n != len(flows) {
		t.Fatalf("CountFlows after checkpoint = %d err=%v, want %d", n, err, len(flows))
	}
	body, _, err := st.GetBodyBytes(ctx, sid, "f-7", true)
	if err != nil || len(body) != 2048 {
		t.Fatalf("body unreadable after checkpoint: %d bytes err=%v", len(body), err)
	}
}
