package store

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// TestConcurrentWritesNoBusy exercises many concurrent writers on one session bundle — the
// mitmproxy push path opens a stream per frame. busy_timeout on every pooled connection
// (via the DSN) must make them queue rather than fail with SQLITE_BUSY.
func TestConcurrentWritesNoBusy(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	sid := uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{
		ID: sid, SourceKind: trafficv1.SourceKind_SOURCE_KIND_MITMPROXY,
		Status: trafficv1.SessionStatus_SESSION_STATUS_DECODING,
	}); err != nil {
		t.Fatal(err)
	}
	aid := uuid.NewString()
	if err := st.CreateAnalysis(ctx, NewAnalysis{ID: aid, SessionID: sid, Engine: "mitmproxy"}); err != nil {
		t.Fatal(err)
	}

	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for k := 0; k < n; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			f := &decode.Flow{ID: uuid.NewString(), Protocol: "TCP", Authority: fmt.Sprintf("h%d", k)}
			if _, err := st.InsertFlows(ctx, sid, aid, []*decode.Flow{f}); err != nil {
				errs <- err
				return
			}
			m := &decode.WsMessage{ID: uuid.NewString(), FlowID: f.ID, Opcode: "binary", Payload: []byte("x")}
			if _, err := st.InsertWsMessages(ctx, sid, []*decode.WsMessage{m}); err != nil {
				errs <- err
			}
		}(k)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent write failed: %v", err)
	}

	if got, err := st.CountFlows(ctx, sid); err != nil || got != n {
		t.Fatalf("CountFlows = %d, err=%v; want %d", got, err, n)
	}
}
