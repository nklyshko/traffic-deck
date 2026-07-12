package server

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// TestForceCloseSessionGuards covers the guards: a missing session is NotFound, and an
// already-finalized session is refused (the finalize path itself is CloseSession's, tested
// elsewhere).
func TestForceCloseSessionGuards(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	ing := &Ingest{st: st}

	if _, err := ing.ForceCloseSession(ctx, &trafficv1.CloseSessionRequest{SessionId: uuid.NewString()}); status.Code(err) != codes.NotFound {
		t.Errorf("missing session: code=%v", status.Code(err))
	}

	for _, term := range []trafficv1.SessionStatus{
		trafficv1.SessionStatus_SESSION_STATUS_CLOSED,
		trafficv1.SessionStatus_SESSION_STATUS_ERROR,
	} {
		sid := uuid.NewString()
		if err := st.CreateSession(ctx, store.NewSession{ID: sid, SourceKind: trafficv1.SourceKind_SOURCE_KIND_GENERIC, Status: term}); err != nil {
			t.Fatal(err)
		}
		if _, err := ing.ForceCloseSession(ctx, &trafficv1.CloseSessionRequest{SessionId: sid}); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("already %v: code=%v", term, status.Code(err))
		}
	}
}
