package store

import (
	"context"
	"testing"

	"github.com/google/uuid"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
)

// TestSessionMetadataRoundTrip checks that capture-source metadata supplied at OpenSession
// (e.g. viewer.columns) persists and is attached on GetSession and ListSessions.
func TestSessionMetadataRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	sid := uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{
		ID: sid, Source: "mitmproxy",
		Status:   trafficv1.SessionStatus_SESSION_STATUS_OPEN,
		Metadata: map[string]string{"viewer.columns": "scrape_group,proxy_provider"},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetSession(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetMetadata()["viewer.columns"] != "scrape_group,proxy_provider" {
		t.Errorf("GetSession metadata = %v", got.GetMetadata())
	}

	// ListSessions attaches it too; a metadata-less session stays empty.
	plain := uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{
		ID: plain, Source: "import",
		Status: trafficv1.SessionStatus_SESSION_STATUS_OPEN,
	}); err != nil {
		t.Fatal(err)
	}
	sessions, err := st.ListSessions(ctx, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]*trafficv1.Session{}
	for _, s := range sessions {
		byID[s.Id] = s
	}
	if byID[sid].GetMetadata()["viewer.columns"] != "scrape_group,proxy_provider" {
		t.Errorf("ListSessions metadata = %v", byID[sid].GetMetadata())
	}
	if len(byID[plain].GetMetadata()) != 0 {
		t.Errorf("plain session should have no metadata: %v", byID[plain].GetMetadata())
	}

	// Delete removes the metadata rows (no leak onto a future same-id session is possible,
	// but verify the row is gone via a fresh session reusing nothing).
	if err := st.FinishSession(ctx, sid, trafficv1.SessionStatus_SESSION_STATUS_CLOSED, 0); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSession(ctx, sid); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.catalog.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM session_metadata WHERE session_id=?`, sid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("session_metadata rows after delete = %d, want 0", n)
	}
}
