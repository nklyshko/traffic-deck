package server

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
	"github.com/nklyshko/traffic-deck/gateway/internal/store"
)

// TestQuerySQL covers what this handler adds over store.QuerySQL (which owns the
// read-only enforcement and is tested there): the status codes a caller branches on.
func TestQuerySQL(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	sid := "s1"
	if err := st.CreateSession(ctx, store.NewSession{ID: sid}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAnalysis(ctx, store.NewAnalysis{ID: "a1", SessionID: sid, Engine: "live"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertFlows(ctx, sid, "a1", []*decode.Flow{
		{ID: "f1", Authority: "api.example.com", Method: "GET", Status: 200},
		{ID: "f2", Authority: "api.example.com", Method: "GET", Status: 429},
	}); err != nil {
		t.Fatal(err)
	}
	v := NewViewer(st, newLiveHub(false))

	resp, err := v.QuerySQL(ctx, &trafficv1.QuerySQLRequest{
		SessionId: sid, Sql: `SELECT status FROM flows WHERE status >= ? ORDER BY status`,
		Params: []string{"400"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetRowsJson()) != 1 || !strings.Contains(resp.GetRowsJson()[0], "429") {
		t.Fatalf("rows = %v, want the one 429", resp.GetRowsJson())
	}
	if resp.GetColumns()[0] != "status" {
		t.Fatalf("columns = %v", resp.GetColumns())
	}

	for _, tc := range []struct {
		name string
		req  *trafficv1.QuerySQLRequest
		want codes.Code
	}{
		{"no sql", &trafficv1.QuerySQLRequest{SessionId: sid}, codes.InvalidArgument},
		{"bad sql", &trafficv1.QuerySQLRequest{SessionId: sid, Sql: "SELECT nope FROM flows"}, codes.InvalidArgument},
		{"a write", &trafficv1.QuerySQLRequest{SessionId: sid, Sql: "DELETE FROM flows"}, codes.InvalidArgument},
		{"unknown session", &trafficv1.QuerySQLRequest{SessionId: "nope", Sql: "SELECT 1"}, codes.NotFound},
	} {
		if _, err := v.QuerySQL(ctx, tc.req); status.Code(err) != tc.want {
			t.Errorf("%s: code = %v (%v), want %v", tc.name, status.Code(err), err, tc.want)
		}
	}
}
