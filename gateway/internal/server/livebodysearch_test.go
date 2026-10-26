package server

import (
	"bytes"
	"context"
	"testing"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
	"github.com/nklyshko/traffic-deck/gateway/internal/store"
)

// bigPage is a body past store.InlineBlobMax with the needle well inside it — the shape
// of a server-rendered page, which is exactly what a body search is asked about.
func bigPage(needle string) []byte {
	b := bytes.Repeat([]byte("x"), store.InlineBlobMax+200<<10)
	copy(b[134<<10:], needle)
	return b
}

func liveBodySearch(t *testing.T) (context.Context, *liveSession, *Viewer) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ls := newFlushSession(t, st, "s1")
	hub := newLiveHub()
	hub.sessions["s1"] = ls
	return ctx, ls, NewViewer(st, hub)
}

func queryIDs(t *testing.T, ctx context.Context, v *Viewer, filter string) []string {
	t.Helper()
	page, err := v.QueryFlows(ctx, &trafficv1.QueryFlowsRequest{SessionId: "s1", Filter: filter, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range page.GetFlows() {
		ids = append(ids, f.GetId())
	}
	return ids
}

// A body search on an open session must see a body in every state it passes through
// before close: unwritten, written but held back, and written. A large page used to
// match only in the last, so a search during capture missed most loads and said nothing.
func TestBodySearchSeesLiveBodiesInEveryState(t *testing.T) {
	ctx, ls, v := liveBodySearch(t)
	ls.onFlow(&decode.Flow{ID: "f1", Method: "GET", Authority: "ok.ru", Path: "/video/1",
		Status: 200, ResponseBody: bigPage("author_link")}, true)

	check := func(state string) {
		t.Helper()
		if ids := queryIDs(t, ctx, v, "~bs author_link"); len(ids) != 1 || ids[0] != "f1" {
			t.Fatalf("%s: matched %v, want [f1]", state, ids)
		}
		if ids := queryIDs(t, ctx, v, "!~bs author_link"); len(ids) != 0 {
			t.Fatalf("%s: negated search matched %v, want none", state, ids)
		}
	}
	check("unwritten")
	if err := ls.flush(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, held := ls.pending["f1"]; !held {
		t.Fatal("setup: the first flush should write the row and hold the body back")
	}
	check("written, body held back")
	if err := ls.flush(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, done := ls.stored["f1"]; !done {
		t.Fatal("setup: the second flush should write the body")
	}
	check("written")
}
