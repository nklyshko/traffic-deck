package store

import (
	"context"
	"fmt"
	"testing"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/filter"
)

// seedQuerySession writes n flows alternating host and method, with a body carrying the
// index, so filters have something to discriminate on.
func seedQuerySession(t *testing.T, n int) (*Store, string) {
	t.Helper()
	ctx := context.Background()
	st, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sid := "s1"
	if err := st.CreateSession(ctx, NewSession{ID: sid}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAnalysis(ctx, NewAnalysis{ID: "a1", SessionID: sid, Engine: "live"}); err != nil {
		t.Fatal(err)
	}
	flows := make([]*decode.Flow, 0, n)
	for i := range n {
		host := "api.example.com"
		method := "GET"
		if i%2 == 1 {
			host, method = "cdn.example.com", "POST"
		}
		flows = append(flows, &decode.Flow{
			ID: fmt.Sprintf("f-%03d", i), FrameNumber: uint64(i), TSUnixMicros: int64(i) * 1000,
			Scheme: "https", Method: method, Authority: host, Path: fmt.Sprintf("/r/%d", i),
			Status: 200, ResponseBody: []byte(fmt.Sprintf("payload-marker-%d", i)),
		})
	}
	if _, err := st.InsertFlows(ctx, sid, "a1", flows); err != nil {
		t.Fatal(err)
	}
	return st, sid
}

func compile(t *testing.T, expr string) *filter.Predicate {
	t.Helper()
	p, err := filter.Compile(expr, nil, nil)
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}
	return p
}

func ids(p *FlowPage) []string {
	out := make([]string, 0, len(p.Flows))
	for _, f := range p.Flows {
		out = append(out, f.GetId())
	}
	return out
}

func TestQueryFlowsFiltersAndPages(t *testing.T) {
	ctx := context.Background()
	st, sid := seedQuerySession(t, 50)
	defer st.Close()

	page, err := st.QueryFlows(ctx, sid, FlowQuery{Filter: compile(t, "~m POST"), Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Flows) != 10 {
		t.Fatalf("page size = %d, want 10", len(page.Flows))
	}
	if page.Matched != 25 {
		t.Fatalf("matched = %d, want 25 (half the session)", page.Matched)
	}
	if page.CountCapped {
		t.Fatal("count should not be capped for a 50-row session")
	}
	for _, f := range page.Flows {
		if f.GetMethod() != "POST" {
			t.Fatalf("non-matching flow in page: %s", f.GetMethod())
		}
	}
	// Rows come back in timeline order.
	if got := ids(page); got[0] != "f-001" || got[9] != "f-019" {
		t.Fatalf("page order wrong: %v", got)
	}
}

// TestQueryFlowsKeysetPaging walks the whole matching set forward and asserts it is
// covered exactly once — the property offset paging loses on a growing session.
func TestQueryFlowsKeysetPaging(t *testing.T) {
	ctx := context.Background()
	st, sid := seedQuerySession(t, 50)
	defer st.Close()

	seen := map[string]int{}
	var cursor *Cursor
	for range 20 {
		page, err := st.QueryFlows(ctx, sid, FlowQuery{
			Filter: compile(t, "~m POST"), Limit: 7, After: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids(page) {
			seen[id]++
		}
		if page.Next == nil {
			break
		}
		cursor = page.Next
	}
	if len(seen) != 25 {
		t.Fatalf("walked %d distinct flows, want 25", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("flow %s returned %d times, want exactly once", id, n)
		}
	}
}

// TestQueryFlowsLastIsEndOfList: "jump to the end" is a query, not an offset computed
// from a total — which is what lets the count stay approximate (ADR-0012 §5).
func TestQueryFlowsLastIsEndOfList(t *testing.T) {
	ctx := context.Background()
	st, sid := seedQuerySession(t, 50)
	defer st.Close()

	page, err := st.QueryFlows(ctx, sid, FlowQuery{Limit: 5, Last: true})
	if err != nil {
		t.Fatal(err)
	}
	got := ids(page)
	if len(got) != 5 || got[4] != "f-049" {
		t.Fatalf("last page = %v, want it to end at f-049", got)
	}
	if got[0] != "f-045" {
		t.Fatalf("last page should be in timeline order, got %v", got)
	}
	if page.Next != nil {
		t.Fatal("there is nothing after the last page")
	}
	if page.Prev == nil {
		t.Fatal("the last page should offer a step backwards")
	}

	back, err := st.QueryFlows(ctx, sid, FlowQuery{Limit: 5, Before: page.Prev})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(back); got[4] != "f-044" {
		t.Fatalf("stepping back gave %v, want it to end at f-044", got)
	}
}

func TestQueryFlowsBodyTerm(t *testing.T) {
	ctx := context.Background()
	st, sid := seedQuerySession(t, 30)
	defer st.Close()

	page, err := st.QueryFlows(ctx, sid, FlowQuery{Filter: compile(t, "~bs payload-marker-7$"), Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Flows) != 1 || page.Flows[0].GetId() != "f-007" {
		t.Fatalf("body filter matched %v, want just f-007", ids(page))
	}
}

func TestQueryFlowsScanCapReportsCapped(t *testing.T) {
	ctx := context.Background()
	st, sid := seedQuerySession(t, 50)
	defer st.Close()

	page, err := st.QueryFlows(ctx, sid,
		FlowQuery{Filter: compile(t, "~m POST"), Limit: 5, ScanCap: 20})
	if err != nil {
		t.Fatal(err)
	}
	if !page.CountCapped {
		t.Fatal("a scan stopped by the cap must say so")
	}
	if page.Scanned > 20 {
		t.Fatalf("scanned %d rows, cap was 20", page.Scanned)
	}
	if page.Matched >= 25 {
		t.Fatalf("matched = %d; a capped count is a lower bound, not the total", page.Matched)
	}
}

func TestQueryFlowsNoFilterCountsExactly(t *testing.T) {
	ctx := context.Background()
	st, sid := seedQuerySession(t, 50)
	defer st.Close()

	page, err := st.QueryFlows(ctx, sid, FlowQuery{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	// With no predicate the total is a COUNT, so it is exact even though the page is small.
	if page.Matched != 50 || page.CountCapped {
		t.Fatalf("matched = %d capped = %v, want an exact 50", page.Matched, page.CountCapped)
	}
}

func TestQueryFlowsAnnotationTerms(t *testing.T) {
	ctx := context.Background()
	st, sid := seedQuerySession(t, 10)
	defer st.Close()

	if err := st.SetMark(ctx, sid, []string{"f-003"}, "red"); err != nil {
		t.Fatal(err)
	}
	tags, groups, err := st.AnnotationNames(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	p, err := filter.Compile("~mark red", tags, groups)
	if err != nil {
		t.Fatal(err)
	}
	page, err := st.QueryFlows(ctx, sid, FlowQuery{Filter: p, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Flows) != 1 || page.Flows[0].GetId() != "f-003" {
		t.Fatalf("~mark matched %v, want just f-003", ids(page))
	}
}
