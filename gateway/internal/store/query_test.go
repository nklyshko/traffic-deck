package store

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

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

// TestQueryFlowsExactlyFullPageHasNoPhantomNext: a page that ends exactly on the last row
// of the list must not offer a Next. The scan already runs past the limit to count matches,
// so it knows there is nothing more — leaving a cursor there steps the viewer onto an empty
// "phantom" page, which is what ↓ on the last row used to do.
func TestQueryFlowsExactlyFullPageHasNoPhantomNext(t *testing.T) {
	ctx := context.Background()
	st, sid := seedQuerySession(t, 10) // ids f-000..f-009
	defer st.Close()

	// First page holds five: five remain after it, so a Next is owed.
	first, err := st.QueryFlows(ctx, sid, FlowQuery{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(first); len(got) != 5 || got[4] != "f-004" {
		t.Fatalf("first page = %v, want f-000..f-004", got)
	}
	if first.Next == nil {
		t.Fatal("first of two full pages must offer a Next")
	}

	// Second page holds the last five exactly. There is nothing beyond it, so despite being
	// full it must offer no Next.
	second, err := st.QueryFlows(ctx, sid, FlowQuery{Limit: 5, After: first.Next})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(second); len(got) != 5 || got[4] != "f-009" {
		t.Fatalf("second page = %v, want f-005..f-009", got)
	}
	if second.Next != nil {
		t.Fatalf("Next = %v, want nil — an exactly-full page at the end has no next page",
			second.Next)
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

func TestQueryFlowsHeaderTerm(t *testing.T) {
	ctx := context.Background()
	st, sid := seedQuerySession(t, 20)
	defer st.Close()

	// Give one flow a distinguishing header.
	if _, err := st.InsertFlows(ctx, sid, "a1", []*decode.Flow{{
		ID: "f-007", FrameNumber: 7, TSUnixMicros: 7000, Method: "GET",
		Authority: "api.example.com", Path: "/r/7", Status: 200,
		RequestHeaders: []decode.Header{{Name: "x-api-key", Value: "s3cret"}},
	}}); err != nil {
		t.Fatal(err)
	}

	page, err := st.QueryFlows(ctx, sid, FlowQuery{Filter: compile(t, "~hq x-api-key"), Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Flows) != 1 || page.Flows[0].GetId() != "f-007" {
		t.Fatalf("header filter matched %v, want just f-007", ids(page))
	}
}

// TestQueryFlowsTimeWindow: a window bounds the scan in SQL, against the same index
// paging uses — so it narrows what is examined rather than testing every row.
func TestQueryFlowsTimeWindow(t *testing.T) {
	ctx := context.Background()
	st, sid := seedQuerySession(t, 50) // ts = i*1000
	defer st.Close()

	page, err := st.QueryFlows(ctx, sid, FlowQuery{
		Limit: 100, SinceMicros: 10_000, UntilMicros: 19_000})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Flows) != 10 {
		t.Fatalf("window returned %d flows, want 10 (f-010..f-019)", len(page.Flows))
	}
	if got := ids(page); got[0] != "f-010" || got[9] != "f-019" {
		t.Fatalf("window bounds wrong: %v", got)
	}
	if page.Matched != 10 {
		t.Fatalf("matched = %d, want the windowed count, not the session's", page.Matched)
	}
	if page.Scanned > 10 {
		t.Fatalf("scanned %d rows: the window should narrow the scan, not filter it", page.Scanned)
	}
}

// TestQueryFlowsPageCarriesNoBodies pins the shape of a page. Hydrating rows through the
// detail path inlined every body, so a few hundred flows became tens of megabytes in one
// response and exceeded the gRPC message limit — a table row needs none of it.
func TestQueryFlowsPageCarriesNoBodies(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, t.TempDir())
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
	// 200 flows with 64 KiB bodies: ~13 MB if a page inlines them.
	flows := make([]*decode.Flow, 0, 200)
	for i := range 200 {
		f := &decode.Flow{
			ID: fmt.Sprintf("f-%03d", i), FrameNumber: uint64(i), TSUnixMicros: int64(i) * 1000,
			Method: "GET", Authority: "api.example.com", Path: fmt.Sprintf("/r/%d", i),
			Status: 200, ResponseBody: make([]byte, 64<<10),
		}
		copy(f.ResponseBody, fmt.Sprintf("body-%d", i))
		for h := range 12 {
			f.RequestHeaders = append(f.RequestHeaders,
				decode.Header{Name: fmt.Sprintf("x-%d", h), Value: "some-header-value"})
		}
		flows = append(flows, f)
	}
	if _, err := st.InsertFlows(ctx, sid, "a1", flows); err != nil {
		t.Fatal(err)
	}

	page, err := st.QueryFlows(ctx, sid, FlowQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Flows) != 200 {
		t.Fatalf("page has %d flows, want 200", len(page.Flows))
	}
	var total int
	for _, f := range page.Flows {
		total += proto.Size(f)
		if n := len(f.GetResponseBody().GetInline()); n != 0 {
			t.Fatalf("flow %s carries %d inline body bytes in a page", f.GetId(), n)
		}
		if n := len(f.GetRequestHeaders()); n != 0 {
			t.Fatalf("flow %s carries %d headers in a page", f.GetId(), n)
		}
	}
	// gRPC's default receive limit is 4 MiB; a full page must sit well inside it.
	if total > 1<<20 {
		t.Fatalf("page serializes to %d bytes, want well under the 4 MiB message limit", total)
	}
}
