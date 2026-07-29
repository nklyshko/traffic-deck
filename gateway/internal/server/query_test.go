package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// collectStream captures what a StreamFlows call sends. Guarded, because the assertions
// read it from the test goroutine while the stream writes from its own.
type collectStream struct {
	grpc.ServerStream
	ctx    context.Context
	mu     sync.Mutex
	events []*trafficv1.FlowEvent
}

func (c *collectStream) Context() context.Context { return c.ctx }
func (c *collectStream) Send(ev *trafficv1.FlowEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}

func (c *collectStream) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// flowCount counts only flow events, skipping the marker a live subscription opens with.
func (c *collectStream) flowCount() int { return len(c.kinds()) }

func (c *collectStream) kinds() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, ev := range c.events {
		switch e := ev.GetEvent().(type) {
		case *trafficv1.FlowEvent_FlowAdded:
			out = append(out, "added:"+e.FlowAdded.GetId())
		case *trafficv1.FlowEvent_FlowUpdated:
			out = append(out, "updated:"+e.FlowUpdated.GetId())
		case *trafficv1.FlowEvent_FlowUnmatched:
			out = append(out, "unmatched:"+e.FlowUnmatched)
		}
	}
	return out
}

// waitFor spins until cond holds or the test would hang, so a streaming assertion does
// not depend on a sleep long enough to be slow and short enough to be flaky.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for the stream")
}

// waitForSubscriber blocks until a StreamFlows call has registered. A following
// subscription is live-only, so anything published before it is up is simply not its
// business — the tests publish after this returns.
func waitForSubscriber(t *testing.T, ls *liveSession) {
	t.Helper()
	waitFor(t, func() bool {
		ls.mu.Lock()
		defer ls.mu.Unlock()
		return len(ls.subs) > 0
	})
}

func queryTestStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sid := "s1"
	if err := st.CreateSession(ctx, store.NewSession{ID: sid}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAnalysis(ctx, store.NewAnalysis{ID: "a1", SessionID: sid, Engine: "live"}); err != nil {
		t.Fatal(err)
	}
	return st, sid
}

// TestStreamFlowsWithoutFollowYieldsNothing: the stream is liveness now, so a
// non-following call has nothing to do. Reading a session's rows — filtered, paged, and
// including an open session's unflushed tail — is QueryFlows' job, covered by
// TestQueryFlowsMergesUnflushedTail and the store's query tests.
func TestStreamFlowsWithoutFollowYieldsNothing(t *testing.T) {
	ctx := context.Background()
	st, sid := queryTestStore(t)
	defer st.Close()

	if _, err := st.InsertFlows(ctx, sid, "a1", []*decode.Flow{
		{ID: "f1", Method: "GET", Authority: "api.example.com", Path: "/a", Status: 200, TSUnixMicros: 1},
	}); err != nil {
		t.Fatal(err)
	}
	v := NewViewer(st, newLiveHub(false))
	s := &collectStream{ctx: ctx}
	if err := v.StreamFlows(&trafficv1.StreamFlowsRequest{SessionId: sid}, s); err != nil {
		t.Fatal(err)
	}
	if got := s.kinds(); len(got) != 0 {
		t.Fatalf("a non-following stream replayed %v; backfill is QueryFlows' job", got)
	}
}

// TestStreamFlowsRetractsOnUpdate is ADR-0012 §6. A flow matching `~q` (no response)
// stops matching when its response arrives; the gateway must say so, because the viewer
// cannot work it out.
func TestStreamFlowsRetractsOnUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, sid := queryTestStore(t)
	defer st.Close()

	hub := newLiveHub(true)
	ls := hub.startPassive(sid)
	v := NewViewer(st, hub)

	s := &collectStream{ctx: ctx}
	done := make(chan error, 1)
	go func() {
		done <- v.StreamFlows(&trafficv1.StreamFlowsRequest{
			SessionId: sid, Filter: "~q", Follow: true}, s)
	}()
	waitForSubscriber(t, ls)

	// A request with no response yet: matches ~q.
	pending := &trafficv1.Flow{Id: "f1", Method: "GET", Authority: "api.example.com", Path: "/a"}
	ls.publish(pending, true)
	waitFor(t, func() bool { return s.flowCount() >= 1 })

	// The response lands: the flow no longer has "no response".
	answered := &trafficv1.Flow{Id: "f1", Method: "GET", Authority: "api.example.com",
		Path: "/a", Status: 200}
	ls.publish(answered, false)
	waitFor(t, func() bool { return s.flowCount() >= 2 })

	cancel()
	<-done

	got := s.kinds()
	if len(got) < 2 || got[0] != "added:f1" || got[1] != "unmatched:f1" {
		t.Fatalf("events = %v, want added:f1 then unmatched:f1", got)
	}
}

// TestStreamFlowsAddsWhenAnUpdateBringsAFlowIn is the other direction: a flow the
// subscription has never seen, which an update makes match, arrives as an add rather
// than an update for a row the viewer does not have.
func TestStreamFlowsAddsWhenAnUpdateBringsAFlowIn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, sid := queryTestStore(t)
	defer st.Close()

	hub := newLiveHub(true)
	ls := hub.startPassive(sid)
	v := NewViewer(st, hub)

	s := &collectStream{ctx: ctx}
	done := make(chan error, 1)
	go func() {
		done <- v.StreamFlows(&trafficv1.StreamFlowsRequest{
			SessionId: sid, Filter: "~s", Follow: true}, s) // has a response
	}()
	waitForSubscriber(t, ls)

	// Published without a status: it does not match, so the subscription hears nothing.
	ls.publish(&trafficv1.Flow{Id: "f1", Method: "GET", Authority: "api.example.com"}, true)
	ls.publish(&trafficv1.Flow{Id: "f1", Method: "GET", Authority: "api.example.com", Status: 200}, false)
	waitFor(t, func() bool { return s.flowCount() >= 1 })
	cancel()
	<-done

	got := s.kinds()
	if len(got) != 1 || got[0] != "added:f1" {
		t.Fatalf("events = %v, want a single added:f1", got)
	}
}

func TestStreamFlowsRejectsBadFilter(t *testing.T) {
	ctx := context.Background()
	st, sid := queryTestStore(t)
	defer st.Close()
	v := NewViewer(st, newLiveHub(false))
	err := v.StreamFlows(&trafficv1.StreamFlowsRequest{SessionId: sid, Filter: "~u (?=x)"},
		&collectStream{ctx: ctx})
	if err == nil {
		t.Fatal("an unsupported regex must be refused, not silently reinterpreted")
	}
}

// TestQueryFlowsMergesUnflushedTail: an open session's newest flows are not in the bundle
// yet, and must still appear (ADR-0012 §8).
func TestQueryFlowsMergesUnflushedTail(t *testing.T) {
	ctx := context.Background()
	st, sid := queryTestStore(t)
	defer st.Close()

	if _, err := st.InsertFlows(ctx, sid, "a1", []*decode.Flow{
		{ID: "stored", Method: "GET", Authority: "api.example.com", Path: "/old",
			Status: 200, TSUnixMicros: 1},
	}); err != nil {
		t.Fatal(err)
	}
	hub := newLiveHub(true)
	ls := hub.startPassive(sid)
	ls.publish(&trafficv1.Flow{Id: "tail", Method: "GET", Authority: "api.example.com",
		Path: "/new", Status: 200, TsUnixMicros: 2}, true)

	v := NewViewer(st, hub)
	page, err := v.QueryFlows(ctx, &trafficv1.QueryFlowsRequest{SessionId: sid, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range page.GetFlows() {
		ids = append(ids, f.GetId())
	}
	if len(ids) != 2 || ids[0] != "stored" || ids[1] != "tail" {
		t.Fatalf("page = %v, want the stored flow then the unflushed tail", ids)
	}
	if page.GetMatched() != 2 {
		t.Fatalf("matched = %d, want 2", page.GetMatched())
	}
}

func TestQueryFlowsFiltersTheTailToo(t *testing.T) {
	ctx := context.Background()
	st, sid := queryTestStore(t)
	defer st.Close()

	hub := newLiveHub(true)
	ls := hub.startPassive(sid)
	ls.publish(&trafficv1.Flow{Id: "a", Method: "GET", Authority: "api.example.com", TsUnixMicros: 1}, true)
	ls.publish(&trafficv1.Flow{Id: "b", Method: "POST", Authority: "api.example.com", TsUnixMicros: 2}, true)

	v := NewViewer(st, hub)
	page, err := v.QueryFlows(ctx, &trafficv1.QueryFlowsRequest{
		SessionId: sid, Filter: "~m POST", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.GetFlows()) != 1 || page.GetFlows()[0].GetId() != "b" {
		t.Fatalf("the unflushed tail must be filtered like the bundle, got %d flows",
			len(page.GetFlows()))
	}
}

// TestStreamFlowsMarksSubscriptionLive: a following stream announces itself, which is
// what lets a viewer close the gap between its QueryFlows and this subscribe — a flow
// published in between is in neither result, and re-querying only helps once the stream
// is guaranteed to carry what comes next.
func TestStreamFlowsMarksSubscriptionLive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, sid := queryTestStore(t)
	defer st.Close()

	hub := newLiveHub(true)
	ls := hub.startPassive(sid)
	v := NewViewer(st, hub)

	s := &collectStream{ctx: ctx}
	done := make(chan error, 1)
	go func() {
		done <- v.StreamFlows(&trafficv1.StreamFlowsRequest{
			SessionId: sid, Follow: true}, s)
	}()
	waitForSubscriber(t, ls)
	waitFor(t, func() bool { return s.count() >= 1 })
	cancel()
	<-done

	s.mu.Lock()
	defer s.mu.Unlock()
	ev, ok := s.events[0].GetEvent().(*trafficv1.FlowEvent_SessionEvent)
	if !ok {
		t.Fatalf("first event = %T, want a session event marking the stream live", s.events[0].GetEvent())
	}
	if got := ev.SessionEvent.GetStatus(); got != trafficv1.SessionStatus_SESSION_STATUS_OPEN {
		t.Fatalf("marker status = %v, want OPEN — a closed status means something else entirely", got)
	}
}

// TestQueryFlowsTailCarriesNoBodies: the unflushed tail is merged from the hub, whose
// protos inline bodies for the event stream. A page must not inherit that — a few hundred
// such flows exceed the gRPC message limit on their own.
func TestQueryFlowsTailCarriesNoBodies(t *testing.T) {
	ctx := context.Background()
	st, sid := queryTestStore(t)
	defer st.Close()

	hub := newLiveHub(true)
	ls := hub.startPassive(sid)
	live := &trafficv1.Flow{
		Id: "tail", Method: "GET", Authority: "api.example.com", Path: "/x",
		Status: 200, TsUnixMicros: 1,
		RequestHeaders: []*trafficv1.Header{{Name: "user-agent", Value: "probe"}},
		ResponseBody: &trafficv1.Body{
			Size: 64 << 10, ContentType: "text/html",
			Content: &trafficv1.Body_Inline{Inline: make([]byte, 64<<10)},
		},
	}
	ls.publish(live, true)

	v := NewViewer(st, hub)
	page, err := v.QueryFlows(ctx, &trafficv1.QueryFlowsRequest{SessionId: sid, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.GetFlows()) != 1 {
		t.Fatalf("page has %d flows, want the tail", len(page.GetFlows()))
	}
	got := page.GetFlows()[0]
	if n := len(got.GetResponseBody().GetInline()); n != 0 {
		t.Fatalf("tail flow carries %d inline body bytes in a page", n)
	}
	if n := len(got.GetRequestHeaders()); n != 0 {
		t.Fatalf("tail flow carries %d headers in a page", n)
	}
	// Size and content-type stay: the viewer gates its body actions on them.
	if got.GetResponseBody().GetSize() != 64<<10 {
		t.Fatalf("body size dropped: %d", got.GetResponseBody().GetSize())
	}
	if got.GetResponseBody().GetContentType() != "text/html" {
		t.Fatalf("content-type dropped: %q", got.GetResponseBody().GetContentType())
	}
}
