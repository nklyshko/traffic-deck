package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// newFlushSession builds a live session wired to st, as hub.start does for a record-live
// capture, but without a decode goroutine — the tests drive onFlow directly.
func newFlushSession(t *testing.T, st *store.Store, sid string) *liveSession {
	t.Helper()
	ctx := context.Background()
	if err := st.CreateSession(ctx, store.NewSession{ID: sid}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := st.CreateAnalysis(ctx, store.NewAnalysis{ID: "a1", SessionID: sid, Engine: "live"}); err != nil {
		t.Fatalf("create analysis: %v", err)
	}
	return &liveSession{
		recordLive: true,
		flows:      map[string]*trafficv1.Flow{},
		dflows:     map[string]*decode.Flow{},
		subs:       map[int]*flowSub{},
		msgSubs:    map[int]chan *trafficv1.WsMessage{},
		sessionID:  sid, analysisID: "a1", sink: st,
		dirty: map[string]struct{}{}, pending: map[string]struct{}{},
		stored:    map[string]storedBody{},
		wake:      make(chan struct{}, 1),
		stopFlush: make(chan struct{}), flushDone: make(chan struct{}),
	}
}

// TestFlushDefersBodyUntilFinal is ADR-0011 §3b: a flow written while its body is still
// arriving must land with a NULL body ref, so no blob is content-addressed from a prefix.
// The body appears only once the flow has settled.
func TestFlushDefersBodyUntilFinal(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ls := newFlushSession(t, st, "s1")

	// Request seen, response still arriving: no status yet.
	f := &decode.Flow{ID: "f1", Method: "POST", Authority: "example.com", Path: "/upload",
		RequestBody: []byte("partial")}
	ls.onFlow(f, true)
	if err := ls.flush(ctx, false); err != nil {
		t.Fatalf("flush 1: %v", err)
	}

	if _, _, err := st.GetBodyBytes(ctx, "s1", "f1", false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("body ref should still be NULL while the body streams, got err=%v", err)
	}
	if got, err := st.GetFlow(ctx, "s1", "f1"); err != nil || got.GetMethod() != "POST" {
		t.Fatalf("row should be written even without its body: %+v err=%v", got, err)
	}

	// Body completes and the response arrives; a quiet cycle then settles it.
	f.RequestBody = []byte("partial-then-complete")
	f.Status = 200
	ls.onFlow(f, false)
	if err := ls.flush(ctx, false); err != nil { // writes the row, still pending
		t.Fatalf("flush 2: %v", err)
	}
	if err := ls.flush(ctx, false); err != nil { // untouched since: settles
		t.Fatalf("flush 3: %v", err)
	}

	body, _, err := st.GetBodyBytes(ctx, "s1", "f1", false)
	if err != nil {
		t.Fatalf("body after settling: %v", err)
	}
	if string(body) != "partial-then-complete" {
		t.Fatalf("stored body = %q, want the final bytes", body)
	}
}

// TestFlushReleasesBodies checks that a settled flow's bytes leave memory while the proto
// keeps size and content-type — the invariant the viewers' view/save affordance rests on.
func TestFlushReleasesBodies(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ls := newFlushSession(t, st, "s1")

	f := &decode.Flow{ID: "f1", Method: "GET", Authority: "example.com", Path: "/x",
		Status: 200, ResponseBody: []byte("hello world"),
		ResponseHeaders: []decode.Header{{Name: "content-type", Value: "text/plain"}}}
	ls.onFlow(f, true)
	for range 2 {
		if err := ls.flush(ctx, false); err != nil {
			t.Fatalf("flush: %v", err)
		}
	}

	// The hub's retained copy is what has to shed the bytes; the decoder's own Flow is
	// deliberately never touched, since it is mutated outside our lock.
	if got := ls.dflows["f1"].ResponseBody; got != nil {
		t.Fatalf("retained flow still holds %d body bytes after release", len(got))
	}
	if f.ResponseBody == nil {
		t.Fatal("the decoder's own Flow must not be mutated by the flusher")
	}
	pf := ls.flows["f1"]
	if got := pf.GetResponseBody().GetSize(); got != uint64(len("hello world")) {
		t.Fatalf("proto body size = %d, want it preserved so the viewer still offers the body", got)
	}
	if pf.GetResponseBody().GetContentType() != "text/plain" {
		t.Fatalf("proto content-type dropped: %q", pf.GetResponseBody().GetContentType())
	}
	if inline := pf.GetResponseBody().GetInline(); len(inline) != 0 {
		t.Fatalf("inline bytes should be cleared, got %d", len(inline))
	}
	// Still readable, now from the bundle.
	body, _, err := st.GetBodyBytes(ctx, "s1", "f1", true)
	if err != nil || string(body) != "hello world" {
		t.Fatalf("released body unreadable from store: %q err=%v", body, err)
	}
}

// TestFlushReleasedFlowSurvivesReflush guards the BodiesStored path: a flow dirtied again
// after its bytes were released must keep the refs it already wrote, not null them.
func TestFlushReleasedFlowSurvivesReflush(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ls := newFlushSession(t, st, "s1")

	f := &decode.Flow{ID: "f1", Method: "GET", Authority: "example.com", Path: "/x",
		Status: 200, ResponseBody: []byte("payload")}
	ls.onFlow(f, true)
	for range 2 {
		if err := ls.flush(ctx, false); err != nil {
			t.Fatalf("flush: %v", err)
		}
	}
	if ls.dflows["f1"].ResponseBody != nil {
		t.Fatal("expected the retained body to be released")
	}

	// A late update (an annotation of the flow by the decoder, a trailing error) re-dirties
	// it. Its bytes are gone, so a naive rewrite would store "" and orphan the blob.
	f.Error = "connection reset (TCP RST)"
	ls.onFlow(f, false)
	if err := ls.flush(ctx, false); err != nil {
		t.Fatalf("re-flush: %v", err)
	}

	body, _, err := st.GetBodyBytes(ctx, "s1", "f1", true)
	if err != nil || string(body) != "payload" {
		t.Fatalf("body lost by re-flush: %q err=%v", body, err)
	}
	got, err := st.GetFlow(ctx, "s1", "f1")
	if err != nil || got.GetError() == "" {
		t.Fatalf("late update not persisted: %+v err=%v", got, err)
	}
}

// TestFlushWebSocketMessages is ADR-0011 §4: frames are written and dropped from the hub,
// leaving a bounded tail rather than the whole conversation.
func TestFlushWebSocketMessages(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ls := newFlushSession(t, st, "s1")

	ls.onFlow(&decode.Flow{ID: "f1", Method: "GET", Authority: "ws.example.com",
		Path: "/socket", Status: 101, Websocket: true}, true)
	for i := range 5 {
		ls.onMessage(&decode.WsMessage{
			ID: string(rune('a' + i)), FlowID: "f1", Opcode: "text",
			FromClient: i%2 == 0, Payload: []byte(strings.Repeat("x", 10))})
	}
	if err := ls.flush(ctx, false); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if len(ls.messages) != 0 {
		t.Fatalf("hub still holds %d frames after flush", len(ls.messages))
	}
	msgs, err := st.ListMessages(ctx, "s1", "f1")
	if err != nil {
		t.Fatalf("list messages: %v", err)
	}
	if len(msgs) != 5 {
		t.Fatalf("stored %d frames, want 5", len(msgs))
	}

	// A WebSocket flow never settles, so its handshake bodies stay in memory.
	if _, released := ls.stored["f1"]; released {
		t.Fatal("WebSocket flow should be exempt from body release")
	}
}

// failingSink fails every write, standing in for a full disk.
type failingSink struct{}

var errSinkFull = errors.New("disk full")

func (failingSink) InsertFlowWrites(context.Context, string, string, []store.FlowWrite) (int, error) {
	return 0, errSinkFull
}
func (failingSink) InsertWsMessages(context.Context, string, []*decode.WsMessage) (int, error) {
	return 0, errSinkFull
}

// TestFlushFailureStopsSession is ADR-0011 §5: a failed write ends the session rather
// than retrying (unbounded memory) or dropping the batch (silent loss).
func TestFlushFailureStopsSession(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ls := newFlushSession(t, st, "s1")
	ls.sink = failingSink{}

	var gotSession string
	var gotErr error
	ls.onFlushErr = func(sid string, err error) { gotSession, gotErr = sid, err }

	ls.onFlow(&decode.Flow{ID: "f1", Method: "GET", Authority: "example.com"}, true)
	err = ls.flush(ctx, false)
	if !errors.Is(err, errSinkFull) {
		t.Fatalf("flush error = %v, want the sink's", err)
	}
	ls.failFlush(err)

	if gotSession != "s1" || !errors.Is(gotErr, errSinkFull) {
		t.Fatalf("owner not notified: session=%q err=%v", gotSession, gotErr)
	}
	// The session is finished: further flushes report the original failure rather than
	// silently resuming.
	if err := ls.flush(ctx, false); !errors.Is(err, errSinkFull) {
		t.Fatalf("flush after failure = %v, want the recorded failure", err)
	}
}

// TestFinalFlushWritesEverything checks the close path: whatever never settled is still
// written, with its bodies, by the final flush.
func TestFinalFlushWritesEverything(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ls := newFlushSession(t, st, "s1")

	// A request that never got a response — it can never settle on its own.
	ls.onFlow(&decode.Flow{ID: "f1", Method: "POST", Authority: "example.com",
		Path: "/pending", RequestBody: []byte("in flight")}, true)
	if err := ls.flush(ctx, false); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if _, _, err := st.GetBodyBytes(ctx, "s1", "f1", false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unsettled body should not be written yet, err=%v", err)
	}

	if err := ls.flush(ctx, true); err != nil {
		t.Fatalf("final flush: %v", err)
	}
	body, _, err := st.GetBodyBytes(ctx, "s1", "f1", false)
	if err != nil || string(body) != "in flight" {
		t.Fatalf("final flush did not write the body: %q err=%v", body, err)
	}
	n, err := st.CountFlows(ctx, "s1")
	if err != nil || n != 1 {
		t.Fatalf("CountFlows = %d err=%v, want 1", n, err)
	}
}

// TestFlusherConcurrentWithPublish runs the real flush loop against a decoder publishing
// concurrently — the arrangement the lock discipline in ADR-0011 §1 exists for (the
// store write must not happen under the mutex the decoder publishes through).
func TestFlusherConcurrentWithPublish(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ls := newFlushSession(t, st, "s1")
	ls.startFlusher()

	const n = 500
	done := make(chan struct{})
	go func() { // a viewer reading the live session throughout
		defer close(done)
		for range 200 {
			ls.liveFlows()
			ls.flowCount()
		}
	}()
	for i := range n {
		id := fmt.Sprintf("f-%d", i)
		f := &decode.Flow{ID: id, Method: "GET", Authority: "example.com",
			Path: fmt.Sprintf("/r/%d", i), RequestBody: []byte("body")}
		ls.onFlow(f, true)
		f.Status = 200 // response arrives; the flow can now settle
		ls.onFlow(f, false)
	}
	<-done

	ls.stopFlusher()
	if err := ls.flush(ctx, true); err != nil {
		t.Fatalf("final flush: %v", err)
	}
	got, err := st.CountFlows(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if got != n {
		t.Fatalf("persisted %d flows, want %d", got, n)
	}
	// Every flow settled, so nothing should still be holding body bytes.
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for id, df := range ls.dflows {
		if df.RequestBody != nil {
			t.Fatalf("flow %s still holds body bytes after the final flush", id)
		}
	}
}
