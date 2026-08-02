package server

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// collectMsgStream captures what a StreamMessages call sends, guarded because the
// assertions read it while the stream writes from its own goroutine.
type collectMsgStream struct {
	grpc.ServerStream
	ctx    context.Context
	mu     sync.Mutex
	events []*trafficv1.MessageEvent
}

func (c *collectMsgStream) Context() context.Context { return c.ctx }
func (c *collectMsgStream) Send(ev *trafficv1.MessageEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}

// added returns the ids of the frames sent, in order.
func (c *collectMsgStream) added() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, ev := range c.events {
		if m := ev.GetMessageAdded(); m != nil {
			out = append(out, m.GetId())
		}
	}
	return out
}

func (c *collectMsgStream) hints() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ev := range c.events {
		if h := ev.GetFilterHints(); h != nil {
			return h.GetHints()
		}
	}
	return nil
}

// msgFixture stores one flow's frames in a closed session's bundle: a text frame each way
// and a binary one, with distinguishable payloads.
func msgFixture(t *testing.T) (*store.Store, string, string) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	sid, fid := uuid.NewString(), uuid.NewString()
	if err := st.CreateSession(ctx, store.NewSession{ID: sid}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertWsMessages(ctx, sid, []*decode.WsMessage{
		{ID: "m1", FlowID: fid, FrameNumber: 1, TSUnixMicros: 1, FromClient: true,
			Opcode: "text", Payload: []byte(`{"op":"subscribe","channel":"trades"}`)},
		{ID: "m2", FlowID: fid, FrameNumber: 2, TSUnixMicros: 2, FromClient: false,
			Opcode: "text", Payload: []byte(`{"op":"ack","channel":"trades"}`)},
		{ID: "m3", FlowID: fid, FrameNumber: 3, TSUnixMicros: 3, FromClient: false,
			Opcode: "binary", Payload: []byte{0x01, 0x02}},
	}); err != nil {
		t.Fatal(err)
	}
	return st, sid, fid
}

func listIDs(t *testing.T, v *Viewer, sid, fid, expr string) []string {
	t.Helper()
	resp, err := v.ListMessages(context.Background(), &trafficv1.ListMessagesRequest{
		SessionId: sid, FlowId: fid, Filter: expr})
	if err != nil {
		t.Fatalf("ListMessages %q: %v", expr, err)
	}
	var out []string
	for _, m := range resp.GetMessages() {
		out = append(out, m.GetId())
	}
	return out
}

// A chatty WebSocket flow is tens of thousands of frames, and until now the only way to
// find one was to scroll. The frames a filter keeps are the gateway's answer, so every
// viewer gets the same one.
func TestListMessagesFilters(t *testing.T) {
	st, sid, fid := msgFixture(t)
	v := NewViewer(st, newLiveHub(false))

	for _, c := range []struct {
		expr string
		want []string
	}{
		{"", []string{"m1", "m2", "m3"}},
		{"~op text", []string{"m1", "m2"}},
		{"~op binary", []string{"m3"}},
		{"~from client", []string{"m1"}},
		{"~from server", []string{"m2", "m3"}},
		{"~b subscribe", []string{"m1"}},
		{"trades", []string{"m1", "m2"}}, // a bare regex matches the payload
		{"~op text ~from server", []string{"m2"}},
		{"!~op binary ~b ack", []string{"m2"}},
	} {
		if got := listIDs(t, v, sid, fid, c.expr); !equalStrings(got, c.want) {
			t.Errorf("filter %q: got %v, want %v", c.expr, got, c.want)
		}
	}
}

// A payload past the inline cap is spilled to a file and comes back as an object_ref with
// no bytes. Matching the proto's inline copy alone would silently never match exactly the
// frames big enough to be worth searching for.
func TestListMessagesMatchesASpilledPayload(t *testing.T) {
	ctx := context.Background()
	st, sid, fid := msgFixture(t)
	big := append(bytes.Repeat([]byte("A"), store.InlineBlobMax+1), []byte("needle")...)
	if _, err := st.InsertWsMessages(ctx, sid, []*decode.WsMessage{
		{ID: "big", FlowID: fid, FrameNumber: 4, TSUnixMicros: 4, Opcode: "text", Payload: big},
	}); err != nil {
		t.Fatal(err)
	}
	v := NewViewer(st, newLiveHub(false))

	if got := listIDs(t, v, sid, fid, "~b needle"); !equalStrings(got, []string{"big"}) {
		t.Fatalf("~b needle over a spilled payload = %v, want [big]", got)
	}
}

// An annotation is filterable on a message for the same reason it is on a flow: they are
// the same record, and the message screen can annotate.
func TestListMessagesFiltersOnAnnotations(t *testing.T) {
	ctx := context.Background()
	st, sid, fid := msgFixture(t)
	if _, err := st.AddComment(ctx, sid, "m2", "look here"); err != nil {
		t.Fatal(err)
	}
	v := NewViewer(st, newLiveHub(false))

	if got := listIDs(t, v, sid, fid, "~comment 'look here'"); len(got) != 0 {
		t.Errorf("quotes match literally, so this should find nothing; got %v", got)
	}
	if got := listIDs(t, v, sid, fid, "~comment look"); !equalStrings(got, []string{"m2"}) {
		t.Errorf("~comment look = %v, want [m2]", got)
	}
}

// A flow term typed into the message filter is refused by name. The alternative — letting
// it fall through to a payload regex — is the quietly-wrong result the language exists to
// avoid: `~m GET` would match nothing and look like an empty timeline.
func TestMessageFilterRejectsFlowTerms(t *testing.T) {
	st, sid, fid := msgFixture(t)
	v := NewViewer(st, newLiveHub(false))

	_, err := v.ListMessages(context.Background(), &trafficv1.ListMessagesRequest{
		SessionId: sid, FlowId: fid, Filter: "~m GET"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ListMessages with a flow term: err = %v, want InvalidArgument", err)
	}
	if !strings.Contains(err.Error(), "~m") {
		t.Errorf("the error should name the offending term, got %v", err)
	}

	s := &collectMsgStream{ctx: context.Background()}
	err = v.StreamMessages(&trafficv1.StreamMessagesRequest{
		SessionId: sid, FlowId: fid, Filter: "~b ("}, s)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("StreamMessages with a bad regex: err = %v, want InvalidArgument", err)
	}
}

func TestListMessagesReturnsHints(t *testing.T) {
	st, sid, fid := msgFixture(t)
	v := NewViewer(st, newLiveHub(false))

	resp, err := v.ListMessages(context.Background(), &trafficv1.ListMessagesRequest{
		SessionId: sid, FlowId: fid, Filter: "~op text & ~from client"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetHints()) == 0 ||
		!strings.Contains(resp.GetHints()[0], "not an operator") {
		t.Fatalf("hints = %v, want a stray-operator warning", resp.GetHints())
	}
}

// Backfill and live arrivals go through one predicate, so a filtered timeline stays
// filtered as it grows — otherwise a filter would hold only until the next frame.
func TestStreamMessagesFiltersBackfillAndLiveFrames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, hub, ls, sid := liveFixture(t)
	fid := uuid.NewString()

	// One stored frame each way, already flushed to the bundle.
	if _, err := st.InsertWsMessages(ctx, sid, []*decode.WsMessage{
		{ID: "stored-text", FlowID: fid, FrameNumber: 1, TSUnixMicros: 1,
			Opcode: "text", Payload: []byte("hello trades")},
		{ID: "stored-ping", FlowID: fid, FrameNumber: 2, TSUnixMicros: 2, Opcode: "ping"},
	}); err != nil {
		t.Fatal(err)
	}

	v := NewViewer(st, hub)
	s := &collectMsgStream{ctx: ctx}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = v.StreamMessages(&trafficv1.StreamMessagesRequest{
			SessionId: sid, FlowId: fid, Follow: true, Filter: "~op text"}, s)
	}()

	waitFor(t, func() bool {
		ls.mu.Lock()
		defer ls.mu.Unlock()
		return len(ls.msgSubs) > 0
	})

	ls.publishMessage(&trafficv1.WsMessage{
		Id: "live-text", FlowId: fid, Opcode: "text",
		Payload: &trafficv1.Body{Size: 2, Content: &trafficv1.Body_Inline{Inline: []byte("xy")}}})
	ls.publishMessage(&trafficv1.WsMessage{Id: "live-pong", FlowId: fid, Opcode: "pong"})

	waitFor(t, func() bool { return len(s.added()) == 2 })
	if got := s.added(); !equalStrings(got, []string{"stored-text", "live-text"}) {
		t.Fatalf("frames = %v, want the stored and live text frames only", got)
	}

	cancel()
	<-done
}

// A stream has no page to carry hints on, so they come as their own event — before any
// frame, since they describe the subscription a viewer is starting to draw.
func TestStreamMessagesSendsHintsFirst(t *testing.T) {
	st, sid, fid := msgFixture(t)
	v := NewViewer(st, newLiveHub(false))

	s := &collectMsgStream{ctx: context.Background()}
	if err := v.StreamMessages(&trafficv1.StreamMessagesRequest{
		SessionId: sid, FlowId: fid, Filter: "~op text & trades"}, s); err != nil {
		t.Fatal(err)
	}
	if h := s.hints(); len(h) == 0 || !strings.Contains(h[0], "not an operator") {
		t.Fatalf("hints = %v, want a stray-operator warning", h)
	}
	if s.events[0].GetFilterHints() == nil {
		t.Error("hints should be the first event, ahead of the frames")
	}
	// ...and the stray `&` really was matched as a payload regex, as the hint says.
	if got := s.added(); len(got) != 0 {
		t.Errorf("frames = %v, want none: no payload holds a literal `&`", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
