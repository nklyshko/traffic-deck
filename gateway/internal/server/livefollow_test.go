package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// A following subscription is the only way a viewer hears about a live capture: its rows
// come from QueryFlows and its updates from here (ADR-0012 §4). So the ways this stream
// can end, and the events that say which happened, are what a live pane's correctness
// rests on — a stream that ends quietly reads as a capture with no traffic.

// openSession returns a store holding one session with the given status, and a hub with
// nothing registered for it — the state between `capture start` and the source's first
// upload.
func openSession(t *testing.T, st2 trafficv1.SessionStatus) (*store.Store, *liveHub, string) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	sid := uuid.NewString()
	if err := st.CreateSession(ctx, store.NewSession{
		ID: sid, Label: "cap", SourceKind: trafficv1.SourceKind_SOURCE_KIND_GENERIC, Status: st2,
	}); err != nil {
		t.Fatal(err)
	}
	return st, newLiveHub(false), sid
}

// sessionStatuses returns the status carried by each session event sent, in order.
func sessionStatuses(c *collectStream) []trafficv1.SessionStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []trafficv1.SessionStatus
	for _, ev := range c.events {
		if se := ev.GetSessionEvent(); se != nil {
			out = append(out, se.GetStatus())
		}
	}
	return out
}

// follow runs StreamFlows in its own goroutine and returns the stream it sends to plus a
// channel closed when the call returns.
func follow(ctx context.Context, v *Viewer, sid string) (*collectStream, chan struct{}) {
	s := &collectStream{ctx: ctx}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = v.StreamFlows(&trafficv1.StreamFlowsRequest{SessionId: sid, Follow: true}, s)
	}()
	return s, done
}

// TestFollowWaitsOutASlowSourceForAsLongAsTheSessionIsOpen pins the fix for a live pane
// that never updated: waitForLive used to give up after five seconds, and a viewer that
// asked to follow a capture whose source had not registered yet got a stream that ended
// immediately — with nothing said, and no reason to reconnect. How long that race lasts
// is the source's business (a device capture registers on its first upload, which waits
// on adb, on the interface, on there being any traffic at all), so the wait is bounded by
// the session staying open, not by a clock.
func TestFollowWaitsOutASlowSourceForAsLongAsTheSessionIsOpen(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the deadline this test exists to disprove")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, hub, sid := openSession(t, trafficv1.SessionStatus_SESSION_STATUS_OPEN)
	v := NewViewer(st, hub)

	s, done := follow(ctx, v, sid)

	// Well past the deadline that used to hang up on this viewer.
	time.Sleep(6 * time.Second)
	select {
	case <-done:
		t.Fatal("the stream gave up on a session that is still open")
	default:
	}

	ls := hub.startPassive(sid) // ...the source finally registers
	waitForSubscriber(t, ls)
	ls.publish(&trafficv1.Flow{Id: "f1", Method: "GET", Authority: "api.example.com"}, true)
	waitFor(t, func() bool { return s.flowCount() == 1 })
	if got := s.kinds(); got[0] != "added:f1" {
		t.Fatalf("events = %v, want the flow published after the wait", got)
	}
}

// TestFollowSaysWhyItStoppedWhenTheSessionCloses: the viewer reconnects when a
// subscription breaks, so the gateway has to distinguish "the capture is over" — else a
// pane would resubscribe to a session that is never going to say anything again.
//
// The subscriber is held still and its buffer filled first, because that is the case with
// no other cover: the hub's own close event is published best-effort like any other, so on
// a full channel it is dropped and the close reaches the viewer as nothing but a stream
// that ended. Saying it as the stream ends is what makes it a guarantee.
func TestFollowSaysWhyItStoppedWhenTheSessionCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, hub, sid := openSession(t, trafficv1.SessionStatus_SESSION_STATUS_OPEN)
	ls := hub.startPassive(sid)
	v := NewViewer(st, hub)

	s := &gatedStream{collectStream: collectStream{ctx: ctx}, gate: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = v.StreamFlows(&trafficv1.StreamFlowsRequest{SessionId: sid, Follow: true}, s)
	}()
	waitForSubscriber(t, ls) // ...and its reader is now stuck in the first Send

	for i := 0; i < liveEventBuffer+8; i++ {
		ls.publish(&trafficv1.Flow{Id: uuid.NewString(), Method: "GET", Authority: "a.example.com"}, true)
	}
	hub.stop(sid) // the close event has nowhere to go
	close(s.gate) // let the reader drain what did fit

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the stream did not end when the session closed")
	}
	got := sessionStatuses(&s.collectStream)
	if len(got) == 0 || got[0] != trafficv1.SessionStatus_SESSION_STATUS_OPEN {
		t.Fatalf("session events = %v, want the live marker first", got)
	}
	if last := got[len(got)-1]; last != trafficv1.SessionStatus_SESSION_STATUS_CLOSED {
		t.Fatalf("last session event = %v, want CLOSED", last)
	}
}

// TestFollowOnAClosedSessionEndsWithItsStatus: same contract for a session that was
// already over when the pane opened. It ends at once — there is nothing to wait for —
// but it still says so rather than hanging up silently.
func TestFollowOnAClosedSessionEndsWithItsStatus(t *testing.T) {
	ctx := context.Background()
	st, hub, sid := openSession(t, trafficv1.SessionStatus_SESSION_STATUS_CLOSED)
	v := NewViewer(st, hub)

	s := &collectStream{ctx: ctx}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := v.StreamFlows(&trafficv1.StreamFlowsRequest{SessionId: sid, Follow: true}, s); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("following a closed session should not wait")
	}
	if got := sessionStatuses(s); len(got) != 1 || got[0] != trafficv1.SessionStatus_SESSION_STATUS_CLOSED {
		t.Fatalf("session events = %v, want one CLOSED", got)
	}
}

// gatedStream is a collectStream whose first Send blocks until it is released, so a test
// can hold the subscription's reader still while the publisher runs away from it.
type gatedStream struct {
	collectStream
	once sync.Once
	gate chan struct{}
}

func (g *gatedStream) Send(ev *trafficv1.FlowEvent) error {
	g.once.Do(func() { <-g.gate })
	return g.collectStream.Send(ev)
}

// TestFollowAsksAViewerToResyncAfterDroppedEvents: publish drops events for a subscriber
// that cannot keep up — it runs on the decode path, under the session's mutex, so
// blocking there would stall the capture to serve a viewer. The drop used to be silent,
// which under ADR-0012 means a row that is missing or stale for the rest of the session:
// the viewer never replays this stream, it queries. Repeating the "subscription live"
// marker is how it is told to query again.
func TestFollowAsksAViewerToResyncAfterDroppedEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, hub, sid := openSession(t, trafficv1.SessionStatus_SESSION_STATUS_OPEN)
	ls := hub.startPassive(sid)
	v := NewViewer(st, hub)

	s := &gatedStream{collectStream: collectStream{ctx: ctx}, gate: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = v.StreamFlows(&trafficv1.StreamFlowsRequest{SessionId: sid, Follow: true}, s)
	}()
	waitForSubscriber(t, ls) // ...and its reader is now stuck in the first Send

	// More than the subscriber's buffer can hold, so the tail of this is dropped.
	for i := 0; i < liveEventBuffer+64; i++ {
		ls.publish(&trafficv1.Flow{Id: uuid.NewString(), Method: "GET", Authority: "a.example.com"}, true)
	}
	waitFor(t, func() bool {
		ls.mu.Lock()
		defer ls.mu.Unlock()
		for _, sub := range ls.subs {
			if sub.missed.Load() {
				return true
			}
		}
		return false
	})

	close(s.gate) // let the reader drain
	waitFor(t, func() bool {
		n := 0
		for _, st := range sessionStatuses(&s.collectStream) {
			if st == trafficv1.SessionStatus_SESSION_STATUS_OPEN {
				n++
			}
		}
		return n >= 2
	})
	if s.flowCount() >= liveEventBuffer+64 {
		t.Fatal("nothing was dropped; this test no longer exercises a slow subscriber")
	}
}
