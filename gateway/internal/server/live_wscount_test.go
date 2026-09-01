package server

import (
	"testing"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
)

// A pushed WebSocket flow is re-published whole as it progresses (mitmproxy re-pushes on
// response and again on websocket_end), and those re-pushes carry WsMessageCount=0 — the
// hub accumulates the count from frames (publishMessage). A re-publish must not reset the
// live ⇅ count the flow row shows: regression where the websocket_end re-push zeroed it.
func TestPublishPreservesAccumulatedWsCount(t *testing.T) {
	ls := &liveSession{
		flows:   map[string]*trafficv1.Flow{},
		subs:    map[int]*flowSub{},
		msgSubs: map[int]chan *trafficv1.WsMessage{},
	}

	const fid = "ws-flow"
	ls.publish(&trafficv1.Flow{Id: fid, Websocket: true}, true)
	for i := 0; i < 6; i++ {
		ls.publishMessage(&trafficv1.WsMessage{Id: "m", FlowId: fid, Opcode: "text"})
	}
	if got := ls.flows[fid].GetWsMessageCount(); got != 6 {
		t.Fatalf("after 6 frames, live count = %d, want 6", got)
	}

	// The websocket_end re-push: whole flow again, no count (build_flow never sets it).
	ls.publish(&trafficv1.Flow{Id: fid, Websocket: true, DurationMicros: 1234}, false)

	f := ls.flows[fid]
	if got := f.GetWsMessageCount(); got != 6 {
		t.Fatalf("after re-push, live count = %d, want 6 (must not reset)", got)
	}
	if !f.GetWebsocket() {
		t.Fatal("Websocket flag lost on re-push")
	}
	if f.GetDurationMicros() != 1234 {
		t.Fatal("re-push should still apply its own fields (duration)")
	}
}
