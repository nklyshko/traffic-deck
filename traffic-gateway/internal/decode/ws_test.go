package decode

import (
	"encoding/hex"
	"testing"
)

func hexOf(s string) string { return hex.EncodeToString([]byte(s)) }

// TestStitchWebsocket drives the stitcher directly: an HTTP/1.1 Upgrade request
// followed by WebSocket frames on the same TCP stream become WsMessages bound to the
// Upgrade flow, with direction taken from the source address.
func TestStitchWebsocket(t *testing.T) {
	ds := &Dataset{}
	st := newStitcher(ds, nil)

	// HTTP/1.1 GET Upgrade request — creates the flow that owns tcp.stream 5.
	st.add(layers{
		"tcp.stream": {"5"}, "frame.number": {"1"}, "frame.time_epoch": {"100.0"},
		"ip.src": {"10.0.0.1"}, "tcp.srcport": {"1234"},
		"ip.dst": {"10.0.0.2"}, "tcp.dstport": {"443"},
		"http.request.method": {"GET"}, "http.host": {"ex.com"}, "http.request.uri": {"/ws"},
	})

	// client → server text frame
	st.add(layers{
		"tcp.stream": {"5"}, "frame.number": {"2"}, "frame.time_epoch": {"101.0"},
		"ip.src": {"10.0.0.1"}, "tcp.srcport": {"1234"},
		"ip.dst": {"10.0.0.2"}, "tcp.dstport": {"443"},
		"websocket.opcode": {"1"}, "websocket.payload": {hexOf("hello")},
	})
	// server → client binary frame
	st.add(layers{
		"tcp.stream": {"5"}, "frame.number": {"3"}, "frame.time_epoch": {"102.0"},
		"ip.src": {"10.0.0.2"}, "tcp.srcport": {"443"},
		"ip.dst": {"10.0.0.1"}, "tcp.dstport": {"1234"},
		"websocket.opcode": {"2"}, "websocket.payload": {hexOf("world")},
	})

	if len(ds.Flows) != 1 || !ds.Flows[0].Websocket {
		t.Fatalf("want 1 websocket flow, got %d (ws=%v)", len(ds.Flows), ds.Flows[0].Websocket)
	}
	if len(ds.Messages) != 2 {
		t.Fatalf("want 2 messages, got %d", len(ds.Messages))
	}
	m0, m1 := ds.Messages[0], ds.Messages[1]
	if m0.FlowID != ds.Flows[0].ID {
		t.Fatalf("message not bound to upgrade flow: %s vs %s", m0.FlowID, ds.Flows[0].ID)
	}
	if !m0.FromClient || m0.Opcode != "text" || string(m0.Payload) != "hello" {
		t.Fatalf("m0 = %+v", m0)
	}
	if m1.FromClient || m1.Opcode != "binary" || string(m1.Payload) != "world" {
		t.Fatalf("m1 = %+v", m1)
	}
}

// A WebSocket frame whose stream has no captured Upgrade flow is dropped, not crashed.
func TestStitchWebsocketOrphan(t *testing.T) {
	ds := &Dataset{}
	st := newStitcher(ds, nil)
	st.add(layers{
		"tcp.stream": {"9"}, "frame.number": {"1"},
		"ip.src": {"10.0.0.1"}, "tcp.srcport": {"1"},
		"websocket.opcode": {"2"}, "websocket.payload": {hexOf("x")},
	})
	if len(ds.Messages) != 0 || len(ds.Flows) != 0 {
		t.Fatalf("orphan ws frame should be dropped: msgs=%d flows=%d", len(ds.Messages), len(ds.Flows))
	}
}
