package decode

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

// wsFrame builds one RFC 6455 frame. maskKey != nil masks the payload (client→server).
func wsFrame(opcode byte, payload []byte, maskKey []byte) []byte {
	var f []byte
	f = append(f, 0x80|opcode) // FIN + opcode
	masked := byte(0)
	if maskKey != nil {
		masked = 0x80
	}
	n := len(payload)
	switch {
	case n < 126:
		f = append(f, masked|byte(n))
	case n < 1<<16:
		f = append(f, masked|126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		f = append(f, ext[:]...)
	default:
		f = append(f, masked|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		f = append(f, ext[:]...)
	}
	body := append([]byte(nil), payload...)
	if maskKey != nil {
		f = append(f, maskKey...)
		for i := range body {
			body[i] ^= maskKey[i&3]
		}
	}
	return append(f, body...)
}

func TestLiveWebSocketUpgradeAndFrames(t *testing.T) {
	var mu sync.Mutex
	var flow *Flow
	var msgs []*WsMessage
	lt := &liveTCP{
		onFlow: func(f *Flow, _ bool) { mu.Lock(); flow = f; mu.Unlock() },
		onMsg:  func(m *WsMessage) { mu.Lock(); msgs = append(msgs, m); mu.Unlock() },
	}
	s := &tcpStream{
		lt:         lt,
		serverHost: "203.0.113.5",
		serverPort: "443",
		clientAddr: "198.51.100.2:51000",
		conn:       tlsdecrypt.NewConn(tlsdecrypt.NewKeylog(""), nil),
	}
	h := newHTTPStream(s)

	// HTTP/1.1 upgrade handshake, then frames.
	h.feed(true, []byte("GET /ws HTTP/1.1\r\nHost: e\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	h.feed(false, []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	// client text frame (masked), server text frame (unmasked).
	h.feed(true, wsFrame(0x1, []byte("ping-from-client"), []byte{0x01, 0x02, 0x03, 0x04}))
	h.feed(false, wsFrame(0x1, []byte("pong-from-server"), nil))
	h.close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(msgs)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if flow == nil || !flow.Websocket || flow.Status != 101 {
		t.Fatalf("flow: %+v", flow)
	}
	if flow.Path != "/ws" {
		t.Errorf("path = %q, want /ws", flow.Path)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d ws messages, want 2", len(msgs))
	}
	// The two directions are read by concurrent goroutines, so order isn't fixed —
	// match by direction.
	var c, srv *WsMessage
	for _, m := range msgs {
		if m.FromClient {
			c = m
		} else {
			srv = m
		}
	}
	if c == nil || c.Opcode != "text" || string(c.Payload) != "ping-from-client" {
		t.Errorf("client frame: %+v", c)
	}
	if srv == nil || srv.Opcode != "text" || string(srv.Payload) != "pong-from-server" {
		t.Errorf("server frame: %+v", srv)
	}
	if c != nil && c.FlowID != flow.ID || srv != nil && srv.FlowID != flow.ID {
		t.Errorf("ws message flow ids don't match the flow")
	}
}
