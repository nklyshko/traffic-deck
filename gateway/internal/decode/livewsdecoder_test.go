package decode

import (
	"sync"
	"testing"
	"time"

	"github.com/nklyshko/traffic-deck/gateway/decoders"
	"github.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

// fakeWSDecoder is a WebSocket binary decoder that claims only the test host, so it can't
// interfere with other tests' connections.
type fakeWSDecoder struct{}

func (fakeWSDecoder) Name() string                     { return "fakews-test" }
func (fakeWSDecoder) MatchesWS(m decoders.WSMeta) bool { return m.Host == "wsdec.test" }
func (fakeWSDecoder) NewSession() decoders.Session     { return fakeWSSession{} }

type fakeWSSession struct{}

func (fakeWSSession) Feed(fromClient bool, data []byte) []decoders.Message {
	return []decoders.Message{{FromClient: fromClient, Payload: append([]byte("D:"), data...),
		Fields: map[string]string{"fake.op": "custom"}}}
}

// TestLiveWebSocketCustomDecoder checks that a registered WSDecoder reframes binary frames
// on the live path (while text/control frames pass through raw).
func TestLiveWebSocketCustomDecoder(t *testing.T) {
	decoders.RegisterWS(fakeWSDecoder{})

	var mu sync.Mutex
	var msgs []*WsMessage
	lt := &liveTCP{
		onFlow: func(f *Flow, _ bool) {},
		onMsg:  func(m *WsMessage) { mu.Lock(); msgs = append(msgs, m); mu.Unlock() },
	}
	s := &tcpStream{
		lt: lt, serverHost: "203.0.113.5", serverPort: "443", clientAddr: "198.51.100.2:51000",
		conn: tlsdecrypt.NewConn(tlsdecrypt.NewKeylog(""), nil),
	}
	h := newHTTPStream(s)

	h.feed(true, []byte("GET /c HTTP/1.1\r\nHost: wsdec.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	h.feed(false, []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	h.feed(true, wsFrame(0x2, []byte("hello"), []byte{1, 2, 3, 4})) // client binary → decoded
	h.feed(false, wsFrame(0x1, []byte("world"), nil))               // server text → raw
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
	// Two messages: the decoded binary frame (carrying its original bytes in Raw) and the
	// text frame. The decoded message's Raw is the original undecoded frame, queryable via MCP.
	if len(msgs) != 2 {
		t.Fatalf("got %d ws messages, want 2: %+v", len(msgs), msgs)
	}
	var decoded, text *WsMessage
	for _, m := range msgs {
		if m.FromClient {
			decoded = m
		} else {
			text = m
		}
	}
	// Reframed, but still labelled by the WebSocket frame it arrived in: the decoder's own
	// label is a field, so `~op ping` can only ever mean the control frame.
	if decoded == nil || decoded.Opcode != "binary" || string(decoded.Payload) != "D:hello" {
		t.Errorf("binary frame not reframed by the decoder: %+v", decoded)
	}
	if decoded != nil && decoded.Metadata["fake.op"] != "custom" {
		t.Errorf("decoder fields missing from the reframed message: %+v", decoded)
	}
	if decoded == nil || string(decoded.Raw) != "hello" {
		t.Errorf("decoded message should carry the original bytes in Raw: %+v", decoded)
	}
	if text == nil || text.Opcode != "text" || string(text.Payload) != "world" {
		t.Errorf("text frame should pass through raw: %+v", text)
	}
	if text != nil && len(text.Raw) != 0 {
		t.Errorf("non-decoded frame should have no Raw: %+v", text)
	}
}
