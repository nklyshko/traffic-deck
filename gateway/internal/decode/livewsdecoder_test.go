package decode

import (
	"sync"
	"testing"
	"time"

	"gitlab.com/nklyshko/traffic-deck/gateway/decoders"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

// fakeWSDecoder is a WebSocket binary decoder that claims only the test host, so it can't
// interfere with other tests' connections.
type fakeWSDecoder struct{}

func (fakeWSDecoder) Name() string                     { return "fakews-test" }
func (fakeWSDecoder) MatchesWS(m decoders.WSMeta) bool { return m.Host == "wsdec.test" }
func (fakeWSDecoder) NewSession() decoders.Session     { return fakeWSSession{} }

type fakeWSSession struct{}

func (fakeWSSession) Feed(fromClient bool, data []byte) []decoders.Message {
	return []decoders.Message{{FromClient: fromClient, Opcode: "custom", Payload: append([]byte("D:"), data...)}}
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
	// Three messages: the raw binary frame (original bytes), its decoded form, and the text
	// frame. The raw + decoded let a caller query the original bytes via MCP.
	if len(msgs) != 3 {
		t.Fatalf("got %d ws messages, want 3: %+v", len(msgs), msgs)
	}
	var rawBin, decoded, text *WsMessage
	for _, m := range msgs {
		switch {
		case m.FromClient && m.Opcode == "binary":
			rawBin = m
		case m.FromClient && m.Opcode == "custom":
			decoded = m
		case !m.FromClient:
			text = m
		}
	}
	if rawBin == nil || string(rawBin.Payload) != "hello" {
		t.Errorf("raw binary frame (original bytes) missing: %+v", rawBin)
	}
	if decoded == nil || string(decoded.Payload) != "D:hello" {
		t.Errorf("binary frame not reframed by the decoder: %+v", decoded)
	}
	if text == nil || text.Opcode != "text" || string(text.Payload) != "world" {
		t.Errorf("text frame should pass through raw: %+v", text)
	}
}
