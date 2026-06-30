package decode

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

func h2encode(fields ...hpack.HeaderField) []byte {
	var b bytes.Buffer
	enc := hpack.NewEncoder(&b)
	for _, f := range fields {
		_ = enc.WriteField(f)
	}
	return b.Bytes()
}

// feedH2 drives one h2Stream with client/server byte streams and returns the final
// state of each emitted flow (keyed by id, last write wins).
func feedH2(t *testing.T, client, server []byte) []*Flow {
	t.Helper()
	var mu sync.Mutex
	latest := map[string]*Flow{}
	var order []string
	lt := &liveTCP{onFlow: func(f *Flow, isNew bool) {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := latest[f.ID]; !ok {
			order = append(order, f.ID)
		}
		latest[f.ID] = f
	}}
	s := &tcpStream{
		lt:         lt,
		serverHost: "203.0.113.5",
		serverPort: "443",
		clientAddr: "198.51.100.2:51000",
		conn:       tlsdecrypt.NewConn(tlsdecrypt.NewKeylog(""), nil),
	}
	h := newH2Stream(s)
	h.feed(true, client)
	h.feed(false, server)
	h.close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := len(order) > 0 && latest[order[len(order)-1]].Status != 0
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	out := make([]*Flow, 0, len(order))
	for _, id := range order {
		out = append(out, latest[id])
	}
	return out
}

func TestLiveHTTP2RequestResponse(t *testing.T) {
	var cbuf bytes.Buffer
	cbuf.WriteString(http2.ClientPreface)
	cf := http2.NewFramer(&cbuf, nil)
	if err := cf.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := cf.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1,
		BlockFragment: h2encode(
			hpack.HeaderField{Name: ":method", Value: "GET"},
			hpack.HeaderField{Name: ":scheme", Value: "https"},
			hpack.HeaderField{Name: ":authority", Value: "example.com"},
			hpack.HeaderField{Name: ":path", Value: "/h2?x=1"},
			hpack.HeaderField{Name: "user-agent", Value: "probe/2"},
		),
		EndStream:  true,
		EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}

	var sbuf bytes.Buffer
	sf := http2.NewFramer(&sbuf, nil)
	if err := sf.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := sf.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1,
		BlockFragment: h2encode(
			hpack.HeaderField{Name: ":status", Value: "200"},
			hpack.HeaderField{Name: "content-type", Value: "application/json"},
		),
		EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sf.WriteData(1, true, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}

	flows := feedH2(t, cbuf.Bytes(), sbuf.Bytes())
	if len(flows) != 1 {
		t.Fatalf("got %d flows, want 1", len(flows))
	}
	f := flows[0]
	if f.Protocol != "HTTP/2" || f.H2StreamID != "1" {
		t.Errorf("proto=%q h2stream=%q", f.Protocol, f.H2StreamID)
	}
	if f.Method != "GET" || f.Path != "/h2" || f.Query != "x=1" || f.Authority != "example.com" {
		t.Errorf("req: method=%q path=%q query=%q authority=%q", f.Method, f.Path, f.Query, f.Authority)
	}
	if f.UserAgent != "probe/2" || !f.TLSDecrypted {
		t.Errorf("meta: ua=%q tls=%v", f.UserAgent, f.TLSDecrypted)
	}
	if f.Status != 200 || f.ContentType != "application/json" {
		t.Errorf("resp: status=%d ct=%q", f.Status, f.ContentType)
	}
	if string(f.ResponseBody) != `{"ok":true}` {
		t.Errorf("body=%q", f.ResponseBody)
	}
}
