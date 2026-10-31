package decode

import (
	"bufio"
	"bytes"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

// feedHTTP drives one httpStream with request/response byte chunks and returns the
// final state of each emitted flow (keyed by id, last write wins), waiting for the
// async parser goroutine to finish.
func feedHTTP(t *testing.T, client, server []byte) []*Flow {
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
		snap := *f // the decoder goes on writing to f once onFlow returns
		latest[f.ID] = &snap
	}}
	s := &tcpStream{
		lt:         lt,
		serverHost: "203.0.113.5",
		serverPort: "443",
		clientAddr: "198.51.100.2:51000",
		conn:       tlsdecrypt.NewConn(tlsdecrypt.NewKeylog(""), nil),
	}
	h := newHTTPStream(s)
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

func TestLiveHTTPRequestResponse(t *testing.T) {
	client := []byte("GET /hi?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: probe/1\r\n\r\n")
	server := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")

	flows := feedHTTP(t, client, server)
	if len(flows) != 1 {
		t.Fatalf("got %d flows, want 1", len(flows))
	}
	f := flows[0]
	if f.Method != "GET" || f.Path != "/hi" || f.Query != "q=1" {
		t.Errorf("request line: method=%q path=%q query=%q", f.Method, f.Path, f.Query)
	}
	if f.Authority != "example.com" {
		t.Errorf("authority = %q, want example.com", f.Authority)
	}
	if f.UserAgent != "probe/1" {
		t.Errorf("user-agent = %q", f.UserAgent)
	}
	if !f.TLSDecrypted || f.Scheme != "https" || f.Protocol != "HTTP/1.1" {
		t.Errorf("meta: tls=%v scheme=%q proto=%q", f.TLSDecrypted, f.Scheme, f.Protocol)
	}
	if f.Status != 200 || f.ContentType != "text/plain" {
		t.Errorf("response: status=%d ct=%q", f.Status, f.ContentType)
	}
	if string(f.ResponseBody) != "hello" {
		t.Errorf("body = %q, want hello", f.ResponseBody)
	}
}

func TestLiveHTTPKeepAliveTwoExchanges(t *testing.T) {
	client := []byte("GET /a HTTP/1.1\r\nHost: h\r\n\r\n" +
		"GET /b HTTP/1.1\r\nHost: h\r\n\r\n")
	server := []byte("HTTP/1.1 204 No Content\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

	flows := feedHTTP(t, client, server)
	if len(flows) != 2 {
		t.Fatalf("got %d flows, want 2", len(flows))
	}
	if flows[0].Path != "/a" || flows[0].Status != 204 {
		t.Errorf("flow0: path=%q status=%d", flows[0].Path, flows[0].Status)
	}
	if flows[1].Path != "/b" || flows[1].Status != 200 || string(flows[1].ResponseBody) != "ok" {
		t.Errorf("flow1: path=%q status=%d body=%q", flows[1].Path, flows[1].Status, flows[1].ResponseBody)
	}
}

func wantHeaders(t *testing.T, side string, got []Header, want ...Header) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s headers\n got %v\nwant %v", side, got, want)
	}
}

// A client's header order and spelling identify it, so they are stored as sent — Host and
// Transfer-Encoding too, which net/http lifts out of its map, and repeats where they stood.
func TestLiveHTTPKeepsHeadersAsTheyWereOnTheWire(t *testing.T) {
	client := []byte("POST /up HTTP/1.1\r\nuser-agent: probe/1\r\nX-b: 2\r\nHOST: example.com\r\n" +
		"X-a: 1\r\nx-b: 3\r\nContent-Length: 2\r\n\r\nhi")
	server := []byte("HTTP/1.1 200 OK\r\nX-z: 1\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=1\r\n" +
		"Date: now\r\nSet-Cookie: b=2\r\n\r\n2\r\nok\r\n0\r\n\r\n")

	f := feedHTTP(t, client, server)[0]
	wantHeaders(t, "request", f.RequestHeaders,
		Header{"user-agent", "probe/1"}, Header{"X-b", "2"}, Header{"HOST", "example.com"},
		Header{"X-a", "1"}, Header{"x-b", "3"}, Header{"Content-Length", "2"})
	wantHeaders(t, "response", f.ResponseHeaders,
		Header{"X-z", "1"}, Header{"Transfer-Encoding", "chunked"}, Header{"Set-Cookie", "a=1"},
		Header{"Date", "now"}, Header{"Set-Cookie", "b=2"})
	if string(f.RequestBody) != "hi" || string(f.ResponseBody) != "ok" {
		t.Errorf("bodies = %q, %q", f.RequestBody, f.ResponseBody)
	}
}

// Each message on a kept-alive connection gets its own head, including one that begins in
// bytes the reader had already buffered, and a head longer than that buffer.
func TestLiveHTTPHeadsOnAKeptAliveConnectionStayApart(t *testing.T) {
	long := strings.Repeat("c", 10000)
	client := []byte("POST /a HTTP/1.1\r\nHost: a.example\r\nContent-Length: 1\r\n\r\nx" +
		"GET /b HTTP/1.1\r\nX-Long: " + long + "\r\nHost: b.example\r\n\r\n")
	server := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-First: 1\r\n\r\nx" +
		"HTTP/1.1 204 No Content\r\nX-Second: 2\r\n\r\n")

	flows := feedHTTP(t, client, server)
	if len(flows) != 2 {
		t.Fatalf("got %d flows, want 2", len(flows))
	}
	wantHeaders(t, "first request", flows[0].RequestHeaders,
		Header{"Host", "a.example"}, Header{"Content-Length", "1"})
	wantHeaders(t, "first response", flows[0].ResponseHeaders,
		Header{"Content-Length", "1"}, Header{"X-First", "1"})
	wantHeaders(t, "second request", flows[1].RequestHeaders,
		Header{"X-Long", long}, Header{"Host", "b.example"})
	wantHeaders(t, "second response", flows[1].ResponseHeaders, Header{"X-Second", "2"})
}

func TestParseWireHeaders(t *testing.T) {
	head := []byte("GET / HTTP/1.1\r\nA:  1 \r\nFolded: one\r\n\t two\r\nEmpty:\nB:2\r\n\r\nNot: this\r\n")
	wantHeaders(t, "parsed", parseWireHeaders(head),
		Header{"A", "1"}, Header{"Folded", "one two"}, Header{"Empty", ""}, Header{"B", "2"})
}

// A head of any size is kept whole, and its buffer is not held for the rest of a connection.
func TestAHugeHeadIsKeptWholeAndItsBufferReleased(t *testing.T) {
	big := strings.Repeat("c", 2<<20)
	head := []byte("GET / HTTP/1.1\r\nHost: a.example\r\nX-Big: " + big + "\r\nX-A: 1\r\n\r\n")
	w := &wireHead{r: bytes.NewReader(head)}
	br := bufio.NewReader(w)
	w.start(br)
	if _, err := http.ReadRequest(br); err != nil {
		t.Fatal(err)
	}
	wantHeaders(t, "request", w.headers(br),
		Header{"Host", "a.example"}, Header{"X-Big", big}, Header{"X-A", "1"})
	if cap(w.buf) > wireHeadKeep {
		t.Errorf("kept a %d byte buffer", cap(w.buf))
	}
}
