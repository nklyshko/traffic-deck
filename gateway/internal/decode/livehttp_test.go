package decode

import (
	"sync"
	"testing"
	"time"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
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
		latest[f.ID] = f
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
