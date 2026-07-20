package decode

import (
	"sync"
	"testing"
	"time"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

// feedProxyTunnel drives one tcpStream through a cleartext CONNECT handshake and then the
// tunnelled directional bytes, returning the flows it emits. A cleartext inner target keeps
// the test off TLS (no key-log); the TLS-inner path reuses the same route()/decryptor that
// the direct-TLS tests already cover.
func feedProxyTunnel(t *testing.T, wantFlows int, chunks []tunnelChunk) []*Flow {
	t.Helper()
	var mu sync.Mutex
	latest := map[string]*Flow{}
	var order []string
	lt := &liveTCP{
		onFlow: func(f *Flow, _ bool) {
			mu.Lock()
			defer mu.Unlock()
			if _, ok := latest[f.ID]; !ok {
				order = append(order, f.ID)
			}
			latest[f.ID] = f
		},
		onMsg: func(*WsMessage) {},
	}
	s := &tcpStream{
		lt:         lt,
		connID:     "0",
		serverHost: "10.0.0.9",
		serverPort: "8080",
		clientAddr: "10.0.0.1:55000",
	}
	s.conn = tlsdecrypt.NewConn(tlsdecrypt.NewKeylog(""), s.onApp)
	for _, c := range chunks {
		s.reassembled(c.fromClient, c.data)
	}
	s.ReassemblyComplete(nil)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := len(order) >= wantFlows && latest[order[len(order)-1]].Status != 0
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

type tunnelChunk struct {
	fromClient bool
	data       []byte
}

// TestLiveHTTPConnectTunnelDecodesInnerFlow: over an HTTP CONNECT proxy, the live decoder
// emits the CONNECT itself and then decodes the request tunnelled underneath — the exact
// case that previously showed only the CONNECT. Both flows carry the proxy (with decoded
// credentials); the inner flow keeps the real target as its authority.
func TestLiveHTTPConnectTunnelDecodesInnerFlow(t *testing.T) {
	flows := feedProxyTunnel(t, 2, []tunnelChunk{
		{true, []byte("CONNECT plain.example:80 HTTP/1.1\r\nHost: plain.example:80\r\n" +
			"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n")},
		{false, []byte("HTTP/1.1 200 Connection established\r\n\r\n")},
		{true, []byte("GET /v1 HTTP/1.1\r\nHost: plain.example\r\n\r\n")},
		{false, []byte("HTTP/1.1 204 No Content\r\n\r\n")},
	})

	if len(flows) != 2 {
		t.Fatalf("want 2 flows (CONNECT + tunnelled GET), got %d: %+v", len(flows), flows)
	}
	connect, inner := flows[0], flows[1]
	if connect.Method != "CONNECT" || connect.Authority != "plain.example:80" {
		t.Errorf("CONNECT flow = %s %q", connect.Method, connect.Authority)
	}
	if inner.Method != "GET" || inner.Authority != "plain.example" || inner.Status != 204 {
		t.Errorf("inner flow = %s %q status=%d", inner.Method, inner.Authority, inner.Status)
	}
	for _, f := range flows {
		if f.Proxy == nil {
			t.Fatalf("%s flow has no proxy attached", f.Method)
		}
		if f.Proxy.Addr != "10.0.0.9:8080" || f.Proxy.Type != "http" {
			t.Errorf("%s flow proxy = %+v", f.Method, f.Proxy)
		}
		if f.Proxy.Username != "user" || f.Proxy.Password != "pass" {
			t.Errorf("%s flow creds = %q/%q", f.Method, f.Proxy.Username, f.Proxy.Password)
		}
	}
}

// A CONNECT the proxy refuses (407) is emitted, but nothing is tunnelled — the connection
// stays in the handshake phase for a retry rather than mis-decoding the next bytes.
func TestLiveHTTPConnectTunnelProxyRefused(t *testing.T) {
	flows := feedProxyTunnel(t, 1, []tunnelChunk{
		{true, []byte("CONNECT plain.example:80 HTTP/1.1\r\nHost: plain.example:80\r\n\r\n")},
		{false, []byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")},
	})
	if len(flows) != 1 || flows[0].Method != "CONNECT" || flows[0].Status != 407 {
		t.Fatalf("want a single 407 CONNECT flow, got %+v", flows)
	}
	if flows[0].Proxy == nil || flows[0].Proxy.Addr != "10.0.0.9:8080" {
		t.Errorf("refused CONNECT should still record the proxy, got %+v", flows[0].Proxy)
	}
}

// TestDetectHTTPConnectProxy: a CONNECT request marks the stream as proxied (with
// decoded Basic credentials), and a later decrypted flow on the same TCP stream
// inherits the proxy.
func TestDetectHTTPConnectProxy(t *testing.T) {
	ds := &Dataset{}
	st := newStitcher(ds, nil)

	// CONNECT api.example.com:443 through proxy 10.0.0.9:8080 with Basic user:pass.
	st.add(layers{
		fTCPStream: {"3"}, fFrameNum: {"1"}, fFrameTime: {"100.0"},
		fIPSrc: {"10.0.0.1"}, fTCPSrcPort: {"55000"},
		fIPDst: {"10.0.0.9"}, fTCPDstPort: {"8080"},
		fH1Method: {"CONNECT"}, fH1URI: {"api.example.com:443"},
		"http.request.line": {"Proxy-Authorization: Basic dXNlcjpwYXNz", "Host: api.example.com:443"},
	})
	// A decrypted HTTP/2 request on the same tunnel (same tcp.stream).
	st.add(layers{
		fTCPStream: {"3"}, fH2StreamID: {"1"}, fFrameNum: {"2"}, fFrameTime: {"101.0"},
		fIPSrc: {"10.0.0.1"}, fTCPSrcPort: {"55000"},
		fIPDst: {"10.0.0.9"}, fTCPDstPort: {"8080"},
		fH2Method: {"GET"}, fH2Authority: {"api.example.com"}, fH2Path: {"/v1"},
	})

	if len(ds.Flows) != 2 {
		t.Fatalf("want 2 flows, got %d", len(ds.Flows))
	}
	for i, f := range ds.Flows {
		if f.Proxy == nil {
			t.Fatalf("flow %d has no proxy", i)
		}
		if f.Proxy.Addr != "10.0.0.9:8080" || f.Proxy.Type != "http" {
			t.Fatalf("flow %d proxy = %+v", i, f.Proxy)
		}
		if f.Proxy.Username != "user" || f.Proxy.Password != "pass" {
			t.Fatalf("flow %d creds = %q/%q", i, f.Proxy.Username, f.Proxy.Password)
		}
	}
	// The inner request's real target is preserved separately from the proxy.
	if ds.Flows[1].Authority != "api.example.com" {
		t.Fatalf("inner authority = %q", ds.Flows[1].Authority)
	}
}

// TestDetectSocksProxy: a SOCKS5 handshake (with user/pass auth) marks the stream,
// and a flow on that stream inherits the proxy.
func TestDetectSocksProxy(t *testing.T) {
	ds := &Dataset{}
	st := newStitcher(ds, nil)

	st.addPacket(layers{
		fTCPStream: {"7"}, fSocksVersion: {"5"},
		fIPSrc: {"10.0.0.1"}, fTCPSrcPort: {"55001"},
		fIPDst: {"10.0.0.20"}, fTCPDstPort: {"1080"},
		fSocksUsername: {"bob"}, fSocksPassword: {"secret"},
	})
	st.add(layers{
		fTCPStream: {"7"}, fH2StreamID: {"1"}, fFrameNum: {"1"}, fFrameTime: {"1.0"},
		fIPSrc: {"10.0.0.1"}, fTCPSrcPort: {"55001"},
		fIPDst: {"10.0.0.20"}, fTCPDstPort: {"1080"},
		fH2Method: {"GET"}, fH2Authority: {"chat.example.com"}, fH2Path: {"/"},
	})

	if len(ds.Flows) != 1 || ds.Flows[0].Proxy == nil {
		t.Fatalf("flows=%d proxy missing", len(ds.Flows))
	}
	p := ds.Flows[0].Proxy
	if p.Type != "socks" || p.Addr != "10.0.0.20:1080" || p.Username != "bob" || p.Password != "secret" {
		t.Fatalf("socks proxy = %+v", p)
	}
}

// TestNoProxyForDirectFlow: a plain flow with no CONNECT/SOCKS on its stream has no proxy.
func TestNoProxyForDirectFlow(t *testing.T) {
	ds := &Dataset{}
	st := newStitcher(ds, nil)
	st.add(layers{
		fTCPStream: {"9"}, fH2StreamID: {"1"}, fFrameNum: {"1"}, fFrameTime: {"1.0"},
		fIPSrc: {"10.0.0.1"}, fTCPSrcPort: {"40000"},
		fIPDst: {"93.184.216.34"}, fTCPDstPort: {"443"},
		fH2Method: {"GET"}, fH2Authority: {"example.com"}, fH2Path: {"/"},
	})
	if len(ds.Flows) != 1 || ds.Flows[0].Proxy != nil {
		t.Fatalf("unexpected proxy on direct flow: %+v", ds.Flows[0].Proxy)
	}
}
