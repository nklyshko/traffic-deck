package decode

import "testing"

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
