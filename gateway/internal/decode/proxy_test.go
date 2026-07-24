package decode

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	gplayers "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

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
		s.reassembled(c.fromClient, c.data, c.ts)
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
	ts         time.Time
}

// feedTunnelStream drives one tcpStream through the given chunks and returns it, for the
// tests that assert on the connection's own state (dropped, re-classified) rather than on
// the flows it emits.
func feedTunnelStream(t *testing.T, chunks []tunnelChunk) *tcpStream {
	t.Helper()
	lt := &liveTCP{onFlow: func(*Flow, bool) {}, onMsg: func(*WsMessage) {}}
	s := &tcpStream{
		lt:         lt,
		connID:     "0",
		serverHost: "10.0.0.9",
		serverPort: "8080",
		clientAddr: "10.0.0.1:55000",
	}
	s.conn = tlsdecrypt.NewConn(tlsdecrypt.NewKeylog(""), s.onApp)
	for _, c := range chunks {
		s.reassembled(c.fromClient, c.data, c.ts)
	}
	s.ReassemblyComplete(nil)
	return s
}

// buildTunnelPcap writes the chunks as an Ethernet/IPv4/TCP capture, one packet each, in
// order — so a lock-step proxy handshake keeps the interleaving it has on the wire (unlike
// buildPcap, which emits one direction after the other).
func buildTunnelPcap(t *testing.T, chunks []tunnelChunk) []byte {
	t.Helper()
	var out bytes.Buffer
	w := pcapgo.NewWriter(&out)
	if err := w.WriteFileHeader(65535, gplayers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	cli, srv := net.IP{10, 0, 0, 1}, net.IP{10, 0, 0, 2}
	seq := map[bool]uint32{true: 1000, false: 5000}
	for _, c := range chunks {
		src, dst := cli, srv
		sport, dport := gplayers.TCPPort(40000), gplayers.TCPPort(1080)
		if !c.fromClient {
			src, dst, sport, dport = srv, cli, dport, sport
		}
		eth := &gplayers.Ethernet{
			SrcMAC: net.HardwareAddr{1, 1, 1, 1, 1, 1}, DstMAC: net.HardwareAddr{2, 2, 2, 2, 2, 2},
			EthernetType: gplayers.EthernetTypeIPv4,
		}
		ip := &gplayers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: gplayers.IPProtocolTCP, SrcIP: src, DstIP: dst}
		tcp := &gplayers.TCP{SrcPort: sport, DstPort: dport, Seq: seq[c.fromClient], ACK: true, PSH: true, Window: 65535}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
			eth, ip, tcp, gopacket.Payload(c.data)); err != nil {
			t.Fatal(err)
		}
		data := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp: c.ts, CaptureLength: len(data), Length: len(data)}, data); err != nil {
			t.Fatal(err)
		}
		seq[c.fromClient] += uint32(len(c.data))
	}
	return out.Bytes()
}

// TestLiveTCPDecodeSocks5EndToEnd runs a SOCKS5 tunnel through the whole live pipeline —
// pcap reader, gopacket reassembly, the packet loop — rather than driving the stream
// directly, so the handshake is parsed from real per-segment reassembly.
func TestLiveTCPDecodeSocks5EndToEnd(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	at := func(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }
	pcap := buildTunnelPcap(t, []tunnelChunk{
		{true, socks5Greeting(socksAuthNone, socksAuthUserPass), at(0)},
		{false, socks5Choice(socksAuthUserPass), at(1)},
		{true, socks5UserPass("bob", "secret"), at(2)},
		{false, []byte{0x01, 0x00}, at(3)},
		{true, socks5Connect("plain.example", 80), at(4)},
		{false, socks5Reply(socksRepSucceeded), at(5)},
		{true, []byte("GET /through-socks HTTP/1.1\r\nHost: plain.example\r\n\r\n"), at(6)},
		{false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"), at(7)},
	})

	var mu sync.Mutex
	latest := map[string]*Flow{}
	if err := LiveTCPDecode(bytes.NewReader(pcap), "",
		func(f *Flow, _ bool) { mu.Lock(); latest[f.ID] = f; mu.Unlock() },
		func(*WsMessage) {}, true); err != nil {
		t.Fatalf("LiveTCPDecode: %v", err)
	}

	// The HTTP parser drains in its own goroutine after the stream closes; wait for the
	// response to land.
	var f *Flow
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && f == nil {
		mu.Lock()
		for _, x := range latest {
			if x.Status != 0 {
				f = x
			}
		}
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	if f == nil {
		t.Fatal("no flow decoded from the SOCKS5 tunnel")
	}
	if f.Method != "GET" || f.Path != "/through-socks" || f.Status != 200 || string(f.ResponseBody) != "hi" {
		t.Errorf("flow = %s %s status=%d body=%q", f.Method, f.Path, f.Status, f.ResponseBody)
	}
	if f.Proxy == nil {
		t.Fatal("tunnelled flow has no proxy attached")
	}
	if f.Proxy.Type != "socks" || f.Proxy.Addr != "10.0.0.2:1080" ||
		f.Proxy.Username != "bob" || f.Proxy.Password != "secret" {
		t.Errorf("proxy = %+v", f.Proxy)
	}
	if f.DstAddr != "plain.example:80" {
		t.Errorf("dst = %q, want the SOCKS target", f.DstAddr)
	}
}

// SOCKS message builders — the handshake bytes as they appear on the wire.

func socks5Greeting(methods ...byte) []byte {
	return append([]byte{socksV5, byte(len(methods))}, methods...)
}

func socks5Choice(method byte) []byte { return []byte{socksV5, method} }

func socks5UserPass(user, pass string) []byte {
	b := []byte{0x01, byte(len(user))}
	b = append(b, user...)
	b = append(b, byte(len(pass)))
	return append(b, pass...)
}

// socks5Connect is a CONNECT request for a domain target (ATYP 0x03).
func socks5Connect(host string, port uint16) []byte {
	b := []byte{socksV5, socksCmdConnect, 0x00, socksAddrDomain, byte(len(host))}
	b = append(b, host...)
	return append(b, byte(port>>8), byte(port))
}

// socks5Reply is a reply carrying the proxy's bound address (0.0.0.0:8080).
func socks5Reply(rep byte) []byte {
	return []byte{socksV5, rep, 0x00, socksAddrIPv4, 0, 0, 0, 0, 0x1f, 0x90}
}

// socks4Request builds a SOCKS4 request; a non-empty domain makes it SOCKS4a (the
// placeholder IP 0.0.0.1 tells the proxy the real target is the trailing hostname).
func socks4Request(port uint16, ip []byte, user, domain string) []byte {
	b := []byte{socksV4, socksCmdConnect, byte(port >> 8), byte(port)}
	b = append(b, ip...)
	b = append(b, user...)
	b = append(b, 0)
	if domain != "" {
		b = append(b, domain...)
		b = append(b, 0)
	}
	return b
}

func socks4Reply(cd byte) []byte {
	return []byte{0x00, cd, 0x1f, 0x90, 0, 0, 0, 0}
}

// TestLiveSocks5TunnelDecodesInnerFlow: over a SOCKS5 proxy (no authentication), the live
// decoder decodes the request tunnelled underneath the handshake. The handshake itself
// carries no request, so it emits no flow of its own — only the proxy it stamps on the
// tunnel's flows, which keep the real target as their authority.
func TestLiveSocks5TunnelDecodesInnerFlow(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	at := func(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }
	flows := feedProxyTunnel(t, 1, []tunnelChunk{
		{true, socks5Greeting(socksAuthNone), at(0)},
		{false, socks5Choice(socksAuthNone), at(1)},
		{true, socks5Connect("plain.example", 80), at(2)},
		{false, socks5Reply(socksRepSucceeded), at(3)},
		{true, []byte("GET /v1 HTTP/1.1\r\nHost: plain.example\r\n\r\n"), at(4)},
		{false, []byte("HTTP/1.1 204 No Content\r\n\r\n"), at(54)},
	})

	if len(flows) != 1 {
		t.Fatalf("want 1 flow (the tunnelled GET), got %d: %+v", len(flows), flows)
	}
	f := flows[0]
	if f.Method != "GET" || f.Authority != "plain.example" || f.Status != 204 {
		t.Errorf("inner flow = %s %q status=%d", f.Method, f.Authority, f.Status)
	}
	if f.Proxy == nil {
		t.Fatalf("tunnelled flow has no proxy attached")
	}
	if f.Proxy.Type != "socks" || f.Proxy.Addr != "10.0.0.9:8080" {
		t.Errorf("proxy = %+v", f.Proxy)
	}
	if f.Proxy.Username != "" || f.Proxy.Password != "" {
		t.Errorf("unauthenticated SOCKS5 should carry no credentials, got %+v", f.Proxy)
	}
	// The tunnel's destination is the real target, not the proxy we connected to.
	if f.DstAddr != "plain.example:80" {
		t.Errorf("inner flow dst = %q, want the SOCKS target", f.DstAddr)
	}
	// Duration comes from packet capture time (54ms - 4ms), not decode wall-clock.
	if f.DurationMicros != 50_000 {
		t.Errorf("inner duration = %dµs, want 50000 (from packet timestamps)", f.DurationMicros)
	}
}

// TestLiveSocks5UserPassTunnel: the RFC 1929 username/password subnegotiation is decoded
// into the proxy's credentials. Both directions also carry handshake and tunnelled bytes
// coalesced into one segment, so the leftovers past the handshake must be re-routed.
func TestLiveSocks5UserPassTunnel(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	at := func(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }
	get := []byte("GET / HTTP/1.1\r\nHost: plain.example\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	flows := feedProxyTunnel(t, 1, []tunnelChunk{
		{true, socks5Greeting(socksAuthNone, socksAuthUserPass), at(0)},
		{false, socks5Choice(socksAuthUserPass), at(1)},
		{true, socks5UserPass("bob", "secret"), at(2)},
		{false, []byte{0x01, 0x00}, at(3)},
		{true, append(socks5Connect("plain.example", 80), get...), at(4)}, // request + tunnelled bytes
		{false, append(socks5Reply(socksRepSucceeded), resp...), at(5)},   // reply + tunnelled bytes
	})

	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %d: %+v", len(flows), flows)
	}
	f := flows[0]
	if f.Method != "GET" || f.Authority != "plain.example" || f.Status != 200 {
		t.Errorf("inner flow = %s %q status=%d", f.Method, f.Authority, f.Status)
	}
	if f.Proxy == nil || f.Proxy.Type != "socks" || f.Proxy.Addr != "10.0.0.9:8080" {
		t.Fatalf("proxy = %+v", f.Proxy)
	}
	if f.Proxy.Username != "bob" || f.Proxy.Password != "secret" {
		t.Errorf("proxy creds = %q/%q, want bob/secret", f.Proxy.Username, f.Proxy.Password)
	}
}

// TestLiveSocks4aTunnel: a SOCKS4a handshake (hostname target + user id) establishes the
// tunnel and the request underneath decodes, with the user id recorded as the credential
// SOCKS4 offers.
func TestLiveSocks4aTunnel(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	at := func(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }
	flows := feedProxyTunnel(t, 1, []tunnelChunk{
		{true, socks4Request(80, []byte{0, 0, 0, 1}, "td", "plain.example"), at(0)},
		{false, socks4Reply(socksV4Granted), at(1)},
		{true, []byte("GET /v4 HTTP/1.1\r\nHost: plain.example\r\n\r\n"), at(2)},
		{false, []byte("HTTP/1.1 204 No Content\r\n\r\n"), at(3)},
	})

	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %d: %+v", len(flows), flows)
	}
	f := flows[0]
	if f.Method != "GET" || f.Path != "/v4" || f.Status != 204 {
		t.Errorf("inner flow = %s %q status=%d", f.Method, f.Path, f.Status)
	}
	if f.Proxy == nil || f.Proxy.Type != "socks" || f.Proxy.Addr != "10.0.0.9:8080" {
		t.Fatalf("proxy = %+v", f.Proxy)
	}
	if f.Proxy.Username != "td" {
		t.Errorf("proxy user = %q, want the SOCKS4 user id", f.Proxy.Username)
	}
	// SOCKS4a: the hostname past the user id is the target, not the 0.0.0.1 placeholder.
	if f.DstAddr != "plain.example:80" {
		t.Errorf("inner flow dst = %q, want the SOCKS4a hostname target", f.DstAddr)
	}
}

// TestLiveSocks5PlainIPv4Target: a request for a literal IPv4 target (ATYP 0x01) resolves
// to that address — the common case for a client that resolves DNS itself.
func TestLiveSocks5PlainIPv4Target(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	req := []byte{socksV5, socksCmdConnect, 0x00, socksAddrIPv4, 93, 184, 216, 34, 0x00, 0x50}
	flows := feedProxyTunnel(t, 1, []tunnelChunk{
		{true, socks5Greeting(socksAuthNone), base},
		{false, socks5Choice(socksAuthNone), base},
		{true, req, base},
		{false, socks5Reply(socksRepSucceeded), base},
		{true, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), base},
		{false, []byte("HTTP/1.1 204 No Content\r\n\r\n"), base},
	})
	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %d: %+v", len(flows), flows)
	}
	if flows[0].DstAddr != "93.184.216.34:80" {
		t.Errorf("inner flow dst = %q", flows[0].DstAddr)
	}
}

// A SOCKS5 CONNECT the proxy refuses carries nothing underneath, so the connection is
// dropped rather than having its next bytes mis-decoded — and no flow is emitted.
func TestLiveSocks5Refused(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	var flows []*Flow
	lt := &liveTCP{onFlow: func(f *Flow, _ bool) { flows = append(flows, f) }, onMsg: func(*WsMessage) {}}
	s := &tcpStream{lt: lt, connID: "0", serverHost: "10.0.0.9", serverPort: "8080", clientAddr: "10.0.0.1:55000"}
	s.conn = tlsdecrypt.NewConn(tlsdecrypt.NewKeylog(""), s.onApp)
	for _, c := range []tunnelChunk{
		{true, socks5Greeting(socksAuthNone), base},
		{false, socks5Choice(socksAuthNone), base},
		{true, socks5Connect("blocked.example", 443), base},
		{false, socks5Reply(0x02), base}, // connection not allowed by ruleset
	} {
		s.reassembled(c.fromClient, c.data, c.ts)
	}
	if len(flows) != 0 {
		t.Fatalf("a refused SOCKS handshake should emit no flow, got %+v", flows)
	}
	if !s.dropped || s.socks != nil {
		t.Errorf("refused handshake: dropped=%v socks=%+v, want dropped with the handshake cleared",
			s.dropped, s.socks)
	}
}

// A SOCKS5 proxy that accepts none of the offered methods likewise leaves nothing to
// decode on the connection.
func TestLiveSocks5NoAcceptableMethods(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	s := feedTunnelStream(t, []tunnelChunk{
		{true, socks5Greeting(socksAuthNone), base},
		{false, socks5Choice(socksNoAcceptable), base},
	})
	if !s.dropped {
		t.Errorf("a proxy refusing every method should drop the connection")
	}
	if s.proxy != nil {
		t.Errorf("no tunnel was established, so no proxy should be stamped: %+v", s.proxy)
	}
}

// TestLiveSocksLookalikeFallsBack: bytes that open like a greeting but whose peer never
// answers as a proxy aren't SOCKS — the connection is handed back to the normal
// classification (with its bytes intact) rather than dropped, so a binary protocol that
// happens to start 0x05 still reaches its decoder.
func TestLiveSocksLookalikeFallsBack(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	s := feedTunnelStream(t, []tunnelChunk{
		{true, []byte{0x05, 0x01, 0x00}, base},
		{false, []byte{0x99, 0x01, 0x02, 0x03}, base}, // not a SOCKS5 method selection
	})
	if s.dropped {
		t.Fatalf("a SOCKS lookalike should not drop the connection")
	}
	if s.socks != nil || s.proxy != nil {
		t.Errorf("handshake should be abandoned: socks=%+v proxy=%+v", s.socks, s.proxy)
	}
	if !s.decided {
		t.Errorf("buffered bytes should have been replayed into classification")
	}
}

// A lookalike whose peer never answers must not buffer the connection's whole byte stream
// waiting for a handshake that isn't coming: past the handshake bound it is handed back to
// normal classification with its bytes intact.
func TestLiveSocksLookalikeStopsBuffering(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	s := feedTunnelStream(t, []tunnelChunk{
		{true, []byte{0x05, 0x01, 0x00}, base},
		{true, bytes.Repeat([]byte{0xab}, socksMaxHandshake+1), base},
	})
	if s.dropped || s.socks != nil {
		t.Fatalf("lookalike should be abandoned, not dropped: dropped=%v socks=%+v", s.dropped, s.socks)
	}
	if !s.decided {
		t.Errorf("buffered bytes should have been replayed into classification")
	}
}

func TestLooksLikeSocks(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int
	}{
		{"socks5 greeting", []byte{0x05, 0x01, 0x00}, socksV5},
		{"socks5 two methods", []byte{0x05, 0x02, 0x00, 0x02}, socksV5},
		{"socks5 partial greeting", []byte{0x05, 0x02, 0x00}, socksV5},
		{"socks5 with trailing bytes", []byte{0x05, 0x01, 0x00, 0x41, 0x42}, 0},
		{"socks5 no methods", []byte{0x05, 0x00}, 0},
		{"socks5 method 0xff", []byte{0x05, 0x01, 0xff}, 0},
		{"socks4 connect", socks4Request(443, []byte{93, 184, 216, 34}, "td", ""), socksV4},
		{"socks4a connect", socks4Request(80, []byte{0, 0, 0, 1}, "", "plain.example"), socksV4},
		{"socks4 bind", []byte{0x04, 0x02, 0x01, 0xbb, 93, 184, 216, 34, 0x00}, 0},
		{"socks4 port 0", []byte{0x04, 0x01, 0x00, 0x00, 93, 184, 216, 34, 0x00}, 0},
		{"socks4 too short", []byte{0x04, 0x01, 0x01, 0xbb}, 0},
		{"http request", []byte("GET / HTTP/1.1\r\n"), 0},
		{"empty", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeSocks(tt.in); got != tt.want {
				t.Errorf("looksLikeSocks(%v) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestSocksAddr(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		addr string
		n    int
		ok   bool
	}{
		{"ipv4", []byte{socksAddrIPv4, 93, 184, 216, 34, 0x01, 0xbb}, "93.184.216.34:443", 7, true},
		{"domain", append([]byte{socksAddrDomain, 3, 'a', '.', 'b'}, 0x00, 0x50), "a.b:80", 7, true},
		{"ipv6", append(append([]byte{socksAddrIPv6}, net.ParseIP("2001:db8::1").To16()...), 0x01, 0xbb),
			"[2001:db8::1]:443", 19, true},
		{"truncated ipv4", []byte{socksAddrIPv4, 93, 184}, "", 0, true},
		{"truncated domain", []byte{socksAddrDomain, 9, 'a'}, "", 0, true},
		{"empty", nil, "", 0, true},
		{"unknown atyp", []byte{0x07, 1, 2, 3}, "", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, n, ok := socksAddr(tt.in)
			if addr != tt.addr || n != tt.n || ok != tt.ok {
				t.Errorf("socksAddr = (%q, %d, %v), want (%q, %d, %v)", addr, n, ok, tt.addr, tt.n, tt.ok)
			}
		})
	}
}

// TestLiveHTTPConnectTunnelDecodesInnerFlow: over an HTTP CONNECT proxy, the live decoder
// emits the CONNECT itself and then decodes the request tunnelled underneath — the exact
// case that previously showed only the CONNECT. Both flows carry the proxy (with decoded
// credentials); the inner flow keeps the real target as its authority.
func TestLiveHTTPConnectTunnelDecodesInnerFlow(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	flows := feedProxyTunnel(t, 2, []tunnelChunk{
		{true, []byte("CONNECT plain.example:80 HTTP/1.1\r\nHost: plain.example:80\r\n" +
			"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"), base},
		{false, []byte("HTTP/1.1 200 Connection established\r\n\r\n"), base.Add(1 * time.Millisecond)},
		{true, []byte("GET /v1 HTTP/1.1\r\nHost: plain.example\r\n\r\n"), base.Add(2 * time.Millisecond)},
		{false, []byte("HTTP/1.1 204 No Content\r\n\r\n"), base.Add(52 * time.Millisecond)},
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
	// Duration comes from packet capture time (52ms - 2ms), not decode wall-clock (~0).
	if inner.DurationMicros != 50_000 {
		t.Errorf("inner duration = %dµs, want 50000 (from packet timestamps)", inner.DurationMicros)
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
	base := time.Unix(1_700_000_000, 0)
	flows := feedProxyTunnel(t, 1, []tunnelChunk{
		{true, []byte("CONNECT plain.example:80 HTTP/1.1\r\nHost: plain.example:80\r\n\r\n"), base},
		{false, []byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"), base.Add(time.Millisecond)},
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
