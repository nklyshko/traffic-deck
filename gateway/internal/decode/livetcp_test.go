package decode

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	gplayers "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"gitlab.com/nklyshko/traffic-deck/gateway/decoders"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlstest"
)

// --- a trivial length-prefixed test protocol + decoder (registered for this test) ---

type echoDecoder struct{}

func (echoDecoder) Name() string { return "echotest" }
func (echoDecoder) Matches(m decoders.StreamMeta) bool {
	return bytes.Contains([]byte(m.SNI), []byte("echo"))
}
func (echoDecoder) NewSession() decoders.Session { return &echoSession{bufs: map[bool][]byte{}} }

type echoSession struct{ bufs map[bool][]byte }

// Feed frames messages of [uint16 length][payload], buffering across calls.
func (s *echoSession) Feed(fromClient bool, data []byte) []decoders.Message {
	buf := append(s.bufs[fromClient], data...)
	var out []decoders.Message
	for len(buf) >= 2 {
		l := int(binary.BigEndian.Uint16(buf[:2]))
		if len(buf) < 2+l {
			break
		}
		out = append(out, decoders.Message{FromClient: fromClient, Opcode: "echo", Payload: append([]byte(nil), buf[2:2+l]...)})
		buf = buf[2+l:]
	}
	s.bufs[fromClient] = buf
	return out
}

func frameMsg(p []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(p))), p...)
}

// TestLiveTCPDecodeEndToEnd runs a real TLS 1.3 exchange of the echo protocol over
// localhost, writes the wire bytes into a synthetic Ethernet/IPv4/TCP pcap, and runs
// LiveTCPDecode over it (gopacket reassembly + Go TLS decryption + decoder), asserting
// the decoded messages match what was sent.
func TestLiveTCPDecodeEndToEnd(t *testing.T) {
	decoders.Register(echoDecoder{})

	clientMsgs := [][]byte{[]byte("alpha"), []byte("beta"), []byte("gamma")}
	serverMsgs := [][]byte{[]byte("RESP-1"), bytes.Repeat([]byte("Z"), 40000)} // multi-record

	var clientApp, serverApp []byte
	for _, m := range clientMsgs {
		clientApp = append(clientApp, frameMsg(m)...)
	}
	for _, m := range serverMsgs {
		serverApp = append(serverApp, frameMsg(m)...)
	}

	c2s, s2c, keylog := tlstest.Exchange(t, "svc.echo.test", clientApp, serverApp)

	dir := t.TempDir()
	klPath := filepath.Join(dir, "key.log")
	if err := os.WriteFile(klPath, keylog, 0o644); err != nil {
		t.Fatal(err)
	}
	pcap := buildPcap(t, c2s, s2c)

	var mu sync.Mutex
	var flows []*Flow
	var got [][2]string // {direction, payload}
	err := LiveTCPDecode(bytes.NewReader(pcap), klPath,
		func(f *Flow, isNew bool) {
			if isNew {
				mu.Lock()
				flows = append(flows, f)
				mu.Unlock()
			}
		},
		func(m *WsMessage) {
			mu.Lock()
			d := "S"
			if m.FromClient {
				d = "C"
			}
			got = append(got, [2]string{d, string(m.Payload)})
			mu.Unlock()
		})
	if err != nil {
		t.Fatalf("LiveTCPDecode: %v", err)
	}

	if len(flows) != 1 || flows[0].Protocol != "ECHOTEST" || flows[0].Authority != "svc.echo.test" {
		t.Fatalf("flow = %+v", flows)
	}
	want := [][2]string{
		{"C", "alpha"}, {"C", "beta"}, {"C", "gamma"},
		{"S", "RESP-1"}, {"S", string(serverMsgs[1])},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d messages, want %d: %+v", len(got), len(want), summarize(got))
	}
	for i := range want {
		if got[i][0] != want[i][0] || got[i][1] != want[i][1] {
			t.Fatalf("msg %d = {%s,%dB}, want {%s,%dB}", i, got[i][0], len(got[i][1]), want[i][0], len(want[i][1]))
		}
	}
}

func summarize(got [][2]string) []string {
	out := make([]string, len(got))
	for i, g := range got {
		out[i] = g[0]
	}
	return out
}

// buildPcap wraps the two directional byte streams into Ethernet/IPv4/TCP packets
// (segmented at ~1200 bytes) and writes a classic pcap. Client packets are emitted
// first so reassembly treats the connecting side as the client.
func buildPcap(t *testing.T, c2s, s2c []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := pcapgo.NewWriter(&out)
	if err := w.WriteFileHeader(65535, gplayers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	cli := net.IP{10, 0, 0, 1}
	srv := net.IP{10, 0, 0, 2}
	emit := func(payload []byte, src, dst net.IP, sport, dport gplayers.TCPPort, seq uint32) {
		for off := 0; off < len(payload); off += 1200 {
			end := off + 1200
			if end > len(payload) {
				end = len(payload)
			}
			seg := payload[off:end]
			eth := &gplayers.Ethernet{SrcMAC: net.HardwareAddr{1, 1, 1, 1, 1, 1}, DstMAC: net.HardwareAddr{2, 2, 2, 2, 2, 2}, EthernetType: gplayers.EthernetTypeIPv4}
			ip := &gplayers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: gplayers.IPProtocolTCP, SrcIP: src, DstIP: dst}
			tcp := &gplayers.TCP{SrcPort: sport, DstPort: dport, Seq: seq + uint32(off), ACK: true, PSH: true, Window: 65535}
			_ = tcp.SetNetworkLayerForChecksum(ip)
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
				eth, ip, tcp, gopacket.Payload(seg)); err != nil {
				t.Fatal(err)
			}
			data := buf.Bytes()
			if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(data), Length: len(data)}, data); err != nil {
				t.Fatal(err)
			}
		}
	}
	emit(c2s, cli, srv, 40000, 443, 1000)
	emit(s2c, srv, cli, 443, 40000, 5000)
	return out.Bytes()
}

// TestLiveTCPDecodeNFLOG is the Android path: the same TLS 1.3 echo exchange wrapped in
// LINKTYPE_NFLOG records (as `tcpdump -i nflog:` produces), decoded by LiveTCPDecode.
func TestLiveTCPDecodeNFLOG(t *testing.T) {
	decoders.Register(echoDecoder{})
	clientApp := frameMsg([]byte("ping"))
	serverApp := append(frameMsg([]byte("pong")), frameMsg(bytes.Repeat([]byte("Q"), 20000))...)
	c2s, s2c, keylog := tlstest.Exchange(t, "svc.echo.nflog", clientApp, serverApp)

	dir := t.TempDir()
	klPath := filepath.Join(dir, "key.log")
	if err := os.WriteFile(klPath, keylog, 0o644); err != nil {
		t.Fatal(err)
	}

	var got [][2]string
	err := LiveTCPDecode(bytes.NewReader(buildNflogPcap(t, c2s, s2c)), klPath,
		func(*Flow, bool) {},
		func(m *WsMessage) {
			d := "S"
			if m.FromClient {
				d = "C"
			}
			got = append(got, [2]string{d, string(m.Payload)})
		})
	if err != nil {
		t.Fatalf("LiveTCPDecode: %v", err)
	}
	want := [][2]string{{"C", "ping"}, {"S", "pong"}, {"S", string(bytes.Repeat([]byte("Q"), 20000))}}
	if len(got) != len(want) {
		t.Fatalf("got %d messages, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("msg %d = {%s,%dB}, want {%s,%dB}", i, got[i][0], len(got[i][1]), want[i][0], len(want[i][1]))
		}
	}
}

// hostEchoDecoder is a custom raw-TCP decoder that claims a connection by its server
// host (like MAX's 155.212.* match) rather than by content — used to prove that HTTP
// traffic to such a host is still classified as HTTP, not swallowed by the decoder.
type hostEchoDecoder struct{}

func (hostEchoDecoder) Name() string                       { return "hostecho" }
func (hostEchoDecoder) Matches(m decoders.StreamMeta) bool { return m.ServerHost == "203.0.113.9" }
func (hostEchoDecoder) NewSession() decoders.Session       { return &echoSession{bufs: map[bool][]byte{}} }

// TestClassifyPrefersHTTPOverHostCustomDecoder is the regression for the live-vs-batch
// gap: a host that matches a raw-TCP custom decoder also serves plain HTTP/2 and HTTP/1.1
// on other connections. Those must classify as HTTP (and emit flows), not be committed to
// the custom decoder — which would frame none of their bytes and drop the flow.
func TestClassifyPrefersHTTPOverHostCustomDecoder(t *testing.T) {
	decoders.Register(hostEchoDecoder{})
	newStream := func() *tcpStream {
		return &tcpStream{
			lt:         &liveTCP{onFlow: func(*Flow, bool) {}, onMsg: func(*WsMessage) {}},
			serverHost: "203.0.113.9", // matches hostEchoDecoder by host
			serverPort: "443",
			clientAddr: "198.51.100.2:52000",
			conn:       tlsdecrypt.NewConn(tlsdecrypt.NewKeylog(""), nil),
		}
	}

	// HTTP/2 preface on a custom-decoder host → HTTP/2, not the custom decoder.
	s := newStream()
	s.classify([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	if s.matched || !s.isH2 {
		t.Errorf("h2 preface: matched=%v isH2=%v isHTTP=%v; want isH2", s.matched, s.isH2, s.isHTTP)
	}
	s.h2Sess.close()

	// HTTP/1.1 request (e.g. a WebSocket upgrade) on a custom-decoder host → HTTP/1.1.
	s = newStream()
	s.classify([]byte("GET /websocket HTTP/1.1\r\nHost: a\r\n\r\n"))
	if s.matched || !s.isHTTP {
		t.Errorf("h1 request: matched=%v isHTTP=%v; want isHTTP", s.matched, s.isHTTP)
	}
	s.httpSess.close()

	// Genuinely binary bytes (a raw custom-protocol frame) on that host → custom decoder.
	s = newStream()
	s.classify([]byte{0x01, 0x00, 0x12, 0x00, 0xff})
	if !s.matched {
		t.Errorf("binary frame: matched=%v; want matched (custom decoder)", s.matched)
	}
	// The custom flow must carry a timestamp, or it persists with time 0 and sorts to the
	// top of the flows list with a blank time column.
	if s.flow == nil || s.flow.TSUnixMicros == 0 {
		t.Errorf("custom flow timestamp not set: %+v", s.flow)
	}
}

// buildNflogPcap wraps the directional streams in IPv4/TCP packets inside NFLOG records
// (no Ethernet), as the Android per-app capture produces.
func buildNflogPcap(t *testing.T, c2s, s2c []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := pcapgo.NewWriter(&out)
	if err := w.WriteFileHeader(65535, linkTypeNFLOG); err != nil {
		t.Fatal(err)
	}
	cli := net.IP{10, 0, 0, 1}
	srv := net.IP{10, 0, 0, 2}
	emit := func(payload []byte, src, dst net.IP, sport, dport gplayers.TCPPort, seq uint32) {
		for off := 0; off < len(payload); off += 1200 {
			end := off + 1200
			if end > len(payload) {
				end = len(payload)
			}
			ip := &gplayers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: gplayers.IPProtocolTCP, SrcIP: src, DstIP: dst}
			tcp := &gplayers.TCP{SrcPort: sport, DstPort: dport, Seq: seq + uint32(off), ACK: true, PSH: true, Window: 65535}
			_ = tcp.SetNetworkLayerForChecksum(ip)
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
				ip, tcp, gopacket.Payload(payload[off:end])); err != nil {
				t.Fatal(err)
			}
			rec := nflogWrap(buf.Bytes())
			if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(rec), Length: len(rec)}, rec); err != nil {
				t.Fatal(err)
			}
		}
	}
	emit(c2s, cli, srv, 40000, 443, 1000)
	emit(s2c, srv, cli, 443, 40000, 5000)
	return out.Bytes()
}

// nflogWrap builds one NFLOG record (AF_INET) carrying ipPacket as NFULA_PAYLOAD.
func nflogWrap(ipPacket []byte) []byte {
	rec := []byte{2, 0, 0, 0} // family=AF_INET, version=0, resource_id=0
	tlv := make([]byte, 4)
	binary.LittleEndian.PutUint16(tlv[0:2], uint16(4+len(ipPacket)))
	binary.LittleEndian.PutUint16(tlv[2:4], 9) // NFULA_PAYLOAD
	rec = append(rec, tlv...)
	rec = append(rec, ipPacket...)
	for len(rec)%4 != 0 { // 4-byte align
		rec = append(rec, 0)
	}
	return rec
}
