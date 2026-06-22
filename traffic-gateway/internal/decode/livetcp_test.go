package decode

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	gplayers "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/nikitak/parsing/traffic-gateway/decoders"
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

	c2s, s2c, keylog := tlsExchange(t, "svc.echo.test", clientApp, serverApp)

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

// tlsExchange performs a real TLS 1.3 handshake + bidirectional app-data exchange over
// localhost, returning the recorded client→server bytes, server→client bytes, and the
// NSS key-log.
func tlsExchange(t *testing.T, sni string, clientApp, serverApp []byte) (c2s, s2c, keylog []byte) {
	t.Helper()
	cert := testCert(t)
	klw := &syncBuf{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		sc := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert},
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, KeyLogWriter: klw})
		buf := make([]byte, len(clientApp))
		if _, err := io.ReadFull(sc, buf); err != nil {
			done <- err
			return
		}
		if _, err := sc.Write(serverApp); err != nil {
			done <- err
			return
		}
		_ = sc.CloseWrite()
		done <- nil
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{Conn: raw}
	cc := tls.Client(rec, &tls.Config{InsecureSkipVerify: true, ServerName: sni,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, KeyLogWriter: klw})
	if _, err := cc.Write(clientApp); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(serverApp))
	if _, err := io.ReadFull(cc, got); err != nil {
		t.Fatal(err)
	}
	cc.Close()
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
	return rec.c2s.Bytes(), rec.s2c.Bytes(), klw.b.Bytes()
}

// recorder/syncBuf/testCert mirror the helpers in the tlsdecrypt tests.
type recorder struct {
	net.Conn
	c2s, s2c bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) {
	n, err := r.Conn.Write(p)
	r.c2s.Write(p[:n])
	return n, err
}
func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.s2c.Write(p[:n])
	return n, err
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *syncBuf) Write(p []byte) (int, error) { w.mu.Lock(); defer w.mu.Unlock(); return w.b.Write(p) }

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
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
