package decode

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	gplayers "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/nklyshko/traffic-deck/gateway/internal/tlstest"
)

// multiPcap writes several conversations into one classic pcap, each packet a second
// after the last so a record's timestamp identifies it.
type multiPcap struct {
	t   *testing.T
	out bytes.Buffer
	w   *pcapgo.Writer
	ts  time.Time
}

func newMultiPcap(t *testing.T) *multiPcap {
	p := &multiPcap{t: t, ts: time.Unix(1_800_000_000, 0)}
	p.w = pcapgo.NewWriter(&p.out)
	if err := p.w.WriteFileHeader(65535, gplayers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *multiPcap) write(layers ...gopacket.SerializableLayer) {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, layers...); err != nil {
		p.t.Fatal(err)
	}
	data := buf.Bytes()
	p.ts = p.ts.Add(time.Second)
	if err := p.w.WritePacket(gopacket.CaptureInfo{Timestamp: p.ts, CaptureLength: len(data), Length: len(data)}, data); err != nil {
		p.t.Fatal(err)
	}
}

func eth() *gplayers.Ethernet {
	return &gplayers.Ethernet{SrcMAC: net.HardwareAddr{1, 1, 1, 1, 1, 1}, DstMAC: net.HardwareAddr{2, 2, 2, 2, 2, 2}, EthernetType: gplayers.EthernetTypeIPv4}
}

func (p *multiPcap) tcp(src, dst net.IP, sport, dport gplayers.TCPPort, seq uint32, payload []byte) {
	for off := 0; off < len(payload); off += 1200 {
		end := min(off+1200, len(payload))
		ip := &gplayers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: gplayers.IPProtocolTCP, SrcIP: src, DstIP: dst}
		tcp := &gplayers.TCP{SrcPort: sport, DstPort: dport, Seq: seq + uint32(off), ACK: true, PSH: true, Window: 65535}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		p.write(eth(), ip, tcp, gopacket.Payload(payload[off:end]))
	}
}

func (p *multiPcap) udp(src, dst net.IP, sport, dport gplayers.UDPPort, payload []byte) {
	ip := &gplayers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: gplayers.IPProtocolUDP, SrcIP: src, DstIP: dst}
	udp := &gplayers.UDP{SrcPort: sport, DstPort: dport}
	_ = udp.SetNetworkLayerForChecksum(ip)
	p.write(eth(), ip, udp, gopacket.Payload(payload))
}

// What ends without a flow is indexed with a reason, its volume, its time span and where
// its first packet sits in the capture — enough to find it again without copying it. A
// TLS connection with no key-log secret, a plaintext stream no parser recognises and a
// UDP conversation that is not QUIC each get one; a decoded HTTP exchange does not.
func TestUndecodedConnectionsAreIndexed(t *testing.T) {
	cli, srv, other := net.IP{10, 0, 0, 1}, net.IP{10, 0, 0, 2}, net.IP{10, 0, 0, 3}
	p := newMultiPcap(t)

	c2s, s2c, _ := tlstest.Exchange(t, "pinned.example", []byte("secret request"), []byte("secret reply"))
	p.tcp(cli, srv, 40001, 443, 1000, c2s)
	p.tcp(srv, cli, 443, 40001, 9000, s2c)

	p.tcp(cli, other, 40002, 7000, 1000, []byte("\x00\x01binary-protocol-hello\x00"))
	p.tcp(other, cli, 7000, 40002, 9000, []byte("\x00\x02ack"))

	p.tcp(cli, srv, 40003, 80, 1000, []byte("GET / HTTP/1.1\r\nHost: plain.example\r\n\r\n"))
	p.tcp(srv, cli, 80, 40003, 9000, []byte("HTTP/1.1 204 No Content\r\n\r\n"))

	p.udp(cli, other, 50000, 3478, []byte("stun-binding-request"))
	p.udp(other, cli, 3478, 50000, []byte("stun-reply"))
	pcap := p.out.Bytes()

	var got []*UndecodedConn
	var flows int
	if err := LiveDecode(bytes.NewReader(pcap), "", Sinks{
		OnFlow:      func(_ *Flow, isNew bool) { flows += map[bool]int{true: 1}[isNew] },
		OnUndecoded: func(u *UndecodedConn) { got = append(got, u) },
	}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].FirstTS < got[j].FirstTS })

	want := []struct{ reason, transport, server, sni string }{
		{UndecodedNoKey, "tcp", "10.0.0.2:443", "pinned.example"},
		{UndecodedUnparsed, "tcp", "10.0.0.3:7000", ""},
		{UndecodedNotQUIC, "udp", "10.0.0.3:3478", ""},
	}
	if len(got) != len(want) {
		for _, u := range got {
			t.Logf("%+v", *u)
		}
		t.Fatalf("got %d undecoded connections, want %d", len(got), len(want))
	}
	if flows != 1 {
		t.Fatalf("got %d flows, want just the plain HTTP exchange", flows)
	}
	for i, w := range want {
		u := got[i]
		if u.Reason != w.reason || u.Transport != w.transport || u.Server != w.server || u.SNI != w.sni {
			t.Errorf("#%d = %s %s %s sni=%q, want %+v", i, u.Reason, u.Transport, u.Server, u.SNI, w)
		}
		if u.BytesUp == 0 || u.BytesDown == 0 || u.LastTS < u.FirstTS {
			t.Errorf("#%d tallied up=%d down=%d first=%d last=%d", i, u.BytesUp, u.BytesDown, u.FirstTS, u.LastTS)
		}
		// The offset names the record of the connection's first packet: its timestamp is
		// the connection's first.
		rec := pcap[u.PcapOffset:]
		sec, usec := binary.LittleEndian.Uint32(rec[0:4]), binary.LittleEndian.Uint32(rec[4:8])
		if ts := int64(sec)*1_000_000 + int64(usec); ts != u.FirstTS {
			t.Errorf("#%d offset %d holds a packet at %d, want its first at %d", i, u.PcapOffset, ts, u.FirstTS)
		}
	}
	if got[0].JA4 == "" {
		t.Error("the TLS connection's ClientHello fingerprint was not kept")
	}

	// Read back from the capture: from the indexed offset, and — the offset unknown, as
	// for pcapng — by scanning the whole file, with the same bytes either way.
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(path, pcap, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, scan := range []bool{false, true} {
		u := *got[0]
		if scan {
			u.PcapOffset = -1
		}
		b, err := ReadConnection(path, &u, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b.Up, c2s) || !bytes.Equal(b.Down, s2c) || b.Gaps != 0 || b.Scanned != scan {
			t.Fatalf("scan=%v: read up %d/%d down %d/%d gaps %d scanned %v", scan,
				len(b.Up), len(c2s), len(b.Down), len(s2c), b.Gaps, b.Scanned)
		}
		desc := strings.Join(DescribeTLS(b.Up, b.Down), "\n")
		if !strings.Contains(desc, `sni="pinned.example"`) || !strings.Contains(desc, "TLS1.3") {
			t.Fatalf("described as:\n%s", desc)
		}
	}
	b, err := ReadConnection(path, got[2], 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if string(b.Up) != "stun-binding-request" || string(b.Down) != "stun-reply" {
		t.Fatalf("UDP read back as %q / %q", b.Up, b.Down)
	}
	// A moved capture (the offset now pointing elsewhere) is noticed, and scanned instead.
	moved := *got[0]
	moved.PcapOffset = got[2].PcapOffset
	if b, err := ReadConnection(path, &moved, 1<<20); err != nil || !b.Scanned || !bytes.Equal(b.Up, c2s) {
		t.Fatalf("a stale offset read %d bytes, scanned=%v, err=%v", len(b.Up), b.Scanned, err)
	}
	// A cap stops a direction and says so.
	if b, _ := ReadConnection(path, got[0], 100); len(b.Down) != 100 || !b.Truncated {
		t.Fatalf("capped read = %d bytes, truncated %v", len(b.Down), b.Truncated)
	}
}
