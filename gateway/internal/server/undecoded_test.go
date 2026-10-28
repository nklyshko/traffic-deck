package server

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	gplayers "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
	"github.com/nklyshko/traffic-deck/gateway/internal/objstore"
	"github.com/nklyshko/traffic-deck/gateway/internal/tlstest"
)

// tlsWithoutKeyPcap is one TLS 1.3 exchange whose key-log secret the decoder never gets:
// the shape of a pinned or foreign connection on an interface-wide capture.
func tlsWithoutKeyPcap(t *testing.T) (pcap, c2s, s2c []byte) {
	t.Helper()
	c2s, s2c, _ = tlstest.Exchange(t, "pinned.example", []byte("request"), []byte("reply"))
	var out bytes.Buffer
	w := pcapgo.NewWriter(&out)
	if err := w.WriteFileHeader(65535, gplayers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	ts := time.Unix(1_800_000_000, 0)
	emit := func(payload []byte, src, dst net.IP, sport, dport gplayers.TCPPort, seq uint32) {
		for off := 0; off < len(payload); off += 1200 {
			end := min(off+1200, len(payload))
			eth := &gplayers.Ethernet{SrcMAC: net.HardwareAddr{1, 1, 1, 1, 1, 1}, DstMAC: net.HardwareAddr{2, 2, 2, 2, 2, 2}, EthernetType: gplayers.EthernetTypeIPv4}
			ip := &gplayers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: gplayers.IPProtocolTCP, SrcIP: src, DstIP: dst}
			tcp := &gplayers.TCP{SrcPort: sport, DstPort: dport, Seq: seq + uint32(off), ACK: true, PSH: true, Window: 65535}
			_ = tcp.SetNetworkLayerForChecksum(ip)
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
				eth, ip, tcp, gopacket.Payload(payload[off:end])); err != nil {
				t.Fatal(err)
			}
			ts = ts.Add(time.Millisecond)
			data := buf.Bytes()
			if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(data), Length: len(data)}, data); err != nil {
				t.Fatal(err)
			}
		}
	}
	cli, srv := net.IP{10, 0, 0, 1}, net.IP{10, 0, 0, 2}
	emit(c2s, cli, srv, 40001, 443, 1000)
	emit(s2c, srv, cli, 443, 40001, 9000)
	return out.Bytes(), c2s, s2c
}

// A pcap session's undecoded connections are listed — with the session's counts, so an
// agent learns there is something it could not read — and one can be read back from the
// capture, with what its handshake shows in the clear.
func TestUndecodedConnectionsAreListedAndReadBack(t *testing.T) {
	ctx := context.Background()
	st, sid := queryTestStore(t)
	defer st.Close()
	obj, err := objstore.NewFSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pcap, c2s, s2c := tlsWithoutKeyPcap(t)
	if _, err := obj.Put(pcapKey(sid), bytes.NewReader(pcap)); err != nil {
		t.Fatal(err)
	}
	var conns []*decode.UndecodedConn
	if err := decode.LiveDecode(bytes.NewReader(pcap), "", decode.Sinks{
		OnFlow: func(*decode.Flow, bool) {}, OnUndecoded: func(u *decode.UndecodedConn) { conns = append(conns, u) },
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordUndecoded(ctx, sid, conns); err != nil {
		t.Fatal(err)
	}
	v := NewViewer(st, newLiveHub())
	v.obj = obj

	list, err := v.ListUndecodedConnections(ctx, &trafficv1.ListUndecodedRequest{SessionId: sid})
	if err != nil {
		t.Fatal(err)
	}
	if !list.GetIndexed() || list.GetTotal() != 1 || list.GetByReason()["no_key"] != 1 {
		t.Fatalf("list = %+v", list)
	}
	c := list.GetConnections()[0]
	if c.GetSni() != "pinned.example" || c.GetServer() != "10.0.0.2:443" || c.GetJa4() == "" {
		t.Fatalf("connection = %+v", c)
	}
	sess, _ := st.GetSession(ctx, sid)
	if sess.GetMetadata()["undecoded.no_key"] != "1" || sess.GetMetadata()["undecoded.udp"] != "0" {
		t.Fatalf("session metadata = %v", sess.GetMetadata())
	}
	if l, _ := v.ListUndecodedConnections(ctx, &trafficv1.ListUndecodedRequest{SessionId: sid, Host: "other"}); l.GetTotal() != 0 {
		t.Fatalf("host filter kept %d", l.GetTotal())
	}

	up, err := v.GetConnectionBytes(ctx, &trafficv1.GetConnectionBytesRequest{SessionId: sid, ConnId: c.GetConnId(), FromClient: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(up.GetData(), c2s) || up.GetTotal() != uint64(len(c2s)) {
		t.Fatalf("client bytes = %d, want %d", len(up.GetData()), len(c2s))
	}
	if tls := strings.Join(up.GetTls(), "\n"); !strings.Contains(tls, `sni="pinned.example"`) {
		t.Fatalf("tls = %s", tls)
	}
	down, err := v.GetConnectionBytes(ctx, &trafficv1.GetConnectionBytesRequest{SessionId: sid, ConnId: c.GetConnId(), Offset: 10, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(down.GetData(), s2c[10:15]) || down.GetOffset() != 10 {
		t.Fatalf("server window = %x at %d", down.GetData(), down.GetOffset())
	}
	if _, err := v.GetConnectionBytes(ctx, &trafficv1.GetConnectionBytesRequest{SessionId: sid, ConnId: "nope"}); err == nil {
		t.Fatal("an unknown connection was read")
	}
}

// A session decoded without the index says so, so an empty list is not read as "nothing
// went undecoded".
func TestASessionWithoutTheIndexSaysSo(t *testing.T) {
	ctx := context.Background()
	st, sid := queryTestStore(t)
	defer st.Close()
	list, err := NewViewer(st, newLiveHub()).ListUndecodedConnections(ctx, &trafficv1.ListUndecodedRequest{SessionId: sid})
	if err != nil {
		t.Fatal(err)
	}
	if list.GetIndexed() {
		t.Fatal("an unindexed session claimed its index")
	}
}
