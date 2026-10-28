package server

import (
	"bytes"
	"testing"

	"github.com/nklyshko/traffic-deck/gateway/decoders"
	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
)

// lineDecoder frames newline-terminated records; it claims only fake.test, by any of the
// names a pushed flow can carry.
type lineDecoder struct{}

func (lineDecoder) Name() string { return "line" }
func (lineDecoder) Matches(m decoders.StreamMeta) bool {
	return m.SNI == "fake.test" || m.Host == "fake.test" || m.ServerHost == "198.51.100.9"
}
func (lineDecoder) NewSession() decoders.Session { return &lineSession{bufs: map[bool][]byte{}} }

type lineSession struct{ bufs map[bool][]byte }

func (s *lineSession) Feed(fromClient bool, data []byte) []decoders.Message {
	buf := append(s.bufs[fromClient], data...)
	var out []decoders.Message
	for {
		i := bytes.IndexByte(buf, '\n')
		if i < 0 {
			break
		}
		out = append(out, decoders.Message{FromClient: fromClient, Payload: buf[:i]})
		buf = buf[i+1:]
	}
	s.bufs[fromClient] = buf
	return out
}

func init() { decoders.Register(lineDecoder{}) }

func pushedTCP(id, authority, dst string, meta map[string]string) *trafficv1.Flow {
	return &trafficv1.Flow{Id: id, Protocol: "TCP", Websocket: true, Authority: authority,
		DstAddr: dst, Metadata: meta}
}

// A raw-TCP connection mitmproxy forwarded is decoded like one the pcap path decrypted:
// a decoder claims it by its SNI, by the name the source inferred, or by the address, and
// the flow keeps the protocol's name — and loses its "undecoded" outcome — on every push.
func TestPushedTCPIsClaimedByEveryNameItCarries(t *testing.T) {
	for _, tc := range []struct {
		name string
		pf   *trafficv1.Flow
	}{
		{"sni", pushedTCP("a", "fake.test", "203.0.113.1:443",
			map[string]string{tlsSNIKey: "fake.test", hostnameSourceKey: "sni", connOutcomeKey: "tcp_passthrough"})},
		{"dns-inferred host", pushedTCP("b", "fake.test:443", "203.0.113.1:443",
			map[string]string{hostnameSourceKey: "dns", connOutcomeKey: "tcp_passthrough"})},
		{"address", pushedTCP("c", "198.51.100.9:443", "198.51.100.9:443",
			map[string]string{hostnameSourceKey: "ip", connOutcomeKey: "tcp_passthrough"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := &Ingest{}
			i.claimPushedTCP(tc.pf)
			if tc.pf.Protocol != "LINE" || tc.pf.Metadata[connOutcomeKey] != "" {
				t.Fatalf("claimed flow = protocol %q outcome %q, want LINE and none",
					tc.pf.Protocol, tc.pf.Metadata[connOutcomeKey])
			}
			// The source re-pushes the flow when the connection closes, as "TCP" again.
			again := pushedTCP(tc.pf.Id, tc.pf.Authority, tc.pf.DstAddr,
				map[string]string{connOutcomeKey: "tcp_passthrough"})
			i.claimPushedTCP(again)
			if again.Protocol != "LINE" || again.Metadata[connOutcomeKey] != "" {
				t.Fatalf("re-pushed flow = protocol %q outcome %q", again.Protocol, again.Metadata[connOutcomeKey])
			}
		})
	}
}

// Chunks are framed per direction across pushes, as mitmproxy delivers a stream in
// arbitrary pieces; an unclaimed connection is left to store its chunks raw.
func TestPushedTCPChunksAreReframedPerDirection(t *testing.T) {
	i := &Ingest{}
	i.claimPushedTCP(pushedTCP("a", "fake.test", "203.0.113.1:443", map[string]string{tlsSNIKey: "fake.test"}))
	if msgs, _, _ := i.decodePushedTCP("a", true, []byte("hel")); len(msgs) != 0 {
		t.Fatalf("a partial record produced %d messages", len(msgs))
	}
	if msgs, _, _ := i.decodePushedTCP("a", false, []byte("pong\n")); len(msgs) != 1 || string(msgs[0].Payload) != "pong" {
		t.Fatalf("server record = %+v", msgs)
	}
	msgs, name, ok := i.decodePushedTCP("a", true, []byte("lo\nworld\n"))
	if !ok || name != "line" || len(msgs) != 2 || string(msgs[0].Payload) != "hello" || string(msgs[1].Payload) != "world" {
		t.Fatalf("client records = %+v (decoder %q, ok %v)", msgs, name, ok)
	}

	other := pushedTCP("z", "mtalk.google.com", "142.250.1.1:5228", map[string]string{tlsSNIKey: "mtalk.google.com"})
	i.claimPushedTCP(other)
	if other.Protocol != "TCP" {
		t.Fatalf("unclaimed flow became %q", other.Protocol)
	}
	if _, _, ok := i.decodePushedTCP("z", true, []byte("x\n")); ok {
		t.Fatal("an unclaimed connection's chunk was decoded")
	}
}
