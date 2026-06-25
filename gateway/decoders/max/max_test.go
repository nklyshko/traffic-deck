package max

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/pierrec/lz4/v4"
	"github.com/vmihailenco/msgpack/v5"

	"gitlab.com/nklyshko/traffic-deck/gateway/decoders"
)

// frame builds a MAX frame with the given cmd/opcode over a (msgpack) payload,
// optionally LZ4-compressed.
func frame(t *testing.T, cmd, opcode uint16, compress bool, payload []byte) []byte {
	t.Helper()
	body := payload
	var flag uint32
	if compress {
		dst := make([]byte, lz4.CompressBlockBound(len(payload)))
		n, err := lz4.CompressBlock(payload, dst, nil)
		if err != nil || n == 0 {
			t.Fatalf("compress: n=%d err=%v (payload not compressible?)", n, err)
		}
		body = dst[:n]
		flag = 1
	}
	h := make([]byte, headerLen)
	h[0] = 1
	binary.BigEndian.PutUint16(h[1:3], cmd)
	h[3] = 7
	binary.BigEndian.PutUint16(h[4:6], opcode)
	binary.BigEndian.PutUint32(h[6:10], (flag<<24)|uint32(len(body)))
	return append(h, body...)
}

func mp(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := msgpack.Marshal(v)
	if err != nil {
		t.Fatalf("msgpack: %v", err)
	}
	return b
}

func decode(t *testing.T, turns []decoders.Turn) []decoders.Message {
	t.Helper()
	return decoders.DecodeTurns(decoder{}, turns)
}

func TestMatches(t *testing.T) {
	d := decoder{}
	if !d.Matches(decoders.StreamMeta{SNI: "api.oneme.ru"}) {
		t.Fatal("should match SNI oneme.ru")
	}
	if !d.Matches(decoders.StreamMeta{ServerHost: "155.212.3.4"}) {
		t.Fatal("should match 155.212 host")
	}
	if d.Matches(decoders.StreamMeta{SNI: "example.com", ServerHost: "1.2.3.4"}) {
		t.Fatal("should not match unrelated host")
	}
}

func TestDecodePlainAndCompressed(t *testing.T) {
	body := mp(t, map[string]interface{}{"hello": "world", "n": int64(42)})
	for _, comp := range []bool{false, true} {
		f := frame(t, 5, 0x12, comp, body)
		msgs := decode(t, []decoders.Turn{{FromClient: true, Data: f}})
		if len(msgs) != 1 {
			t.Fatalf("comp=%v: want 1 message, got %d", comp, len(msgs))
		}
		m := msgs[0]
		if m.Opcode != "cmd5/op0x12" || !m.FromClient {
			t.Fatalf("comp=%v: bad msg %+v", comp, m)
		}
		if !strings.Contains(string(m.Payload), `"hello":"world"`) {
			t.Fatalf("comp=%v: payload = %s", comp, m.Payload)
		}
	}
}

func TestFramingMultipleInOneTurn(t *testing.T) {
	a := frame(t, 1, 0x1, false, mp(t, "a"))
	b := frame(t, 2, 0x2, false, mp(t, "b"))
	msgs := decode(t, []decoders.Turn{{FromClient: true, Data: append(a, b...)}})
	if len(msgs) != 2 || msgs[0].Opcode != "cmd1/op0x1" || msgs[1].Opcode != "cmd2/op0x2" {
		t.Fatalf("framing: %+v", msgs)
	}
}

func TestFramingSplitAcrossTurns(t *testing.T) {
	f := frame(t, 9, 0x9, false, mp(t, map[string]int{"x": 1}))
	cut := len(f) - 3
	msgs := decode(t, []decoders.Turn{
		{FromClient: false, Data: f[:cut]},
		{FromClient: false, Data: f[cut:]},
	})
	if len(msgs) != 1 || msgs[0].FromClient {
		t.Fatalf("split framing: %+v", msgs)
	}
}

func TestEmptyPayload(t *testing.T) {
	f := frame(t, 3, 0x0, false, nil)
	msgs := decode(t, []decoders.Turn{{FromClient: true, Data: f}})
	if len(msgs) != 1 || !strings.Contains(string(msgs[0].Payload), "empty") {
		t.Fatalf("empty payload: %+v", msgs)
	}
}

func TestSkipUndecodable(t *testing.T) {
	// comp flag set but payload is not valid LZ4 → frame skipped, no error.
	h := make([]byte, headerLen)
	binary.BigEndian.PutUint32(h[6:10], (1<<24)|4)
	f := append(h, []byte{0xff, 0xff, 0xff, 0xff}...)
	msgs := decode(t, []decoders.Turn{{FromClient: true, Data: f}})
	if len(msgs) != 0 {
		t.Fatalf("want 0 (skipped), got %+v", msgs)
	}
}

// TestSessionIncrementalFeed mimics the live poller: a single frame is delivered in
// several small byte slices (split inside the header and the payload), and a second
// direction is interleaved. The session must emit each frame exactly once, only when
// it's complete — the core of incremental-framing mode.
func TestSessionIncrementalFeed(t *testing.T) {
	c := frame(t, 1, 0x1, false, mp(t, map[string]int{"x": 1}))
	s := frame(t, 2, 0x2, false, mp(t, "srv"))
	sess := decoder{}.NewSession()

	var got []decoders.Message
	feed := func(fromClient bool, b []byte) { got = append(got, sess.Feed(fromClient, b)...) }

	// Dribble the client frame in chunks (mid-header, mid-payload); nothing until done.
	feed(true, c[:4])
	feed(true, c[4:headerLen+1])
	if len(got) != 0 {
		t.Fatalf("emitted before frame complete: %+v", got)
	}
	// Interleave a partial server frame — wrong direction must not complete the client one.
	feed(false, s[:5])
	if len(got) != 0 {
		t.Fatalf("server bytes completed a client frame: %+v", got)
	}
	feed(true, c[headerLen+1:]) // finish the client frame
	feed(false, s[5:])          // finish the server frame
	if len(got) != 2 {
		t.Fatalf("want 2 frames, got %d: %+v", len(got), got)
	}
	if !got[0].FromClient || got[0].Opcode != "cmd1/op0x1" {
		t.Fatalf("client frame wrong: %+v", got[0])
	}
	if got[1].FromClient || got[1].Opcode != "cmd2/op0x2" {
		t.Fatalf("server frame wrong: %+v", got[1])
	}
}
