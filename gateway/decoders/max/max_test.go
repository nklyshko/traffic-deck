package max

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/vmihailenco/msgpack/v5"

	"gitlab.com/nklyshko/traffic-deck/gateway/decoders"
)

// frame builds a MAX frame with the given cmd/opcode over a (msgpack) payload,
// optionally LZ4-compressed. cmd is one byte and seq the two after it — the layout real
// traffic shows (every response used to read as "cmd256", the sequence number's high byte
// caught in a cmd field that was never 16 bits wide).
func frame(t *testing.T, cmd byte, opcode uint16, compress bool, payload []byte) []byte {
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
	h[1] = cmd
	binary.BigEndian.PutUint16(h[2:4], 7) // seq
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
		if m.Opcode != "op0x12" || !m.FromClient {
			t.Fatalf("comp=%v: bad msg %+v", comp, m)
		}
		// The header's own fields travel beside the payload, for the viewer's columns.
		if m.Fields["max.cmd"] != "cmd5" || m.Fields["max.seq"] != "7" ||
			m.Fields["max.opcode"] != "op0x12" {
			t.Fatalf("comp=%v: fields = %v", comp, m.Fields)
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
	if len(msgs) != 2 || msgs[0].Opcode != "op0x1" || msgs[1].Opcode != "op0x2" {
		t.Fatalf("framing: %+v", msgs)
	}
	if msgs[0].Fields["max.cmd"] != "Response(1)" || msgs[1].Fields["max.cmd"] != "Push(2)" {
		t.Fatalf("cmd fields: %v / %v", msgs[0].Fields, msgs[1].Fields)
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

func TestKeepUndecodableRaw(t *testing.T) {
	// comp flag set but payload is not valid LZ4 → the frame is kept with its raw
	// bytes (like the reference client's decoded=None path) rather than dropped.
	h := make([]byte, headerLen)
	binary.BigEndian.PutUint32(h[6:10], (1<<24)|4)
	raw := []byte{0xff, 0xff, 0xff, 0xff}
	f := append(h, raw...)
	msgs := decode(t, []decoders.Turn{{FromClient: true, Data: f}})
	if len(msgs) != 1 {
		t.Fatalf("want 1 (kept raw), got %+v", msgs)
	}
	if msgs[0].ContentType != "application/octet-stream" || !bytes.Equal(msgs[0].Payload, raw) {
		t.Fatalf("want raw octet-stream payload, got %+v", msgs[0])
	}
}

func TestMatchesWS(t *testing.T) {
	d := decoder{}
	if !d.MatchesWS(decoders.WSMeta{Host: "api.oneme.ru", Path: "/websocket"}) {
		t.Fatal("should match oneme.ru WebSocket")
	}
	if !d.MatchesWS(decoders.WSMeta{SNI: "web.max.ru"}) {
		t.Fatal("should match max.ru SNI")
	}
	if d.MatchesWS(decoders.WSMeta{Host: "example.com"}) {
		t.Fatal("should not match unrelated host")
	}
}

// rawFrame builds a frame with an explicit compression flag over a pre-encoded body.
func rawFrame(comp byte, body []byte) []byte {
	h := make([]byte, headerLen)
	h[0] = 1
	binary.BigEndian.PutUint16(h[1:3], 5)
	binary.BigEndian.PutUint16(h[4:6], 0x12)
	binary.BigEndian.PutUint32(h[6:10], (uint32(comp)<<24)|uint32(len(body)))
	return append(h, body...)
}

func TestDecodeZstd(t *testing.T) {
	body := mp(t, map[string]interface{}{"hello": "world"})
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	z := enc.EncodeAll(body, nil)
	f := rawFrame(compZstd, z) // comp=0xFF
	msgs := decode(t, []decoders.Turn{{FromClient: true, Data: f}})
	if len(msgs) != 1 || !strings.Contains(string(msgs[0].Payload), `"hello":"world"`) {
		t.Fatalf("zstd decode: %+v", msgs)
	}
}

// MAX sometimes prefixes 1-4 service bytes before the msgpack body; the offset retry
// must skip them and decode the real value (and not stop at a leading byte).
func TestDecodeMsgpackLeadingServiceBytes(t *testing.T) {
	body := append([]byte{0xf5, 0x12}, mp(t, map[string]string{"k": "v"})...)
	f := rawFrame(0, body) // uncompressed
	msgs := decode(t, []decoders.Turn{{FromClient: true, Data: f}})
	if len(msgs) != 1 || !strings.Contains(string(msgs[0].Payload), `"k":"v"`) {
		t.Fatalf("offset decode: %+v", msgs)
	}
}

// MAX boxes 64-bit ids in msgpack ext type 1 (body = a msgpack int). The registered
// ext decoder must unbox it so frames carrying ids still decode to JSON.
func TestDecodeBoxedIDExt(t *testing.T) {
	// {"id": ext1(int32 42)} — c7 05 01 d2 0000002a is ext8 len5 type1 wrapping int32 42.
	body := []byte{0x81, 0xa2, 'i', 'd', 0xc7, 0x05, 0x01, 0xd2, 0x00, 0x00, 0x00, 0x2a}
	f := rawFrame(0, body)
	msgs := decode(t, []decoders.Turn{{FromClient: false, Data: f}})
	if len(msgs) != 1 || !strings.Contains(string(msgs[0].Payload), `"id":42`) {
		t.Fatalf("boxed-id ext decode: %+v", msgs)
	}
}

// MAX keys its presence/chat maps by a boxed-id ext (a non-string key); the untyped
// map decoder must accept it (the default string-keyed decoder rejects code c7).
func TestDecodeBoxedIDExtAsMapKey(t *testing.T) {
	// {ext1(int32 7): {"status": 2}}
	body := []byte{0x81, 0xc7, 0x05, 0x01, 0xd2, 0, 0, 0, 7,
		0x81, 0xa6, 's', 't', 'a', 't', 'u', 's', 0x02}
	f := rawFrame(0, body)
	msgs := decode(t, []decoders.Turn{{FromClient: false, Data: f}})
	if len(msgs) != 1 || !strings.Contains(string(msgs[0].Payload), `"7":{"status":2}`) {
		t.Fatalf("ext-as-map-key decode: %+v", msgs)
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
	if !got[0].FromClient || got[0].Opcode != "op0x1" {
		t.Fatalf("client frame wrong: %+v", got[0])
	}
	if got[1].FromClient || got[1].Opcode != "op0x2" {
		t.Fatalf("server frame wrong: %+v", got[1])
	}
}
