package decode

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/nikitak/parsing/traffic-gateway/decoders"
	_ "github.com/nikitak/parsing/traffic-gateway/decoders/max" // register the MAX decoder
)

// maxFrame builds a plain (uncompressed) MAX frame over a msgpack body.
func maxFrame(t *testing.T, cmd, opcode uint16, body interface{}) []byte {
	t.Helper()
	payload, err := msgpack.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	h := make([]byte, 10)
	h[0] = 1
	binary.BigEndian.PutUint16(h[1:3], cmd)
	h[3] = 1
	binary.BigEndian.PutUint16(h[4:6], opcode)
	binary.BigEndian.PutUint32(h[6:10], uint32(len(payload))) // comp flag 0
	return append(h, payload...)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// parseFollowRaw turns tshark follow output into directional turns.
func TestParseFollowRaw(t *testing.T) {
	c := maxFrame(t, 1, 0x1, "hi") // client->server (non-indented)
	s := maxFrame(t, 2, 0x2, "yo") // server->client (tab-indented)
	out := "\n" +
		"===================================================================\n" +
		"Follow: tls,raw\n" +
		"Filter: tls.stream eq 1\n" +
		"Node 0: 10.0.0.1:52000\n" +
		"Node 1: 155.212.1.1:443\n" +
		"===================================================================\n" +
		hex.EncodeToString(c) + "\n" +
		"\t" + hex.EncodeToString(s) + "\n"

	turns := parseFollowRaw(out)
	if len(turns) != 2 {
		t.Fatalf("want 2 turns, got %d", len(turns))
	}
	if !turns[0].FromClient || turns[1].FromClient {
		t.Fatalf("direction wrong: %+v", []bool{turns[0].FromClient, turns[1].FromClient})
	}
	if !bytesEqual(turns[0].Data, c) || !bytesEqual(turns[1].Data, s) {
		t.Fatalf("turn bytes wrong: %x / %x", turns[0].Data, turns[1].Data)
	}
}

// parsed turns feed the registered MAX decoder end to end.
func TestParsedTurnsDecodeMAX(t *testing.T) {
	frame := maxFrame(t, 5, 0x10, map[string]interface{}{"hello": "world"})
	out := "Node 0: a\nNode 1: b\n" + hex.EncodeToString(frame) + "\n"
	turns := parseFollowRaw(out)

	d := decoders.Match(decoders.StreamMeta{SNI: "api.oneme.ru"})
	if len(d) == 0 {
		t.Fatal("MAX decoder not registered/matched")
	}
	msgs := decoders.DecodeTurns(d[0], turns)
	if len(msgs) != 1 {
		t.Fatalf("decode: n=%d", len(msgs))
	}
	if msgs[0].Opcode != "cmd5/op0x10" || !strings.Contains(string(msgs[0].Payload), `"hello":"world"`) {
		t.Fatalf("msg = %+v", msgs[0])
	}
}
