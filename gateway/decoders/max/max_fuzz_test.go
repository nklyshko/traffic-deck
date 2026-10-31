package max

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// A crafted LZ4 block whose match length is built from a long run of 0xFF bytes expands
// ~255x; in a 16 MiB frame that is gigabytes. The decoder must stop at maxDecompressed.
func TestLZ4BombIsCapped(t *testing.T) {
	var src bytes.Buffer
	src.WriteByte(0x1F)                            // literal len 1, match len 15+4 (+ext)
	src.WriteByte('A')                             // the literal
	src.Write([]byte{0x01, 0x00})                  // offset 1: repeat the last byte
	src.Write(bytes.Repeat([]byte{0xFF}, 300_000)) // match length ext: ~76.5 MB
	src.WriteByte(0x00)
	out, capped := lz4BlockDecompress(src.Bytes())
	if len(out) > maxDecompressed || !capped {
		t.Fatalf("lz4 output %d bytes (capped=%v); want at most %d, capped", len(out), capped, maxDecompressed)
	}
}

// A frame kept raw because it hit a bound says which one, and is logged once per
// connection; a frame merely in an encoding plain msgpack can't read carries no such field.
func TestAFrameKeptRawForABoundSaysWhich(t *testing.T) {
	var lz4 bytes.Buffer
	lz4.Write([]byte{0x1F, 'A', 0x01, 0x00})
	lz4.Write(bytes.Repeat([]byte{0xFF}, 300_000))
	lz4.WriteByte(0x00)
	bomb := maxFrame(lz4.Bytes())
	bomb[6] = 0x01 // LZ4-compressed

	deep := maxFrame(append(bytes.Repeat([]byte{0x91}, 1000), 0xc0))
	plain := maxFrame([]byte{0xc1}) // never valid msgpack, not a bound

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	s := decoder{}.NewSession()
	msgs := s.Feed(false, append(append(append(bomb, bomb...), deep...), plain...))
	if len(msgs) != 4 {
		t.Fatalf("got %d messages, want 4", len(msgs))
	}
	if why := msgs[0].Fields[limitField]; !strings.Contains(why, "64 MiB") {
		t.Errorf("LZ4 bomb: %s = %q", limitField, why)
	}
	if !bytes.Equal(msgs[0].Payload, lz4.Bytes()) {
		t.Error("LZ4 bomb: the compressed frame was not kept as it came")
	}
	if why := msgs[2].Fields[limitField]; !strings.Contains(why, "deeper than 64") {
		t.Errorf("deep nesting: %s = %q", limitField, why)
	}
	if why, ok := msgs[3].Fields[limitField]; ok {
		t.Errorf("unparseable frame: %s = %q, want none", limitField, why)
	}
	if n := strings.Count(logBuf.String(), "64 MiB"); n != 1 {
		t.Errorf("the LZ4 bound was logged %d times for one connection, want 1:\n%s", n, logBuf.String())
	}
}

// The structural check must accept everything a real encoder writes...
func TestMsgpackSaneAcceptsEncodedValues(t *testing.T) {
	values := []interface{}{
		nil, true, int8(-5), uint64(1 << 40), -1 << 40, 3.5, float32(1.25), "", "hi",
		string(bytes.Repeat([]byte("x"), 300)), string(bytes.Repeat([]byte("y"), 70000)),
		[]byte{1, 2, 3}, bytes.Repeat([]byte{7}, 70000), []interface{}{}, []interface{}{1, "a", nil},
		map[string]interface{}{"a": 1, "b": []interface{}{map[string]interface{}{"c": "d"}}},
		make([]interface{}, 20), time.Unix(1_700_000_000, 5),
	}
	for _, v := range values {
		b, err := msgpack.Marshal(v)
		if err != nil {
			t.Fatalf("marshal %T: %v", v, err)
		}
		if ok, _ := msgpackSane(b); !ok {
			t.Errorf("msgpackSane rejected a valid encoding of %T (% x…)", v, b[:min(len(b), 12)])
		}
	}
}

// ...and reject the shapes that make the library allocate or recurse without bound.
func TestMsgpackSaneRejectsBombs(t *testing.T) {
	for name, b := range map[string][]byte{
		"array32 of 3.7e9":   {0xdd, 0xdd, 0x30, 0x30, 0x30, 0xc0},
		"map32 of 4e9":       {0xdf, 0xff, 0xff, 0xff, 0xff, 0xc0, 0xc0},
		"str32 past the end": {0xdb, 0x00, 0x10, 0x00, 0x00, 'a'},
		"deep nesting":       append(bytes.Repeat([]byte{0x91}, 1000), 0xc0),
		"trailing bytes":     {0xc0, 0xc0},
	} {
		if ok, _ := msgpackSane(b); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func maxFrame(payload []byte) []byte {
	f := make([]byte, headerLen, headerLen+len(payload))
	binary.BigEndian.PutUint32(f[6:10], uint32(len(payload)))
	return append(f, payload...)
}

// FuzzFeed runs arbitrary bytes, split across both directions, through a MAX session:
// framing, header decode, LZ4/zstd decompression and msgpack. It must never panic.
func FuzzFeed(f *testing.F) {
	f.Add(maxFrame([]byte{0x80}), uint16(0))
	f.Add(append(maxFrame([]byte{1, 2, 3}), maxFrame(nil)...), uint16(5))
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF}, uint16(3))
	f.Fuzz(func(_ *testing.T, data []byte, split uint16) {
		s := decoder{}.NewSession()
		k := int(split) % (len(data) + 1)
		s.Feed(true, data[:k])
		s.Feed(false, data[k:])
		s.Feed(true, data)
	})
}

// FuzzLZ4 asserts the block decompressor never panics and never exceeds its cap.
func FuzzLZ4(f *testing.F) {
	f.Add([]byte{0x10, 'a'})
	f.Add([]byte{0x1F, 'a', 0x01, 0x00, 0xFF, 0x00})
	f.Fuzz(func(t *testing.T, src []byte) {
		if out, _ := lz4BlockDecompress(src); len(out) > maxDecompressed {
			t.Fatalf("output %d bytes exceeds the cap", len(out))
		}
	})
}
