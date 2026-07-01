package qpackdec

import (
	"encoding/hex"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func want(t *testing.T, got []HeaderField, exp ...HeaderField) {
	t.Helper()
	if len(got) != len(exp) {
		t.Fatalf("got %d fields, want %d: %v", len(got), len(exp), got)
	}
	for i := range exp {
		if got[i] != exp[i] {
			t.Fatalf("field %d = %v, want %v", i, got[i], exp[i])
		}
	}
}

// RFC 9204 Appendix B.1: literal field line with a static name reference, no dynamic table.
func TestStaticNameRef(t *testing.T) {
	d := New()
	f, blocked, err := d.DecodeFieldSection(mustHex(t, "0000510b2f696e6465782e68746d6c"))
	if err != nil || blocked {
		t.Fatalf("err=%v blocked=%v", err, blocked)
	}
	want(t, f, HeaderField{":path", "/index.html"})
}

// RFC 9204 Appendix B.2: encoder-stream inserts referenced by post-base indexed field lines.
func TestDynamicTable(t *testing.T) {
	d := New()
	// Set Dynamic Table Capacity=220, then two Insert With Name Reference (static :authority
	// = www.example.com, :path = /sample/path).
	enc := "3fbd01" +
		"c00f" + hex.EncodeToString([]byte("www.example.com")) +
		"c10c" + hex.EncodeToString([]byte("/sample/path"))
	if err := d.ReadEncoderStream(mustHex(t, enc)); err != nil {
		t.Fatal(err)
	}
	if d.InsertCount() != 2 {
		t.Fatalf("insert count = %d, want 2", d.InsertCount())
	}
	f, blocked, err := d.DecodeFieldSection(mustHex(t, "03811011"))
	if err != nil || blocked {
		t.Fatalf("err=%v blocked=%v", err, blocked)
	}
	want(t, f,
		HeaderField{":authority", "www.example.com"},
		HeaderField{":path", "/sample/path"})
}

// A field section whose Required Insert Count exceeds the inserts received so far is blocked
// until the encoder stream catches up.
func TestBlockedThenUnblocked(t *testing.T) {
	d := New()
	if err := d.ReadEncoderStream(mustHex(t, "3fbd01")); err != nil { // capacity only, no inserts
		t.Fatal(err)
	}
	if _, blocked, err := d.DecodeFieldSection(mustHex(t, "03811011")); err != nil || !blocked {
		t.Fatalf("expected blocked; err=%v blocked=%v", err, blocked)
	}
	// Now the inserts arrive; the same section decodes.
	enc := "c00f" + hex.EncodeToString([]byte("www.example.com")) +
		"c10c" + hex.EncodeToString([]byte("/sample/path"))
	if err := d.ReadEncoderStream(mustHex(t, enc)); err != nil {
		t.Fatal(err)
	}
	f, blocked, err := d.DecodeFieldSection(mustHex(t, "03811011"))
	if err != nil || blocked {
		t.Fatalf("err=%v blocked=%v", err, blocked)
	}
	want(t, f,
		HeaderField{":authority", "www.example.com"},
		HeaderField{":path", "/sample/path"})
}

// Encoder-stream instructions may be split across ReadEncoderStream calls (streamed).
func TestEncoderStreamSplit(t *testing.T) {
	d := New()
	full := mustHex(t, "3fbd01c00f"+hex.EncodeToString([]byte("www.example.com")))
	for i := range full { // feed one byte at a time
		if err := d.ReadEncoderStream(full[i : i+1]); err != nil {
			t.Fatal(err)
		}
	}
	if d.InsertCount() != 1 {
		t.Fatalf("insert count = %d, want 1", d.InsertCount())
	}
	if e, ok := d.dynByAbs(0); !ok || e.Value != "www.example.com" {
		t.Fatalf("dynamic entry 0 = %v ok=%v", e, ok)
	}
}

func TestReadStringHuffman(t *testing.T) {
	enc := hpack.AppendHuffmanString(nil, "example.com")
	buf := append([]byte{0x80 | byte(len(enc))}, enc...) // H=1, 7-bit length
	s, n, ok := readString(7, buf)
	if !ok || s != "example.com" || n != len(buf) {
		t.Fatalf("readString huffman: s=%q n=%d ok=%v", s, n, ok)
	}
}
