package qpackdec

import "testing"

// A string length near 2^64 used to wrap the bounds check (ni+l) to a small value and then
// slice with a negative bound; a static index above 2^63 went negative through int() and
// passed its check. Both must now be rejected without panicking.
func TestHugeWireIntegersAreRejected(t *testing.T) {
	// Length 2^64-5 (prefix 127 + base-128 digits 124,126,127x7,1): the old check computed
	// ni+l = 11+2^64-5 = 6, which "fit" the 12-byte buffer, then sliced p[11:6].
	huge := []byte{0x7f, 0xfc, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 'x'}
	if _, _, ok := readString(7, huge); ok {
		t.Fatal("readString accepted a length far past the buffer")
	}
	// Insert With Name Reference, static, index 2^63+62 (prefix 63 + 0x7f digits): int()
	// made it negative, so it passed `int(idx) >= len(staticTable)` and indexed out of range.
	d := New()
	enc := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x01, 'v'}
	if err := d.ReadEncoderStream(enc); err == nil {
		t.Fatal("a static index past the table was accepted")
	}
}

// FuzzDecoder feeds arbitrary encoder-stream bytes (which build the dynamic table) and then
// an arbitrary field section to a fresh decoder. It must never panic.
func FuzzDecoder(f *testing.F) {
	f.Add([]byte{0x3f, 0xe1, 0x1f}, []byte{0x00, 0x00, 0xd1})               // set capacity; :method GET
	f.Add([]byte{0xc0 | 17, 0x03, 'f', 'o', 'o'}, []byte{0x02, 0x00, 0x80}) // insert name-ref
	f.Add([]byte{}, []byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(_ *testing.T, enc, field []byte) {
		d := New()
		_ = d.ReadEncoderStream(enc)
		_, _, _ = d.DecodeFieldSection(field)
	})
}
