package quicdecrypt

import "testing"

// A crafted long-header Initial whose token-length varint is enormous used to advance the
// parse offset past the datagram and panic on the next slice (a gateway-wide crash, since
// nothing recovered it). It must now be rejected cleanly.
func TestParseLongHeaderRejectsHugeTokenLength(t *testing.T) {
	data := []byte{
		0xC0,                   // long header, type = Initial
		0x00, 0x00, 0x00, 0x01, // version
		0x00, // DCID len 0
		0x00, // SCID len 0
		// token length: 8-byte varint (0xC0 prefix) = 0x3FFFFFFFFFFFFFFF
		0xC0, 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	}
	if _, ok := parseLongHeader(data); ok {
		t.Fatal("parseLongHeader accepted a packet with a token longer than the datagram")
	}
}

// FuzzParseLongHeader asserts the long-header parser never panics on arbitrary input. Seed
// corpus includes the historical crasher above.
func FuzzParseLongHeader(f *testing.F) {
	f.Add([]byte{0xC0, 0, 0, 0, 1, 0, 0, 0xC0, 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0xC0, 0, 0, 0, 1, 2, 0xAA, 0xBB, 3, 0xCC, 0xDD, 0xEE, 0x01})
	f.Fuzz(func(_ *testing.T, data []byte) {
		parseLongHeader(data) // must not panic
	})
}

// FuzzParseFrames asserts the frame walker never panics on arbitrary payload bytes.
func FuzzParseFrames(f *testing.F) {
	f.Add([]byte{0x06, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF}) // CRYPTO off=0 len=4
	f.Add([]byte{0x08, 0x01, 0xFF})                         // STREAM, truncated
	f.Fuzz(func(_ *testing.T, p []byte) {
		parseFrames(p) // must not panic
	})
}
