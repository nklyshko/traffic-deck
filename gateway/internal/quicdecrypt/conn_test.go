package quicdecrypt

import "testing"

func TestStreamReasm(t *testing.T) {
	var r streamReasm
	if out := r.add(0, []byte("hello")); string(out) != "hello" {
		t.Fatalf("first add = %q", out)
	}
	// out-of-order: offset 10 buffered, then the gap fills.
	if out := r.add(10, []byte("world")); out != nil {
		t.Fatalf("gap add should buffer, got %q", out)
	}
	if out := r.add(5, []byte("XXXXX")); string(out) != "XXXXXworld" {
		t.Fatalf("fill add = %q, want XXXXXworld", out)
	}
	// overlap with already-delivered bytes is trimmed.
	if out := r.add(12, []byte("rldDONE")); string(out) != "DONE" {
		t.Fatalf("overlap add = %q, want DONE", out)
	}
}

func TestCryptoReasm(t *testing.T) {
	var r cryptoReasm
	// handshake msg: type=1 len=6 body="abcdef", delivered in two CRYPTO frames.
	if msg := r.add(0, []byte{0x01, 0x00, 0x00, 0x06, 'a', 'b'}); msg != nil {
		t.Fatalf("incomplete should not yield, got %x", msg)
	}
	msg := r.add(6, []byte("cdef"))
	if string(msg) != "\x01\x00\x00\x06abcdef" {
		t.Fatalf("reassembled = %x", msg)
	}
}
