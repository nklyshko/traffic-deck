package quicdecrypt

import "testing"

func TestStreamReasm(t *testing.T) {
	var r streamReasm
	if out, _ := r.add(0, []byte("hello"), false); string(out) != "hello" {
		t.Fatalf("first add = %q", out)
	}
	// out-of-order: offset 10 buffered, then the gap fills.
	if out, _ := r.add(10, []byte("world"), false); out != nil {
		t.Fatalf("gap add should buffer, got %q", out)
	}
	if out, _ := r.add(5, []byte("XXXXX"), false); string(out) != "XXXXXworld" {
		t.Fatalf("fill add = %q, want XXXXXworld", out)
	}
	// overlap with already-delivered bytes is trimmed.
	if out, _ := r.add(12, []byte("rldDONE"), false); string(out) != "DONE" {
		t.Fatalf("overlap add = %q, want DONE", out)
	}
}

// The end of a stream is what tells an HTTP/3 response its body is complete, so it must
// be reported exactly once, and only when every byte before the FIN is in — a FIN that
// overtakes the data, or arrives again, must not end the stream early or twice.
func TestStreamReasmReportsTheEndOnce(t *testing.T) {
	var r streamReasm
	if _, ended := r.add(5, []byte("world"), true); ended {
		t.Fatal("a FIN ahead of a gap ended the stream")
	}
	out, ended := r.add(0, []byte("hello"), false)
	if string(out) != "helloworld" || !ended {
		t.Fatalf("gap fill = %q ended=%v, want all bytes and the end", out, ended)
	}
	if _, ended := r.add(5, []byte("world"), true); ended {
		t.Fatal("a retransmitted FIN ended the stream a second time")
	}

	var empty streamReasm
	if _, ended := empty.add(0, nil, true); !ended {
		t.Fatal("a bare FIN on an empty stream did not end it")
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
