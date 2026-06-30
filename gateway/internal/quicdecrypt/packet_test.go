package quicdecrypt

import (
	"encoding/hex"
	"testing"
)

func TestReadVarint(t *testing.T) {
	cases := []struct {
		hex string
		val uint64
		n   int
	}{
		{"25", 0x25, 1},
		{"7bbd", 0x3bbd, 2},
		{"9d7f3e7d", 0x1d7f3e7d, 4},
		{"c2197c5eff14e88c", 0x2197c5eff14e88c, 8},
	}
	for _, c := range cases {
		v, n := readVarint(unhex(t, c.hex))
		if v != c.val || n != c.n {
			t.Errorf("readVarint(%s) = (%#x, %d), want (%#x, %d)", c.hex, v, n, c.val, c.n)
		}
	}
}

// End-to-end Stage-2 over the RFC 9001 A.2 vector: decrypt the client Initial, walk its
// frames to the CRYPTO frame, and parse the ClientHello for client_random + SNI.
func TestParseClientInitialFrames(t *testing.T) {
	packet := unhex(t, a2PacketHex)
	dcid := unhex(t, "8394c8f03e515708")
	client, _ := initialSecrets(dcid)
	k, _ := deriveKeys(client, aes128gcm)
	_, payload, _, ok := k.open(packet, 18, 18+1182, true, 0)
	if !ok {
		t.Fatal("decrypt failed")
	}
	crypto, streams, ok := parseFrames(payload)
	if !ok || len(crypto) == 0 {
		t.Fatalf("parseFrames: ok=%v crypto=%d streams=%d", ok, len(crypto), len(streams))
	}
	if crypto[0].offset != 0 {
		t.Errorf("crypto offset = %d, want 0", crypto[0].offset)
	}
	ch, ok := parseClientHello(crypto[0].data)
	if !ok {
		t.Fatal("parseClientHello failed")
	}
	if got := hex.EncodeToString(ch.random); got != "ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c" {
		t.Errorf("client_random = %s", got)
	}
	if ch.sni != "example.com" {
		t.Errorf("sni = %q, want example.com", ch.sni)
	}
}

func TestParseStreamFrame(t *testing.T) {
	// STREAM frame, type 0x0f (OFF|LEN|FIN): id=4, off=8, len=3, data=abc, FIN set.
	frame := []byte{0x0f, 0x04, 0x08, 0x03, 'a', 'b', 'c'}
	_, streams, ok := parseFrames(frame)
	if !ok || len(streams) != 1 {
		t.Fatalf("parseFrames: ok=%v streams=%d", ok, len(streams))
	}
	s := streams[0]
	if s.id != 4 || s.offset != 8 || string(s.data) != "abc" || !s.fin {
		t.Errorf("stream = %+v", s)
	}
}

func TestParseServerHelloSuite(t *testing.T) {
	// Minimal ServerHello: type 2, body = legacy_version(0303) random(32x aa) session_id<1>=00
	// cipher_suite(1301). bodyLen = 2+32+1+2 = 37 = 0x25.
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)       // empty session_id
	body = append(body, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	msg := append([]byte{0x02, 0x00, 0x00, byte(len(body))}, body...)
	id, ok := parseServerHello(msg)
	if !ok || id != 0x1301 {
		t.Errorf("parseServerHello = (%#x, %v), want (0x1301, true)", id, ok)
	}
}

// A server Initial begins with an ACK frame before the CRYPTO frame; parseFrames must
// skip the ACK (and other frames) by length to reach the CRYPTO/STREAM frames.
func TestParseFramesSkipsACK(t *testing.T) {
	// ACK (0x02): largest=0, delay=0, range_count=0, first_range=0  -> 02 00 00 00 00
	// then CRYPTO (0x06): offset=0, len=3, data="abc"
	p := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x03, 'a', 'b', 'c'}
	crypto, _, ok := parseFrames(p)
	if !ok || len(crypto) != 1 || string(crypto[0].data) != "abc" {
		t.Fatalf("ok=%v crypto=%d data=%q", ok, len(crypto), func() string {
			if len(crypto) > 0 {
				return string(crypto[0].data)
			}
			return ""
		}())
	}
	// NEW_CONNECTION_ID (0x18) before a STREAM frame must also be skipped.
	// 0x18 seq=1 retire=0 len=4 cid=11223344 token=16 bytes, then STREAM 0x0a id=0 len=2 "hi"
	p2 := []byte{0x18, 0x01, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44}
	p2 = append(p2, make([]byte, 16)...)
	p2 = append(p2, 0x0a, 0x00, 0x02, 'h', 'i')
	_, streams, ok := parseFrames(p2)
	if !ok || len(streams) != 1 || string(streams[0].data) != "hi" {
		t.Fatalf("ok=%v streams=%d", ok, len(streams))
	}
}
