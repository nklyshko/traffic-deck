package tlsdecrypt

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlstest"
)

// TestCapturesClientHelloVerbatim runs a real TLS 1.3 handshake and checks that Conn keeps
// the ClientHello handshake message verbatim (msg_type + length + body), that it re-parses
// to the same fingerprint, and that a normal handshake reports exactly one CH and no HRR.
func TestCapturesClientHelloVerbatim(t *testing.T) {
	c2s, s2c, keylog := tlstest.Exchange(t, "example.org", []byte("hi"), []byte("ok"))
	klPath := filepath.Join(t.TempDir(), "key.log")
	if err := os.WriteFile(klPath, keylog, 0o644); err != nil {
		t.Fatal(err)
	}
	conn := NewConn(NewKeylog(klPath), func(bool, []byte) {})
	conn.Feed(true, c2s)
	conn.Feed(false, s2c)

	hellos := conn.ClientHellos()
	if len(hellos) != 1 {
		t.Fatalf("ClientHellos n=%d, want 1", len(hellos))
	}
	raw := hellos[0]
	if len(raw) < 4 || raw[0] != 1 { // handshake type 1 = ClientHello
		t.Fatalf("first byte = %#x, want a ClientHello handshake message", raw[0])
	}
	bodyLen := int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if 4+bodyLen != len(raw) {
		t.Fatalf("length prefix %d doesn't match captured %d bytes", bodyLen, len(raw)-4)
	}
	// The captured bytes must be the exact fingerprint subject: re-parsing the body yields
	// the same JA3/JA4 as the live parse.
	reparsed := parseClientHelloInfo(raw[4:])
	if reparsed == nil || reparsed.JA3 != conn.ClientHello().JA3 || reparsed.JA4 != conn.ClientHello().JA4 {
		t.Errorf("re-parsed fingerprint mismatch: %+v vs %+v", reparsed, conn.ClientHello())
	}
	if conn.HRRSeen() {
		t.Error("HRRSeen = true for a normal handshake")
	}
}

// TestHelloRetryDetection covers the HRR random matcher and that parsing a ServerHello whose
// random is the HRR sentinel flips HRRSeen.
func TestHelloRetryDetection(t *testing.T) {
	if !IsHelloRetryRandom(helloRetryRequestRandom) {
		t.Error("IsHelloRetryRandom rejected the sentinel value")
	}
	if IsHelloRetryRandom(make([]byte, 32)) {
		t.Error("IsHelloRetryRandom accepted an all-zero random")
	}

	// Minimal HRR ServerHello body: legacy_version, HRR random, empty session_id,
	// cipher_suite, compression, empty extensions.
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})      // legacy_version TLS 1.2
	body.Write(helloRetryRequestRandom) // the HRR sentinel random
	body.WriteByte(0x00)                // session_id length 0
	body.Write([]byte{0x13, 0x01})      // cipher_suite TLS_AES_128_GCM_SHA256
	body.WriteByte(0x00)                // compression_method null
	body.Write([]byte{0x00, 0x00})      // extensions length 0

	c := NewConn(nil, func(bool, []byte) {})
	c.parseServerHello(body.Bytes())
	if !c.HRRSeen() {
		t.Error("HRRSeen = false after parsing a HelloRetryRequest")
	}
}
