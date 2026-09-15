package tlsdecrypt

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nklyshko/traffic-deck/gateway/internal/tlstest"
)

// TestDecryptAgainstCryptoTLS runs a real TLS 1.3 handshake + bidirectional app data,
// then feeds the recorded wire bytes through Conn and asserts the recovered plaintext
// (and SNI) match — crypto/tls is the ground truth.
func TestDecryptAgainstCryptoTLS(t *testing.T) {
	clientMsg := []byte("GET /v1 — hello from client " + strings.Repeat("c", 200))
	serverMsg := []byte("200 OK — hello from server " + strings.Repeat("s", 60000)) // multi-record
	c2s, s2c, keylog := tlstest.Exchange(t, "api.oneme.ru", clientMsg, serverMsg)

	klPath := filepath.Join(t.TempDir(), "key.log")
	if err := os.WriteFile(klPath, keylog, 0o644); err != nil {
		t.Fatal(err)
	}
	var gotC2S, gotS2C bytes.Buffer
	conn := NewConn(NewKeylog(klPath), func(fromClient bool, data []byte) {
		if fromClient {
			gotC2S.Write(data)
		} else {
			gotS2C.Write(data)
		}
	})
	// Feed client→server first (no ServerHello yet → app records buffer), then
	// server→client (ServerHello unblocks both directions).
	conn.Feed(true, c2s)
	conn.Feed(false, s2c)

	if conn.SNI() != "api.oneme.ru" {
		t.Fatalf("SNI = %q, want api.oneme.ru", conn.SNI())
	}
	// The real crypto/tls ClientHello parses into a JA3/JA4 fingerprint.
	ch := conn.ClientHello()
	if ch == nil {
		t.Fatal("ClientHello not parsed")
	}
	if ch.SNI != "api.oneme.ru" || len(ch.Ciphers) == 0 || len(ch.Extensions) == 0 {
		t.Errorf("ClientHello = %+v", ch)
	}
	if len(ch.JA3) != 32 { // md5 hex
		t.Errorf("JA3 = %q, want 32 hex chars", ch.JA3)
	}
	if len(ch.JA4) < 10 || ch.JA4[0] != 't' {
		t.Errorf("JA4 = %q", ch.JA4)
	}
	if conn.Unsupported() {
		t.Fatal("reported unsupported for a TLS 1.3 connection")
	}
	if !bytes.Equal(gotC2S.Bytes(), clientMsg) {
		t.Fatalf("client→server decrypt mismatch: got %d bytes, want %d", gotC2S.Len(), len(clientMsg))
	}
	if !bytes.Equal(gotS2C.Bytes(), serverMsg) {
		t.Fatalf("server→client decrypt mismatch: got %d bytes, want %d", gotS2C.Len(), len(serverMsg))
	}
}

// TestDecryptByteAtATime feeds the recorded streams one byte at a time to prove the
// incremental record framing + deferred decryption work under arbitrary fragmentation.
func TestDecryptByteAtATime(t *testing.T) {
	clientMsg := []byte("ping")
	serverMsg := []byte("pong-" + strings.Repeat("z", 3000))
	c2s, s2c, keylog := tlstest.Exchange(t, "x.oneme.ru", clientMsg, serverMsg)

	klPath := filepath.Join(t.TempDir(), "key.log")
	if err := os.WriteFile(klPath, keylog, 0o644); err != nil {
		t.Fatal(err)
	}
	var gotS2C bytes.Buffer
	conn := NewConn(NewKeylog(klPath), func(fromClient bool, data []byte) {
		if !fromClient {
			gotS2C.Write(data)
		}
	})
	feedByteAtATime(conn, true, c2s)
	feedByteAtATime(conn, false, s2c)
	if !bytes.Equal(gotS2C.Bytes(), serverMsg) {
		t.Fatalf("byte-at-a-time decrypt mismatch: got %d, want %d", gotS2C.Len(), len(serverMsg))
	}
}

func feedByteAtATime(c *Conn, fromClient bool, b []byte) {
	for i := 0; i < len(b); i++ {
		c.Feed(fromClient, b[i:i+1])
	}
}
