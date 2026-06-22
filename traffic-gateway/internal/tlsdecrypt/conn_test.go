package tlsdecrypt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder wraps a net.Conn and captures the raw bytes in both directions as seen by
// the client: Write = client→server, Read = server→client. All access is from one
// goroutine in the test (crypto/tls drives the handshake synchronously), so no locking.
type recorder struct {
	net.Conn
	c2s, s2c bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) {
	n, err := r.Conn.Write(p)
	r.c2s.Write(p[:n])
	return n, err
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.s2c.Write(p[:n])
	return n, err
}

type lockedWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func genCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"api.oneme.ru"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestDecryptAgainstCryptoTLS runs a real TLS 1.3 handshake + bidirectional app data
// over localhost, records the wire bytes and key-log, then feeds them through Conn and
// asserts the recovered plaintext (and SNI) match — crypto/tls is the ground truth.
func TestDecryptAgainstCryptoTLS(t *testing.T) {
	cert := genCert(t)
	klw := &lockedWriter{}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	clientMsg := []byte("GET /v1 — hello from client " + strings.Repeat("c", 200))
	serverMsg := []byte("200 OK — hello from server " + strings.Repeat("s", 60000)) // multi-record

	done := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		sc := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			KeyLogWriter: klw,
		})
		buf := make([]byte, len(clientMsg))
		if _, err := io.ReadFull(sc, buf); err != nil {
			done <- err
			return
		}
		if _, err := sc.Write(serverMsg); err != nil {
			done <- err
			return
		}
		_ = sc.CloseWrite()
		done <- nil
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{Conn: raw}
	cc := tls.Client(rec, &tls.Config{
		InsecureSkipVerify: true, ServerName: "api.oneme.ru",
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		KeyLogWriter: klw,
	})
	if _, err := cc.Write(clientMsg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(serverMsg))
	if _, err := io.ReadFull(cc, got); err != nil {
		t.Fatal(err)
	}
	cc.Close()
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}

	// Build a key-log file from the captured secrets and replay the recorded records.
	klPath := filepath.Join(t.TempDir(), "key.log")
	if err := os.WriteFile(klPath, klw.b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	var c2s, s2c bytes.Buffer
	conn := NewConn(NewKeylog(klPath), func(fromClient bool, data []byte) {
		if fromClient {
			c2s.Write(data)
		} else {
			s2c.Write(data)
		}
	})
	// Feed client→server first (no ServerHello yet → app records buffer), then
	// server→client (ServerHello unblocks both directions).
	conn.Feed(true, rec.c2s.Bytes())
	conn.Feed(false, rec.s2c.Bytes())

	if conn.SNI() != "api.oneme.ru" {
		t.Fatalf("SNI = %q, want api.oneme.ru", conn.SNI())
	}
	if conn.Unsupported() {
		t.Fatal("reported unsupported for a TLS 1.3 connection")
	}
	if !bytes.Equal(c2s.Bytes(), clientMsg) {
		t.Fatalf("client→server decrypt mismatch: got %d bytes, want %d", c2s.Len(), len(clientMsg))
	}
	if !bytes.Equal(s2c.Bytes(), serverMsg) {
		t.Fatalf("server→client decrypt mismatch: got %d bytes, want %d", s2c.Len(), len(serverMsg))
	}
}

// TestDecryptByteAtATime feeds the recorded streams one byte at a time to prove the
// incremental record framing + deferred decryption work under arbitrary fragmentation.
func TestDecryptByteAtATime(t *testing.T) {
	cert := genCert(t)
	klw := &lockedWriter{}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	clientMsg := []byte("ping")
	serverMsg := []byte("pong-" + strings.Repeat("z", 3000))
	done := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		sc := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert},
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, KeyLogWriter: klw})
		buf := make([]byte, len(clientMsg))
		io.ReadFull(sc, buf)
		sc.Write(serverMsg)
		sc.CloseWrite()
		done <- nil
	}()
	raw, _ := net.Dial("tcp", ln.Addr().String())
	rec := &recorder{Conn: raw}
	cc := tls.Client(rec, &tls.Config{InsecureSkipVerify: true, ServerName: "x.oneme.ru",
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, KeyLogWriter: klw})
	cc.Write(clientMsg)
	got := make([]byte, len(serverMsg))
	io.ReadFull(cc, got)
	cc.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	klPath := filepath.Join(t.TempDir(), "key.log")
	os.WriteFile(klPath, klw.b.Bytes(), 0o644)
	var s2c bytes.Buffer
	conn := NewConn(NewKeylog(klPath), func(fromClient bool, data []byte) {
		if !fromClient {
			s2c.Write(data)
		}
	})
	feedByteAtATime(conn, true, rec.c2s.Bytes())
	feedByteAtATime(conn, false, rec.s2c.Bytes())
	if !bytes.Equal(s2c.Bytes(), serverMsg) {
		t.Fatalf("byte-at-a-time decrypt mismatch: got %d, want %d", s2c.Len(), len(serverMsg))
	}
}

func feedByteAtATime(c *Conn, fromClient bool, b []byte) {
	for i := 0; i < len(b); i++ {
		c.Feed(fromClient, b[i:i+1])
	}
}
