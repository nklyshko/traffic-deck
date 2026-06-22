// Package tlstest provides shared helpers for tests that need real TLS 1.3 traffic:
// a handshake plus a bidirectional application-data exchange over localhost, returning
// the recorded wire bytes per direction and the NSS key-log.
package tlstest

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
	"sync"
	"testing"
	"time"
)

// recorder wraps a net.Conn capturing both directions as seen by the client:
// Write = client→server, Read = server→client.
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

// syncWriter is a goroutine-safe sink for the key-log (both peers write to it).
type syncWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func cert(t *testing.T) tls.Certificate {
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
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Exchange runs a TLS 1.3 handshake over localhost, sends clientApp then serverApp, and
// returns the recorded client→server bytes, server→client bytes, and the NSS key-log.
func Exchange(t *testing.T, sni string, clientApp, serverApp []byte) (c2s, s2c, keylog []byte) {
	t.Helper()
	crt := cert(t)
	klw := &syncWriter{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		sc := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{crt},
			MinVersion:   tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			KeyLogWriter: klw,
		})
		buf := make([]byte, len(clientApp))
		if _, err := io.ReadFull(sc, buf); err != nil {
			done <- err
			return
		}
		if _, err := sc.Write(serverApp); err != nil {
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
		InsecureSkipVerify: true, ServerName: sni,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		KeyLogWriter: klw,
	})
	if _, err := cc.Write(clientApp); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(serverApp))
	if _, err := io.ReadFull(cc, got); err != nil {
		t.Fatal(err)
	}
	cc.Close()
	if err := <-done; err != nil {
		t.Fatalf("tls server: %v", err)
	}
	return rec.c2s.Bytes(), rec.s2c.Bytes(), klw.b.Bytes()
}
