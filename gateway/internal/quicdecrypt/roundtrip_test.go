package quicdecrypt

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

// seal is the inverse of keys.open: it AEAD-encrypts a packet and applies header
// protection, so tests can build real protected QUIC packets. hdr is the unprotected
// header including the (cleartext) packet-number bytes at pnOffset.
func seal(k *keys, hdr []byte, pnOffset, pnLen int, pn uint64, payload []byte, long bool) []byte {
	nonce := make([]byte, 12)
	copy(nonce, k.iv)
	var pnb [8]byte
	binary.BigEndian.PutUint64(pnb[:], pn)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= pnb[i]
	}
	ct := k.aead.Seal(nil, nonce, payload, hdr)
	pkt := append(append([]byte(nil), hdr...), ct...)
	mask := k.hp.mask(pkt[pnOffset+4 : pnOffset+4+16])
	if long {
		pkt[0] ^= mask[0] & 0x0f
	} else {
		pkt[0] ^= mask[0] & 0x1f
	}
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt
}

func putVarint(v uint64) []byte {
	if v < 64 {
		return []byte{byte(v)}
	}
	return []byte{0x40 | byte(v>>8), byte(v)}
}

// buildInitial assembles + seals a long-header Initial packet (1-byte pn) carrying payload.
func buildInitial(k *keys, dcid, scid []byte, pn uint64, payload []byte) []byte {
	length := 1 + len(payload) + 16 // pn + ciphertext + GCM tag
	hdr := []byte{0xc0}             // long | fixed | Initial | pnLen-1=0
	hdr = append(hdr, 0x00, 0x00, 0x00, 0x01)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = append(hdr, 0x00) // token length 0
	hdr = append(hdr, putVarint(uint64(length))...)
	pnOffset := len(hdr)
	hdr = append(hdr, byte(pn))
	return seal(k, hdr, pnOffset, 1, pn, payload, true)
}

// build1RTT assembles + seals a short-header 1-RTT packet (1-byte pn) with the given DCID.
func build1RTT(k *keys, dcid []byte, pn uint64, payload []byte) []byte {
	hdr := []byte{0x40} // short | fixed | pnLen-1=0
	hdr = append(hdr, dcid...)
	pnOffset := len(hdr)
	hdr = append(hdr, byte(pn))
	return seal(k, hdr, pnOffset, 1, pn, payload, false)
}

// buildZeroRTT assembles + seals a long-header 0-RTT packet (1-byte pn) carrying payload.
// Same shape as an Initial but without the token field.
func buildZeroRTT(k *keys, dcid, scid []byte, pn uint64, payload []byte) []byte {
	length := 1 + len(payload) + 16
	hdr := []byte{0xd0} // long | fixed | 0-RTT (type 01) | pnLen-1=0
	hdr = append(hdr, 0x00, 0x00, 0x00, 0x01)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = append(hdr, putVarint(uint64(length))...)
	pnOffset := len(hdr)
	hdr = append(hdr, byte(pn))
	return seal(k, hdr, pnOffset, 1, pn, payload, true)
}

func cryptoFrameBytes(msg []byte) []byte {
	out := []byte{frmCrypto}
	out = append(out, putVarint(0)...)
	out = append(out, putVarint(uint64(len(msg)))...)
	return append(out, msg...)
}

func streamFrameBytes(id uint64, data []byte) []byte {
	out := []byte{0x0a} // STREAM with LEN bit (0x08|0x02), offset 0
	out = append(out, putVarint(id)...)
	out = append(out, putVarint(uint64(len(data)))...)
	return append(out, data...)
}

func clientHelloMsg(random []byte, sni string) []byte {
	name := []byte(sni)
	entry := append([]byte{0x00}, byte(len(name)>>8), byte(len(name)))
	entry = append(entry, name...)
	list := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	sniExt := append([]byte{0x00, 0x00, byte(len(list) >> 8), byte(len(list))}, list...)
	exts := append([]byte{byte(len(sniExt) >> 8), byte(len(sniExt))}, sniExt...)

	body := []byte{0x03, 0x03}
	body = append(body, random...)
	body = append(body, 0x00)                   // session_id len 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites: TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)             // compression methods
	body = append(body, exts...)
	return append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func serverHelloMsg(suiteID uint16) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id len 0
	body = append(body, byte(suiteID>>8), byte(suiteID))
	return append([]byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// TestConnRoundTrip drives a full synthetic connection through Conn: client/server
// Initial (handshake) + a 1-RTT STREAM, and checks the stream is decrypted, reassembled,
// and delivered. The packet crypto is independently verified by the RFC 9001 vectors.
func TestConnRoundTrip(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	clientSCID := []byte{0x11, 0x12, 0x13, 0x14}
	serverSCID := []byte{0x21, 0x22, 0x23, 0x24}
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 1)
	}
	clientTS := make([]byte, 32)
	serverTS := make([]byte, 32)
	for i := range clientTS {
		clientTS[i] = byte(0xa0 + i)
		serverTS[i] = byte(0xb0 + i)
	}

	dir := t.TempDir()
	klPath := filepath.Join(dir, "key.log")
	klData := "CLIENT_TRAFFIC_SECRET_0 " + hex.EncodeToString(random) + " " + hex.EncodeToString(clientTS) + "\n" +
		"SERVER_TRAFFIC_SECRET_0 " + hex.EncodeToString(random) + " " + hex.EncodeToString(serverTS) + "\n"
	if err := os.WriteFile(klPath, []byte(klData), 0o644); err != nil {
		t.Fatal(err)
	}

	type delivery struct {
		id   uint64
		fc   bool
		data string
	}
	var got []delivery
	c := NewConn(tlsdecrypt.NewKeylog(klPath), func(id uint64, fromClient bool, data []byte) {
		got = append(got, delivery{id, fromClient, string(data)})
	})

	// Initial keys are deterministic from the client DCID; 1-RTT keys come from the keylog.
	clSec, svSec := initialSecrets(dcid)
	clInit, _ := deriveKeys(clSec, aes128gcm)
	svInit, _ := deriveKeys(svSec, aes128gcm)
	suite, _ := suiteByID(0x1301)
	clApp, _ := deriveKeys(clientTS, suite)
	svApp, _ := deriveKeys(serverTS, suite)

	// 1) client Initial with the ClientHello → Conn learns client_random + SNI.
	ci := buildInitial(clInit, dcid, clientSCID, 0, cryptoFrameBytes(clientHelloMsg(random, "example.com")))
	c.Feed(true, ci)
	if c.SNI != "example.com" {
		t.Fatalf("SNI = %q after client Initial", c.SNI)
	}
	// The QUIC ClientHello parses into a JA3/JA4 fingerprint, marked as QUIC transport.
	if c.ClientHello == nil {
		t.Fatal("ClientHello fingerprint not parsed from QUIC Initial")
	}
	if len(c.ClientHello.JA4) == 0 || c.ClientHello.JA4[0] != 'q' {
		t.Errorf("QUIC JA4 = %q, want a 'q…' fingerprint", c.ClientHello.JA4)
	}
	// 2) server Initial with the ServerHello → Conn learns the cipher suite + serverSCID.
	si := buildInitial(svInit, clientSCID, serverSCID, 0, cryptoFrameBytes(serverHelloMsg(0x1301)))
	c.Feed(false, si)
	// 3) client request + server response on bidi stream 0 — BOTH at offset 0. A bidi
	// stream carries each direction with independent offsets, so they must reassemble
	// separately (regression: a single per-id buffer mixed them and corrupted the second).
	c.Feed(true, build1RTT(clApp, serverSCID, 0, streamFrameBytes(0, []byte("request-bytes"))))
	c.Feed(false, build1RTT(svApp, clientSCID, 0, streamFrameBytes(0, []byte("response-bytes"))))

	if len(got) != 2 {
		t.Fatalf("got %d deliveries, want 2: %+v", len(got), got)
	}
	want := map[bool]string{true: "request-bytes", false: "response-bytes"}
	for _, d := range got {
		if d.id != 0 || d.data != want[d.fc] {
			t.Errorf("delivery %+v; want id=0 data=%q", d, want[d.fc])
		}
	}
}

// TestConn0RTT checks that client 0-RTT early data — which arrives before the ServerHello
// reveals the cipher suite — is buffered and decrypted once the suite is known.
func TestConn0RTT(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	clientSCID := []byte{0x11, 0x12, 0x13, 0x14}
	serverSCID := []byte{0x21, 0x22, 0x23, 0x24}
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 1)
	}
	earlyTS := make([]byte, 32)
	for i := range earlyTS {
		earlyTS[i] = byte(0xc0 + i)
	}

	dir := t.TempDir()
	klPath := filepath.Join(dir, "key.log")
	kl := "CLIENT_EARLY_TRAFFIC_SECRET " + hex.EncodeToString(random) + " " + hex.EncodeToString(earlyTS) + "\n"
	if err := os.WriteFile(klPath, []byte(kl), 0o644); err != nil {
		t.Fatal(err)
	}

	var got []string
	c := NewConn(tlsdecrypt.NewKeylog(klPath), func(id uint64, fromClient bool, data []byte) {
		if fromClient {
			got = append(got, string(data))
		}
	})

	clSec, svSec := initialSecrets(dcid)
	clInit, _ := deriveKeys(clSec, aes128gcm)
	svInit, _ := deriveKeys(svSec, aes128gcm)
	suite, _ := suiteByID(0x1301)
	earlyKey, _ := deriveKeys(earlyTS, suite)

	// 1) client Initial (ClientHello) → learns client_random.
	c.Feed(true, buildInitial(clInit, dcid, clientSCID, 0, cryptoFrameBytes(clientHelloMsg(random, "example.com"))))
	// 2) client 0-RTT with early request data — arrives before the ServerHello, so it's
	// buffered (the suite isn't known yet).
	c.Feed(true, buildZeroRTT(earlyKey, dcid, clientSCID, 1, streamFrameBytes(0, []byte("early-request"))))
	if len(got) != 0 {
		t.Fatalf("0-RTT delivered before ServerHello: %v", got)
	}
	// 3) server Initial (ServerHello) reveals the suite → buffered 0-RTT decrypts.
	c.Feed(false, buildInitial(svInit, clientSCID, serverSCID, 0, cryptoFrameBytes(serverHelloMsg(0x1301))))

	if len(got) != 1 || got[0] != "early-request" {
		t.Fatalf("0-RTT deliveries = %v; want [early-request]", got)
	}
}

// streamFrameBytesAt is streamFrameBytes with an explicit offset (OFF|LEN bits), so a test
// can split one stream across several packets and check they reassemble in order.
func streamFrameBytesAt(id, offset uint64, data []byte) []byte {
	out := []byte{0x0e} // STREAM with OFF|LEN (0x08|0x04|0x02)
	out = append(out, putVarint(id)...)
	out = append(out, putVarint(offset)...)
	out = append(out, putVarint(uint64(len(data)))...)
	return append(out, data...)
}

// bufFixture is a handshaken Conn whose key.log exists but is still empty — dumpcap
// records from before the browser has written any secret — plus the packet-protection
// keys to build 1-RTT packets with and the key-log lines to append when the secrets
// "flush". Deliveries land in got, in call order.
type bufFixture struct {
	c                      *Conn
	klPath, klSecrets      string
	clApp, svApp           *keys
	clientSCID, serverSCID []byte
	got                    []string
}

func newBufFixture(t *testing.T) *bufFixture {
	t.Helper()
	f := &bufFixture{
		clientSCID: []byte{0x11, 0x12, 0x13, 0x14},
		serverSCID: []byte{0x21, 0x22, 0x23, 0x24},
	}
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	random := make([]byte, 32)
	clientTS := make([]byte, 32)
	serverTS := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 1)
		clientTS[i] = byte(0xa0 + i)
		serverTS[i] = byte(0xb0 + i)
	}
	f.klSecrets = "CLIENT_TRAFFIC_SECRET_0 " + hex.EncodeToString(random) + " " + hex.EncodeToString(clientTS) + "\n" +
		"SERVER_TRAFFIC_SECRET_0 " + hex.EncodeToString(random) + " " + hex.EncodeToString(serverTS) + "\n"

	f.klPath = filepath.Join(t.TempDir(), "key.log")
	if err := os.WriteFile(f.klPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f.c = NewConn(tlsdecrypt.NewKeylog(f.klPath), func(_ uint64, _ bool, data []byte) {
		f.got = append(f.got, string(data))
	})

	clSec, svSec := initialSecrets(dcid)
	clInit, _ := deriveKeys(clSec, aes128gcm)
	svInit, _ := deriveKeys(svSec, aes128gcm)
	suite, _ := suiteByID(0x1301)
	f.clApp, _ = deriveKeys(clientTS, suite)
	f.svApp, _ = deriveKeys(serverTS, suite)

	// Handshake: client_random + SNI from the ClientHello, cipher suite from the
	// ServerHello. Everything but the key-log secrets is now known.
	f.c.Feed(true, buildInitial(clInit, dcid, f.clientSCID, 0, cryptoFrameBytes(clientHelloMsg(random, "example.com"))))
	f.c.Feed(false, buildInitial(svInit, f.clientSCID, f.serverSCID, 0, cryptoFrameBytes(serverHelloMsg(0x1301))))
	if f.c.suite == nil {
		t.Fatal("suite not learned from the ServerHello")
	}
	if f.c.app[0] != nil {
		t.Fatal("1-RTT keys derived from an empty key.log")
	}
	return f
}

// flushSecrets appends the 1-RTT secrets to the key-log, as the browser does a few
// milliseconds after the handshake completes.
func (f *bufFixture) flushSecrets(t *testing.T) {
	t.Helper()
	fh, err := os.OpenFile(f.klPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fh.WriteString(f.klSecrets); err != nil {
		t.Fatal(err)
	}
	fh.Close()
}

// TestConn1RTTBuffered is the regression test for requests lost to the key-log flush race.
// A browser writes *_TRAFFIC_SECRET_0 a few milliseconds after the handshake completes;
// the client 1-RTT packets sent in that window used to be dropped outright. In a real
// capture they carry the QPACK encoder-stream setup, so losing them left every later
// HEADERS blocked on a dynamic table that was never initialized.
func TestConn1RTTBuffered(t *testing.T) {
	f := newBufFixture(t)

	// Client 1-RTT before the secrets land: buffered, not dropped.
	f.c.Feed(true, build1RTT(f.clApp, f.serverSCID, 0, streamFrameBytesAt(0, 0, []byte("part-one "))))
	f.c.Feed(true, build1RTT(f.clApp, f.serverSCID, 1, streamFrameBytesAt(0, 9, []byte("part-two "))))
	if len(f.got) != 0 {
		t.Fatalf("delivered %v before the keys were available", f.got)
	}

	f.flushSecrets(t)
	// The next packet derives the keys, which replays the buffered two ahead of it.
	f.c.Feed(true, build1RTT(f.clApp, f.serverSCID, 2, streamFrameBytesAt(0, 18, []byte("part-three"))))

	if got := strings.Join(f.got, ""); got != "part-one part-two part-three" {
		t.Fatalf("stream 0 = %q, want the three parts in order", got)
	}
	if len(f.got) != 3 || f.got[0] != "part-one " {
		t.Fatalf("deliveries = %v; want the buffered packets replayed first, in arrival order", f.got)
	}
}

// TestConn1RTTBothDirectionsBuffered covers the server direction: a response that arrives
// before the secrets flush is replayed too, triggered by a packet from the other side.
func TestConn1RTTBothDirectionsBuffered(t *testing.T) {
	f := newBufFixture(t)

	f.c.Feed(false, build1RTT(f.svApp, f.clientSCID, 0, streamFrameBytesAt(0, 0, []byte("response-"))))
	f.c.Feed(false, build1RTT(f.svApp, f.clientSCID, 1, streamFrameBytesAt(0, 9, []byte("bytes"))))
	if len(f.got) != 0 {
		t.Fatalf("delivered %v before the keys were available", f.got)
	}

	f.flushSecrets(t)
	// Derivation is triggered from the *client* direction; both directions still replay.
	f.c.Feed(true, build1RTT(f.clApp, f.serverSCID, 0, streamFrameBytesAt(0, 0, []byte("request-bytes"))))

	if got := strings.Join(f.got, ""); !strings.Contains(got, "response-bytes") {
		t.Fatalf("deliveries = %v; want the buffered server bytes replayed", f.got)
	}
	if !strings.Contains(strings.Join(f.got, ""), "request-bytes") {
		t.Fatalf("deliveries = %v; want the triggering client packet too", f.got)
	}
}

// TestConn1RTTBufferCapped: a connection whose secrets never arrive — one from a process
// not started under SSLKEYLOGFILE, which an unfiltered capture tracks like any other —
// must not buffer its whole lifetime's traffic. Past the cap it drops, as before the fix.
func TestConn1RTTBufferCapped(t *testing.T) {
	f := newBufFixture(t)

	payload := streamFrameBytesAt(4, 0, make([]byte, 1200))
	for sent := 0; sent <= max1RTTBuffered; {
		pkt := build1RTT(f.clApp, f.serverSCID, 0, payload)
		f.c.Feed(true, pkt)
		sent += len(pkt)
	}
	if !f.c.app1RTTFull {
		t.Fatal("buffer never hit its cap")
	}
	if f.c.app1RTTBytes != 0 || f.c.app1RTT[0] != nil {
		t.Fatalf("capped buffer still holds %d bytes in %d packets — memory not released",
			f.c.app1RTTBytes, len(f.c.app1RTT[0]))
	}

	// Keys arriving late now recover only live traffic; the flood stays dropped.
	f.flushSecrets(t)
	f.c.Feed(true, build1RTT(f.clApp, f.serverSCID, 1, streamFrameBytesAt(0, 0, []byte("live-request"))))
	if len(f.got) != 1 || f.got[0] != "live-request" {
		t.Fatalf("deliveries = %v; want just [live-request]", f.got)
	}
}
