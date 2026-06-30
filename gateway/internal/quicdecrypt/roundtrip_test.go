package quicdecrypt

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
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
	body = append(body, 0x00)             // session_id len 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites: TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)       // compression methods
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

	var gotID uint64
	var gotFromClient bool
	var gotData []byte
	c := NewConn(tlsdecrypt.NewKeylog(klPath), func(id uint64, fromClient bool, data []byte) {
		gotID, gotFromClient, gotData = id, fromClient, data
	})

	// Initial keys are deterministic from the client DCID; 1-RTT keys come from the keylog.
	clSec, svSec := initialSecrets(dcid)
	clInit, _ := deriveKeys(clSec, aes128gcm)
	svInit, _ := deriveKeys(svSec, aes128gcm)
	suite, _ := suiteByID(0x1301)
	clApp, _ := deriveKeys(clientTS, suite)

	// 1) client Initial with the ClientHello → Conn learns client_random + SNI.
	ci := buildInitial(clInit, dcid, clientSCID, 0, cryptoFrameBytes(clientHelloMsg(random, "example.com")))
	c.Feed(true, ci)
	if c.SNI != "example.com" {
		t.Fatalf("SNI = %q after client Initial", c.SNI)
	}
	// 2) server Initial with the ServerHello → Conn learns the cipher suite + serverSCID.
	si := buildInitial(svInit, clientSCID, serverSCID, 0, cryptoFrameBytes(serverHelloMsg(0x1301)))
	c.Feed(false, si)
	// 3) client 1-RTT carrying a STREAM frame (DCID = server's SCID).
	app := build1RTT(clApp, serverSCID, 0, streamFrameBytes(0, []byte("hello-http3")))
	c.Feed(true, app)

	if string(gotData) != "hello-http3" || gotID != 0 || !gotFromClient {
		t.Fatalf("onStream got (id=%d fromClient=%v data=%q), want (0, true, hello-http3)", gotID, gotFromClient, gotData)
	}
}
