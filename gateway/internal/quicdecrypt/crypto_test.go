package quicdecrypt

import (
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// RFC 9001 Appendix A.1: Initial secrets + keys derived from the client DCID.
func TestInitialKeysRFC9001(t *testing.T) {
	dcid := unhex(t, "8394c8f03e515708")
	client, server := initialSecrets(dcid)
	if got := hex.EncodeToString(client); got != "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea" {
		t.Errorf("client_initial_secret = %s", got)
	}
	if got := hex.EncodeToString(server); got != "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b" {
		t.Errorf("server_initial_secret = %s", got)
	}
	check := func(name, secretHex, label string, n int, want string) {
		got := hex.EncodeToString(hkdfExpandLabel(aes128gcm.newHash, unhex(t, secretHex), label, n))
		if got != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
	cs := hex.EncodeToString(client)
	check("client key", cs, "quic key", 16, "1f369613dd76d5467730efcbe3b1a22d")
	check("client iv", cs, "quic iv", 12, "fa044b2f42a3fd3b46fb255c")
	check("client hp", cs, "quic hp", 16, "9f50449e04a0e810283a1e9933adedd2")
	ss := hex.EncodeToString(server)
	check("server key", ss, "quic key", 16, "cf3a5331653c364c88f0f379b6067e37")
	check("server iv", ss, "quic iv", 12, "0ac1493ca1905853b0bba03e")
	check("server hp", ss, "quic hp", 16, "c206b8d9b9f0f37644430b490eeaa314")
}

// RFC 9001 Appendix A.2: decrypt the client Initial packet (AES-128-GCM + AES header
// protection) and confirm the payload starts with the expected CRYPTO frame.
func TestDecryptClientInitialRFC9001(t *testing.T) {
	packet := unhex(t, a2PacketHex)
	wantPrefix := unhex(t, "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff")
	dcid := unhex(t, "8394c8f03e515708")
	client, _ := initialSecrets(dcid)
	k, err := deriveKeys(client, aes128gcm)
	if err != nil {
		t.Fatal(err)
	}
	// header: c3 ver(4) dcidlen(1)=08 dcid(8) scidlen(1)=00 tokenlen(1)=00 length(2)=449e
	// → pnOffset = 1+4+1+8+1+0+1+2 = 18; length 0x449e = 1182 → payloadEnd = 18+1182.
	hdr, pt, pn, ok := k.open(packet, 18, 18+1182, true, 0)
	if !ok {
		t.Fatal("decrypt failed")
	}
	if pn != 2 {
		t.Errorf("packet number = %d, want 2", pn)
	}
	if hdr[0] != 0xc3 {
		t.Errorf("unprotected first byte = %#x, want 0xc3", hdr[0])
	}
	if !strings.HasPrefix(hex.EncodeToString(pt), hex.EncodeToString(wantPrefix)) {
		t.Errorf("payload prefix mismatch; got %s…", hex.EncodeToString(pt)[:80])
	}
}

// RFC 9001 Appendix A.5: decrypt a ChaCha20-Poly1305 short-header packet (PING frame).
func TestDecryptChaChaShortHeaderRFC9001(t *testing.T) {
	secret := unhex(t, "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
	s, _ := suiteByID(0x1303)
	k, err := deriveKeys(secret, s)
	if err != nil {
		t.Fatal(err)
	}
	packet := unhex(t, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
	// short header: 1 flags byte + 0-length DCID → pnOffset = 1; full packet is 21 bytes.
	_, pt, pn, ok := k.open(packet, 1, len(packet), false, 654360563)
	if !ok {
		t.Fatal("decrypt failed")
	}
	if pn != 654360564 {
		t.Errorf("packet number = %d, want 654360564", pn)
	}
	if hex.EncodeToString(pt) != "01" {
		t.Errorf("plaintext = %s, want 01", hex.EncodeToString(pt))
	}
}
