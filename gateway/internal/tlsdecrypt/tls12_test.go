package tlsdecrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestPRF12SHA256 checks prf12 against the canonical TLS 1.2 P_SHA256 test vector
// (widely cited from the IETF TLS WG mailing list).
func TestPRF12SHA256(t *testing.T) {
	secret, _ := hex.DecodeString("9bbe436ba940f017b17652849a71db35")
	seed, _ := hex.DecodeString("a0ba9f936cda311827a6f796ffd5198c")
	want, _ := hex.DecodeString(
		"e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a" +
			"6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab" +
			"4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701" +
			"87347b66")

	got := prf12(sha256.New, secret, "test label", seed, len(want))
	if !bytes.Equal(got, want) {
		t.Fatalf("prf12 mismatch:\n got %x\nwant %x", got, want)
	}
}

// TestTLS12GCMRoundTrip crafts real TLS 1.2 AES-128-GCM records (encrypting with stdlib
// GCM the way a TLS stack would) and verifies tls12Decryptor.open recovers the plaintext
// and advances the sequence number across records.
func TestTLS12GCMRoundTrip(t *testing.T) {
	master := bytes.Repeat([]byte{0x2a}, 48)
	clientRandom := bytes.Repeat([]byte{0x11}, 32)
	serverRandom := bytes.Repeat([]byte{0x22}, 32)
	suite, ok := tls12SuiteByID(0xc02f) // ECDHE-RSA-AES128-GCM-SHA256
	if !ok {
		t.Fatal("suite 0xc02f not found")
	}

	// Independently derive the server_write key + fixed IV (the decryptor reads the
	// server half for fromClient=false), so the encryption side isn't circular.
	kb := prf12(suite.prfHash, master, "key expansion", append(append([]byte{}, serverRandom...), clientRandom...),
		2*suite.keyLen+2*suite.fixedIVLen)
	serverKey := kb[suite.keyLen : 2*suite.keyLen]
	serverIV := kb[2*suite.keyLen+suite.fixedIVLen : 2*suite.keyLen+2*suite.fixedIVLen]
	block, _ := aes.NewCipher(serverKey)
	gcm, _ := cipher.NewGCM(block)

	dec, err := newTLS12Decryptor(suite, master, clientRandom, serverRandom, false)
	if err != nil {
		t.Fatal(err)
	}

	seal := func(seq uint64, plaintext []byte) []byte {
		explicit := make([]byte, 8)
		binary.BigEndian.PutUint64(explicit, seq) // TLS stacks commonly use seq as the explicit nonce
		nonce := append(append([]byte{}, serverIV...), explicit...)
		aad := make([]byte, 8)
		binary.BigEndian.PutUint64(aad, seq)
		aad = append(aad, ctAppData, 0x03, 0x03, byte(len(plaintext)>>8), byte(len(plaintext)))
		ct := gcm.Seal(nil, nonce, plaintext, aad)
		frag := append(explicit, ct...)
		header := []byte{ctAppData, 0x03, 0x03, byte(len(frag) >> 8), byte(len(frag))}
		return append(header, frag...)
	}

	for seq, msg := range [][]byte{[]byte("hello tls 1.2"), []byte("second record")} {
		rec := seal(uint64(seq), msg)
		got, ok := dec.open(rec[:recHeaderLen], rec[recHeaderLen:])
		if !ok {
			t.Fatalf("record %d: open failed", seq)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("record %d: got %q want %q", seq, got, msg)
		}
	}
}
