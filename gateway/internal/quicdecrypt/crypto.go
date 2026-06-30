// Package quicdecrypt passively decrypts QUIC (RFC 9000) packet protection (RFC 9001)
// from a captured datagram stream plus an NSS key-log, so the gateway can decode
// HTTP/3 live, in-process, without re-running tshark. Scope: QUIC v1, TLS 1.3 AEAD
// suites (AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305). Initial packets are decrypted
// with the version-derived secrets; Handshake/1-RTT use the key-log traffic secrets
// (keyed by the ClientHello's client_random, recovered from the Initial CRYPTO frame).
package quicdecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Version1 is QUIC v1 (RFC 9000). initialSaltV1 is its Initial-secret salt (RFC 9001 §5.2).
const Version1 = 0x00000001

var initialSaltV1 = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// suite holds the AEAD parameters of a TLS 1.3 cipher suite as used by QUIC.
type suite struct {
	keyLen  int
	newHash func() hash.Hash
	chacha  bool
	aead    func(key []byte) (cipher.AEAD, error)
}

func gcmAEAD(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// aes128gcm is the suite used for all QUIC Initial packets (RFC 9001 §5.2).
var aes128gcm = &suite{keyLen: 16, newHash: sha256.New, aead: gcmAEAD}

// suiteByID maps a TLS 1.3 cipher-suite id (from the ServerHello) to its parameters.
func suiteByID(id uint16) (*suite, bool) {
	switch id {
	case 0x1301:
		return &suite{16, sha256.New, false, gcmAEAD}, true
	case 0x1302:
		return &suite{32, sha512.New384, false, gcmAEAD}, true
	case 0x1303:
		return &suite{32, sha256.New, true, chacha20poly1305.New}, true
	}
	return nil, false
}

// hkdfExpandLabel is HKDF-Expand-Label (RFC 8446 §7.1); QUIC reuses it with the same
// "tls13 " prefix and its own labels ("quic key"/"quic iv"/"quic hp", "client in", …).
func hkdfExpandLabel(newHash func() hash.Hash, secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 3+len(full)+1)
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.Expand(newHash, secret, info), out); err != nil {
		return nil
	}
	return out
}

// initialSecrets derives the client and server Initial traffic secrets for a connection
// from its (client-chosen) Destination Connection ID (RFC 9001 §5.2).
func initialSecrets(dcid []byte) (client, server []byte) {
	initial := hkdf.Extract(sha256.New, dcid, initialSaltV1)
	client = hkdfExpandLabel(sha256.New, initial, "client in", 32)
	server = hkdfExpandLabel(sha256.New, initial, "server in", 32)
	return client, server
}

// headerProtector produces the 5-byte header-protection mask from a ciphertext sample
// (RFC 9001 §5.4).
type headerProtector interface {
	mask(sample []byte) []byte
}

type aesHP struct{ b cipher.Block }

func (h aesHP) mask(sample []byte) []byte {
	out := make([]byte, 16)
	h.b.Encrypt(out, sample[:16]) // AES-ECB single block
	return out[:5]
}

type chachaHP struct{ key []byte }

func (h chachaHP) mask(sample []byte) []byte {
	c, err := chacha20.NewUnauthenticatedCipher(h.key, sample[4:16])
	if err != nil {
		return make([]byte, 5)
	}
	c.SetCounter(binary.LittleEndian.Uint32(sample[0:4]))
	out := make([]byte, 5)
	c.XORKeyStream(out, out)
	return out
}

// keys is one direction's QUIC packet-protection keys (RFC 9001 §5.1).
type keys struct {
	aead cipher.AEAD
	iv   []byte
	hp   headerProtector
}

func deriveKeys(secret []byte, s *suite) (*keys, error) {
	key := hkdfExpandLabel(s.newHash, secret, "quic key", s.keyLen)
	iv := hkdfExpandLabel(s.newHash, secret, "quic iv", 12)
	hpKey := hkdfExpandLabel(s.newHash, secret, "quic hp", s.keyLen)
	aead, err := s.aead(key)
	if err != nil {
		return nil, err
	}
	k := &keys{aead: aead, iv: iv}
	if s.chacha {
		k.hp = chachaHP{hpKey}
	} else {
		b, err := aes.NewCipher(hpKey)
		if err != nil {
			return nil, err
		}
		k.hp = aesHP{b}
	}
	return k, nil
}

// decodePacketNumber reconstructs the full packet number from its truncated on-wire
// value, given the number of bytes used and the largest packet number seen so far in
// this number space (RFC 9000 Appendix A).
func decodePacketNumber(truncated uint64, pnLen int, largest uint64) uint64 {
	pnBits := uint(pnLen * 8)
	pnWin := uint64(1) << pnBits
	pnHalf := pnWin / 2
	expected := largest + 1
	candidate := (expected &^ (pnWin - 1)) | truncated
	if candidate+pnHalf <= expected && candidate+pnWin < (uint64(1)<<62) {
		return candidate + pnWin
	}
	if candidate > expected+pnHalf && candidate >= pnWin {
		return candidate - pnWin
	}
	return candidate
}

// open removes header protection and AEAD-decrypts one packet that starts at packet[0],
// with the packet-number field at pnOffset. longHeader selects the 4- vs 5-bit first-byte
// mask. payloadEnd bounds the protected payload (pnOffset .. payloadEnd covers pn+ct+tag).
// Returns the unprotected header (AAD), the decrypted frames, the full packet number, and
// the byte just past this packet. ok is false if decryption fails.
func (k *keys) open(packet []byte, pnOffset, payloadEnd int, longHeader bool, largestPN uint64) (header, plaintext []byte, pn uint64, ok bool) {
	if pnOffset+4+16 > len(packet) || payloadEnd > len(packet) || payloadEnd < pnOffset+4 {
		return nil, nil, 0, false
	}
	sample := packet[pnOffset+4 : pnOffset+4+16]
	mask := k.hp.mask(sample)

	hdr := make([]byte, payloadEnd) // work on a copy; we mutate the protected bytes
	copy(hdr, packet[:payloadEnd])
	if longHeader {
		hdr[0] ^= mask[0] & 0x0f
	} else {
		hdr[0] ^= mask[0] & 0x1f
	}
	pnLen := int(hdr[0]&0x03) + 1
	var truncated uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] ^= mask[1+i]
		truncated = truncated<<8 | uint64(hdr[pnOffset+i])
	}
	pn = decodePacketNumber(truncated, pnLen, largestPN)

	aad := hdr[:pnOffset+pnLen]
	ct := packet[pnOffset+pnLen : payloadEnd]

	nonce := make([]byte, 12)
	copy(nonce, k.iv)
	var pnb [8]byte
	binary.BigEndian.PutUint64(pnb[:], pn)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= pnb[i]
	}
	out, err := k.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, nil, 0, false
	}
	return aad, out, pn, true
}
