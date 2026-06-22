package tlsdecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// suite holds the parameters of a TLS 1.3 cipher suite needed for record decryption.
type suite struct {
	id      uint16
	keyLen  int
	newHash func() hash.Hash
	aead    func(key []byte) (cipher.AEAD, error)
}

const ivLen = 12 // all TLS 1.3 AEADs use a 12-byte nonce

func gcmAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// suiteByID returns the parameters for a TLS 1.3 suite, or (nil,false) if unsupported.
func suiteByID(id uint16) (*suite, bool) {
	switch id {
	case 0x1301: // TLS_AES_128_GCM_SHA256
		return &suite{id, 16, sha256.New, gcmAEAD}, true
	case 0x1302: // TLS_AES_256_GCM_SHA384
		return &suite{id, 32, sha512.New384, gcmAEAD}, true
	case 0x1303: // TLS_CHACHA20_POLY1305_SHA256
		return &suite{id, 32, sha256.New, chacha20poly1305.New}, true
	}
	return nil, false
}

// hkdfExpandLabel implements HKDF-Expand-Label (RFC 8446 §7.1).
func hkdfExpandLabel(newHash func() hash.Hash, secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // empty context
	out := make([]byte, length)
	r := hkdf.Expand(newHash, secret, info)
	if _, err := r.Read(out); err != nil {
		return nil
	}
	return out
}

// recordDecryptor decrypts one direction's TLS 1.3 application records from a traffic
// secret, advancing the per-direction sequence number and rotating on KeyUpdate.
type recordDecryptor struct {
	s      *suite
	secret []byte
	aead   cipher.AEAD
	iv     []byte
	seq    uint64
}

func newRecordDecryptor(s *suite, secret []byte) (*recordDecryptor, error) {
	d := &recordDecryptor{s: s, secret: secret}
	return d, d.deriveKeys()
}

func (d *recordDecryptor) deriveKeys() error {
	key := hkdfExpandLabel(d.s.newHash, d.secret, "key", d.s.keyLen)
	d.iv = hkdfExpandLabel(d.s.newHash, d.secret, "iv", ivLen)
	aead, err := d.s.aead(key)
	if err != nil {
		return err
	}
	d.aead = aead
	d.seq = 0
	return nil
}

// open attempts to decrypt one TLSCiphertext record fragment with the current key at
// the current sequence number. additionalData is the 5-byte record header. On success
// it returns the inner plaintext + content type and advances the sequence number; on
// failure (e.g. a handshake-phase record under a different key) it returns ok=false
// and does NOT advance, so the next application record still aligns at the right seq.
func (d *recordDecryptor) open(header, fragment []byte) (plaintext []byte, contentType byte, ok bool) {
	nonce := make([]byte, ivLen)
	copy(nonce, d.iv)
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, d.seq)
	for i := 0; i < 8; i++ {
		nonce[ivLen-8+i] ^= seqBytes[i]
	}
	out, err := d.aead.Open(nil, nonce, fragment, header)
	if err != nil {
		return nil, 0, false
	}
	d.seq++
	// Strip zero padding; the last non-zero byte is the real content type (RFC 8446 §5.4).
	i := len(out) - 1
	for i >= 0 && out[i] == 0 {
		i--
	}
	if i < 0 {
		return nil, 0, false // all-zero: malformed
	}
	return out[:i], out[i], true
}

// keyUpdate rotates to the next application traffic secret (RFC 8446 §7.2) and resets
// the sequence number — applied when a post-handshake key_update is seen in this direction.
func (d *recordDecryptor) keyUpdate() error {
	d.secret = hkdfExpandLabel(d.s.newHash, d.secret, "traffic upd", d.s.newHash().Size())
	return d.deriveKeys()
}
