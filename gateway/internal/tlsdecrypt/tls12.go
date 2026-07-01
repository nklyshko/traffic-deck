package tlsdecrypt

// TLS 1.2 (RFC 5246) record decryption for the AEAD cipher suites (AES-GCM, RFC 5288;
// ChaCha20-Poly1305, RFC 7905). Unlike TLS 1.3, keys come from the master secret (the
// key-log's CLIENT_RANDOM line) via the TLS 1.2 PRF, and the record's content type is the
// cleartext outer record type (records aren't inner-typed). CBC suites and TLS <1.2 are
// left to later steps / the batch tshark pass.

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

// tls12Suite holds the parameters of a TLS 1.2 AEAD cipher suite needed for decryption.
type tls12Suite struct {
	id         uint16
	keyLen     int // AEAD key length
	fixedIVLen int // implicit ("salt") IV length from the key block
	prfHash    func() hash.Hash
	aead       func(key []byte) (cipher.AEAD, error)
	chacha     bool // ChaCha20-Poly1305 nonce construction (RFC 7905) vs GCM explicit nonce
}

// tls12SuiteByID returns the parameters for a supported TLS 1.2 AEAD suite. CBC and other
// suites return (nil,false) so the connection falls back to the batch tshark pass.
func tls12SuiteByID(id uint16) (*tls12Suite, bool) {
	switch id {
	// AES-128-GCM-SHA256
	case 0xc02b, 0xc02f, 0x009c, 0x009e, 0xc09c, 0xc09e:
		return &tls12Suite{id, 16, 4, sha256.New, gcmAEAD, false}, true
	// AES-256-GCM-SHA384
	case 0xc02c, 0xc030, 0x009d, 0x009f, 0xc09d, 0xc09f:
		return &tls12Suite{id, 32, 4, sha512.New384, gcmAEAD, false}, true
	// ChaCha20-Poly1305-SHA256 (RFC 7905): 12-byte implicit IV, no explicit nonce on the wire
	case 0xcca8, 0xcca9, 0xccaa:
		return &tls12Suite{id, 32, 12, sha256.New, chacha20poly1305.New, true}, true
	}
	return nil, false
}

// pHash is TLS 1.2's P_hash (RFC 5246 §5): repeated HMAC over evolving A(i) values.
func pHash(newHash func() hash.Hash, secret, seed []byte, n int) []byte {
	out := make([]byte, 0, n)
	a := seed // A(0) = seed
	for len(out) < n {
		am := hmac.New(newHash, secret)
		am.Write(a)
		a = am.Sum(nil) // A(i) = HMAC(secret, A(i-1))

		hm := hmac.New(newHash, secret)
		hm.Write(a)
		hm.Write(seed)
		out = append(out, hm.Sum(nil)...)
	}
	return out[:n]
}

// prf12 is the TLS 1.2 PRF: P_hash(secret, label || seed).
func prf12(newHash func() hash.Hash, secret []byte, label string, seed []byte, n int) []byte {
	ls := make([]byte, 0, len(label)+len(seed))
	ls = append(ls, label...)
	ls = append(ls, seed...)
	return pHash(newHash, secret, ls, n)
}

// tls12Decryptor decrypts one direction's TLS 1.2 AEAD records, advancing the per-
// direction sequence number (which starts at 0 with the encrypted Finished).
type tls12Decryptor struct {
	suite *tls12Suite
	aead  cipher.AEAD
	iv    []byte // fixed/implicit IV (salt) for this direction
	seq   uint64
}

// newTLS12Decryptor derives the direction's write key + fixed IV from the master secret
// via key expansion (RFC 5246 §6.3) and builds the AEAD.
func newTLS12Decryptor(s *tls12Suite, masterSecret, clientRandom, serverRandom []byte, fromClient bool) (*tls12Decryptor, error) {
	// key_block = PRF(master_secret, "key expansion", server_random + client_random)
	seed := make([]byte, 0, 64)
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)
	need := 2*s.keyLen + 2*s.fixedIVLen // no MAC keys for AEAD suites
	kb := prf12(s.prfHash, masterSecret, "key expansion", seed, need)

	// Layout: client_write_key, server_write_key, client_write_IV, server_write_IV.
	p := 0
	clientKey := kb[p : p+s.keyLen]
	p += s.keyLen
	serverKey := kb[p : p+s.keyLen]
	p += s.keyLen
	clientIV := kb[p : p+s.fixedIVLen]
	p += s.fixedIVLen
	serverIV := kb[p : p+s.fixedIVLen]

	key, iv := serverKey, serverIV
	if fromClient {
		key, iv = clientKey, clientIV
	}
	aead, err := s.aead(key)
	if err != nil {
		return nil, err
	}
	return &tls12Decryptor{suite: s, aead: aead, iv: append([]byte(nil), iv...)}, nil
}

// open decrypts one TLS 1.2 AEAD record fragment. header is the 5-byte record header
// (type + version + ciphertext length). On success it advances the sequence number.
func (d *tls12Decryptor) open(header, frag []byte) ([]byte, bool) {
	var nonce, ct []byte
	if d.suite.chacha {
		// RFC 7905: nonce = fixed_iv XOR (0^4 || seq); no explicit nonce on the wire.
		nonce = make([]byte, 12)
		copy(nonce, d.iv)
		var s [8]byte
		binary.BigEndian.PutUint64(s[:], d.seq)
		for i := 0; i < 8; i++ {
			nonce[4+i] ^= s[i]
		}
		ct = frag
	} else {
		// GCM: nonce = fixed_iv(4) || explicit_nonce(8); explicit nonce prefixes the record.
		if len(frag) < 8 {
			return nil, false
		}
		nonce = make([]byte, 12)
		copy(nonce, d.iv)
		copy(nonce[4:], frag[:8])
		ct = frag[8:]
	}
	if len(ct) < d.aead.Overhead() {
		return nil, false
	}
	plainLen := len(ct) - d.aead.Overhead()

	// AAD = seq(8) || type(1) || version(2) || plaintext_length(2)  (RFC 5246 §6.2.3.3).
	aad := make([]byte, 0, 13)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], d.seq)
	aad = append(aad, s[:]...)
	aad = append(aad, header[0], header[1], header[2], byte(plainLen>>8), byte(plainLen))

	out, err := d.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, false
	}
	d.seq++
	return out, true
}
