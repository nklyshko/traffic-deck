package tlsdecrypt

// TLS 1.2 (RFC 5246) record decryption for the AEAD cipher suites (AES-GCM, RFC 5288;
// ChaCha20-Poly1305, RFC 7905) and the AES-CBC suites (MAC-then-encrypt, RFC 5246
// §6.2.3.2 with the explicit per-record IV of RFC 5246 §6.2.3.2). Unlike TLS 1.3, keys
// come from the master secret (the key-log's CLIENT_RANDOM line) via the TLS 1.2 PRF, and
// the record's content type is the cleartext outer record type (records aren't
// inner-typed). TLS <1.2 is left to later steps / the batch tshark pass.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

// tls12Suite holds the parameters of a TLS 1.2 cipher suite needed for decryption. A suite
// is either AEAD (aead != nil) or CBC (cbc == true); prfHash is the suite's PRF hash.
type tls12Suite struct {
	id      uint16
	keyLen  int // bulk cipher key length
	prfHash func() hash.Hash

	// AEAD suites:
	aead       func(key []byte) (cipher.AEAD, error)
	fixedIVLen int  // implicit ("salt") IV length from the key block
	chacha     bool // ChaCha20-Poly1305 nonce construction (RFC 7905) vs GCM explicit nonce

	// CBC suites (MAC-then-encrypt, HMAC over seq||header||content):
	cbc      bool
	macHash  func() hash.Hash
	macLen   int // HMAC output/key length (SHA1=20, SHA256=32, SHA384=48)
	blockNew func(key []byte) (cipher.Block, error)
}

func aesBlock(key []byte) (cipher.Block, error) { return aes.NewCipher(key) }

// tls12SuiteByID returns the parameters for a supported TLS 1.2 suite (AEAD or AES-CBC).
// Unsupported suites (e.g. 3DES/RC4) return (nil,false) so the connection falls back to
// the batch tshark pass.
func tls12SuiteByID(id uint16) (*tls12Suite, bool) {
	switch id {
	// --- AEAD ---
	// AES-128-GCM-SHA256
	case 0xc02b, 0xc02f, 0x009c, 0x009e, 0xc09c, 0xc09e:
		return &tls12Suite{id: id, keyLen: 16, prfHash: sha256.New, aead: gcmAEAD, fixedIVLen: 4}, true
	// AES-256-GCM-SHA384
	case 0xc02c, 0xc030, 0x009d, 0x009f, 0xc09d, 0xc09f:
		return &tls12Suite{id: id, keyLen: 32, prfHash: sha512.New384, aead: gcmAEAD, fixedIVLen: 4}, true
	// ChaCha20-Poly1305-SHA256 (RFC 7905): 12-byte implicit IV, no explicit nonce on the wire
	case 0xcca8, 0xcca9, 0xccaa:
		return &tls12Suite{id: id, keyLen: 32, prfHash: sha256.New, aead: chacha20poly1305.New, fixedIVLen: 12, chacha: true}, true

	// --- AES-CBC (explicit per-record IV; PRF is SHA-256 except for the SHA384 suites) ---
	// AES-128-CBC-SHA (SHA-1 MAC)
	case 0x002f, 0x0033, 0xc009, 0xc013:
		return &tls12Suite{id: id, keyLen: 16, prfHash: sha256.New, cbc: true, macHash: sha1.New, macLen: 20, blockNew: aesBlock}, true
	// AES-256-CBC-SHA (SHA-1 MAC)
	case 0x0035, 0x0039, 0xc00a, 0xc014:
		return &tls12Suite{id: id, keyLen: 32, prfHash: sha256.New, cbc: true, macHash: sha1.New, macLen: 20, blockNew: aesBlock}, true
	// AES-128-CBC-SHA256
	case 0x003c, 0x0067, 0xc023, 0xc027:
		return &tls12Suite{id: id, keyLen: 16, prfHash: sha256.New, cbc: true, macHash: sha256.New, macLen: 32, blockNew: aesBlock}, true
	// AES-256-CBC-SHA256
	case 0x003d, 0x006b:
		return &tls12Suite{id: id, keyLen: 32, prfHash: sha256.New, cbc: true, macHash: sha256.New, macLen: 32, blockNew: aesBlock}, true
	// AES-256-CBC-SHA384 (SHA-384 MAC and PRF)
	case 0xc024, 0xc028:
		return &tls12Suite{id: id, keyLen: 32, prfHash: sha512.New384, cbc: true, macHash: sha512.New384, macLen: 48, blockNew: aesBlock}, true
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

// tls12Decryptor decrypts one direction's TLS 1.2 records, advancing the per-direction
// sequence number (which starts at 0 with the encrypted Finished).
type tls12Decryptor struct {
	suite *tls12Suite
	seq   uint64

	// AEAD:
	aead cipher.AEAD
	iv   []byte // fixed/implicit IV (salt)

	// CBC:
	block  cipher.Block
	macKey []byte
}

// newTLS12Decryptor derives the direction's key material from the master secret via key
// expansion (RFC 5246 §6.3) and builds the AEAD or CBC record layer.
func newTLS12Decryptor(s *tls12Suite, masterSecret, clientRandom, serverRandom []byte, fromClient bool) (*tls12Decryptor, error) {
	// key_block = PRF(master_secret, "key expansion", server_random + client_random)
	seed := make([]byte, 0, 64)
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)
	need := 2*s.macLen + 2*s.keyLen + 2*s.fixedIVLen // macLen==0 for AEAD, fixedIVLen==0 for CBC
	kb := prf12(s.prfHash, masterSecret, "key expansion", seed, need)

	// Layout: client_write_MAC, server_write_MAC, client_write_key, server_write_key,
	// client_write_IV, server_write_IV.
	p := 0
	take := func(n int) []byte { v := kb[p : p+n]; p += n; return v }
	clientMAC, serverMAC := take(s.macLen), take(s.macLen)
	clientKey, serverKey := take(s.keyLen), take(s.keyLen)
	clientIV, serverIV := take(s.fixedIVLen), take(s.fixedIVLen)

	mac, key, iv := serverMAC, serverKey, serverIV
	if fromClient {
		mac, key, iv = clientMAC, clientKey, clientIV
	}
	d := &tls12Decryptor{suite: s, iv: append([]byte(nil), iv...), macKey: append([]byte(nil), mac...)}
	if s.cbc {
		block, err := s.blockNew(key)
		if err != nil {
			return nil, err
		}
		d.block = block
		return d, nil
	}
	aead, err := s.aead(key)
	if err != nil {
		return nil, err
	}
	d.aead = aead
	return d, nil
}

// aad12 builds the TLS 1.2 additional data / MAC header: seq(8) || type(1) || version(2)
// || content_length(2) (RFC 5246 §6.2.3.3).
func (d *tls12Decryptor) aad12(header []byte, contentLen int) []byte {
	aad := make([]byte, 0, 13)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], d.seq)
	aad = append(aad, s[:]...)
	return append(aad, header[0], header[1], header[2], byte(contentLen>>8), byte(contentLen))
}

// open decrypts one TLS 1.2 record fragment. header is the 5-byte record header (type +
// version + ciphertext length). On success it advances the sequence number.
func (d *tls12Decryptor) open(header, frag []byte) ([]byte, bool) {
	if d.suite.cbc {
		return d.openCBC(header, frag)
	}
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
	out, err := d.aead.Open(nil, nonce, ct, d.aad12(header, plainLen))
	if err != nil {
		return nil, false
	}
	d.seq++
	return out, true
}

// openCBC decrypts one TLS 1.2 AES-CBC record: strip the explicit IV, CBC-decrypt, remove
// PKCS-style TLS padding, split off and verify the trailing HMAC. Returns false on any
// structural or MAC failure (so the caller bails to the batch pass).
func (d *tls12Decryptor) openCBC(header, frag []byte) ([]byte, bool) {
	bs := d.block.BlockSize()
	// GenericBlockCipher: explicit IV (one block) || CBC(content || MAC || padding || pad_len).
	if len(frag) < bs+bs || (len(frag)-bs)%bs != 0 {
		return nil, false
	}
	iv, ct := frag[:bs], frag[bs:]
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(d.block, iv).CryptBlocks(plain, ct)

	// Remove padding: the last byte is padding_length; that many preceding bytes (all equal
	// to padding_length) plus the length byte itself are padding.
	padLen := int(plain[len(plain)-1])
	if padLen+1 > len(plain) {
		return nil, false
	}
	body := plain[:len(plain)-padLen-1]
	if len(body) < d.macLen() {
		return nil, false
	}
	content := body[:len(body)-d.macLen()]
	mac := body[len(body)-d.macLen():]

	// MAC = HMAC(mac_key, seq || type || version || content_length || content).
	m := hmac.New(d.suite.macHash, d.macKey)
	m.Write(d.aad12(header, len(content)))
	m.Write(content)
	if !hmac.Equal(mac, m.Sum(nil)) {
		return nil, false
	}
	d.seq++
	return content, true
}

func (d *tls12Decryptor) macLen() int { return d.suite.macLen }
