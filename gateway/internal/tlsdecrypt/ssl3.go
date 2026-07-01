package tlsdecrypt

// SSL 3.0 (RFC 6101) key derivation and record MAC. SSL 3.0 predates the TLS PRF and HMAC:
// the key block is built from nested MD5(master || SHA1(salt || master || randoms)) blocks,
// and the record MAC is a bespoke two-pass hash (not HMAC) that — unlike TLS — omits the
// protocol version. Record encryption is CBC with an implicit IV, like TLS 1.0. Only the
// AES-CBC suites we already have a block cipher for are handled; everything else (RC4,
// 3DES) falls back to the batch pass. SSL 3.0 is long dead (POODLE); this exists for
// completeness against archived captures.

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"hash"
)

// ssl3KeyBlock derives `n` bytes of key material (RFC 6101 §6.2.2). The i-th 16-byte chunk
// is MD5(master || SHA1(salt_i || master || server_random || client_random)) where salt_i
// is the (i+1)-th letter repeated i+1 times: "A", "BB", "CCC", ...
func ssl3KeyBlock(master, clientRandom, serverRandom []byte, n int) []byte {
	out := make([]byte, 0, n+md5.Size)
	for i := 0; len(out) < n; i++ {
		salt := make([]byte, i+1)
		for j := range salt {
			salt[j] = byte('A' + i)
		}
		sh := sha1.New()
		sh.Write(salt)
		sh.Write(master)
		sh.Write(serverRandom)
		sh.Write(clientRandom)

		mh := md5.New()
		mh.Write(master)
		mh.Write(sh.Sum(nil))
		out = append(out, mh.Sum(nil)...)
	}
	return out[:n]
}

// ssl3MAC computes the SSL 3.0 record MAC (RFC 6101 §5.2.3.1):
//
//	hash(mac_secret || pad2 || hash(mac_secret || pad1 || seq || type || length || content))
//
// pad1/pad2 are 0x36/0x5c repeated (48 bytes for MD5, 40 for SHA-1 = hash block size minus
// output size). Note the absence of the version field that the TLS MAC includes.
func ssl3MAC(newHash func() hash.Hash, macSecret []byte, macLen int, seq uint64, typ byte, content []byte) []byte {
	padLen := 64 - macLen // 48 for MD5, 40 for SHA-1
	pad1 := make([]byte, padLen)
	pad2 := make([]byte, padLen)
	for i := range pad1 {
		pad1[i], pad2[i] = 0x36, 0x5c
	}
	meta := make([]byte, 0, 11)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	meta = append(meta, s[:]...)
	meta = append(meta, typ, byte(len(content)>>8), byte(len(content)))

	inner := newHash()
	inner.Write(macSecret)
	inner.Write(pad1)
	inner.Write(meta)
	inner.Write(content)

	outer := newHash()
	outer.Write(macSecret)
	outer.Write(pad2)
	outer.Write(inner.Sum(nil))
	return outer.Sum(nil)
}
