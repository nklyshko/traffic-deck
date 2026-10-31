package tlsdecrypt

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"testing"
)

// The SSL 3.0 MAC pads are RFC 6101's literal counts, 48 bytes for MD5 and 40 for SHA-1.
// Deriving them as 64 minus the hash size gave 44 for SHA-1, so every SSL 3.0 record MAC we
// computed (all our SSL 3.0 suites are SHA-1) was wrong. The round-trip test cannot see
// that, since it builds its expected MAC with ssl3MAC too; this one spells the RFC out.
func TestSSL3MACUsesTheRFCPadLengths(t *testing.T) {
	secret := bytes.Repeat([]byte{0x0b}, 20)
	content := []byte("hello")
	for _, tc := range []struct {
		name    string
		newHash func() hash.Hash
		size    int
		pad     int
	}{
		{"SHA-1", sha1.New, sha1.Size, 40},
		{"MD5", md5.New, md5.Size, 48},
	} {
		var meta [11]byte
		binary.BigEndian.PutUint64(meta[:8], 7)
		meta[8], meta[9], meta[10] = 23, 0, byte(len(content))

		inner := tc.newHash()
		inner.Write(secret)
		inner.Write(bytes.Repeat([]byte{0x36}, tc.pad))
		inner.Write(meta[:])
		inner.Write(content)
		outer := tc.newHash()
		outer.Write(secret)
		outer.Write(bytes.Repeat([]byte{0x5c}, tc.pad))
		outer.Write(inner.Sum(nil))

		if got := ssl3MAC(tc.newHash, secret, tc.size, 7, 23, content); !bytes.Equal(got, outer.Sum(nil)) {
			t.Errorf("%s: MAC does not match RFC 6101 with a %d-byte pad", tc.name, tc.pad)
		}
	}
}
