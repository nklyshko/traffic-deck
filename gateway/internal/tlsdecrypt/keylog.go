// Package tlsdecrypt passively decrypts TLS application data from a captured record
// stream using an NSS key-log (SSLKEYLOGFILE), so the gateway can decode custom raw-TCP
// protocols live, in-process, without re-running tshark.
//
// Scope:
//   - TLS 1.3 — AEAD suites (AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305); keys from the
//     *_TRAFFIC_SECRET_0 key-log secrets.
//   - TLS 1.2 — the same AEAD suites plus the AES-CBC suites (MAC-then-encrypt); keys from
//     the CLIENT_RANDOM master secret via the TLS 1.2 PRF.
//
// Streams using an unsupported version or suite (e.g. TLS 1.2 3DES/RC4, or TLS <1.2) are
// reported unsupported and left to the batch tshark pass. For TLS 1.3 we never need to
// decrypt the handshake (handshake-phase records simply fail the AEAD and are skipped);
// for TLS 1.2 the ChangeCipherSpec marks where each direction's records become encrypted.
package tlsdecrypt

import (
	"encoding/hex"
	"os"
	"strings"
	"sync"
)

// Keylog is an NSS key-log: secrets keyed by (label, client_random). Backed by a file
// that grows during a live capture, so lookups lazily re-read it when a secret is
// missing.
type Keylog struct {
	path string

	mu      sync.Mutex
	secrets map[string][]byte // key: label + ":" + clientRandomHex
	size    int64             // bytes already parsed (incremental re-read)
}

// NewKeylog returns a Keylog backed by path (which may not exist yet / be empty).
func NewKeylog(path string) *Keylog {
	return &Keylog{path: path, secrets: map[string][]byte{}}
}

// Get returns the secret for (label, clientRandom), re-reading the file once if the
// secret isn't known yet (it may have just been appended).
func (k *Keylog) Get(label string, clientRandom []byte) ([]byte, bool) {
	key := label + ":" + hex.EncodeToString(clientRandom)
	k.mu.Lock()
	defer k.mu.Unlock()
	if s, ok := k.secrets[key]; ok {
		return s, true
	}
	k.reloadLocked()
	s, ok := k.secrets[key]
	return s, ok
}

// reloadLocked parses any bytes appended to the key-log since the last read.
func (k *Keylog) reloadLocked() {
	if k.path == "" {
		return
	}
	f, err := os.Open(k.path)
	if err != nil {
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() <= k.size {
		return
	}
	if _, err := f.Seek(k.size, 0); err != nil {
		return
	}
	buf := make([]byte, fi.Size()-k.size)
	n, _ := f.Read(buf)
	k.size += int64(n)
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		label, crand, secretHex := fields[0], fields[1], fields[2]
		secret, err := hex.DecodeString(secretHex)
		if err != nil {
			continue
		}
		k.secrets[label+":"+strings.ToLower(crand)] = secret
	}
}
