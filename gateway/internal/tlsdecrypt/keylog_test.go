package tlsdecrypt

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKeylogReloadHandlesPartialLine covers the live-capture race where the key-log is
// read while a secret line is only half-written: the reader must not consume (and
// mis-parse) the partial line, or it caches a truncated/wrong secret and the connection
// never decrypts live — surfacing as a spurious "no key-log secret".
func TestKeylogReloadHandlesPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.log")
	crand := make([]byte, 32) // all-zero client random
	crandHex := strings.Repeat("00", 32)
	secretHex := strings.Repeat("ab", 32)
	full := "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + crandHex + " " + secretHex + "\n"

	// Write everything except the newline and the last 8 hex chars of the secret — a read
	// landing mid-secret. (Even truncation stays valid hex, so the old code would have
	// stored the wrong secret rather than skipping it.)
	partial := full[:len(full)-9]
	if err := os.WriteFile(path, []byte(partial), 0o644); err != nil {
		t.Fatal(err)
	}

	kl := NewKeylog(path)
	if _, ok := kl.Get("CLIENT_HANDSHAKE_TRAFFIC_SECRET", crand); ok {
		t.Fatal("secret must be absent while its line is only partially written")
	}

	// Complete the line; the full (correct) secret must now be read.
	if err := os.WriteFile(path, []byte(full), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := kl.Get("CLIENT_HANDSHAKE_TRAFFIC_SECRET", crand)
	if !ok {
		t.Fatal("secret must be present once its line completes")
	}
	want, _ := hex.DecodeString(secretHex)
	if !bytes.Equal(got, want) {
		t.Fatalf("secret = %x, want %x (a truncated read must not be cached)", got, want)
	}
}
