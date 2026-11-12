package store

import "testing"

// Sessions recorded before the marker stored per-reason counts instead; either says the
// index was recorded, and neither means it never was.
func TestUndecodedIndexed(t *testing.T) {
	for _, c := range []struct {
		md   map[string]string
		want bool
	}{
		{map[string]string{"undecoded.indexed": "true"}, true},
		{map[string]string{"undecoded.no_key": "0", "undecoded.udp": "3"}, true},
		{map[string]string{"conn.undecoded.tls_rejected": "2"}, false},
		{nil, false},
	} {
		if got := UndecodedIndexed(c.md); got != c.want {
			t.Errorf("UndecodedIndexed(%v) = %v, want %v", c.md, got, c.want)
		}
	}
}
