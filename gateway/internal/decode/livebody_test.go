package decode

import (
	"bytes"
	"testing"
)

// TestSetUnlimitedLiveBodies checks the live body cap and its removal for record-live mode.
func TestSetUnlimitedLiveBodies(t *testing.T) {
	saved := maxLiveBody
	defer func() { maxLiveBody = saved }()

	maxLiveBody = 4
	if got := appendCapped(nil, []byte("hello")); string(got) != "hell" {
		t.Fatalf("capped append = %q, want %q", got, "hell")
	}

	SetUnlimitedLiveBodies()
	big := bytes.Repeat([]byte("x"), 1<<20)
	if got := appendCapped(nil, big); len(got) != len(big) {
		t.Fatalf("uncapped append = %d bytes, want %d", len(got), len(big))
	}
}
