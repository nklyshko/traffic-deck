package server

import (
	"context"
	"testing"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
)

// TestCheckUpdatesOffIsUnknownNotUpToDate: with checking disabled there is no answer to give,
// and the reply must say so the only way the wire allows — checked_unix_ms = 0. Answering
// with a zero-value success and a 0 timestamp (rather than an error) is what lets the viewer
// clients collapse "off", "not checked yet" and "unreachable" into one None/null, so no UI
// can render an empty component list as "nothing to update".
func TestCheckUpdatesOffIsUnknownNotUpToDate(t *testing.T) {
	c := NewControl(nil, nil, t.TempDir(), "", nil, nil, nil)
	got, err := c.CheckUpdates(context.Background(), &trafficv1.CheckUpdatesRequest{Refresh: true})
	if err != nil {
		t.Fatalf("CheckUpdates with checking off: %v", err)
	}
	if got.GetCheckedUnixMs() != 0 || len(got.GetComponents()) != 0 {
		t.Errorf("got %+v, want an empty status with checked_unix_ms = 0", got)
	}
}
