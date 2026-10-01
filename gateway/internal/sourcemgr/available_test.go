package sourcemgr

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// The service and log lists had the same defect as the capture picker: built from a map, so
// shuffled on every call. Keyed order also keeps a module's processes in the order its
// manifest declared them, which the `%02d` in the key already encodes.
func TestServicesAreListedInKeyOrder(t *testing.T) {
	svcs := NewServices("127.0.0.1:8080", map[string]ServiceSpec{
		"mcp":                    {Label: "MCP server"},
		"module:acme:01-web":     {Label: "acme / web"},
		"module:acme:00-adapter": {Label: "acme / adapter"},
	})
	want := []string{"mcp", "module:acme:00-adapter", "module:acme:01-web"}

	for range 20 {
		var got []string
		for _, s := range svcs.List() {
			got = append(got, s.Name)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
}

// names of the sources a viewer would be offered, sorted so the assertion doesn't depend on
// map order.
func offered(ctx context.Context, m *Manager) []string {
	var out []string
	for _, s := range m.Available(ctx) {
		out = append(out, s.Name)
	}
	slices.Sort(out)
	return out
}

// The picker is something a user builds muscle memory on, so the order has to be the same
// every time it opens — iterating the registry map handed it a fresh shuffle on each open.
// Ordered by the label shown, not the dispatch name, and case-insensitively, so a
// lowercase label is not exiled to the end.
func TestSourcesAreOrderedTheSameWayEveryTime(t *testing.T) {
	specs := map[string]Spec{
		"chrome":       {Label: "Chrome"},
		"chrome-pktap": {Label: "Chrome (per-process)"},
		"firefox":      {Label: "Firefox"},
		"android":      {Label: "Android"},
		"mitmproxy":    {Label: "mitmproxy"},
		"acme":         {}, // no label: the name is what a viewer shows
	}
	want := []string{"acme", "android", "chrome", "chrome-pktap", "firefox", "mitmproxy"}

	// Repeated, because one pass through a map can agree with the answer by luck.
	for range 20 {
		m := New("127.0.0.1:8080", specs)
		var got []string
		for _, s := range m.Sources() {
			got = append(got, s.Name)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
}

// A source the user starts by hand is only worth offering while it is running: picking one
// that is not just sits there, which is what sent every viewer to "starting …" for two
// minutes. Everything the gateway can start itself stays on the list unconditionally.
func TestAvailableOffersAnExternalSourceOnlyWhileItListens(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	live := ln.Addr().String()

	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String() // closed below: a port nothing is on
	if err := dead.Close(); err != nil {
		t.Fatal(err)
	}

	m := New("127.0.0.1:8080", map[string]Spec{
		"chrome":  {Argv: []string{"chrome"}},                    // spawned on demand
		"acme":    {Addr: live, Module: "acme"},                  // module processes to start
		"running": {Addr: live, Module: "r", External: true},     // the user's, up
		"stopped": {Addr: deadAddr, Module: "s", External: true}, // the user's, down
	})
	t.Cleanup(m.Close)

	ctx := context.Background()
	if got, want := offered(ctx, m), []string{"acme", "chrome", "running"}; !slices.Equal(got, want) {
		t.Errorf("offered %v, want %v", got, want)
	}
	// The registry itself is unchanged — the log catalogue reads it, and a source that
	// cannot run still has a log worth opening.
	if len(m.Sources()) != 4 {
		t.Errorf("Sources() dropped something: %v", m.Sources())
	}

	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := offered(ctx, m), []string{"acme", "chrome"}; !slices.Equal(got, want) {
		t.Errorf("after the daemon stopped, offered %v, want %v", got, want)
	}
}

// The probe races by construction — the daemon can stop between the list and the capture —
// so the start path has to fail, and fail quickly, with something to act on.
func TestStartingAStoppedExternalSourceFailsAtOnce(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	m := New("127.0.0.1:8080", map[string]Spec{
		"pktap": {Addr: addr, Module: "pktap", External: true},
	})
	t.Cleanup(m.Close)

	start := time.Now()
	_, err = m.Describe(context.Background(), "pktap", nil)
	if err == nil {
		t.Fatal("describe against nothing should fail")
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("took %s to report an unreachable source; the whole point is not to hang", took)
	}
	for _, want := range []string{"started by", "start it and try again", addr} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
}
