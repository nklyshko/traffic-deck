package updates

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// git runs a git command in dir, failing the test on error. Identity is passed per command so
// the test does not depend on the machine's git config.
func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-C", dir,
		"-c", "user.name=test", "-c", "user.email=test@example.com",
		"-c", "commit.gpgsign=false"}, args...)
	out, err := exec.Command("git", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func commit(t *testing.T, dir, msg string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, msg+".txt"), []byte(msg), 0o644); err != nil {
		t.Fatal(err)
	}
	gitT(t, dir, "add", ".")
	gitT(t, dir, "commit", "-m", msg)
}

// TestCheckOneComparesAgainstTheRemoteTip walks the states a real checkout can be in. The
// remote is a local path, so ls-remote reaches it without a network.
func TestCheckOneComparesAgainstTheRemoteTip(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	origin := filepath.Join(root, "origin")
	if err := os.Mkdir(origin, 0o755); err != nil {
		t.Fatal(err)
	}
	gitT(t, origin, "init", "-b", "main")
	commit(t, origin, "first")

	work := filepath.Join(root, "work")
	gitT(t, root, "clone", "--quiet", origin, work)

	ctx := context.Background()
	comp := Component{Name: "work", Dir: work, UpdateHint: "run update.sh"}

	got := checkOne(ctx, comp)
	if got.Err != "" || got.Available || got.LocalRev == "" || got.RemoteRev == "" {
		t.Fatalf("fresh clone: %+v, want up to date with both revs known", got)
	}
	if got.UpdateHint != "run update.sh" {
		t.Errorf("the manifest's hint should be carried through verbatim, got %q", got.UpdateHint)
	}

	// A checkout carrying local commits is not behind: the remote's tip is still present
	// here. Comparing against HEAD instead would report this as an update.
	commit(t, work, "local-work")
	if got := checkOne(ctx, comp); got.Available || got.Err != "" {
		t.Errorf("local commits: %+v, want up to date", got)
	}

	// The remote publishes a commit this checkout has never seen.
	commit(t, origin, "second")
	got = checkOne(ctx, comp)
	if !got.Available || got.Err != "" {
		t.Fatalf("remote ahead: %+v, want an available update", got)
	}
	if want := short(gitT(t, origin, "rev-parse", "HEAD")); got.RemoteRev != want {
		t.Errorf("remote rev = %q, want %q", got.RemoteRev, want)
	}
}

// TestCheckOneReportsUnknownRatherThanUpToDate: every way a check can fail must come back as
// an error with update_available false — a component that cannot be checked is unknown, and
// unknown read as "up to date" is the failure mode the whole feature exists to avoid.
func TestCheckOneReportsUnknownRatherThanUpToDate(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	plain := filepath.Join(root, "plain")
	if err := os.Mkdir(plain, 0o755); err != nil {
		t.Fatal(err)
	}
	gitT(t, plain, "init", "-b", "main")
	commit(t, plain, "first")

	cases := map[string]string{
		"not a git checkout": filepath.Join(root, "nothing"),
		"no upstream branch": plain, // a repo with no remote at all
	}
	for wantErr, dir := range cases {
		got := checkOne(context.Background(), Component{Name: "c", Dir: dir})
		if got.Available {
			t.Errorf("%s: update_available must stay false, got %+v", wantErr, got)
		}
		if !strings.Contains(got.Err, wantErr) {
			t.Errorf("%s: error = %q", wantErr, got.Err)
		}
	}
}

// TestRefreshHoldsTheRateFloor: the viewers own the cadence, so the gateway's protection is
// this — a refresh that arrives right after a completed check is answered from the cache and
// dials nothing. Ten tabs opening at once cost one round, not ten.
func TestRefreshHoldsTheRateFloor(t *testing.T) {
	calls := 0
	c := NewChecker(func() []Component {
		calls++
		return nil
	})

	if st := c.Status(); st.CheckedUnixMs != 0 || st.Components != nil {
		t.Fatalf("before any check the answer is unknown, not empty-and-fresh: %+v", st)
	}
	first := c.Refresh(context.Background())
	if first.CheckedUnixMs == 0 {
		t.Fatal("a completed check must stamp checked_unix_ms")
	}
	second := c.Refresh(context.Background())
	if second.CheckedUnixMs != first.CheckedUnixMs {
		t.Errorf("a refresh inside the rate floor should return the cache, got a new stamp")
	}
	if calls != 1 {
		t.Errorf("components resolved %d times, want 1 — the second refresh dialed", calls)
	}
}

// TestFindSelfIgnoresAnUnrelatedCheckout is the regression that matters most here: asking git
// "which repo is this directory in" answers with whatever the user happens to be standing in,
// and reporting *that* as TrafficDeck would tell them to update the wrong thing.
func TestFindSelfIgnoresAnUnrelatedCheckout(t *testing.T) {
	root := t.TempDir()
	checkout := filepath.Join(root, "traffic-deck")
	deep := filepath.Join(checkout, "gateway", "cmd", "gateway")
	if err := os.MkdirAll(filepath.Join(checkout, filepath.Dir(selfMarker)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checkout, selfMarker), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	// Found from anywhere inside the checkout, including the binary's own build directory.
	for _, start := range []string{checkout, deep} {
		if got := findSelf(start); got != checkout {
			t.Errorf("findSelf(%q) = %q, want %q", start, got, checkout)
		}
	}
	// Some other directory — a repo of someone else's — is not TrafficDeck.
	elsewhere := filepath.Join(root, "unrelated")
	if err := os.Mkdir(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := findSelf(elsewhere); got != "" {
		t.Errorf("findSelf(%q) = %q, want no answer", elsewhere, got)
	}
	// The binary's own location wins over the working directory, since it is the copy that
	// would actually be replaced by an update.
	if got := findSelf(deep, elsewhere); got != checkout {
		t.Errorf("order: got %q, want %q", got, checkout)
	}
}

// TrafficDeck is the only component with nowhere to declare its own hint: it has no manifest,
// and one claiming this checkout loses Dedupe to the entry List puts first. So the setting is
// the only way an install updated by one script covering several checkouts can correct it, and
// List has to consult it rather than carry the literal default.
func TestListTakesTheSelfHintFromTheSetting(t *testing.T) {
	t.Setenv("TRAFFIC_DECK_HOME", t.TempDir()) // no real modules or config.toml in the way
	t.Setenv("GATEWAY_UPDATE_HINT", "run /opt/td/update.sh")

	found := false
	for _, c := range List() {
		if c.Name != "trafficdeck" {
			continue
		}
		found = true
		if c.UpdateHint != "run /opt/td/update.sh" {
			t.Errorf("self hint = %q, want the setting's value", c.UpdateHint)
		}
	}
	if !found {
		t.Skip("no TrafficDeck checkout around this test binary, so there is no self entry")
	}
}

// TestRefreshWaitsForTheCheckAlreadyRunning is the bug the TUI surfaced: pressing U during the
// launch check returned the still-empty cache, whose checked_unix_ms = 0 is how "unknown" is
// spelled — so the viewer announced that checks were off, and only a second press worked.
// A refresh with nothing cached must wait for the answer instead.
func TestRefreshWaitsForTheCheckAlreadyRunning(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	c := NewChecker(func() []Component {
		close(started)
		<-release // hold the "launch check" open
		return nil
	})

	go c.Refresh(context.Background()) // stands in for the check kicked off at launch
	<-started

	got := make(chan Status, 1)
	go func() { got <- c.Refresh(context.Background()) }()
	select {
	case st := <-got:
		t.Fatalf("returned %+v while a check was in flight, want it to wait", st)
	case <-time.After(50 * time.Millisecond): // still waiting, as it should be
	}

	close(release)
	if st := <-got; st.CheckedUnixMs == 0 {
		t.Error("waited, then still answered unknown — the viewer reads that as 'checks are off'")
	}
}

// A caller that gives up is not made to wait forever, and gets the honest unknown.
func TestRefreshStopsWaitingWhenTheCallerDoes(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	started := make(chan struct{})
	c := NewChecker(func() []Component {
		close(started)
		<-release
		return nil
	})
	go c.Refresh(context.Background())
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if st := c.Refresh(ctx); st.CheckedUnixMs != 0 {
		t.Errorf("got %+v, want the unknown cache once the deadline passed", st)
	}
}

// TestRateFloorStaysShortEnoughForAButton guards the incident that set this value: with a
// three-minute floor, a viewer's "check for updates" button reported everything up to date
// for three minutes after a commit had been published, and only a gateway restart fixed it.
// The floor is there to collapse a burst of viewers, which takes seconds, not minutes — this
// is the assertion that stops it drifting back up "to be safe".
func TestRateFloorStaysShortEnoughForAButton(t *testing.T) {
	if rateFloor > 30*time.Second {
		t.Errorf("rateFloor = %s: long enough that a user pressing a check button gets a "+
			"stale answer; it only has to outlast a burst", rateFloor)
	}
}
