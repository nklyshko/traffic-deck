// Package updates answers "is a newer version published?" by reading git — for the
// TrafficDeck checkout itself and for every module whose manifest declares a `source_dir`.
//
// The gateway does the reading for all of them (ADR-0014): a module is not running most of
// the time (its processes start lazily, and a dial-only source like pktap has none at all),
// so an RPC could reach none of them at launch — which is exactly when a notification is
// wanted. Doing it here is also one implementation instead of one per module language.
package updates

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nklyshko/traffic-deck/gateway/internal/config"
	"github.com/nklyshko/traffic-deck/gateway/internal/sourcemgr"
)

const (
	// componentTimeout bounds one component's check. It covers a network round trip to a
	// remote that may be a VPN away, and it is per component because they run concurrently.
	componentTimeout = 15 * time.Second
	// rateFloor is how soon after a completed check a refresh is answered from the cache
	// instead of dialing again. It exists to collapse a *burst* — ten tabs opening at once,
	// a page-reload loop — into one round of ls-remote, so it only has to outlast a burst.
	//
	// Kept short on purpose. It was three minutes, and a viewer with a "check for updates"
	// button then lied for three minutes after anything else had asked: the gateway cannot
	// tell an automatic poll from a human pressing the button, so the floor has to be short
	// enough that being wrong about that barely matters. A page-reload loop now costs one
	// ls-remote every 15s, which is the price of a manual check being honest.
	rateFloor = 15 * time.Second
)

// Component is one checkout to compare against its remote. ComponentSpec is reused as-is:
// a module's manifest is where these come from.
type Component = sourcemgr.ComponentSpec

// Result is one component's answer. Err explains why a component is unknown, and Available
// is false whenever it is set — offline must never read as up to date.
type Result struct {
	Name       string
	Available  bool
	LocalRev   string
	RemoteRev  string
	UpdateHint string
	Err        string
}

// Status is the whole cached answer. CheckedUnixMs is 0 until a check completes, which a
// viewer must not render as "nothing to update" — see Control.CheckUpdates.
type Status struct {
	Components    []Result
	CheckedUnixMs int64
}

// Checker holds the cached answer and does the checking. Safe for concurrent use.
type Checker struct {
	list func() []Component // resolved per check: manifests can change under a running gateway

	mu       sync.Mutex
	status   Status
	inflight chan struct{} // non-nil while a check runs, closed when it finishes
}

func NewChecker(list func() []Component) *Checker { return &Checker{list: list} }

// Status returns the cached answer without touching the network — the call for a viewer's
// first paint. Unknown until the first check completes, deliberately: this call must not wait.
func (c *Checker) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// Refresh contacts each component's remote and returns the new answer. Two cases short-circuit
// it, and the difference between them is the whole point:
//
//   - A check completed within rateFloor: the cache comes back unchanged. That is a normal
//     outcome, not an error — N viewers asking at once cost one round of ls-remote.
//   - A check is in flight: wait for it, rather than answering with the cache. With a warm
//     cache that would be indistinguishable from the rate floor, but with a cold one it would
//     hand back checked_unix_ms = 0 — "unknown" — which every viewer renders as "no answer at
//     all" (the TUI said "checks are off"). The launch check makes a cold cache the normal
//     state of the first few seconds, which is exactly when a viewer asks.
func (c *Checker) Refresh(ctx context.Context) Status {
	c.mu.Lock()
	if wait := c.inflight; wait != nil {
		cached := c.status
		c.mu.Unlock()
		if cached.CheckedUnixMs != 0 {
			return cached
		}
		select {
		case <-wait:
			return c.Status()
		case <-ctx.Done():
			return cached // caller gave up; still unknown, which is honest
		}
	}
	if c.status.CheckedUnixMs != 0 && time.Since(time.UnixMilli(c.status.CheckedUnixMs)) < rateFloor {
		defer c.mu.Unlock()
		return c.status
	}
	done := make(chan struct{})
	c.inflight = done
	c.mu.Unlock()

	status := Status{Components: check(ctx, c.list()), CheckedUnixMs: time.Now().UnixMilli()}

	c.mu.Lock()
	c.status = status
	c.inflight = nil
	c.mu.Unlock()
	close(done) // after the store, so a waiter reading Status() sees this answer
	return status
}

// check runs every component concurrently, each with its own timeout: one unreachable remote
// must not decide how long the others take, nor keep the rest from being reported.
func check(ctx context.Context, cs []Component) []Result {
	out := make([]Result, len(cs))
	var wg sync.WaitGroup
	for i, comp := range cs {
		wg.Go(func() {
			cctx, cancel := context.WithTimeout(ctx, componentTimeout)
			defer cancel()
			out[i] = checkOne(cctx, comp)
		})
	}
	wg.Wait()
	return out
}

// checkOne compares one checkout against its upstream: resolve the tracking branch, ask the
// remote for its tip, and report an update when that commit is not present locally.
//
// Deliberately not `fetch` + `rev-list --count HEAD..@{upstream}`, which would give a commit
// count ("3 behind") — it downloads objects and writes remote-tracking refs into a checkout
// the user may be working in, from a background task in a long-lived daemon. An update
// notification does not justify mutating a working tree, so the count is given up.
//
// "Not present locally" rather than "differs from HEAD" is what keeps a checkout carrying
// local commits from being reported as behind.
func checkOne(ctx context.Context, c Component) Result {
	r := Result{Name: c.Name, UpdateHint: c.UpdateHint}
	head, err := git(ctx, c.Dir, "rev-parse", "--short=12", "HEAD")
	if err != nil {
		r.Err = fmt.Sprintf("not a git checkout: %v", err)
		return r
	}
	r.LocalRev = head

	// The upstream is read from config rather than parsed out of `@{upstream}`: that prints
	// "origin/release/1.2", which cannot be split back into remote and branch without
	// guessing where the slash belongs.
	branch, err := git(ctx, c.Dir, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		r.Err = fmt.Sprintf("cannot read the current branch: %v", err)
		return r
	}
	remote, rErr := git(ctx, c.Dir, "config", "--get", "branch."+branch+".remote")
	ref, mErr := git(ctx, c.Dir, "config", "--get", "branch."+branch+".merge")
	if rErr != nil || mErr != nil || remote == "" || ref == "" {
		// Includes a detached HEAD, where branch is the literal "HEAD" and has no config.
		r.Err = fmt.Sprintf("no upstream branch for %q — nothing to compare against", branch)
		return r
	}

	ls, err := git(ctx, c.Dir, "ls-remote", remote, ref)
	if err != nil {
		r.Err = fmt.Sprintf("cannot reach %s: %v", remote, err)
		return r
	}
	sha, _, _ := strings.Cut(ls, "\t")
	if sha == "" {
		r.Err = fmt.Sprintf("%s has no %s", remote, ref)
		return r
	}
	r.RemoteRev = short(sha)
	// cat-file is the whole comparison: a commit the remote publishes and we do not have is
	// an update, whatever else this checkout carries on top.
	if _, err := git(ctx, c.Dir, "cat-file", "-e", sha+"^{commit}"); err != nil {
		r.Available = true
	}
	return r
}

// short trims a sha for display. Both revs are abbreviated to the same width — a fixed 12
// rather than git's auto-scaling `--short`, so the two sides of "a1b2c3 → d4e5f6" can't come
// back different lengths. Nothing here is ever fed back to git.
func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// git runs one git command in dir with prompting disarmed, returning its trimmed stdout or
// the first line of its stderr as the error.
//
// Disarming is not decoration. The gateway spawns children with no controlling terminal
// (which is why a module needing sudo cannot ask for a password), so a git that decides to
// ask for an SSH key passphrase or a host-key confirmation would sit until its timeout with
// nothing on screen to explain it. Refused, the same case returns a string a viewer can show.
func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_SSH_COMMAND=ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := firstLine(stderr.String()); msg != "" {
			return "", errors.New(msg)
		}
		if ctx.Err() != nil {
			return "", fmt.Errorf("timed out after %s", componentTimeout)
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// firstLine is git's complaint: the first line of its stderr, which carries the cause, without
// the "fatal: Could not read from remote repository" boilerplate under it.
//
// The trim is applied to the line taken, not to the buffer before cutting. Trimming first only
// reaches the buffer's own two ends, so the first line keeps whatever trailing space it had —
// and ssh leaves one after "…nodename nor servname provided, or not known", which a viewer then
// showed as "or not known )".
func firstLine(stderr string) string {
	line, _, _ := strings.Cut(stderr, "\n")
	return strings.TrimSpace(line)
}

// List is every component to check, TrafficDeck first so a manifest naming a directory
// *inside* this checkout is deduplicated away rather than reported as a repo of its own.
//
// Being first is also why TrafficDeck's own hint comes from a setting rather than a manifest:
// a manifest claiming this checkout loses the dedupe, so there would be no way to correct the
// hint for an install that is updated by one script covering several checkouts.
func List() []Component {
	var out []Component
	if dir := selfDir(); dir != "" {
		out = append(out, Component{
			Name: "trafficdeck", Dir: dir, UpdateHint: config.SelfUpdateHint()})
	}
	out = append(out, sourcemgr.Components(sourcemgr.PluginsDir())...)
	return sourcemgr.Dedupe(out)
}

// selfMarker is a file only a TrafficDeck checkout has, sitting at its root: the gRPC
// contract this binary was generated from.
const selfMarker = "proto/traffic/v1/control.proto"

// selfDir is the TrafficDeck checkout this gateway was built from, found by walking up from
// the running binary (symlinks resolved, so a link onto PATH still finds the checkout behind
// it), then from the working directory — `go run` puts the binary in a temp dir. "" when
// neither leads to one; an installed copy with no sources beside it is simply not checked.
func selfDir() string {
	var starts []string
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		starts = append(starts, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	return findSelf(starts...)
}

// findSelf walks up from each start looking for the marker, in order.
//
// Deliberately not `git rev-parse --show-toplevel`: that answers "which repo is this
// directory in", which for an installed binary run from anywhere is whatever repo the user
// happens to be standing in — and it would be reported as TrafficDeck, telling them to update
// the wrong thing. The marker asks the question that actually matters, and a directory that
// is a checkout of something else fails it. Same walk as main.findTUIDir.
func findSelf(starts ...string) string {
	for _, start := range starts {
		for dir := start; ; {
			if _, err := os.Stat(filepath.Join(dir, selfMarker)); err == nil {
				return dir
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return ""
}
