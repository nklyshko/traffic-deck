package sourcemgr

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeManifest(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "acme.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadManifestsParses(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, `
name = "acme"

[[process]]
name = "adapter"
cwd = "/opt/acme"
command = ["acme-adapter", "--listen", "127.0.0.1:7070"]
env = { TOKEN = "x" }

[[process]]
name = "web"
command = ["npm", "run", "dev"]

[control]
addr = "127.0.0.1:7070"
source = "acme"
label = "Acme"
keep_warm = true
`)
	ms := LoadManifests(dir)
	if len(ms) != 1 {
		t.Fatalf("got %d manifests, want 1", len(ms))
	}
	m := ms[0]
	if m.Name != "acme" || len(m.Process) != 2 {
		t.Fatalf("parsed %+v", m)
	}
	if m.Process[0].Cwd != "/opt/acme" || m.Process[0].Env["TOKEN"] != "x" {
		t.Errorf("process[0] = %+v", m.Process[0])
	}
	if m.Control == nil || m.Control.Addr != "127.0.0.1:7070" || !m.Control.KeepWarm {
		t.Errorf("control = %+v", m.Control)
	}
}

func TestLoadManifestsSkipsBadFiles(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "this is not : valid = toml [[")
	if got := LoadManifests(dir); len(got) != 0 {
		t.Errorf("a malformed manifest should be skipped, got %+v", got)
	}
}

func TestApplyManifestsRegistersSourceAndProcesses(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, `
name = "acme"
[[process]]
name = "adapter"
command = ["acme-adapter"]
[control]
addr = "127.0.0.1:7070"
source = "acme"
label = "Acme"
`)
	src := map[string]Spec{}
	svc := map[string]ServiceSpec{}
	ApplyManifests(dir, src, svc)

	if s, ok := src["acme"]; !ok || s.Addr != "127.0.0.1:7070" || s.Label != "Acme" || s.Module != "acme" {
		t.Errorf("module source = %+v (ok=%v)", src["acme"], ok)
	}
	// The adapter process is registered against its module, started on first use of the
	// acme source rather than auto-started at launch (the module has a [control] source).
	var found bool
	for _, spec := range svc {
		if len(spec.Argv) == 1 && spec.Argv[0] == "acme-adapter" {
			found = true
			if spec.AutoStart {
				t.Errorf("adapter should not auto-start when the module has a capture source: %+v", spec)
			}
			if spec.Module != "acme" {
				t.Errorf("adapter service Module = %q, want acme", spec.Module)
			}
		}
	}
	if !found {
		t.Errorf("adapter process not registered as a service: %+v", svc)
	}
}

// A module with processes but no [control] source has no capture type to gate on, so its
// processes still auto-start at launch.
func TestApplyManifestsAutoStartsProcessesWithoutControl(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, `
name = "acme"
[[process]]
name = "web"
command = ["npm", "run", "dev"]
`)
	src := map[string]Spec{}
	svc := map[string]ServiceSpec{}
	ApplyManifests(dir, src, svc)

	if len(src) != 0 {
		t.Errorf("no [control] block should register no source, got %+v", src)
	}
	var found bool
	for _, spec := range svc {
		if len(spec.Argv) == 3 && spec.Argv[0] == "npm" {
			found = true
			if !spec.AutoStart || spec.Module != "" {
				t.Errorf("web service = %+v, want AutoStart and no Module", spec)
			}
		}
	}
	if !found {
		t.Errorf("web process not registered: %+v", svc)
	}
}

// A module UI is something a user has to open, so the manifest can say where it is: the
// gateway narrates it on start and hands it to viewers, instead of the address being
// knowable only from the module's own output.
func TestApplyManifestsCarriesProcessURL(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, `
name = "acme"
[[process]]
name = "web"
command = ["npm", "run", "dev"]
url = "http://127.0.0.1:8081"
detail = "loopback only"
`)
	svc := map[string]ServiceSpec{}
	ApplyManifests(dir, map[string]Spec{}, svc)

	for _, spec := range svc {
		if spec.URL != "http://127.0.0.1:8081" || spec.Detail != "loopback only" {
			t.Errorf("web service = %+v, want the manifest's url and detail", spec)
		}
		return
	}
	t.Errorf("web process not registered: %+v", svc)
}

// A viewer is not a service: it must never auto-start alongside the foreground copy the
// user selected, so it stays out of the service registry entirely.
func TestApplyManifestsExcludesViewerProcesses(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, `
name = "acme"
[[process]]
name = "adapter"
command = ["acme-adapter"]
[[process]]
name = "ui"
command = ["acme-ui"]
viewer = true
`)
	svc := map[string]ServiceSpec{}
	ApplyManifests(dir, map[string]Spec{}, svc)

	for key, spec := range svc {
		if spec.Argv[0] == "acme-ui" {
			t.Errorf("viewer process registered as service %q: %+v", key, spec)
		}
	}
	if len(svc) != 1 {
		t.Errorf("want only the adapter registered, got %+v", svc)
	}

	viewers := Viewers(dir)
	if len(viewers) != 1 || viewers[0].Key() != "acme:ui" {
		t.Fatalf("Viewers = %+v, want just acme:ui", viewers)
	}
}

// TestModuleSourceDialsControlAddr is the end-to-end dial-only path: a manifest whose
// [control].addr points at a running CaptureSourceService, reached without spawning.
func TestModuleSourceDialsControlAddr(t *testing.T) {
	fake := &fakeSource{name: "acme"}
	addr := serveFake(t, fake)

	dir := t.TempDir()
	writeManifest(t, dir, `
name = "acme"
[control]
addr = "`+addr+`"
source = "acme"
`)
	src := map[string]Spec{}
	svc := map[string]ServiceSpec{}
	ApplyManifests(dir, src, svc)

	m := New("127.0.0.1:8080", src)
	t.Cleanup(m.Close)
	d, err := m.Describe(context.Background(), "acme", nil)
	if err != nil {
		t.Fatalf("describe module source: %v", err)
	}
	if d.GetMessage() != "acme" {
		t.Errorf("dialed the wrong source: %q", d.GetMessage())
	}
}

func TestComponentsNeedsAnExplicitSourceDir(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, `
name = "acme"
source_dir = "/opt/acme"
update_hint = "run /opt/acme/update.sh"

[[process]]
name = "adapter"
cwd = "/opt/acme"
command = ["acme-adapter"]
`)
	// A module that declares no source_dir opts out, and its process cwd must not stand in
	// for one: that guesses at the checkout, and a wrong guess tells someone to update the
	// wrong thing.
	if err := os.WriteFile(filepath.Join(dir, "quiet.toml"), []byte(`
name = "quiet"

[[process]]
name = "adapter"
cwd = "/opt/quiet"
command = ["quiet-adapter"]
`), 0o644); err != nil {
		t.Fatal(err)
	}

	got := Components(dir)
	if len(got) != 1 {
		t.Fatalf("got %+v, want only the module with a source_dir", got)
	}
	if got[0].Name != "acme" || got[0].Dir != "/opt/acme" ||
		got[0].UpdateHint != "run /opt/acme/update.sh" {
		t.Errorf("component = %+v", got[0])
	}
}

func TestDedupeKeepsTheFirstClaimOnACheckout(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	// "trafficdeck" is first, as the gateway assembles it, so it wins over a module naming
	// the same checkout by another path — plugins/pktap.toml lives inside the TrafficDeck
	// repo and is not a repo of its own.
	got := Dedupe([]ComponentSpec{
		{Name: "trafficdeck", Dir: real},
		{Name: "pktap", Dir: link},
		{Name: "missing", Dir: "/nonexistent/acme"},
	})
	if len(got) != 2 {
		t.Fatalf("got %+v, want trafficdeck and missing", got)
	}
	if got[0].Name != "trafficdeck" {
		t.Errorf("the first claim should win, got %q", got[0].Name)
	}
	// An unresolvable path is not silently dropped — the checker reports why it failed.
	if got[1].Name != "missing" {
		t.Errorf("a checkout that does not exist should survive dedupe, got %q", got[1].Name)
	}
}
