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

	if s, ok := src["acme"]; !ok || s.Addr != "127.0.0.1:7070" || s.Label != "Acme" {
		t.Errorf("module source = %+v (ok=%v)", src["acme"], ok)
	}
	// The adapter process became an auto-start service.
	var found bool
	for _, spec := range svc {
		if len(spec.Argv) == 1 && spec.Argv[0] == "acme-adapter" && spec.AutoStart {
			found = true
		}
	}
	if !found {
		t.Errorf("adapter process not registered as an auto-start service: %+v", svc)
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
