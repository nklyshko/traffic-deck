package install

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o755); err != nil {
		t.Fatal(err)
	}
}

func runningFrom(t *testing.T, exe string) {
	t.Helper()
	old := executable
	executable = func() (string, error) { return exe, nil }
	t.Cleanup(func() { executable = old })
}

func TestDevBinaryFindsItsOwnCheckoutNotTheWorkingDirectory(t *testing.T) {
	binRepo := t.TempDir()
	touch(t, filepath.Join(binRepo, checkoutMarker))
	touch(t, filepath.Join(binRepo, "trafficdeck"))
	cwdRepo := t.TempDir()
	touch(t, filepath.Join(cwdRepo, checkoutMarker))
	t.Chdir(cwdRepo)
	runningFrom(t, filepath.Join(binRepo, "trafficdeck"))

	want, _ := filepath.EvalSymlinks(binRepo)
	if got := Checkout(); got != want {
		t.Errorf("Checkout() = %q, want %q", got, want)
	}
	if got := Prefix(); got != "" {
		t.Errorf("Prefix() = %q, want none", got)
	}
}

func TestAnUnrelatedRepoIsNotACheckout(t *testing.T) {
	runningFrom(t, filepath.Join(t.TempDir(), "trafficdeck"))
	if got := Checkout(); got != "" {
		t.Errorf("Checkout() = %q, want none", got)
	}
}

func TestInstalledBinaryNeverFindsACheckout(t *testing.T) {
	repo := t.TempDir()
	touch(t, filepath.Join(repo, checkoutMarker))
	prefix := filepath.Join(repo, "prefix")
	touch(t, filepath.Join(prefix, "bin", "trafficdeck"))
	touch(t, filepath.Join(prefix, manifestName))
	t.Chdir(repo)
	runningFrom(t, filepath.Join(prefix, "bin", "trafficdeck"))

	if got := Checkout(); got != "" {
		t.Errorf("Checkout() = %q, want none", got)
	}
	want, _ := filepath.EvalSymlinks(prefix)
	if got := Prefix(); got != want {
		t.Errorf("Prefix() = %q, want %q", got, want)
	}
}

func TestPrefixFollowsTheSymlinkOntoPath(t *testing.T) {
	prefix := t.TempDir()
	touch(t, filepath.Join(prefix, "bin", "trafficdeck"))
	touch(t, filepath.Join(prefix, manifestName))
	link := filepath.Join(t.TempDir(), "trafficdeck")
	if err := os.Symlink(filepath.Join(prefix, "bin", "trafficdeck"), link); err != nil {
		t.Fatal(err)
	}
	runningFrom(t, link)

	want, _ := filepath.EvalSymlinks(prefix)
	if got := Prefix(); got != want {
		t.Errorf("Prefix() = %q, want %q", got, want)
	}
}

func TestInstalledResolveStopsAtLibexec(t *testing.T) {
	prefix := t.TempDir()
	touch(t, filepath.Join(prefix, "bin", "trafficdeck"))
	touch(t, filepath.Join(prefix, manifestName))
	touch(t, filepath.Join(prefix, "libexec", "present"))
	runningFrom(t, filepath.Join(prefix, "bin", "trafficdeck"))

	pathDir := t.TempDir()
	touch(t, filepath.Join(pathDir, "absent"))
	t.Setenv("PATH", pathDir)
	never := func() []string { t.Error("an installed binary used the dev launcher"); return nil }

	real, _ := filepath.EvalSymlinks(prefix)
	want := []string{filepath.Join(real, "libexec", "present")}
	if got := Resolve("TD_TEST_UNSET", "present", never); !reflect.DeepEqual(got, want) {
		t.Errorf("Resolve(present) = %v, want %v", got, want)
	}
	if got := Resolve("TD_TEST_UNSET", "absent", never); got != nil {
		t.Errorf("Resolve(absent) = %v: fell through to PATH", got)
	}
	t.Setenv("TD_TEST_SET", "my launcher")
	if got := Resolve("TD_TEST_SET", "absent", never); !reflect.DeepEqual(got, []string{"my", "launcher"}) {
		t.Errorf("Resolve(override) = %v", got)
	}
}
