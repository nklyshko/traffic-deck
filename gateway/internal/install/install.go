// Package install answers which copy of TrafficDeck is running, and so where its components
// are (ADR-0017). The answer comes from the executable and never the working directory: a
// frozen install launched from inside a checkout must not pick up that checkout's code.
package install

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
)

// manifestName marks an install prefix. `make install` writes it last, so a half-finished
// install is not mistaken for a working one.
const manifestName = "install.toml"

// checkoutMarker is a file only a TrafficDeck checkout has, at its root. Checking for it
// rather than asking git keeps a checkout of some other project from being taken for this one.
const checkoutMarker = "proto/traffic/v1/control.proto"

// executable is a seam for tests, which cannot move the running binary.
var executable = os.Executable

// Info is install.toml. Remote and Branch are what update checks compare against; they are
// recorded because the checkout may since have moved on, switched branch or gone (ADR-0017 §4).
type Info struct {
	Commit    string `toml:"commit"`
	Dirty     bool   `toml:"dirty"`
	SourceDir string `toml:"source_dir"`
	Remote    string `toml:"remote"`
	Branch    string `toml:"branch"`
	Date      string `toml:"date"`
	Viewer    string `toml:"viewer"`
}

// exeDir is the directory of the real binary. Symlinks are resolved because macOS's
// os.Executable can return the ~/.local/bin link, which sits beside neither a prefix nor a
// checkout.
func exeDir() string {
	exe, err := executable()
	if err != nil {
		return ""
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return filepath.Dir(exe)
}

// snapshot is what this process learned about its install, once: a running gateway is the
// code it started with, so a reinstall under it (or the moment its prefix is being replaced)
// must not change what it reports about itself.
type snapshot struct {
	prefix string
	info   Info
	err    error
}

func load() snapshot {
	dir := exeDir()
	if dir == "" {
		return snapshot{err: errNotInstalled}
	}
	prefix := filepath.Dir(dir)
	if _, err := os.Stat(filepath.Join(prefix, manifestName)); err != nil {
		return snapshot{err: errNotInstalled}
	}
	var info Info
	_, err := toml.DecodeFile(filepath.Join(prefix, manifestName), &info)
	return snapshot{prefix: prefix, info: info, err: err}
}

var errNotInstalled = errors.New("not an installed binary")

// current is the snapshot, taken on first use — config.Load, at startup.
var current = sync.OnceValue(load)

// Prefix is the install prefix this binary runs from, or "" for a dev build.
func Prefix() string { return current().prefix }

// Read is install.toml from this binary's prefix, as it was when the process started.
func Read() (Info, error) {
	s := current()
	return s.info, s.err
}

// Viewer is the default foreground viewer chosen at install time, or "" for a dev build or an
// install that made no choice.
func Viewer() string {
	info, err := Read()
	if err != nil {
		return ""
	}
	return info.Viewer
}

// Checkout is the checkout this dev binary sits in, or "" — always "" when installed, even
// for a prefix placed inside a repo, so an installed binary cannot find a checkout at all.
func Checkout() string {
	dir := exeDir()
	if dir == "" || Prefix() != "" {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, checkoutMarker)); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// Resolve finds how to launch a component, or nil if it can't be. envVar is its explicit
// override, script its console script, and dev its launcher from a checkout.
//
// An installed binary stops at libexec on purpose: falling through to PATH could reach a dev
// venv's console script, which is checkout code again. A missing component is not installed.
func Resolve(envVar, script string, dev func() []string) []string {
	if env := os.Getenv(envVar); env != "" {
		return strings.Fields(env)
	}
	if prefix := Prefix(); prefix != "" {
		p := filepath.Join(prefix, "libexec", script)
		if _, err := os.Stat(p); err != nil {
			return nil
		}
		return []string{p}
	}
	if argv := dev(); argv != nil {
		return argv
	}
	if p, err := exec.LookPath(script); err == nil {
		return []string{p}
	}
	return nil
}
