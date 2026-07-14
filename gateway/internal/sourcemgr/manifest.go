package sourcemgr

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/BurntSushi/toml"
)

// Third-party modules self-enroll by dropping a manifest in $TRAFFIC_DECK_HOME/plugins/
// (default ~/.traffic-deck/plugins) after their own setup — TrafficDeck installs nothing.
// A manifest declares the processes to launch (a module's adapter, its web UI) and,
// optionally, a [control] block: an address already speaking CaptureSourceService, which
// registers the module as a capture source the gateway dials (not spawns). See ADR-0010.
//
// A manifest is executable trust: whatever is dropped in plugins/ runs inside TrafficDeck,
// like a shell rc file — the price of zero-setup local modules.

// Manifest is one module's plugins/<name>.toml.
type Manifest struct {
	Name    string        `toml:"name"`
	Process []ProcessSpec `toml:"process"`
	Control *ControlSpec  `toml:"control"`
}

// ProcessSpec is one long-lived process a module runs (launched at gateway startup, in
// declared order, reaped by group-kill on shutdown).
type ProcessSpec struct {
	Name    string            `toml:"name"`
	Cwd     string            `toml:"cwd"`
	Command []string          `toml:"command"`
	Env     map[string]string `toml:"env"`
}

// ControlSpec declares that the module speaks CaptureSourceService at Addr, so it appears
// as a capture source the gateway dials.
type ControlSpec struct {
	Addr     string `toml:"addr"`
	Source   string `toml:"source"`
	Label    string `toml:"label"`
	KeepWarm bool   `toml:"keep_warm"`
}

// PluginsDir is $TRAFFIC_DECK_HOME/plugins (default ~/.traffic-deck/plugins), the same root
// the capture SDK uses. "" if no home can be resolved.
func PluginsDir() string {
	home := os.Getenv("TRAFFIC_DECK_HOME")
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = filepath.Join(h, ".traffic-deck")
		}
	}
	if home == "" {
		return ""
	}
	return filepath.Join(home, "plugins")
}

// LoadManifests reads every *.toml in dir. A malformed manifest is logged and skipped, so
// one bad plugin doesn't take the gateway down.
func LoadManifests(dir string) []Manifest {
	if dir == "" {
		return nil
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.toml"))
	sort.Strings(paths)
	var out []Manifest
	for _, p := range paths {
		var m Manifest
		if _, err := toml.DecodeFile(p, &m); err != nil {
			log.Printf("plugin manifest %s: %v — skipped", p, err)
			continue
		}
		if m.Name == "" {
			log.Printf("plugin manifest %s: missing name — skipped", p)
			continue
		}
		out = append(out, m)
	}
	return out
}

// ApplyManifests merges the modules found in dir into the source and service registries:
// each module's processes become auto-start services, and a [control] block registers a
// dial-only capture source.
func ApplyManifests(dir string, srcSpecs map[string]Spec, svcSpecs map[string]ServiceSpec) {
	for _, m := range LoadManifests(dir) {
		for i, p := range m.Process {
			if len(p.Command) == 0 {
				continue
			}
			key := fmt.Sprintf("module:%s:%02d-%s", m.Name, i, p.Name)
			svcSpecs[key] = ServiceSpec{
				Argv: p.Command, Cwd: p.Cwd, Env: p.Env, AutoStart: true,
				Label: m.Name + " / " + p.Name,
			}
		}
		if m.Control != nil && m.Control.Addr != "" {
			name := m.Control.Source
			if name == "" {
				name = m.Name
			}
			label := m.Control.Label
			if label == "" {
				label = m.Name
			}
			srcSpecs[name] = Spec{Addr: m.Control.Addr, Label: label, KeepWarm: m.Control.KeepWarm}
			log.Printf("plugin %q: capture source at %s", m.Name, m.Control.Addr)
		}
	}
}
