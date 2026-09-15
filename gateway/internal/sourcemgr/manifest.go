package sourcemgr

import (
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/config"
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

// ProcessSpec is one long-lived process a module runs (started in declared order — lazily
// on first use of the module's capture source, or at launch if it has none — and reaped by
// group-kill on shutdown).
type ProcessSpec struct {
	Name    string            `toml:"name"`
	Cwd     string            `toml:"cwd"`
	Command []string          `toml:"command"`
	Env     map[string]string `toml:"env"`
	// URL is where this process is reachable once up (a module UI's address). Optional, and
	// only narration: the gateway says it on start and hands it to viewers in ServiceInfo,
	// so a UI a user has to open is discoverable without reading the module's own output.
	URL string `toml:"url"`
	// Detail is a one-line note for the viewer's service list (an exposure warning, say).
	Detail string `toml:"detail"`
	// Viewer marks this process as a foreground viewer GATEWAY_VIEWER can select by name.
	// It is not a service: it never auto-starts and is never tied to a capture source —
	// it runs only when selected, in the foreground, owning stdin/stdout/stderr. A module
	// may declare several (a TUI and a web bridge); one is selected per run.
	Viewer bool `toml:"viewer"`
	// Screen says this viewer paints the terminal (a full-screen TUI), so the gateway and
	// every child must stop writing to it while the viewer runs. A viewer that only prints
	// lines leaves it false and shares the terminal with the gateway's log.
	Screen bool `toml:"screen"`
}

// ViewerSpec is one module process marked `viewer = true`: what GATEWAY_VIEWER selects and
// runFused runs in the foreground. Addressed as "<module>" or, when a module declares more
// than one, "<module>:<process>".
type ViewerSpec struct {
	Module  string
	Process string
	Argv    []string
	Cwd     string
	Env     map[string]string
	URL     string
	Screen  bool
}

// Key is the viewer's fully-qualified name, "<module>:<process>".
func (v ViewerSpec) Key() string { return v.Module + ":" + v.Process }

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
	home := config.Home()
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

// Viewers lists every `viewer = true` process across the modules in dir, in manifest order.
func Viewers(dir string) []ViewerSpec {
	var out []ViewerSpec
	for _, m := range LoadManifests(dir) {
		for _, p := range m.Process {
			if !p.Viewer || len(p.Command) == 0 {
				continue
			}
			out = append(out, ViewerSpec{
				Module: m.Name, Process: p.Name, Argv: p.Command,
				Cwd: p.Cwd, Env: p.Env, URL: p.URL, Screen: p.Screen,
			})
		}
	}
	return out
}

// SelectViewer picks the viewer GATEWAY_VIEWER names: "<module>" when that module declares
// exactly one, or "<module>:<process>" to disambiguate. Reports found=false when the name
// matches no module at all, so the caller can fall through to treating it as a command; an
// ambiguous or empty module is an error, since silently picking one of a user's viewers is
// worse than saying which names exist.
func SelectViewer(viewers []ViewerSpec, name string) (spec ViewerSpec, found bool, err error) {
	var matches []ViewerSpec
	for _, v := range viewers {
		if strings.EqualFold(name, v.Key()) {
			return v, true, nil // fully qualified: one answer by construction
		}
		if strings.EqualFold(name, v.Module) {
			matches = append(matches, v)
		}
	}
	switch len(matches) {
	case 0:
		return ViewerSpec{}, false, nil
	case 1:
		return matches[0], true, nil
	default:
		keys := make([]string, 0, len(matches))
		for _, v := range matches {
			keys = append(keys, v.Key())
		}
		return ViewerSpec{}, true, fmt.Errorf("module %q declares %d viewers: name one of %s",
			name, len(matches), strings.Join(keys, ", "))
	}
}

// ApplyManifests merges the modules found in dir into the source and service registries.
// A module's processes (its adapter, its web UI) are tied to its capture type: a module
// with a [control] block has its processes tagged with the module name and started lazily,
// the first time that capture source is requested (see Manager.ensure) — so a module's
// adapter and UI come up only when its capture is used, not at gateway launch. A module
// with no [control] source has no capture type to gate on, so its processes auto-start.
func ApplyManifests(dir string, srcSpecs map[string]Spec, svcSpecs map[string]ServiceSpec) {
	for _, m := range LoadManifests(dir) {
		lazy := m.Control != nil && m.Control.Addr != ""
		for i, p := range m.Process {
			if len(p.Command) == 0 || p.Viewer {
				continue // a viewer isn't a service: it runs only when GATEWAY_VIEWER selects it
			}
			key := fmt.Sprintf("module:%s:%02d-%s", m.Name, i, p.Name)
			spec := ServiceSpec{
				Argv: p.Command, Cwd: p.Cwd, Env: p.Env,
				Label:  m.Name + " / " + p.Name,
				URL:    p.URL,
				Detail: p.Detail,
			}
			if lazy {
				spec.Module = m.Name // started on first use of the module's source
			} else {
				spec.AutoStart = true // no capture type to gate on; start at launch
			}
			svcSpecs[key] = spec
		}
		if lazy {
			name := m.Control.Source
			if name == "" {
				name = m.Name
			}
			label := m.Control.Label
			if label == "" {
				label = m.Name
			}
			srcSpecs[name] = Spec{
				Addr: m.Control.Addr, Module: m.Name, Label: label, KeepWarm: m.Control.KeepWarm,
			}
			log.Printf("plugin %q: capture source at %s (processes start on first use)",
				m.Name, m.Control.Addr)
		}
	}
}
