package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nklyshko/traffic-deck/gateway/internal/sourcemgr"
)

// installViewerModule points $TRAFFIC_DECK_HOME at a temp home holding one plugin manifest.
func installViewerModule(t *testing.T, manifest string) {
	t.Helper()
	home := t.TempDir()
	plugins := filepath.Join(home, "plugins")
	if err := os.MkdirAll(plugins, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugins, "acme.toml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRAFFIC_DECK_HOME", home)
}

// The gateway knows nothing about any particular viewer: "none" means nothing runs in the
// foreground, a module name resolves through its manifest, and anything else is a command.
func TestResolveViewer(t *testing.T) {
	installViewerModule(t, `
name = "acme"
[[process]]
name    = "web"
command = ["echo", "acme-web"]
cwd     = "/tmp"
env     = { ACME = "1" }
url     = "http://127.0.0.1:8081"
viewer  = true
`)
	t.Run("none runs nothing in the foreground", func(t *testing.T) {
		v, err := resolveViewer("none")
		if err != nil || v != nil {
			t.Fatalf("resolveViewer(none) = %+v, %v; want nil, nil", v, err)
		}
	})

	// The point of declaring a viewer in the manifest: cwd, env and url come with it, and a
	// viewer that only prints lines leaves the terminal to the gateway's log.
	t.Run("a module viewer carries its manifest", func(t *testing.T) {
		v, err := resolveViewer("acme")
		if err != nil {
			t.Fatalf("resolveViewer(acme): %v", err)
		}
		if strings.Join(v.argv, " ") != "echo acme-web" || v.cwd != "/tmp" ||
			v.env["ACME"] != "1" || v.url != "http://127.0.0.1:8081" || v.screen {
			t.Fatalf("viewer = %+v, want the manifest's argv/cwd/env/url and screen=false", v)
		}
	})

	t.Run("addressable module:process", func(t *testing.T) {
		if _, err := resolveViewer("acme:web"); err != nil {
			t.Fatalf("resolveViewer(acme:web): %v", err)
		}
	})

	// A bare command is assumed to paint the screen: the reverse mistake scribbles the
	// gateway's log over a full-screen viewer.
	t.Run("a command owns the screen", func(t *testing.T) {
		v, err := resolveViewer("echo hi")
		if err != nil {
			t.Fatalf("resolveViewer(echo hi): %v", err)
		}
		if !v.screen || strings.Join(v.argv, " ") != "echo hi" {
			t.Fatalf("viewer = %+v, want argv [echo hi] and screen=true", v)
		}
	})

	// The answer to a typo is the list of what this machine actually accepts.
	t.Run("an unknown name lists the choices", func(t *testing.T) {
		_, err := resolveViewer("tuii")
		if err == nil {
			t.Fatal("a viewer that isn't a keyword, a module or a command must fail")
		}
		for _, want := range []string{`"tui"`, `"none"`, `"acme:web"`} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error should offer %s, got: %v", want, err)
			}
		}
	})
}

// Many viewers may be defined; exactly one is selected. A module name that matches several
// must say which, rather than silently running one of them.
func TestResolveViewerAmbiguousModule(t *testing.T) {
	installViewerModule(t, `
name = "acme"
[[process]]
name    = "tui"
command = ["echo", "tui"]
viewer  = true
screen  = true
[[process]]
name    = "web"
command = ["echo", "web"]
viewer  = true
`)
	_, err := resolveViewer("acme")
	if err == nil {
		t.Fatal("a module with two viewers must not resolve by module name alone")
	}
	if !strings.Contains(err.Error(), "acme:tui") || !strings.Contains(err.Error(), "acme:web") {
		t.Fatalf("error should name both viewers, got: %v", err)
	}

	v, err := resolveViewer("acme:tui")
	if err != nil {
		t.Fatalf("resolveViewer(acme:tui): %v", err)
	}
	if !v.screen {
		t.Errorf("viewer = %+v, want screen=true from the manifest", v)
	}
}

// With no foreground viewer the gateway just sits there, so a setup where nothing serves a
// UI at all is invisible without this.
func TestWarnNoViewer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		services []sourcemgr.ServiceInfo
		warn     bool
	}{
		{"nothing registered", nil, true},
		{"only the MCP server", []sourcemgr.ServiceInfo{{Name: "mcp", Running: true}}, true},
		{"the module is registered but down", []sourcemgr.ServiceInfo{{Name: "module:acme:00-web"}}, true},
		{"the module is up", []sourcemgr.ServiceInfo{
			{Name: "mcp", Running: true},
			{Name: "module:acme:00-web", Running: true},
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureLog(t)
			warnNoViewer(tc.services)
			if warned := strings.Contains(buf.String(), "nothing is serving a UI"); warned != tc.warn {
				t.Fatalf("warned = %v, want %v; log:\n%s", warned, tc.warn, buf.String())
			}
		})
	}
}
