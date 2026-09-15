package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig points $TRAFFIC_DECK_HOME at a temp dir holding the given config.toml, and
// clears the env vars under test so a developer who exports them doesn't see a false failure.
func writeConfig(t *testing.T, body string) {
	t.Helper()
	for _, key := range []string{"GATEWAY_VIEWER", "GATEWAY_ADDR", "GATEWAY_MCP", "GATEWAY_LOG_MAX_BACKUPS", "GATEWAY_LIVE_DECODE"} {
		t.Setenv(key, "")
	}
	home := t.TempDir()
	if body != "" {
		if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TRAFFIC_DECK_HOME", home)
}

// The file exists so a permanent choice doesn't have to live in a shell rc — but a one-off
// env var in front of the command still has to win, or overriding for one run is impossible.
func TestFileSetsDefaultsAndEnvWins(t *testing.T) {
	writeConfig(t, `
GATEWAY_VIEWER = "none"
GATEWAY_ADDR = "127.0.0.1:9999"
gateway_mcp = false
GATEWAY_LOG_MAX_BACKUPS = 3
`)
	cfg := Load()
	if cfg.Viewer != "none" {
		t.Errorf("Viewer = %q, want the file's %q", cfg.Viewer, "none")
	}
	if cfg.GRPCAddr != "127.0.0.1:9999" {
		t.Errorf("GRPCAddr = %q, want the file's value", cfg.GRPCAddr)
	}
	if cfg.StartMCP {
		t.Error("StartMCP = true; a lowercase key and a TOML bool must both take effect")
	}
	if cfg.LogMaxBackups != 3 {
		t.Errorf("LogMaxBackups = %d, want the file's 3", cfg.LogMaxBackups)
	}
	if cfg.LiveDecode != true {
		t.Error("LiveDecode should keep its built-in default when the file is silent")
	}

	t.Setenv("GATEWAY_VIEWER", "tui")
	if got := Load().Viewer; got != "tui" {
		t.Errorf("Viewer = %q with the env var set, want the env to override the file", got)
	}
}

// A broken config file must not stop the gateway from starting: it falls back to defaults,
// same posture as a malformed plugin manifest.
func TestMalformedFileFallsBackToDefaults(t *testing.T) {
	writeConfig(t, "this is not toml = = =")
	if got := Load().Viewer; got != "tui" {
		t.Errorf("Viewer = %q, want the default after an unparseable file", got)
	}
}

func TestNoFileIsFine(t *testing.T) {
	writeConfig(t, "")
	cfg := Load()
	if cfg.Viewer != "tui" || cfg.GRPCAddr != "127.0.0.1:7331" {
		t.Errorf("with no config.toml, want built-in defaults, got %+v", cfg)
	}
}
