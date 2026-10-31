package config

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig points $TRAFFIC_DECK_HOME at a temp dir holding the given config.toml, and
// clears the env vars under test so a developer who exports them doesn't see a false failure.
func writeConfig(t *testing.T, body string) {
	t.Helper()
	for _, key := range []string{"GATEWAY_VIEWER", "GATEWAY_ADDR", "GATEWAY_MCP", "GATEWAY_LOG_MAX_BACKUPS", "GATEWAY_LIVE_DECODE", "GATEWAY_UPDATE_HINT", "GATEWAY_RECORD_LIVE"} {
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
	if cfg.GatewayAddr != "127.0.0.1:9999" {
		t.Errorf("GatewayAddr = %q, want the file's value", cfg.GatewayAddr)
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

// The removed setting is named rather than silently ignored: whoever set it expects a
// tshark re-decode on close that no longer happens.
func TestRecordLiveOffIsReportedAsIgnored(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	writeConfig(t, "")
	Load()
	if buf.Len() != 0 {
		t.Fatalf("unset: logged %q, want nothing", buf.String())
	}
	t.Setenv("GATEWAY_RECORD_LIVE", "off")
	Load()
	if out := buf.String(); !strings.Contains(out, "GATEWAY_RECORD_LIVE=off is no longer supported") ||
		!strings.Contains(out, "import --decoder tshark") {
		t.Fatalf("off: logged %q, want the removal and its replacement named", out)
	}
}

func TestNoFileIsFine(t *testing.T) {
	writeConfig(t, "")
	cfg := Load()
	if cfg.Viewer != "tui" || cfg.GatewayAddr != "127.0.0.1:7331" {
		t.Errorf("with no config.toml, want built-in defaults, got %+v", cfg)
	}
}

// TrafficDeck cannot carry its own update_hint in a manifest — the gateway's own component
// comes first and wins the dedupe — so this setting is the only way an install updated by one
// script covering several checkouts can correct the advice.
func TestSelfUpdateHintDefaultsToAPlainCheckout(t *testing.T) {
	writeConfig(t, "")
	if got := SelfUpdateHint(); got != "git pull && make build" {
		t.Errorf("SelfUpdateHint() = %q, want the plain-checkout default", got)
	}
}

func TestSelfUpdateHintFromFileAndEnv(t *testing.T) {
	writeConfig(t, "GATEWAY_UPDATE_HINT = \"run ~/bundle/update.sh\"\n")
	if got := SelfUpdateHint(); got != "run ~/bundle/update.sh" {
		t.Errorf("SelfUpdateHint() = %q, want the value from config.toml", got)
	}
	// Env wins, so the launcher wrapper an installer writes does not need to edit config.toml.
	t.Setenv("GATEWAY_UPDATE_HINT", "run /opt/td/update.sh")
	if got := SelfUpdateHint(); got != "run /opt/td/update.sh" {
		t.Errorf("SelfUpdateHint() = %q, want the environment to win", got)
	}
}

// Fingerprints live under the same home as plugins and config.toml: a TRAFFIC_DECK_HOME
// that moved those must move them too, not leave them in ~/.traffic-deck.
func TestFingerprintsFollowTrafficDeckHome(t *testing.T) {
	writeConfig(t, "")
	t.Setenv("TRAFFICDECK_FP_DIR", "")
	home := os.Getenv("TRAFFIC_DECK_HOME")
	if got, want := Load().FingerprintsDir, filepath.Join(home, "fingerprints"); got != want {
		t.Fatalf("FingerprintsDir = %q, want %q", got, want)
	}
}
