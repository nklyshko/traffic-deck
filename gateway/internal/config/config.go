// Package config loads gateway configuration from the environment, with
// $TRAFFIC_DECK_HOME/config.toml (default ~/.traffic-deck/config.toml) underneath it as the
// place to make a choice permanent without a shell rc. Env wins over the file.
package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsfp"
)

type Config struct {
	GRPCAddr string // listen address for the gRPC server
	DataRoot string // root for session bundles + catalog.sqlite
	// TsharkPath is the tshark binary, used only for the optional batch decode: pcap
	// import (--decoder tshark), and (record-live off) the authoritative batch pass /
	// tshark-verify on close. The live decode needs no tshark.
	TsharkPath string
	// LiveDecode toggles the live pipeline. When true (default) a streaming session
	// decodes flows live, fully in-process in Go (no tshark): TCP/QUIC reassembly, TLS
	// decryption from the key-log, and HTTP/1.1, HTTP/2, HTTP/3, WebSocket and custom
	// raw-TCP framing — plaintext or TLS. When false, no live decode runs and the capture
	// is decoded only by the batch tshark pass on session close (the pre-live behavior).
	LiveDecode bool
	// RecordLive persists the live-decoded flows on close and skips the batch tshark
	// re-decode. Only takes effect when LiveDecode is on and the session has a live decode
	// running. Default true: the in-process live decode is authoritative and no batch
	// tshark pass runs on close. Set GATEWAY_RECORD_LIVE=off to instead run the batch pass
	// on close (authoritative, full bodies) — useful for verifying the live decoder.
	RecordLive bool
	// TsharkVerify, on session close, compares the live-decoded flows against a tshark
	// batch decode and logs any differences. Requires LiveDecode on. With RecordLive
	// off it compares against the authoritative tshark pass that runs anyway; with
	// RecordLive on it runs an extra diagnostic tshark decode (not persisted) just for
	// the comparison. Default false. (Env: GATEWAY_TSHARK_VERIFY.)
	TsharkVerify bool
	// StartMCP auto-starts the MCP server on launch (GATEWAY_MCP), so an agent can attach
	// without a viewer having to toggle it. Default true; set GATEWAY_MCP=off to keep it
	// down. It binds loopback and serves read-only, and a gateway with no MCP launcher
	// installed just logs that and carries on. The TUI can also toggle it with X.
	StartMCP bool
	// Viewer picks what one-command mode (`trafficdeck` with no args) runs in the
	// foreground: "tui" (default), "none" (nothing — a module serves the UI and the gateway
	// just stays up), or a command line to run instead. Kept verbatim: a command is
	// case-sensitive.
	Viewer string

	// FingerprintsDir is the directory of user TLS-fingerprint files (*.json) that
	// register additional well-known ClientHello fingerprints on top of the compiled-in
	// builtin set. Default ~/.traffic-deck/fingerprints; override with TRAFFICDECK_FP_DIR.
	// Empty (home undeterminable and unset) means builtin-only.
	FingerprintsDir string

	// Logging. File logging is on by default (no env needed): logs are teed to stderr and
	// to a size-rolling file. Set GATEWAY_LOG_FILE=off to log to stderr only.
	LogFile       string // rolling log file path; "off" disables. Default <DataRoot>/logs/gateway.log
	LogMaxSizeMB  int    // rotate after the file reaches this size (MiB)
	LogMaxBackups int    // number of rotated files to retain
	LogMaxAgeDays int    // delete rotated files older than this many days (0 = keep)
	LogCompress   bool   // gzip rotated files
}

// Home is $TRAFFIC_DECK_HOME (default ~/.traffic-deck), the per-user root shared with the
// capture tools: plugin manifests, fingerprints, and config.toml live under it. "" if no
// home can be resolved.
func Home() string {
	if home := os.Getenv("TRAFFIC_DECK_HOME"); home != "" {
		return home
	}
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return filepath.Join(h, ".traffic-deck")
	}
	return ""
}

// source resolves one setting: the environment first, then $TRAFFIC_DECK_HOME/config.toml,
// then the built-in default. Env wins so a one-off `GATEWAY_VIEWER=web trafficdeck` still
// overrides the file, and the file exists so a permanent choice doesn't have to live in a
// shell rc.
type source map[string]string

// loadFile reads config.toml into env-var-keyed strings. The keys *are* the env var names
// (`GATEWAY_VIEWER = "web"`), matched case-insensitively — one name per setting to document
// and no mapping table to keep in sync. A malformed or unreadable file is logged and
// ignored rather than fatal, like a bad plugin manifest: config is not worth refusing to
// start over.
func loadFile() source {
	home := Home()
	if home == "" {
		return nil
	}
	path := filepath.Join(home, "config.toml")
	var raw map[string]any
	if _, err := toml.DecodeFile(path, &raw); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("config: ignoring %s: %v", path, err)
		}
		return nil
	}
	s := make(source, len(raw))
	for k, v := range raw {
		// A nested table is not a setting — it's someone expecting sections we don't have.
		if _, ok := v.(map[string]any); ok {
			log.Printf("config: ignoring [%s] in %s: settings are flat, keyed by env var name", k, path)
			continue
		}
		s[strings.ToUpper(k)] = fmt.Sprint(v)
	}
	return s
}

func (s source) str(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if v := s[key]; v != "" {
		return v
	}
	return def
}

// boolean reads a boolean setting (1/true/yes/on enable; 0/false/no/off disable).
func (s source) boolean(key string, def bool) bool {
	switch strings.ToLower(s.str(key, "")) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

// integer reads an integer setting, falling back to def when unset or unparseable.
func (s source) integer(key string, def int) int {
	if n, err := strconv.Atoi(s.str(key, "")); err == nil {
		return n
	}
	return def
}

// Load reads config from the environment and $TRAFFIC_DECK_HOME/config.toml (env wins),
// with sensible local-dev defaults.
func Load() Config {
	s := loadFile()
	dataRoot := s.str("DATA_ROOT", "./data")
	return Config{
		GRPCAddr:        s.str("GATEWAY_ADDR", "127.0.0.1:7331"),
		DataRoot:        dataRoot,
		TsharkPath:      s.str("TSHARK_PATH", "tshark"),
		LiveDecode:      s.boolean("GATEWAY_LIVE_DECODE", true),
		RecordLive:      s.boolean("GATEWAY_RECORD_LIVE", true),
		TsharkVerify:    s.boolean("GATEWAY_TSHARK_VERIFY", false),
		StartMCP:        s.boolean("GATEWAY_MCP", true),
		Viewer:          s.str("GATEWAY_VIEWER", "tui"),
		FingerprintsDir: s.str("TRAFFICDECK_FP_DIR", tlsfp.DefaultDir()),
		LogFile:         s.str("GATEWAY_LOG_FILE", filepath.Join(dataRoot, "logs", "gateway.log")),
		LogMaxSizeMB:    s.integer("GATEWAY_LOG_MAX_SIZE_MB", 50),
		LogMaxBackups:   s.integer("GATEWAY_LOG_MAX_BACKUPS", 10),
		LogMaxAgeDays:   s.integer("GATEWAY_LOG_MAX_AGE_DAYS", 30),
		LogCompress:     s.boolean("GATEWAY_LOG_COMPRESS", true),
	}
}
