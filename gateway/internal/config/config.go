// Package config loads gateway configuration from the environment.
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	// StartMCP auto-starts the MCP server on launch (GATEWAY_MCP), for headless agent
	// access without a viewer. Default false; the TUI can also toggle it.
	StartMCP bool

	// Logging. File logging is on by default (no env needed): logs are teed to stderr and
	// to a size-rolling file. Set GATEWAY_LOG_FILE=off to log to stderr only.
	LogFile       string // rolling log file path; "off" disables. Default <DataRoot>/logs/gateway.log
	LogMaxSizeMB  int    // rotate after the file reaches this size (MiB)
	LogMaxBackups int    // number of rotated files to retain
	LogMaxAgeDays int    // delete rotated files older than this many days (0 = keep)
	LogCompress   bool   // gzip rotated files
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// getbool reads a boolean env var (1/true/yes/on enable; 0/false/no/off disable).
func getbool(key string, def bool) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

// getint reads an integer env var, falling back to def when unset or unparseable.
func getint(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// Load reads config from env with sensible local-dev defaults.
func Load() Config {
	dataRoot := getenv("DATA_ROOT", "./data")
	return Config{
		GRPCAddr:      getenv("GATEWAY_ADDR", "127.0.0.1:8080"),
		DataRoot:      dataRoot,
		TsharkPath:    getenv("TSHARK_PATH", "tshark"),
		LiveDecode:    getbool("GATEWAY_LIVE_DECODE", true),
		RecordLive:    getbool("GATEWAY_RECORD_LIVE", true),
		TsharkVerify:  getbool("GATEWAY_TSHARK_VERIFY", false),
		StartMCP:      getbool("GATEWAY_MCP", false),
		LogFile:       getenv("GATEWAY_LOG_FILE", filepath.Join(dataRoot, "logs", "gateway.log")),
		LogMaxSizeMB:  getint("GATEWAY_LOG_MAX_SIZE_MB", 50),
		LogMaxBackups: getint("GATEWAY_LOG_MAX_BACKUPS", 10),
		LogMaxAgeDays: getint("GATEWAY_LOG_MAX_AGE_DAYS", 30),
		LogCompress:   getbool("GATEWAY_LOG_COMPRESS", true),
	}
}
