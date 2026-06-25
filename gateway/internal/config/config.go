// Package config loads gateway configuration from the environment.
package config

import (
	"os"
	"strings"
)

type Config struct {
	GRPCAddr   string // listen address for the gRPC server
	DataRoot   string // root for session bundles + catalog.sqlite
	TsharkPath string // path to the tshark binary (decode dependency)
	// LiveDecode toggles the live pipeline. When true (default) a streaming session
	// decodes flows live (tshark for HTTP/WS/HTTP3 + in-process Go TLS decryption for
	// custom raw-TCP). When false, no live decode runs and the capture is decoded only
	// by the batch tshark pass on session close (the pre-live behavior).
	LiveDecode bool
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

// Load reads config from env with sensible local-dev defaults.
func Load() Config {
	return Config{
		GRPCAddr:   getenv("GATEWAY_ADDR", "127.0.0.1:8080"),
		DataRoot:   getenv("DATA_ROOT", "./data"),
		TsharkPath: getenv("TSHARK_PATH", "tshark"),
		LiveDecode: getbool("GATEWAY_LIVE_DECODE", true),
	}
}
