// Package config loads gateway configuration from the environment (plan §10).
package config

import "os"

type Config struct {
	GRPCAddr   string // listen address for the gRPC server
	DataRoot   string // root for session bundles + catalog.sqlite
	TsharkPath string // path to the tshark binary (decode dependency)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Load reads config from env with sensible local-dev defaults.
func Load() Config {
	return Config{
		GRPCAddr:   getenv("GATEWAY_ADDR", "127.0.0.1:8080"),
		DataRoot:   getenv("DATA_ROOT", "./data"),
		TsharkPath: getenv("TSHARK_PATH", "tshark"),
	}
}
