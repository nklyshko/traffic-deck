// Package tlsfp classifies a TLS ClientHello fingerprint into a human-readable client
// name (e.g. "Chrome 150", "OkHttp (Android)") from a registry of well-known
// fingerprints. The registry is a compiled-in builtin set (builtin.json, embedded)
// plus any JSON files a user drops into a directory (default
// ~/.traffic-deck/fingerprints, override TRAFFICDECK_FP_DIR) — so new fingerprints are
// registered without modifying or rebuilding TrafficDeck.
//
// Classification is a pure function of the fingerprint, run at serve time, so editing
// the registry re-labels existing captured flows without re-decoding them.
package tlsfp

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed builtin.json
var builtinFS embed.FS

// Fingerprint is the ClientHello view a classifier matches on.
type Fingerprint struct {
	JA4 string
	JA3 string
	SNI string
}

// Match is a recognized client. Zero value (Name == "") means "unrecognized".
type Match struct {
	Name    string // display label, e.g. "Chrome"
	Version string // optional version, e.g. "150"
	Source  string // where the matching row came from: "builtin" or the file basename
	score   int    // match specificity; higher wins
}

// String renders the label the viewer shows, e.g. "Chrome 150".
func (m Match) String() string {
	if m.Name == "" {
		return ""
	}
	if m.Version != "" {
		return m.Name + " " + m.Version
	}
	return m.Name
}

// row is one fingerprint entry as stored in JSON. Exactly one match key
// (ja4 / ja4_pre / ja4_b / ja3) is expected; sni optionally constrains the row.
type row struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	JA4     string `json:"ja4"`     // exact JA4 (most specific)
	JA4B    string `json:"ja4_b"`   // JA4 cipher section (client family)
	JA4Pre  string `json:"ja4_pre"` // JA4 prefix, e.g. the "a_b" sections (client + version era)
	JA3     string `json:"ja3"`     // exact legacy JA3 MD5
	SNI     string `json:"sni"`     // optional additional constraint
	Note    string `json:"note"`

	source string // filled at load: "builtin" or file basename
	order  int    // load order; later (user files) wins ties
}

// file is the on-disk JSON shape: {"fingerprints": [ {row}, ... ]}. A bare top-level
// array is also accepted for convenience.
type file struct {
	Fingerprints []row `json:"fingerprints"`
}

// Registry holds the loaded fingerprint rows and matches against them.
type Registry struct {
	rows []row
}

func score(r row) int {
	switch {
	case r.JA4 != "":
		return 100
	case r.JA4Pre != "":
		return 70
	case r.JA4B != "":
		return 50
	case r.JA3 != "":
		return 40
	}
	return 0
}

// ja4B returns the cipher section of a JA4 string (the middle of a_b_c), or "".
func ja4B(ja4 string) string {
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		return ""
	}
	return parts[1]
}

// matches reports whether r claims fp.
func (r row) matches(fp Fingerprint) bool {
	if r.SNI != "" && !strings.EqualFold(r.SNI, fp.SNI) {
		return false
	}
	switch {
	case r.JA4 != "":
		return r.JA4 == fp.JA4
	case r.JA4Pre != "":
		return fp.JA4 != "" && strings.HasPrefix(fp.JA4, r.JA4Pre)
	case r.JA4B != "":
		return fp.JA4 != "" && r.JA4B == ja4B(fp.JA4)
	case r.JA3 != "":
		return r.JA3 == fp.JA3
	}
	return false
}

// Classify returns the best match for fp. ok is false when nothing matched.
func (r *Registry) Classify(fp Fingerprint) (Match, bool) {
	if fp.JA4 == "" && fp.JA3 == "" {
		return Match{}, false
	}
	best := -1
	for i := range r.rows {
		row := r.rows[i]
		if !row.matches(fp) {
			continue
		}
		// Higher score wins; equal score → later load order (user > builtin) wins;
		// an SNI-constrained row outranks an equal-score unconstrained one.
		if best < 0 {
			best = i
			continue
		}
		b := r.rows[best]
		if score(row) > score(b) ||
			(score(row) == score(b) && row.hasSNI() && !b.hasSNI()) ||
			(score(row) == score(b) && row.hasSNI() == b.hasSNI() && row.order >= b.order) {
			best = i
		}
	}
	if best < 0 {
		return Match{}, false
	}
	b := r.rows[best]
	return Match{Name: b.Name, Version: b.Version, Source: b.source, score: score(b)}, true
}

func (r row) hasSNI() bool { return r.SNI != "" }

// parse reads a file's JSON (either {"fingerprints":[...]} or a bare [...]), tags each
// valid row with its source and load order, and returns them. Malformed rows are
// skipped and reported in the error list (never fatal).
func parse(data []byte, source string, startOrder int) ([]row, []error) {
	var f file
	if err := json.Unmarshal(data, &f); err != nil || f.Fingerprints == nil {
		// Fall back to a bare top-level array.
		var arr []row
		if err2 := json.Unmarshal(data, &arr); err2 != nil {
			return nil, []error{fmt.Errorf("%s: %w", source, err)}
		}
		f.Fingerprints = arr
	}
	var out []row
	var errs []error
	for i, r := range f.Fingerprints {
		if r.Name == "" {
			errs = append(errs, fmt.Errorf("%s row %d: missing name", source, i))
			continue
		}
		if r.JA4 == "" && r.JA4Pre == "" && r.JA4B == "" && r.JA3 == "" {
			errs = append(errs, fmt.Errorf("%s row %d (%q): no match key (ja4/ja4_pre/ja4_b/ja3)", source, i, r.Name))
			continue
		}
		r.source = source
		r.order = startOrder + i
		out = append(out, r)
	}
	return out, errs
}

// LoadRegistry builds a Registry from the embedded builtin set plus every *.json file
// in dir (sorted by name; later files win ties). A missing dir is fine (builtin only).
// Malformed files/rows are skipped and returned as errs for logging.
func LoadRegistry(dir string) (*Registry, []error) {
	var rows []row
	var errs []error

	b, err := builtinFS.ReadFile("builtin.json")
	if err != nil {
		errs = append(errs, fmt.Errorf("builtin: %w", err))
	} else {
		br, be := parse(b, "builtin", 0)
		rows, errs = append(rows, br...), append(errs, be...)
	}

	if dir != "" {
		entries, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		sort.Strings(entries)
		for _, path := range entries {
			data, err := os.ReadFile(path)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(path), err))
				continue
			}
			fr, fe := parse(data, filepath.Base(path), len(rows)+1)
			rows, errs = append(rows, fr...), append(errs, fe...)
		}
	}
	return &Registry{rows: rows}, errs
}

// --- package-level default registry with lazy hot-reload -------------------

var (
	mu          sync.RWMutex
	defReg      = &Registry{}
	watchDir    string
	lastReload  time.Time
	reloadEvery = 2 * time.Second
	// LogErrors, if set, is called with load errors on (re)load. Wired to the gateway
	// logger by Configure's caller; nil keeps loading silent.
	LogErrors func([]error)
)

// init loads the builtin-only registry so Classify works before Configure is called
// (e.g. on code paths that never point it at a user directory).
func init() { reload() }

// Configure points the default registry at dir and loads it once. Pass "" to use only
// the builtin set. Safe to call once at startup.
func Configure(dir string) {
	mu.Lock()
	watchDir = dir
	mu.Unlock()
	reload()
}

func reload() {
	mu.RLock()
	dir := watchDir
	mu.RUnlock()
	reg, errs := LoadRegistry(dir)
	mu.Lock()
	defReg = reg
	lastReload = time.Now()
	mu.Unlock()
	if len(errs) > 0 && LogErrors != nil {
		LogErrors(errs)
	}
}

// dirChanged reports whether any *.json under watchDir has an mtime newer than the last
// reload (cheap stat scan, throttled by the caller).
func dirChanged() bool {
	mu.RLock()
	dir, since := watchDir, lastReload
	mu.RUnlock()
	if dir == "" {
		return false
	}
	// The directory's own mtime bumps when a file is added or removed; a file's mtime
	// bumps when it's edited — cover both.
	if fi, err := os.Stat(dir); err == nil && fi.ModTime().After(since) {
		return true
	}
	entries, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, p := range entries {
		if fi, err := os.Stat(p); err == nil && fi.ModTime().After(since) {
			return true
		}
	}
	return false
}

// Classify classifies fp against the default registry, hot-reloading the user directory
// at most once per reloadEvery when its files change on disk.
func Classify(fp Fingerprint) (Match, bool) {
	mu.RLock()
	stale := time.Since(lastReload) >= reloadEvery
	mu.RUnlock()
	if stale && dirChanged() {
		reload()
	}
	mu.RLock()
	reg := defReg
	mu.RUnlock()
	return reg.Classify(fp)
}

// Name is a convenience: the display label for fp, or "" if unrecognized.
func Name(fp Fingerprint) string {
	m, ok := Classify(fp)
	if !ok {
		return ""
	}
	return m.String()
}

// DefaultDir returns the default user fingerprint directory
// (~/.traffic-deck/fingerprints), or "" if the home dir can't be determined.
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".traffic-deck", "fingerprints")
}
