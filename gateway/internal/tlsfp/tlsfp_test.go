package tlsfp

import (
	"os"
	"path/filepath"
	"testing"
)

// Real JA4s (see builtin.json provenance): chromeExact/okhttp* are verified captures,
// chromeFamilyOnly is a synthetic Chromium-cipher JA4 whose exact era hash isn't listed
// (stands in for a future Chrome like 139/144), fxPre matches the Firefox a_b prefix.
const (
	chromeExact      = "t13d1516h2_8daaf6152771_806a8c22fdea" // Chrome 150
	chrome120        = "t13d1516h2_8daaf6152771_02713d6af862" // Chrome 120-131
	chromeFamilyOnly = "t13d1599h2_8daaf6152771_deadbeef0000" // Chromium cipher, unknown era
	okhttpJA4        = "t13d171100_5b57614c22b0_2e6c25d3f76f" // Android OkHttp
	firefoxPre       = "t13d1715h2_5b57614c22b0_999999999999" // Firefox a_b, novel c
	unknownJA4       = "t13d9999h2_ffffffffffff_ffffffffffff"
)

func TestBuiltinClassify(t *testing.T) {
	reg, errs := LoadRegistry("")
	if len(errs) != 0 {
		t.Fatalf("builtin load errors: %v", errs)
	}

	tests := []struct {
		name string
		fp   Fingerprint
		want string
		ok   bool
	}{
		{"chrome 150 exact", Fingerprint{JA4: chromeExact}, "Chrome 150", true},
		{"chrome 120-131 exact", Fingerprint{JA4: chrome120}, "Chrome 120-131", true},
		{"chrome future/family", Fingerprint{JA4: chromeFamilyOnly}, "Chrome/Chromium", true},
		{"okhttp exact", Fingerprint{JA4: okhttpJA4}, "OkHttp (Android)", true},
		{"firefox prefix", Fingerprint{JA4: firefoxPre}, "Firefox", true},
		{"unknown", Fingerprint{JA4: unknownJA4}, "", false},
		{"empty", Fingerprint{}, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := reg.Classify(tc.fp)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (match %+v)", ok, tc.ok, m)
			}
			if m.String() != tc.want {
				t.Fatalf("name = %q, want %q", m.String(), tc.want)
			}
		})
	}
}

// Firefox and Android OkHttp share cipher hash 5b57614c22b0; the ja4_pre prefix (which
// includes the extension count in ja4_a) must keep them apart — the collision bug that
// prompted dropping the bare cipher-family match for these two.
func TestFirefoxOkHttpNotConflated(t *testing.T) {
	reg, _ := LoadRegistry("")
	if m, _ := reg.Classify(Fingerprint{JA4: firefoxPre}); m.Name != "Firefox" {
		t.Fatalf("firefox prefix classified as %q, want Firefox", m.Name)
	}
	if m, _ := reg.Classify(Fingerprint{JA4: okhttpJA4}); m.Name != "OkHttp (Android)" {
		t.Fatalf("okhttp classified as %q, want OkHttp (Android)", m.Name)
	}
}

// Specificity order: exact JA4 > ja4_pre > ja4_b.
func TestSpecificityOrdering(t *testing.T) {
	reg, _ := LoadRegistry("")
	// chromeExact hits an exact row (Chrome 150) even though it also matches the ja4_b
	// Chromium family — exact must win.
	if m, _ := reg.Classify(Fingerprint{JA4: chromeExact}); m.String() != "Chrome 150" {
		t.Fatalf("exact did not beat family: %q", m.String())
	}
}

// A user file registers a new fingerprint and overrides a builtin family row via SNI.
func TestUserDirOverrides(t *testing.T) {
	dir := t.TempDir()
	const custom = `{"fingerprints":[
		{"name":"AcmeApp","ja4_b":"8daaf6152771","sni":"api.acme.test"},
		{"name":"MyChrome","version":"999","ja4":"` + chromeExact + `"}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "user.json"), []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	reg, errs := LoadRegistry(dir)
	if len(errs) != 0 {
		t.Fatalf("unexpected load errors: %v", errs)
	}

	// User exact row wins the tie against the builtin exact row (later load order).
	if m, _ := reg.Classify(Fingerprint{JA4: chromeExact}); m.String() != "MyChrome 999" {
		t.Fatalf("user override failed: got %q", m.String())
	}
	// SNI-constrained user family row beats the unconstrained builtin Chromium family row
	// for a fingerprint only the family matches.
	fp := Fingerprint{JA4: chromeFamilyOnly, SNI: "api.acme.test"}
	if m, _ := reg.Classify(fp); m.Name != "AcmeApp" {
		t.Fatalf("sni-constrained match failed: got %q", m.Name)
	}
	// Same fingerprint, different SNI → falls back to the builtin family row.
	fp.SNI = "other.test"
	if m, _ := reg.Classify(fp); m.Name != "Chrome/Chromium" {
		t.Fatalf("sni fallback failed: got %q", m.Name)
	}
}

// Malformed rows are skipped and reported, never fatal; valid rows still load.
func TestMalformedRowsSkipped(t *testing.T) {
	dir := t.TempDir()
	const bad = `{"fingerprints":[
		{"version":"1","ja4":"x"},
		{"name":"NoKey"},
		{"name":"Good","ja4":"` + unknownJA4 + `"}
	]}`
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte(bad), 0o644)
	reg, errs := LoadRegistry(dir)
	if len(errs) != 2 {
		t.Fatalf("expected 2 row errors, got %d: %v", len(errs), errs)
	}
	if m, ok := reg.Classify(Fingerprint{JA4: unknownJA4}); !ok || m.Name != "Good" {
		t.Fatalf("valid row after malformed ones did not load: %+v ok=%v", m, ok)
	}
}

// A bare top-level JSON array is accepted too.
func TestBareArray(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "arr.json"),
		[]byte(`[{"name":"Bare","ja4":"`+unknownJA4+`"}]`), 0o644)
	reg, errs := LoadRegistry(dir)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	if m, _ := reg.Classify(Fingerprint{JA4: unknownJA4}); m.Name != "Bare" {
		t.Fatalf("bare array not parsed: %q", m.Name)
	}
}
