package tlsfp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real JA4s (see builtin.json provenance): chromeExact/okhttpJA4 are verified captures,
// chromeFamilyOnly is a synthetic Chromium-cipher JA4 whose exact era hash isn't listed
// (stands in for a future Chrome like 139/144), firefoxPre matches the Firefox a_b prefix.
const (
	chromeExact      = "t13d1516h2_8daaf6152771_806a8c22fdea" // Chrome 150
	chrome120        = "t13d1516h2_8daaf6152771_02713d6af862" // Chrome 120-131
	chromeFamilyOnly = "t13d1599h2_8daaf6152771_deadbeef0000" // Chromium cipher, unknown era
	okhttpJA4        = "t13d171100_5b57614c22b0_2e6c25d3f76f" // Android OkHttp
	firefoxPre       = "t13d1715h2_5b57614c22b0_999999999999" // Firefox a_b, novel c
	unknownJA4       = "t13d9999h2_ffffffffffff_ffffffffffff"
)

// Firefox 155, from a local verified capture: Gecko User-Agent, Mozilla-owned host, and
// decrypted with Firefox's own SSLKEYLOGFILE, so the client is not in question. Note
// ff155H2 shares ja4_a AND ja4_b with chrome150Overlap — the whole a_b prefix — which is
// why only an exact row can separate the two engines.
const (
	ff155H2          = "t13d1517h2_8daaf6152771_3cbfd9057e0d" // TLS 1.3 + HTTP/2
	ff155H1          = "t13d1516h1_8daaf6152771_e6d2851837fd" // TLS 1.3, h1 ALPN
	ff155TLS12       = "t12d1211h2_d34a8e72043a_810e2f290f6f" // TLS 1.2 fallback
	ff155QUIC        = "q13d0315h3_55b375c5d22e_dc5437974b47" // QUIC + HTTP/3
	chrome150Overlap = "t13d1517h2_8daaf6152771_a87ad97598a9" // Chrome 150, same a_b as ff155H2
)

// The name the cipher-family rows carry. Modern Firefox adopted Chromium's cipher lists, so
// a bare cipher-hash match can no longer name one engine and the row says so.
const chromiumFamilyName = "Chrome/Chromium or Firefox"

// Chrome 133, YaBrowser Android and the Yamarket WebView all present this one JA4 and are
// only distinguishable by JA3 — the case combined ja4+ja3 rows exist for. Verified captures.
const (
	sharedJA4    = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	chrome133JA3 = "5edab8002293165cb74a0f79175dcdbc"
	yamarketJA3  = "cacebb32470a74ee9ab712dc919118b3"
	yaBrowserJA3 = "093e9cab323b23c342d26b3bea10bc82"
)

// Every builtin row is single-key, so the count term of score is 1 across the board and
// classification reduces to the historical key-tier ordering — the builtin set must behave
// exactly as it did before match keys could be combined.
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
		{"chrome 133 exact", Fingerprint{JA4: sharedJA4}, "Chrome 133", true},
		{"future/family: names both engines", Fingerprint{JA4: chromeFamilyOnly}, "Chrome/Chromium or Firefox", true},
		{"okhttp exact", Fingerprint{JA4: okhttpJA4}, "OkHttp (Android)", true},
		{"firefox prefix", Fingerprint{JA4: firefoxPre}, "Firefox", true},
		{"unknown", Fingerprint{JA4: unknownJA4}, "", false},
		{"empty", Fingerprint{}, "", false},
		// A JA3 on the fingerprint must not disturb a single-key ja4 row: the row simply
		// doesn't constrain JA3, so it still matches and still wins.
		{"exact ja4 with a ja3 present", Fingerprint{JA4: chromeExact, JA3: yamarketJA3}, "Chrome 150", true},
		{"family ja4 with a ja3 present", Fingerprint{JA4: chromeFamilyOnly, JA3: yamarketJA3}, "Chrome/Chromium or Firefox", true},
		// No builtin row carries a ja3 key, so a JA3-only fingerprint matches nothing.
		{"ja3 only", Fingerprint{JA3: chrome133JA3}, "", false},
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

// Specificity order among single-key rows: exact JA4 > ja4_pre > ja4_b. Score is now
// primarily the number of match keys a row constrains, so this ordering rides on the
// within-count tie-break — and it must hold even though the ja4_b family row loads after
// (builtin.json) the exact rows it overlaps, which the load-order tie-break alone would
// resolve the wrong way.
func TestSpecificityOrdering(t *testing.T) {
	reg, _ := LoadRegistry("")
	// Each of these also matches the ja4_b Chromium family row; the exact row must win.
	for _, ja4 := range []string{chromeExact, chrome120, sharedJA4} {
		m, _ := reg.Classify(Fingerprint{JA4: ja4})
		if m.Name == chromiumFamilyName {
			t.Fatalf("%s: family row beat the exact row (got %q)", ja4, m.String())
		}
		if m.Version == "" {
			t.Fatalf("%s: expected a versioned exact match, got %q", ja4, m.String())
		}
	}
}

// The score invariants the registry's precedence rests on: a row constraining more keys
// always outranks one constraining fewer (that's what lets a ja4+ja3 row pin a sub-variant),
// and within an equal count the key tiers keep their historical order.
func TestScoreOrdering(t *testing.T) {
	var (
		exact    = row{JA4: chromeExact}
		pre      = row{JA4Pre: "t13d1516h2_8daaf6152771"}
		family   = row{JA4B: "8daaf6152771"}
		ja3Only  = row{JA3: chrome133JA3}
		combined = row{JA4: chromeExact, JA3: chrome133JA3}
		weakPair = row{JA4B: "8daaf6152771", JA3: chrome133JA3}
	)
	if !(score(exact) > score(pre) && score(pre) > score(family) && score(family) > score(ja3Only)) {
		t.Fatalf("single-key tiers out of order: ja4=%d ja4_pre=%d ja4_b=%d ja3=%d",
			score(exact), score(pre), score(family), score(ja3Only))
	}
	// Count dominates the tier sum: even the weakest two-key row beats the strongest one-key row.
	if score(weakPair) <= score(exact) {
		t.Fatalf("two keys did not beat one: ja4_b+ja3=%d ja4=%d", score(weakPair), score(exact))
	}
	if score(combined) <= score(exact) {
		t.Fatalf("ja4+ja3 (%d) did not beat bare ja4 (%d)", score(combined), score(exact))
	}
	// sni is a constraint but not a match key: it must not inflate the count, or an
	// sni-scoped family row would outrank an exact-JA4 row. Classify tie-breaks on it instead.
	if got := score(row{JA4B: "8daaf6152771", SNI: "api.acme.test"}); got != score(family) {
		t.Fatalf("sni changed the score: %d, want %d", got, score(family))
	}
	// A keyless row scores 0; parse rejects these, so this is just the floor.
	if got := score(row{Name: "x"}); got != 0 {
		t.Fatalf("keyless row scored %d, want 0", got)
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
	if m, _ := reg.Classify(fp); m.Name != chromiumFamilyName {
		t.Fatalf("sni fallback failed: got %q", m.Name)
	}
}

// A row carrying both ja4 and ja3 outranks a row with only ja4, so two clients
// sharing a JA4 but differing in JA3 get distinct names.
func TestCombinedJA4JA3Row(t *testing.T) {
	dir := t.TempDir()
	const custom = `{"fingerprints":[
		{"name":"Chrome","version":"133","ja4":"` + sharedJA4 + `"},
		{"name":"Yamarket","version":"WebView","ja4":"` + sharedJA4 + `","ja3":"` + yamarketJA3 + `"},
		{"name":"YaBrowser","version":"Android 26","ja4":"` + sharedJA4 + `","ja3":"` + yaBrowserJA3 + `"}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "sub.json"), []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	reg, errs := LoadRegistry(dir)
	if len(errs) != 0 {
		t.Fatalf("load errors: %v", errs)
	}
	tests := []struct {
		name string
		ja3  string
		want string
	}{
		// Chrome 133's own JA3 is in no combined row → falls through to the bare-JA4 row.
		{"bare ja4 fallback", chrome133JA3, "Chrome 133"},
		// These two JA3s each pin a combined row, which outranks the bare-JA4 row.
		{"yamarket", yamarketJA3, "Yamarket WebView"},
		{"yabrowser", yaBrowserJA3, "YaBrowser Android 26"},
		// No JA3 at all → only the bare-JA4 row can match.
		{"ja4 only", "", "Chrome 133"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := reg.Classify(Fingerprint{JA4: sharedJA4, JA3: tc.ja3})
			if !ok || m.String() != tc.want {
				t.Fatalf("got %q (ok=%v), want %q", m.String(), ok, tc.want)
			}
		})
	}
}

// A combined row must match on ALL its keys: the right JA3 under the wrong JA4 is not a
// match, so it does not steal a name from another client's fingerprint.
func TestCombinedRowRequiresBothKeys(t *testing.T) {
	dir := t.TempDir()
	const custom = `{"fingerprints":[
		{"name":"Yamarket","version":"WebView","ja4":"` + sharedJA4 + `","ja3":"` + yamarketJA3 + `"}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "sub.json"), []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	reg, _ := LoadRegistry(dir)
	// Yamarket's JA3 but Chrome 150's JA4 → the combined row is out; the builtin exact
	// JA4 row answers instead.
	if m, _ := reg.Classify(Fingerprint{JA4: chromeExact, JA3: yamarketJA3}); m.String() != "Chrome 150" {
		t.Fatalf("combined row matched on ja3 alone: got %q", m.String())
	}
	// Neither key matches anything → unrecognized.
	if m, ok := reg.Classify(Fingerprint{JA4: unknownJA4, JA3: yamarketJA3}); ok {
		t.Fatalf("unexpected match: %q", m.String())
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

// Modern Firefox adopted Chromium's cipher lists, which broke the assumption the two
// cipher-family rows were built on: a bare 'ja4_b' match used to mean Chromium and now
// does not. Firefox 155's flows were being reported as "Chrome/Chromium" — on traffic to
// Mozilla's own hosts, decrypted with Firefox's own key-log.
//
// The fix is in two parts, and both are asserted here: exact rows for the fingerprints we
// have actually captured (so a known Firefox is named as Firefox), and family rows that
// name both engines (so an unknown client sharing the cipher list is not misattributed to
// one of them).
func TestFirefox155NotReportedAsChrome(t *testing.T) {
	reg, errs := LoadRegistry("")
	if len(errs) != 0 {
		t.Fatalf("builtin load errors: %v", errs)
	}
	for _, tc := range []struct{ name, ja4, want string }{
		{"TLS 1.3 + HTTP/2", ff155H2, "Firefox 155"},
		{"TLS 1.3, h1 ALPN", ff155H1, "Firefox 155"},
		{"TLS 1.2 fallback", ff155TLS12, "Firefox 155"},
		{"QUIC + HTTP/3", ff155QUIC, "Firefox (QUIC) 155"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := reg.Classify(Fingerprint{JA4: tc.ja4})
			if !ok {
				t.Fatalf("not classified at all")
			}
			if got := m.String(); got != tc.want {
				t.Fatalf("classified as %q, want %q", got, tc.want)
			}
			if strings.HasPrefix(m.Name, "Chrome") {
				t.Errorf("Firefox reported as a Chrome name: %q", m.Name)
			}
		})
	}
}

// Chrome must not have been sacrificed to fix Firefox: the engines share ja4_a and ja4_b,
// so both exact rows have to coexist and each win for its own extension hash. If a future
// edit ever replaces these with a ja4_pre row, one of these two assertions fails.
func TestChromeAndFirefoxShareAPrefixAndStayDistinct(t *testing.T) {
	reg, _ := LoadRegistry("")

	pre := func(ja4 string) string { return ja4[:strings.LastIndex(ja4, "_")] }
	if pre(ff155H2) != pre(chrome150Overlap) {
		t.Fatalf("premise broken: %q and %q no longer share an a_b prefix",
			pre(ff155H2), pre(chrome150Overlap))
	}

	if m, _ := reg.Classify(Fingerprint{JA4: ff155H2}); m.Name != "Firefox" {
		t.Errorf("shared prefix, Firefox extension hash: got %q, want Firefox", m.String())
	}
	if m, _ := reg.Classify(Fingerprint{JA4: chrome150Overlap}); m.Name != "Chrome" {
		t.Errorf("shared prefix, Chrome extension hash: got %q, want Chrome", m.String())
	}
}

// A cipher list we can't pin to an engine must not be attributed to one. Both family rows
// name both engines — that is the honest answer for a bare cipher-hash match, and it is
// what stops the next Firefox release from being labelled Chrome.
func TestCipherFamilyRowsNameBothEngines(t *testing.T) {
	reg, _ := LoadRegistry("")
	for _, tc := range []struct{ name, ja4 string }{
		// Chromium's TLS cipher list, extension hash belonging to no row we ship.
		{"TLS family", "t13d1599h2_8daaf6152771_deadbeef0000"},
		// Chromium's QUIC cipher list, likewise unknown era.
		{"QUIC family", "q13d0399h3_55b375c5d22e_deadbeef0000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := reg.Classify(Fingerprint{JA4: tc.ja4})
			if !ok {
				t.Fatalf("cipher-family row did not match")
			}
			if !strings.Contains(m.Name, "Chrome") || !strings.Contains(m.Name, "Firefox") {
				t.Errorf("name %q claims one engine; a cipher-list match cannot tell them apart", m.Name)
			}
		})
	}
}
