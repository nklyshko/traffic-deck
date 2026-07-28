package filter

import (
	"strings"
	"testing"
)

func testFlow() *Flow {
	return &Flow{
		Scheme: "https", Method: "GET", Authority: "api.example.com",
		Path: "/v1/things", Query: "page=2", Status: 200,
		ContentTyp: "application/json", TCPStream: "12", H2StreamID: "3",
		MarkColor: "red", Favorite: true,
		TagNames: []string{"t-auth"}, GroupNames: []string{"g-api"},
		Comments: []string{"looks suspicious"},
		Metadata: map[string]string{"proxy_provider": "acme"},
		Body: func(d Direction) string {
			if d == Request {
				return `{"user":"alice"}`
			}
			return `{"token":"abc123"}`
		},
	}
}

var names = map[string]string{"t-auth": "auth"}
var groups = map[string]string{"g-api": "api"}

func match(t *testing.T, expr string) bool {
	t.Helper()
	p, err := Compile(expr, names, groups)
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}
	return p.Match(testFlow())
}

func TestTermsMatchTheirField(t *testing.T) {
	for _, c := range []struct {
		expr string
		want bool
	}{
		{"~m GET", true}, {"~m POST", false},
		{"~d example", true}, {"~d other.com", false},
		{"~u things", true}, {"~u /v2/", false},
		{"~u page=2", true}, // the URL includes the query
		{"~c 200", true}, {"~c 404", false},
		{"~t json", true}, {"~t html", false},
		{"~conn '^12$'", false}, // quotes match literally — see the hint
		{"~conn 12", true}, {"~stream 3", true},
		{"~mark red", true}, {"~mark blue", false},
		{"~tag auth", true}, {"~tag other", false},
		{"~group api", true},
		{"~comment suspicious", true},
		{"~meta proxy_provider=acme", true},
		{"~meta proxy_provider=other", false},
		{"~meta proxy_provider", true}, // presence, no `=`
		{"~meta absent", false},
		{"~s", true}, {"~q", false}, {"~fav", true},
		{"things", true},   // bare regex matches the URL
		{"nomatch", false}, // ditto
	} {
		if got := match(t, c.expr); got != c.want {
			t.Errorf("%q = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestBodyTerms(t *testing.T) {
	for _, c := range []struct {
		expr string
		want bool
	}{
		{"~b alice", true},  // either direction
		{"~b abc123", true}, // ditto, response side
		{"~bq alice", true}, // request only
		{"~bq abc123", false},
		{"~bs abc123", true}, // response only
		{"~bs alice", false},
		{"~b nothere", false},
	} {
		if got := match(t, c.expr); got != c.want {
			t.Errorf("%q = %v, want %v", c.expr, got, c.want)
		}
	}
}

// TestBodyTermsSortLast is ADR-0012 §2a: a body must not be read for a row that some
// cheaper term already rejected.
func TestBodyTermsSortLast(t *testing.T) {
	f := testFlow()
	read := 0
	f.Body = func(Direction) string { read++; return "irrelevant" }

	p, err := Compile("~b anything ~m POST", names, groups) // body term written first
	if err != nil {
		t.Fatal(err)
	}
	if p.Match(f) {
		t.Fatal("should not match: the method is GET")
	}
	if read != 0 {
		t.Fatalf("body read %d times for a flow rejected by ~m", read)
	}
	if !p.ReadsBodies() {
		t.Fatal("ReadsBodies should report true")
	}
	if q, _ := Compile("~m GET", names, groups); q.ReadsBodies() {
		t.Fatal("a filter with no body term should not report reading bodies")
	}
}

func TestNegationAndAnding(t *testing.T) {
	for _, c := range []struct {
		expr string
		want bool
	}{
		{"!~m POST", true},
		{"!~m GET", false},
		{"! ~m POST", true},      // detached `!`
		{"~m GET ~c 200", true},  // ANDed
		{"~m GET ~c 404", false}, // one failing term fails the whole filter
		{"~m GET !~t html", true},
	} {
		if got := match(t, c.expr); got != c.want {
			t.Errorf("%q = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestCaseInsensitiveByDefault(t *testing.T) {
	// The viewers have always compiled with IGNORECASE; losing it would change the
	// meaning of every filter already in use.
	if !match(t, "~d API.EXAMPLE.COM") {
		t.Error("matching should be case-insensitive")
	}
	if !match(t, "~m get") {
		t.Error("matching should be case-insensitive")
	}
}

func TestEmptyFilterMatchesEverything(t *testing.T) {
	p, err := Compile("   ", names, groups)
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Fatal("an empty expression should compile to a nil predicate")
	}
	if !p.Match(testFlow()) {
		t.Fatal("a nil predicate must match everything")
	}
}

func TestMissingArgumentIsAnError(t *testing.T) {
	for _, expr := range []string{"~m", "~meta", "~b"} {
		if _, err := Compile(expr, names, groups); err == nil {
			t.Errorf("%q should be a parse error", expr)
		}
	}
}

// TestUnsupportedRegexIsRefused is ADR-0012 §3: RE2 has no lookarounds or
// backreferences, and a filter using them must fail loudly rather than match a
// different set than it used to.
func TestUnsupportedRegexIsRefused(t *testing.T) {
	for _, c := range []struct{ expr, want string }{
		{`~u (?=foo)`, "lookahead"},
		{`~u (?!foo)`, "lookahead"},
		{`~u (?<=foo)`, "lookbehind"},
		{`~u (a)\1`, "backreference"},
	} {
		_, err := Compile(c.expr, names, groups)
		if err == nil {
			t.Errorf("%q should be refused", c.expr)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q error = %q, want it to name %q", c.expr, err, c.want)
		}
	}
}

func TestNilBodyMakesBodyTermsNotMatch(t *testing.T) {
	f := testFlow()
	f.Body = nil
	p, err := Compile("~b alice", names, groups)
	if err != nil {
		t.Fatal(err)
	}
	if p.Match(f) {
		t.Fatal("a body term should not match when bodies are unavailable")
	}
}

func TestHints(t *testing.T) {
	for _, c := range []struct{ expr, want string }{
		{"~d a & ~c 200", "not an operator"},
		{"(~d a)", "parentheses"},
		{"200", "matches the URL, not the status"},
		{"~d 'example.com'", "quoted"},
	} {
		hints := Hints(c.expr)
		found := false
		for _, h := range hints {
			if strings.Contains(h, c.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("Hints(%q) = %v, want one mentioning %q", c.expr, hints, c.want)
		}
	}
	if h := Hints("~d example.com ~c 200"); len(h) != 0 {
		t.Errorf("a clean expression should produce no hints, got %v", h)
	}
}
