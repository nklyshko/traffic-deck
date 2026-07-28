// Package filter is the flow filter language, evaluated in the gateway (ADR-0012).
//
// It was previously implemented twice, in the TUI and in the MCP server, over each
// viewer's in-memory copy of a whole session. Evaluating it here means one implementation
// for every client, and — because the predicate now runs in the same process as the
// bundle — makes body matching possible at all.
//
// The grammar is mitmproxy-style and deliberately flat: space-separated terms, ANDed, a
// leading `!` negating one. There is no `&`/`|`/`()` grouping; a stray operator is a URL
// regex, which is what Hints exists to warn about.
package filter

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Direction selects which body a body term reads.
type Direction int

const (
	Request Direction = iota
	Response
)

// Flow is the view of a flow the language can see. Bodies are behind a func because they
// are the one thing that costs a read: body terms sort last, so Body is only called for a
// row that has already passed every cheaper term (ADR-0012 §2a).
type Flow struct {
	Scheme     string
	Method     string
	Authority  string
	Path       string
	Query      string
	Status     uint32
	ContentTyp string
	TCPStream  string
	H2StreamID string

	MarkColor  string
	Favorite   bool
	TagNames   []string
	GroupNames []string
	Comments   []string
	Metadata   map[string]string

	// Body returns the decoded body for a direction, or "" if there is none. Nil means
	// bodies are unavailable, in which case body terms simply do not match.
	Body func(Direction) string
}

// URL is the haystack for `~u` and for a bare regex, composed the way the viewers
// compose it for display so a filter matches what the user sees.
func (f *Flow) URL() string {
	scheme := f.Scheme
	if scheme == "" {
		scheme = "https"
	}
	u := scheme + "://" + f.Authority + f.Path
	if f.Query != "" {
		u += "?" + f.Query
	}
	return u
}

func (f *Flow) body(d Direction) string {
	if f.Body == nil {
		return ""
	}
	return f.Body(d)
}

// Predicate is a compiled filter.
type Predicate struct{ terms []term }

type term struct {
	neg  bool
	body bool // reads a body; sorted last so only survivors pay for it
	eval func(*Flow) bool
}

// Match reports whether f satisfies every term. A nil Predicate matches everything, so
// an empty filter needs no special case at the call site.
func (p *Predicate) Match(f *Flow) bool {
	if p == nil {
		return true
	}
	for _, t := range p.terms {
		ok := t.eval(f)
		if t.neg {
			ok = !ok
		}
		if !ok {
			return false
		}
	}
	return true
}

// ReadsBodies reports whether any term needs a body, so a caller can skip loading them
// for the common filter that does not.
func (p *Predicate) ReadsBodies() bool {
	if p == nil {
		return false
	}
	for _, t := range p.terms {
		if t.body {
			return true
		}
	}
	return false
}

// argTerms take a regex argument; flagTerms take none.
var argTerms = map[string]bool{
	"~m": true, "~d": true, "~u": true, "~c": true, "~t": true,
	"~conn": true, "~stream": true,
	"~mark": true, "~tag": true, "~group": true, "~comment": true, "~meta": true,
	"~b": true, "~bq": true, "~bs": true,
}

var flagTerms = map[string]bool{"~s": true, "~q": true, "~fav": true}

type parsed struct {
	term string // "" for a bare URL regex
	arg  string
	neg  bool
}

// parse tokenizes into (term, arg, negated) triples. Shared by Compile and Hints so the
// hints always describe the same parse the predicate was built from.
func parse(expr string) ([]parsed, error) {
	toks := strings.Fields(expr)
	var out []parsed
	for i := 0; i < len(toks); i++ {
		t, neg := toks[i], false
		if t == "!" {
			neg = true
			i++
			if i >= len(toks) {
				break
			}
			t = toks[i]
		} else if strings.HasPrefix(t, "!") && len(t) > 1 {
			neg, t = true, t[1:]
		}

		switch {
		case flagTerms[t]:
			out = append(out, parsed{term: t, neg: neg})
		case argTerms[t]:
			i++
			if i >= len(toks) {
				if t == "~meta" {
					return nil, fmt.Errorf("~meta needs a key=regex (or key) argument")
				}
				return nil, fmt.Errorf("%s needs an argument", t)
			}
			out = append(out, parsed{term: t, arg: toks[i], neg: neg})
		default:
			out = append(out, parsed{arg: t, neg: neg})
		}
	}
	return out, nil
}

// compileRx compiles a term's regex. Matching is case-insensitive, as it has always been
// in the viewers — dropping that would change the meaning of every filter already in use.
//
// The engine here is RE2, which has no lookarounds or backreferences. Those are refused
// with an error naming the construct rather than silently matching a different set: a
// filter that quietly stops meaning what it meant is the failure worth avoiding
// (ADR-0012 §3).
func compileRx(pat string) (*regexp.Regexp, error) {
	rx, err := regexp.Compile("(?i)" + pat)
	if err == nil {
		return rx, nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "(?="), strings.Contains(msg, "(?!"):
		return nil, fmt.Errorf("bad regex %q: lookahead is not supported", pat)
	case strings.Contains(msg, "(?<"):
		return nil, fmt.Errorf("bad regex %q: lookbehind is not supported", pat)
	case strings.Contains(msg, "invalid escape sequence"):
		return nil, fmt.Errorf("bad regex %q: backreferences are not supported (%v)", pat, err)
	}
	return nil, fmt.Errorf("bad regex %q: %v", pat, err)
}

// Compile turns an expression into a Predicate, or nil for an empty one. tagNames and
// groupNames map ids to names, since `~tag`/`~group` match what the user sees.
func Compile(expr string, tagNames, groupNames map[string]string) (*Predicate, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}
	terms, err := parse(expr)
	if err != nil {
		return nil, err
	}

	p := &Predicate{}
	for _, t := range terms {
		trm := term{neg: t.neg}
		switch t.term {
		case "~s":
			trm.eval = func(f *Flow) bool { return f.Status != 0 }
		case "~q":
			trm.eval = func(f *Flow) bool { return f.Status == 0 }
		case "~fav":
			trm.eval = func(f *Flow) bool { return f.Favorite }
		case "~meta":
			key, pat, hasPat := strings.Cut(t.arg, "=")
			if !hasPat || pat == "" {
				// `~meta key` with no `=` matches flows carrying the key at all.
				trm.eval = func(f *Flow) bool { _, ok := f.Metadata[key]; return ok }
				break
			}
			rx, err := compileRx(pat)
			if err != nil {
				return nil, err
			}
			trm.eval = func(f *Flow) bool { return rx.MatchString(f.Metadata[key]) }
		case "~b", "~bq", "~bs":
			rx, err := compileRx(t.arg)
			if err != nil {
				return nil, err
			}
			trm.body = true
			switch t.term {
			case "~bq":
				trm.eval = func(f *Flow) bool { return rx.MatchString(f.body(Request)) }
			case "~bs":
				trm.eval = func(f *Flow) bool { return rx.MatchString(f.body(Response)) }
			default:
				trm.eval = func(f *Flow) bool {
					return rx.MatchString(f.body(Request)) || rx.MatchString(f.body(Response))
				}
			}
		default:
			rx, err := compileRx(t.arg)
			if err != nil {
				return nil, err
			}
			get := fieldGetter(t.term, tagNames, groupNames)
			trm.eval = func(f *Flow) bool { return rx.MatchString(get(f)) }
		}
		p.terms = append(p.terms, trm)
	}

	// Body terms last: a body is read only for a row that already passed everything else.
	sort.SliceStable(p.terms, func(i, j int) bool { return !p.terms[i].body && p.terms[j].body })
	return p, nil
}

// fieldGetter returns the haystack for a term; "" (a bare regex) matches the URL.
func fieldGetter(name string, tagNames, groupNames map[string]string) func(*Flow) string {
	switch name {
	case "~m":
		return func(f *Flow) string { return f.Method }
	case "~d":
		return func(f *Flow) string { return f.Authority }
	case "~c":
		return func(f *Flow) string {
			if f.Status == 0 {
				return ""
			}
			return strconv.FormatUint(uint64(f.Status), 10)
		}
	case "~t":
		return func(f *Flow) string { return f.ContentTyp }
	case "~conn":
		return func(f *Flow) string { return f.TCPStream }
	case "~stream":
		return func(f *Flow) string { return f.H2StreamID }
	case "~mark":
		return func(f *Flow) string { return f.MarkColor }
	case "~tag":
		return func(f *Flow) string { return strings.Join(resolve(f.TagNames, tagNames), " ") }
	case "~group":
		return func(f *Flow) string { return strings.Join(resolve(f.GroupNames, groupNames), " ") }
	case "~comment":
		return func(f *Flow) string { return strings.Join(f.Comments, " ") }
	default: // "~u" and a bare regex
		return func(f *Flow) string { return f.URL() }
	}
}

// resolve maps ids to names, leaving an id in place when it has no name — the viewers do
// the same, so a filter still matches something for an annotation the client hasn't seen.
func resolve(ids []string, names map[string]string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if n, ok := names[id]; ok {
			out = append(out, n)
		} else {
			out = append(out, id)
		}
	}
	return out
}
