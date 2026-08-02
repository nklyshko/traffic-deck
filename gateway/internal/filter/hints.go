package filter

// Advisory diagnostics for an expression that parses but does not mean what it looks
// like. These are part of the language, not the viewer: the grammar accepts `&`, `|` and
// parentheses as ordinary URL regexes rather than rejecting them, so `~d a & ~c 200`
// silently filters on something else entirely. Every check here is for a mistake the
// grammar cannot catch, which is why they are warnings beside the results rather than
// errors (ADR-0012 §9).

import (
	"fmt"
	"regexp"
	"strings"
)

var booleanTokens = map[string]bool{
	"&": true, "&&": true, "|": true, "||": true, "and": true, "or": true,
}

var threeDigits = regexp.MustCompile(`^\d{3}$`)

// Hints returns advisory warnings for a flow expression, or nil when there is nothing
// suspicious. A genuine parse error is reported on its own, so it yields no hints.
func Hints(expr string) []string { return hints(expr, flowGrammar) }

// MessageHints is the same for a message expression. It shares every check that is about
// the grammar rather than about flows; the status-code one does not apply, since the
// message language has no `~c` to suggest.
func MessageHints(expr string) []string { return hints(expr, messageGrammar) }

func hints(expr string, g grammar) []string {
	terms, err := parse(strings.TrimSpace(expr), g)
	if err != nil {
		return nil
	}
	var bare []string
	for _, t := range terms {
		if t.term == "" && t.arg != "" {
			bare = append(bare, t.arg)
		}
	}

	var out []string
	for _, b := range bare {
		if booleanTokens[strings.ToLower(b)] {
			out = append(out, fmt.Sprintf(
				"`%s` is not an operator — terms are ANDed automatically, so it was matched "+
					"as a regex against %s. Just drop it.", b, g.bareWhat))
			break
		}
	}
	for _, b := range bare {
		if strings.HasPrefix(b, "(") || strings.HasSuffix(b, ")") {
			out = append(out, fmt.Sprintf(
				"`%s` — parentheses are not supported for grouping; the filter is a flat "+
					"list of ANDed terms.", b))
			break
		}
	}
	for _, b := range bare {
		if g.args["~c"] && threeDigits.MatchString(b) {
			out = append(out, fmt.Sprintf(
				"a bare `%s` matches the URL, not the status — use `~c %s`. "+
					"(~s/~q take no argument.)", b, b))
			break
		}
	}
	for _, t := range terms {
		a := t.arg
		if len(a) > 1 && a[0] == a[len(a)-1] && (a[0] == '\'' || a[0] == '"') {
			out = append(out, fmt.Sprintf(
				"%s is quoted — arguments are not quote-parsed, so the quotes match "+
					"literally. Write %s instead.", a, a[1:len(a)-1]))
			break
		}
	}
	return out
}
