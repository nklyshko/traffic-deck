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

// Hints returns advisory warnings for expr, or nil when there is nothing suspicious. A
// genuine parse error is reported on its own, so it yields no hints.
func Hints(expr string) []string {
	terms, err := parse(strings.TrimSpace(expr))
	if err != nil {
		return nil
	}
	var bare []string
	for _, t := range terms {
		if t.term == "" && t.arg != "" {
			bare = append(bare, t.arg)
		}
	}

	var hints []string
	for _, b := range bare {
		if booleanTokens[strings.ToLower(b)] {
			hints = append(hints, fmt.Sprintf(
				"`%s` is not an operator — terms are ANDed automatically, so it was matched "+
					"as a regex against the URL. Just drop it.", b))
			break
		}
	}
	for _, b := range bare {
		if strings.HasPrefix(b, "(") || strings.HasSuffix(b, ")") {
			hints = append(hints, fmt.Sprintf(
				"`%s` — parentheses are not supported for grouping; the filter is a flat "+
					"list of ANDed terms.", b))
			break
		}
	}
	for _, b := range bare {
		if threeDigits.MatchString(b) {
			hints = append(hints, fmt.Sprintf(
				"a bare `%s` matches the URL, not the status — use `~c %s`. "+
					"(~s/~q take no argument.)", b, b))
			break
		}
	}
	for _, t := range terms {
		a := t.arg
		if len(a) > 1 && a[0] == a[len(a)-1] && (a[0] == '\'' || a[0] == '"') {
			hints = append(hints, fmt.Sprintf(
				"%s is quoted — arguments are not quote-parsed, so the quotes match "+
					"literally. Write %s instead.", a, a[1:len(a)-1]))
			break
		}
	}
	return hints
}
