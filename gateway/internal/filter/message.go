package filter

// The message filter language: the same grammar as the flow language over a different
// record. A WebSocket/TCP-parsed frame has a payload, an opcode and a direction, and no
// method, status, header or URL — so it gets its own term table rather than a flow
// predicate applied to a shape it does not have.
//
// Two deliberate differences from the flow dialect:
//
//   - A bare regex matches the **payload**, not a URL. The payload is what a message
//     timeline shows and what a reader is looking for; there is nothing else it could
//     usefully mean.
//   - A `~`-prefixed token this dialect does not define is an **error**. The flow
//     language lets one fall through to a bare regex, and cannot stop doing so without
//     changing what existing expressions mean. Here the terms a user is most likely to
//     bring over — `~m`, `~c`, `~h`, `~d` — are exactly the ones that would silently
//     become payload regexes and match nothing, which is the quietly-wrong failure the
//     rest of the language works to avoid.

import (
	"sort"
	"strings"
)

// Message is the view of a frame the language can see. Payload is behind a func for the
// same reason a flow's body is: it is the one thing that costs a read, so it sorts last
// and is only called for a frame that passed every cheaper term.
type Message struct {
	Opcode     string // text | binary | close | ping | pong | continuation
	FromClient bool   // direction: true = client→server

	MarkColor  string
	Favorite   bool
	TagNames   []string
	GroupNames []string
	Comments   []string
	// Metadata is whatever the decoder pulled out of the frame header (a command code, a
	// sequence number), matched by `~meta <key>=<re>` exactly as a flow's source metadata
	// is. Opaque here: the language knows there are keys, not what any of them mean.
	Metadata map[string]string

	// Payload returns the frame's decoded payload as text, or "" if there is none. Nil
	// means payloads are unavailable, in which case payload terms simply do not match.
	Payload func() string
}

func (m *Message) payload() string {
	if m.Payload == nil {
		return ""
	}
	return m.Payload()
}

// direction is the haystack for `~from`: the words a user would write for each way a
// frame can travel, so `~from client` and `~from s` both do the obvious thing.
func (m *Message) direction() string {
	if m.FromClient {
		return "client"
	}
	return "server"
}

// MessagePredicate is a compiled message filter.
type MessagePredicate struct{ terms []msgTerm }

type msgTerm struct {
	neg  bool
	cost int
	eval func(*Message) bool
}

// Match reports whether m satisfies every term. A nil MessagePredicate matches
// everything, so an empty filter needs no special case at the call site.
func (p *MessagePredicate) Match(m *Message) bool {
	if p == nil {
		return true
	}
	for _, t := range p.terms {
		ok := t.eval(m)
		if t.neg {
			ok = !ok
		}
		if !ok {
			return false
		}
	}
	return true
}

// ReadsPayloads reports whether any term needs a payload, so a caller can skip wiring the
// loader for a filter that does not — the common case of `~op` or `~from` alone.
func (p *MessagePredicate) ReadsPayloads() bool {
	if p == nil {
		return false
	}
	for _, t := range p.terms {
		if t.cost == costBody {
			return true
		}
	}
	return false
}

var messageGrammar = grammar{
	args: map[string]bool{
		"~b": true, "~op": true, "~from": true, "~meta": true,
		"~mark": true, "~tag": true, "~group": true, "~comment": true,
	},
	flags:       map[string]bool{"~fav": true},
	strictTerms: true,
	what:        "message filter",
	terms: "message terms are ~b ~op ~from ~meta ~mark ~tag ~group ~comment ~fav " +
		"(a bare regex matches the payload)",
	bareWhat: "the payload",
}

// CompileMessage turns an expression into a MessagePredicate, or nil for an empty one.
// tagNames and groupNames map ids to names, since `~tag`/`~group` match what the user
// sees — the same contract as Compile.
func CompileMessage(expr string, tagNames, groupNames map[string]string) (*MessagePredicate, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}
	terms, err := parse(expr, messageGrammar)
	if err != nil {
		return nil, err
	}

	p := &MessagePredicate{}
	for _, t := range terms {
		trm := msgTerm{neg: t.neg}
		// The two terms whose argument is not a plain regex, handled before the compile.
		switch t.term {
		case "~fav":
			trm.eval = func(m *Message) bool { return m.Favorite }
			p.terms = append(p.terms, trm)
			continue
		case "~meta":
			key, pat, hasPat := strings.Cut(t.arg, "=")
			if !hasPat || pat == "" {
				// `~meta key` with no `=` matches frames carrying the key at all.
				trm.eval = func(m *Message) bool { _, ok := m.Metadata[key]; return ok }
			} else {
				mrx, err := compileRx(pat)
				if err != nil {
					return nil, err
				}
				trm.eval = func(m *Message) bool { return mrx.MatchString(m.Metadata[key]) }
			}
			p.terms = append(p.terms, trm)
			continue
		}

		rx, err := compileRx(t.arg)
		if err != nil {
			return nil, err
		}
		switch t.term {
		case "~op":
			trm.eval = func(m *Message) bool { return rx.MatchString(m.Opcode) }
		case "~from":
			trm.eval = func(m *Message) bool { return rx.MatchString(m.direction()) }
		case "~mark":
			trm.eval = func(m *Message) bool { return rx.MatchString(m.MarkColor) }
		case "~tag":
			trm.eval = func(m *Message) bool {
				return rx.MatchString(strings.Join(resolve(m.TagNames, tagNames), " "))
			}
		case "~group":
			trm.eval = func(m *Message) bool {
				return rx.MatchString(strings.Join(resolve(m.GroupNames, groupNames), " "))
			}
		case "~comment":
			trm.eval = func(m *Message) bool { return rx.MatchString(strings.Join(m.Comments, " ")) }
		default: // "~b" and a bare regex
			trm.cost = costBody
			trm.eval = func(m *Message) bool { return rx.MatchString(m.payload()) }
		}
		p.terms = append(p.terms, trm)
	}

	// Cheapest first, so a frame rejected by its opcode never costs a payload read.
	sort.SliceStable(p.terms, func(i, j int) bool { return p.terms[i].cost < p.terms[j].cost })
	return p, nil
}
