// Package decoders is the registry + contract for custom (non-HTTP) protocol
// decoders (plan §8). Decoders are compiled-in Go modules under decoders/<name>/
// that self-register via init() — the gateway blank-imports them. Each decoder turns
// a TLS-decrypted (or plaintext) TCP connection's directional byte stream into
// message-shaped records, surfaced like WebSocket frames in the viewer.
package decoders

import "sort"

// StreamMeta identifies a TCP connection so a decoder can decide if it handles it.
type StreamMeta struct {
	TCPStream  string
	ServerHost string // server IP (or resolved host)
	ServerPort string
	SNI        string // TLS ClientHello server name, if any
}

// Turn is one directional chunk of a connection's (decrypted) byte stream, in time
// order. A protocol frame may span multiple turns of the same direction.
type Turn struct {
	FromClient   bool
	Data         []byte
	TSUnixMicros int64
}

// Message is one decoded protocol frame.
type Message struct {
	FromClient   bool
	Opcode       string // short label, e.g. "cmd5/op0x12"
	Summary      string // optional one-line summary
	Payload      []byte // decoded payload (e.g. JSON)
	ContentType  string // payload content type, e.g. "application/json"
	TSUnixMicros int64
}

// Decoder decodes one custom TCP protocol. It is a factory for stateful Sessions so
// that decoding works both in batch (feed all turns at once) and live (feed bytes as
// they arrive over the growing capture, plan §8.2).
type Decoder interface {
	Name() string            // short id, e.g. "max"
	Matches(StreamMeta) bool // does this decoder handle the connection?
	NewSession() Session     // a fresh framer for one connection
}

// Session statefully frames one connection's decrypted directional byte stream. Feed
// is called with newly-arrived bytes for a direction (in arrival order across calls)
// and returns the messages whose frames completed with those bytes; it must buffer a
// partial frame until the rest arrives. A frame stays within one direction.
type Session interface {
	Feed(fromClient bool, data []byte) []Message
}

// DecodeTurns runs a decoder over a full set of turns — the batch path. Equivalent to
// feeding each turn to a fresh session in order.
func DecodeTurns(d Decoder, turns []Turn) []Message {
	s := d.NewSession()
	var out []Message
	for _, t := range turns {
		out = append(out, s.Feed(t.FromClient, t.Data)...)
	}
	return out
}

var registry = map[string]Decoder{}

// Register adds a decoder (call from init()). Last registration of a name wins.
func Register(d Decoder) { registry[d.Name()] = d }

// Match returns the decoders that claim a connection (sorted by name for determinism).
func Match(m StreamMeta) []Decoder {
	var out []Decoder
	for _, d := range registry {
		if d.Matches(m) {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// All returns every registered decoder.
func All() []Decoder {
	out := make([]Decoder, 0, len(registry))
	for _, d := range registry {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
