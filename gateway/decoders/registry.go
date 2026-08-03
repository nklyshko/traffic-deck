// Package decoders is the registry + contract for custom (non-HTTP) protocol
// decoders. Decoders are compiled-in Go modules under decoders/<name>/
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
	Opcode       string // short label, e.g. "Auth" or "op0x12"
	Payload      []byte // decoded payload (e.g. JSON)
	ContentType  string // payload content type, e.g. "application/json"
	TSUnixMicros int64

	// Fields are whatever this protocol's frame header carries that is worth showing
	// beside the payload — a command code, a sequence number, a stream id. They are
	// opaque to everything downstream: the gateway stores them verbatim and viewers show
	// them as optional columns, the same treatment a capture source's flow metadata gets.
	//
	// This is deliberately a map rather than named fields. MAX is one decoder of many and
	// its header is its own; a protocol's framing must not become part of the record every
	// other protocol is carried in. Namespace keys with the decoder's name ("max.cmd") so
	// two decoders in one session cannot collide.
	Fields map[string]string
}

// Decoder decodes one custom TCP protocol. It is a factory for stateful Sessions so
// that decoding works both in batch (feed all turns at once) and live (feed bytes as
// they arrive over the growing capture).
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

// --- WebSocket binary decoders --------------------------------------------
//
// Some protocols (e.g. MAX) that once ran over a raw TLS/TCP stream now tunnel the
// same frames inside WebSocket *binary* messages. A WSDecoder is the WebSocket analog
// of Decoder: it claims a connection by its HTTP Upgrade request (host/path) rather
// than a raw TCP stream, and reuses Session to frame each direction's ordered binary
// payloads into the same message-shaped records. One decoder type can implement both
// Decoder and WSDecoder to handle a protocol over either transport.

// WSMeta identifies a WebSocket connection (its HTTP Upgrade request) so a decoder can
// decide whether it handles the binary frames carried on it.
type WSMeta struct {
	Host string // Upgrade request authority/host
	Path string // Upgrade request path
	SNI  string // TLS ClientHello server name, if any
}

// WSDecoder decodes the binary messages of one WebSocket sub-protocol. Session is fed
// each binary message's payload in arrival order per direction (WebSocket preserves
// message boundaries, but Session still buffers a partial frame split across messages).
type WSDecoder interface {
	Name() string
	MatchesWS(WSMeta) bool // does this decoder handle the WebSocket connection?
	NewSession() Session   // a fresh framer for one connection (shared with the TCP path)
}

var wsRegistry = map[string]WSDecoder{}

// RegisterWS adds a WebSocket binary decoder (call from init()). Last name wins.
func RegisterWS(d WSDecoder) { wsRegistry[d.Name()] = d }

// MatchWS returns the WS decoders that claim a connection (sorted by name).
func MatchWS(m WSMeta) []WSDecoder {
	var out []WSDecoder
	for _, d := range wsRegistry {
		if d.MatchesWS(m) {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// AllWS returns every registered WebSocket binary decoder.
func AllWS() []WSDecoder {
	out := make([]WSDecoder, 0, len(wsRegistry))
	for _, d := range wsRegistry {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
