package decode

import "time"

// UndecodedConn is a connection a packet capture carried that produced no flow: a TLS
// handshake whose key-log secret never arrived, one that did not complete in the capture,
// an unsupported version or suite, bytes no parser recognised, a QUIC connection with no
// secret, or UDP that is not QUIC. On an interface-wide capture most of these belong to
// other programs — which is why they are kept out of the flow list — but some can be the
// captured app under certificate pinning or speaking a protocol nothing decodes, so each
// is indexed: enough to tell them apart (SNI, JA4, volume, time) and to find the bytes in
// capture.pcap again without copying them.
type UndecodedConn struct {
	ConnID    string // the live decoder's connection id ("quic:" or "udp:" prefixed for UDP)
	Transport string // "tcp" or "udp"
	Client    string // host:port that opened it
	Server    string // host:port it went to
	SNI       string
	JA4       string // the ClientHello fingerprint, to compare with the app's own connections
	Reason    string // see the Undecoded* constants
	Detail    string // the decoder's own words, e.g. an unsupported suite's name
	BytesUp   uint64 // payload bytes client→server
	BytesDown uint64 // payload bytes server→client
	FirstTS   int64  // unix micros of its first packet
	LastTS    int64  // unix micros of its last packet
	// PcapOffset is the byte offset of its first packet's record in the capture as the
	// decoder read it — where to start reading it back; negative when unknown (pcapng). A
	// hint, not a promise: a capture rewritten afterwards (a per-process prune) moves
	// packets, so a reader checks the record it finds there.
	PcapOffset int64
}

// Reasons an UndecodedConn carries.
const (
	UndecodedNoKey       = "no_key"               // handshake complete, no key-log secret for it
	UndecodedHandshake   = "handshake_incomplete" // no ServerHello in the capture
	UndecodedUnsupported = "unsupported"          // a TLS/QUIC version or suite the decoder lacks
	UndecodedUnparsed    = "unparsed"             // bytes in hand, but no parser recognised them
	UndecodedNotQUIC     = "udp"                  // UDP that is not QUIC
)

// connTally is what every tracked connection counts about itself for its UndecodedConn,
// should it end without a flow.
type connTally struct {
	offset             int64
	first, last        time.Time
	bytesUp, bytesDown uint64
}

func (t *connTally) start(offset int64, ts time.Time) {
	t.offset, t.first, t.last = offset, ts, ts
}

func (t *connTally) add(fromClient bool, n int, ts time.Time) {
	if fromClient {
		t.bytesUp += uint64(n)
	} else {
		t.bytesDown += uint64(n)
	}
	if ts.After(t.last) {
		t.last = ts
	}
	if t.first.IsZero() {
		t.first = ts
	}
}

func (t *connTally) record(connID, transport, client, server, reason string) *UndecodedConn {
	return &UndecodedConn{
		ConnID: connID, Transport: transport, Client: client, Server: server, Reason: reason,
		BytesUp: t.bytesUp, BytesDown: t.bytesDown,
		FirstTS: tsMicros(t.first), LastTS: tsMicros(t.last), PcapOffset: t.offset,
	}
}

// maxUDPTracked caps the non-QUIC UDP conversations one capture indexes: an interface-wide
// capture of a busy host can see an unbounded number (every DNS query is one), and these
// are the least likely to be the captured app's.
const maxUDPTracked = 20000

// reportUndecoded hands a record to the sink, if there is one (a liveTCP a test built by
// hand has none).
func (f *liveTCP) reportUndecoded(u *UndecodedConn) {
	if f.onUndecoded != nil {
		f.onUndecoded(u)
	}
}
