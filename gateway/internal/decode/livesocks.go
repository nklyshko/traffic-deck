package decode

// SOCKS proxy tunnels in the live decoder, the counterpart of the HTTP CONNECT tunnel in
// livetcp.go. SOCKS4/4a (a bare request + reply) and SOCKS5 (RFC 1928, with the RFC 1929
// username/password subnegotiation) are parsed off the wire; once the proxy grants the
// CONNECT, the connection restarts decoding the tunnelled bytes as a fresh connection to
// the real target, so requests, WebSocket frames and custom protocols inside the tunnel
// decode exactly as they do on a direct connection.
//
// Unlike CONNECT — a real HTTP request/response that gets its own flow — a SOCKS handshake
// is a few binary bytes that carry no request of their own, so it emits no flow. It only
// stamps the proxy onto the connection, and the flows the tunnel carries are what the user
// sees. That matches what the batch tshark pass records for SOCKS (stitcher.noteSocksProxy).

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"strconv"
)

const (
	socksV4 = 4
	socksV5 = 5

	socksCmdConnect = 0x01 // BIND / UDP ASSOCIATE tunnel no stream we could decode here

	socksAuthNone     = 0x00 // SOCKS5 method: no authentication
	socksAuthUserPass = 0x02 // SOCKS5 method: RFC 1929 username/password
	socksNoAcceptable = 0xff // SOCKS5 method selection: none of the offered methods

	socksAddrIPv4   = 0x01 // SOCKS5 ATYP
	socksAddrDomain = 0x03
	socksAddrIPv6   = 0x04

	socksRepSucceeded = 0x00 // SOCKS5 reply code
	socksV4Granted    = 90   // SOCKS4 reply code

	// socksMaxHandshake bounds what an *incomplete* handshake may buffer per direction.
	// Every SOCKS message is small, so more than this with the phase still unparseable
	// means the bytes aren't a handshake — and it stops an unterminated SOCKS4 user id
	// (or a lookalike's byte stream) from buffering without end.
	socksMaxHandshake = 4096
)

// socksPhase is where in the handshake a connection is, in wire order. SOCKS4 has only a
// request/reply, so it starts (and stays) at socksRequest.
type socksPhase int

const (
	socksGreeting socksPhase = iota // SOCKS5: client method list → the proxy's chosen method
	socksAuth                       // SOCKS5: RFC 1929 username/password → its status
	socksRequest                    // the CONNECT request → the proxy's reply
)

// socksHandshake accumulates one connection's handshake across packets. req/resp hold the
// bytes of each direction not yet consumed by a completed phase; whatever is left when the
// proxy grants the CONNECT is the first of the tunnelled traffic.
type socksHandshake struct {
	version  int
	phase    socksPhase
	req      []byte // client→proxy bytes awaiting parse
	resp     []byte // proxy→client bytes awaiting parse
	advanced bool   // a phase has completed — this really is SOCKS, not a lookalike
	username string
	password string
	target   string // host:port the client asked the proxy to reach
}

// socksStep is what one parse attempt concluded.
type socksStep int

const (
	socksNeedMore    socksStep = iota // the phase's bytes haven't all arrived yet
	socksAdvanced                     // phase done, parse the next one
	socksEstablished                  // the proxy granted the CONNECT; the rest is tunnelled
	socksRefused                      // a genuine handshake the proxy didn't grant
	socksNotSocks                     // the bytes only looked like SOCKS — decode normally
)

// looksLikeSocks reports the SOCKS version the client's first bytes open, or 0. It runs
// only on a cleartext connection (a TLS record is recognized first), so the risk is a
// custom binary protocol that happens to start 0x04/0x05 — hence the structural checks
// below rather than a bare version-byte match.
func looksLikeSocks(b []byte) int {
	switch {
	case len(b) >= 2 && b[0] == socksV5:
		// VER, NMETHODS, METHODS — and nothing more: the client cannot send another byte
		// until the proxy picks a method, so a segment carrying trailing bytes (or an empty
		// method list, or 0xff, which is only ever a reply) is some other protocol.
		n := int(b[1])
		if n == 0 || len(b) > 2+n {
			return 0
		}
		for _, m := range b[2:] {
			if m == socksNoAcceptable {
				return 0
			}
		}
		return socksV5
	case len(b) >= 9 && b[0] == socksV4 && b[1] == socksCmdConnect:
		// VN, CD, DSTPORT, DSTIP, USERID… — port 0 is never a CONNECT target.
		if binary.BigEndian.Uint16(b[2:4]) == 0 {
			return 0
		}
		return socksV4
	}
	return 0
}

// newSocksHandshake starts a handshake for the version looksLikeSocks recognized.
func newSocksHandshake(version int) *socksHandshake {
	h := &socksHandshake{version: version}
	if version == socksV4 {
		h.phase = socksRequest // SOCKS4 has no method negotiation
	}
	return h
}

// feedSocks drives the handshake with one direction's bytes and acts on the outcome:
// on success the tunnel is established and decoding restarts underneath it; a refusal
// leaves nothing decodable on the connection; and bytes that turn out not to be SOCKS
// (before any phase completed, so both buffers are still whole) are replayed into the
// normal path, which is what lets a custom binary protocol that merely opened like a
// greeting still reach its decoder.
func (s *tcpStream) feedSocks(fromClient bool, data []byte) {
	h := s.socks
	if fromClient {
		h.req = append(h.req, data...)
	} else {
		h.resp = append(h.resp, data...)
	}
	for {
		switch h.step() {
		case socksNeedMore:
			return
		case socksAdvanced:
			continue
		case socksEstablished:
			s.establishSocks(h)
			return
		case socksRefused:
			log.Printf("live decode: SOCKS%d proxy %s:%s refused the connection%s — nothing to decode",
				h.version, s.serverHost, s.serverPort, socksTargetSuffix(h.target))
			s.socks = nil
			s.dropped = true
			return
		case socksNotSocks:
			req, resp := h.req, h.resp
			s.socks = nil
			s.sniffed = false // re-sniff: route() classifies the connection from scratch
			s.route(true, req)
			s.route(false, resp)
			return
		}
	}
}

func socksTargetSuffix(target string) string {
	if target == "" {
		return ""
	}
	return " to " + target
}

// step parses as much of the current phase as the buffered bytes allow.
func (h *socksHandshake) step() socksStep {
	var st socksStep
	switch {
	case h.version == socksV4:
		st = h.request4()
	case h.phase == socksGreeting:
		st = h.greeting()
	case h.phase == socksAuth:
		st = h.auth()
	default:
		st = h.request5()
	}
	// The cap applies only to a phase that is still incomplete: bytes a phase can consume
	// are parsed first (a client that optimistically pipelines a large request behind its
	// CONNECT is tunnelled, not abandoned), so being over it means these aren't handshake
	// bytes — or are ones we've lost sync with.
	if st == socksNeedMore && (len(h.req) > socksMaxHandshake || len(h.resp) > socksMaxHandshake) {
		return h.abandon()
	}
	if st == socksAdvanced {
		h.advanced = true
	}
	return st
}

// abandon reports how to treat bytes that don't parse: as a lookalike to decode normally
// while no phase has completed (both buffers are still intact, so they can be replayed),
// and otherwise as a handshake we lost sync with — those bytes are gone, so the connection
// can only be dropped.
func (h *socksHandshake) abandon() socksStep {
	if h.advanced {
		return socksRefused
	}
	return socksNotSocks
}

// greeting parses the SOCKS5 method negotiation: the client's offered methods and the
// method the proxy picked.
func (h *socksHandshake) greeting() socksStep {
	if len(h.req) < 2 {
		return socksNeedMore
	}
	n := int(h.req[1])
	if len(h.req) < 2+n || len(h.resp) < 2 {
		return socksNeedMore
	}
	if h.resp[0] != socksV5 {
		return h.abandon()
	}
	method := h.resp[1]
	h.req, h.resp = h.req[2+n:], h.resp[2:]
	switch method {
	case socksAuthNone:
		h.phase = socksRequest
	case socksAuthUserPass:
		h.phase = socksAuth
	default:
		// 0xff (no acceptable methods), GSSAPI, or a private method whose subnegotiation
		// we can't follow — either way the tunnelled bytes are out of reach.
		return socksRefused
	}
	return socksAdvanced
}

// auth parses the RFC 1929 username/password subnegotiation. The credentials are recorded
// even when the proxy rejects them: they are what was seen on the wire.
func (h *socksHandshake) auth() socksStep {
	if len(h.req) < 2 {
		return socksNeedMore
	}
	if h.req[0] != 0x01 { // subnegotiation version, not the SOCKS version
		return socksRefused
	}
	ulen := int(h.req[1])
	if len(h.req) < 3+ulen {
		return socksNeedMore
	}
	plen := int(h.req[2+ulen])
	total := 3 + ulen + plen
	if len(h.req) < total || len(h.resp) < 2 {
		return socksNeedMore
	}
	h.username, h.password = string(h.req[2:2+ulen]), string(h.req[3+ulen:total])
	status := h.resp[1]
	h.req, h.resp = h.req[total:], h.resp[2:]
	if status != 0 {
		return socksRefused
	}
	h.phase = socksRequest
	return socksAdvanced
}

// request5 parses the SOCKS5 CONNECT request and the proxy's reply. The reply repeats the
// request's shape with the proxy's bound address, which we skip past — the target the
// client asked for is what identifies the tunnel.
func (h *socksHandshake) request5() socksStep {
	if len(h.req) < 4 {
		return socksNeedMore
	}
	if h.req[0] != socksV5 {
		return h.abandon()
	}
	target, n, ok := socksAddr(h.req[3:])
	if !ok {
		return h.abandon()
	}
	if n == 0 {
		return socksNeedMore
	}
	if h.req[1] != socksCmdConnect {
		return socksRefused // BIND / UDP ASSOCIATE: no tunnelled stream on this connection
	}
	if len(h.resp) < 4 {
		return socksNeedMore
	}
	if h.resp[0] != socksV5 {
		return h.abandon()
	}
	_, rn, rok := socksAddr(h.resp[3:])
	if !rok {
		return h.abandon()
	}
	if rn == 0 {
		return socksNeedMore
	}
	rep := h.resp[1]
	h.target = target
	h.req, h.resp = h.req[3+n:], h.resp[3+rn:]
	if rep != socksRepSucceeded {
		return socksRefused
	}
	return socksEstablished
}

// request4 parses the SOCKS4 request (VN, CD, DSTPORT, DSTIP, USERID, NUL) and its 8-byte
// reply. A DSTIP of 0.0.0.x with x non-zero is SOCKS4a: the real target is a hostname that
// follows the user id, so the tunnel keeps the name rather than the placeholder address.
func (h *socksHandshake) request4() socksStep {
	const hdr = 8 // VN, CD, DSTPORT(2), DSTIP(4)
	if len(h.req) < hdr+1 {
		return socksNeedMore
	}
	end := bytes.IndexByte(h.req[hdr:], 0)
	if end < 0 {
		return socksNeedMore
	}
	user := string(h.req[hdr : hdr+end])
	n := hdr + end + 1
	host := net.IP(h.req[4:8]).String()
	if bytes.Equal(h.req[4:7], []byte{0, 0, 0}) && h.req[7] != 0 {
		dend := bytes.IndexByte(h.req[n:], 0)
		if dend < 0 {
			return socksNeedMore
		}
		host = string(h.req[n : n+dend])
		n += dend + 1
	}
	if len(h.resp) < hdr {
		return socksNeedMore
	}
	if h.resp[0] != 0x00 { // the reply's VN is 0, not 4
		return h.abandon()
	}
	cd := h.resp[1]
	h.username = user
	h.target = net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(h.req[2:4]))))
	h.req, h.resp = h.req[n:], h.resp[hdr:]
	if cd != socksV4Granted {
		return socksRefused
	}
	return socksEstablished
}

// socksAddr parses a SOCKS5 ATYP-prefixed address plus its 2-byte port, returning the
// host:port and how many bytes it spans. ok is false for an ATYP that isn't SOCKS5's;
// n == 0 with ok means the address hasn't fully arrived.
func socksAddr(b []byte) (string, int, bool) {
	if len(b) < 1 {
		return "", 0, true
	}
	var host string
	var n int
	switch b[0] {
	case socksAddrIPv4:
		if len(b) < 1+net.IPv4len+2 {
			return "", 0, true
		}
		host, n = net.IP(b[1:1+net.IPv4len]).String(), 1+net.IPv4len
	case socksAddrDomain:
		if len(b) < 2 {
			return "", 0, true
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", 0, true
		}
		host, n = string(b[2:2+l]), 2+l
	case socksAddrIPv6:
		if len(b) < 1+net.IPv6len+2 {
			return "", 0, true
		}
		host, n = net.IP(b[1:1+net.IPv6len]).String(), 1+net.IPv6len
	default:
		return "", 0, false
	}
	port := binary.BigEndian.Uint16(b[n : n+2])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), n + 2, true
}

// establishSocks switches the connection over to the granted tunnel: the peer we've been
// talking to is the proxy, the target is the real destination, and everything after the
// reply is a fresh connection to it (usually opening with a TLS ClientHello).
func (s *tcpStream) establishSocks(h *socksHandshake) {
	s.proxy = &FlowProxy{
		Addr:     net.JoinHostPort(s.serverHost, s.serverPort),
		Type:     "socks",
		Username: h.username,
		Password: h.password,
	}
	if host, port, err := net.SplitHostPort(h.target); err == nil {
		s.serverHost, s.serverPort = host, port
	}
	leftClient, leftServer := h.req, h.resp
	s.socks = nil
	s.sniffed, s.decided, s.plaintext = false, false, false
	s.preBuf = nil
	s.route(true, leftClient)  // the tunnelled client bytes (typically a TLS ClientHello)
	s.route(false, leftServer) // and any server bytes already past the reply
}
