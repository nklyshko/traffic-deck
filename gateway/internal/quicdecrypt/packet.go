package quicdecrypt

// QUIC packet + frame + handshake parsing (RFC 9000). Just enough to: split a UDP
// datagram into (possibly coalesced) packets, walk the frames of a decrypted payload,
// reassemble CRYPTO/STREAM data, and pull the client_random + SNI from a ClientHello and
// the cipher suite from a ServerHello.

// readVarint decodes a QUIC variable-length integer (RFC 9000 §16); n is bytes consumed
// (0 if truncated).
func readVarint(b []byte) (val uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	val = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		val = val<<8 | uint64(b[i])
	}
	return val, n
}

type pktKind int

const (
	pktInitial pktKind = iota
	pkt0RTT
	pktHandshake
	pktShort // 1-RTT
	pktOther
)

// longHeader describes one parsed long-header packet within a datagram.
type longHeader struct {
	kind     pktKind
	version  uint32
	dcid     []byte
	scid     []byte
	pnOffset int // packet-number offset within the packet slice
	end      int // end of this packet within the datagram (next coalesced packet starts here)
}

// parseLongHeader parses a long-header packet starting at data[0]. ok is false if the
// header is malformed/truncated. For Retry (no length field) ok is false (skipped).
func parseLongHeader(data []byte) (h longHeader, ok bool) {
	if len(data) < 7 || data[0]&0x80 == 0 {
		return h, false
	}
	h.version = uint32(data[1])<<24 | uint32(data[2])<<16 | uint32(data[3])<<8 | uint32(data[4])
	switch (data[0] & 0x30) >> 4 {
	case 0:
		h.kind = pktInitial
	case 1:
		h.kind = pkt0RTT
	case 2:
		h.kind = pktHandshake
	default:
		return h, false // Retry: no protected payload
	}
	p := 5
	if p >= len(data) {
		return h, false
	}
	dl := int(data[p])
	p++
	if p+dl > len(data) {
		return h, false
	}
	h.dcid = data[p : p+dl]
	p += dl
	if p >= len(data) {
		return h, false
	}
	sl := int(data[p])
	p++
	if p+sl > len(data) {
		return h, false
	}
	h.scid = data[p : p+sl]
	p += sl
	if h.kind == pktInitial { // token
		tl, n := readVarint(data[p:])
		if n == 0 {
			return h, false
		}
		p += n + int(tl)
	}
	length, n := readVarint(data[p:])
	if n == 0 {
		return h, false
	}
	p += n
	h.pnOffset = p
	h.end = p + int(length)
	if h.end > len(data) || h.pnOffset >= h.end {
		return h, false
	}
	return h, true
}

// Frame types we care about (RFC 9000 §19); others are skipped by length.
const (
	frmPadding    = 0x00
	frmPing       = 0x01
	frmCrypto     = 0x06
	frmStreamLo   = 0x08 // 0x08..0x0f: STREAM, low 3 bits are OFF/LEN/FIN flags
	frmStreamHi   = 0x0f
	frmConnClose1 = 0x1c
	frmConnClose2 = 0x1d
)

// cryptoFrame / streamFrame carry the offset+data the reassembler needs.
type cryptoFrame struct {
	offset uint64
	data   []byte
}

type streamFrame struct {
	id     uint64
	offset uint64
	data   []byte
	fin    bool
}

// parseFrames walks a decrypted packet payload, returning CRYPTO and STREAM frames (in
// order). ACK/flow-control/etc. frames are skipped. Returns false on a malformed frame.
func parseFrames(p []byte) (crypto []cryptoFrame, streams []streamFrame, ok bool) {
	i := 0
	for i < len(p) {
		t := p[i]
		i++
		switch {
		case t == frmPadding || t == frmPing:
			// no body
		case t == frmCrypto:
			off, n := readVarint(p[i:])
			if n == 0 {
				return nil, nil, false
			}
			i += n
			ln, n2 := readVarint(p[i:])
			if n2 == 0 {
				return nil, nil, false
			}
			i += n2
			if i+int(ln) > len(p) {
				return nil, nil, false
			}
			crypto = append(crypto, cryptoFrame{off, p[i : i+int(ln)]})
			i += int(ln)
		case t >= frmStreamLo && t <= frmStreamHi:
			id, n := readVarint(p[i:])
			if n == 0 {
				return nil, nil, false
			}
			i += n
			var off uint64
			if t&0x04 != 0 { // OFF bit
				off, n = readVarint(p[i:])
				if n == 0 {
					return nil, nil, false
				}
				i += n
			}
			ln := uint64(len(p) - i)
			if t&0x02 != 0 { // LEN bit
				ln, n = readVarint(p[i:])
				if n == 0 {
					return nil, nil, false
				}
				i += n
			}
			if i+int(ln) > len(p) {
				return nil, nil, false
			}
			streams = append(streams, streamFrame{id, off, p[i : i+int(ln)], t&0x01 != 0})
			i += int(ln)
		case t == frmConnClose1 || t == frmConnClose2:
			return crypto, streams, true // stop at close
		default:
			// Unhandled frame type: we can't know its length, so stop parsing this
			// packet (we've already collected the frames we care about up to here).
			return crypto, streams, true
		}
	}
	return crypto, streams, true
}

// clientHelloInfo / serverHelloInfo are the handshake bits we need.
type clientHelloInfo struct {
	random []byte // 32-byte client_random (the key-log lookup key)
	sni    string
}

// parseClientHello extracts client_random + SNI from a TLS ClientHello handshake message
// (the CRYPTO payload of the client Initial). Returns ok=false if it's not a ClientHello
// or is truncated.
func parseClientHello(msg []byte) (clientHelloInfo, bool) {
	var ci clientHelloInfo
	if len(msg) < 4 || msg[0] != 1 { // handshake type 1 = ClientHello
		return ci, false
	}
	bodyLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	b := msg[4:]
	if len(b) < bodyLen || bodyLen < 2+32 {
		return ci, false
	}
	b = b[:bodyLen]
	p := 2 // legacy_version
	ci.random = b[p : p+32]
	p += 32
	var ok bool
	if p, ok = skipVec(b, p, 1); !ok { // session_id
		return ci, true
	}
	if p, ok = skipVec(b, p, 2); !ok { // cipher_suites
		return ci, true
	}
	if p, ok = skipVec(b, p, 1); !ok { // compression_methods
		return ci, true
	}
	ci.sni = parseSNI(b, p)
	return ci, true
}

// parseServerHello returns the negotiated cipher-suite id from a ServerHello.
func parseServerHello(msg []byte) (uint16, bool) {
	if len(msg) < 4 || msg[0] != 2 { // handshake type 2 = ServerHello
		return 0, false
	}
	bodyLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	b := msg[4:]
	if len(b) < bodyLen {
		return 0, false
	}
	b = b[:bodyLen]
	p := 2 + 32 // legacy_version + random
	var ok bool
	if p, ok = skipVec(b, p, 1); !ok { // session_id
		return 0, false
	}
	if p+2 > len(b) {
		return 0, false
	}
	return uint16(b[p])<<8 | uint16(b[p+1]), true
}

// skipVec advances past a vector with a `lenBytes`-byte length prefix.
func skipVec(b []byte, p, lenBytes int) (int, bool) {
	if p+lenBytes > len(b) {
		return p, false
	}
	n := 0
	for i := 0; i < lenBytes; i++ {
		n = n<<8 | int(b[p+i])
	}
	p += lenBytes + n
	return p, p <= len(b)
}

// parseSNI scans ClientHello extensions from p for the host_name server name.
func parseSNI(b []byte, p int) string {
	if p+2 > len(b) {
		return ""
	}
	end := p + 2 + (int(b[p])<<8 | int(b[p+1]))
	p += 2
	if end > len(b) {
		end = len(b)
	}
	for p+4 <= end {
		etype := int(b[p])<<8 | int(b[p+1])
		elen := int(b[p+2])<<8 | int(b[p+3])
		p += 4
		if p+elen > end {
			return ""
		}
		if etype == 0 { // server_name
			d := b[p : p+elen]
			if len(d) >= 5 && d[2] == 0 {
				nlen := int(d[3])<<8 | int(d[4])
				if 5+nlen <= len(d) {
					return string(d[5 : 5+nlen])
				}
			}
			return ""
		}
		p += elen
	}
	return ""
}
