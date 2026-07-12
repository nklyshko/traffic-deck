package tlsdecrypt

// Conn passively decrypts one TLS 1.2 or 1.3 connection from its two directional record
// streams, fed incrementally. It parses the cleartext ClientHello (client_random + SNI)
// and ServerHello (negotiated version + cipher suite), then decrypts application_data
// records using key material from the key-log, delivering application plaintext via
// onApp. The negotiated version (from the ServerHello) selects the record layer.

import (
	"bytes"
	"fmt"
)

const (
	recHeaderLen   = 5
	ctHandshake    = 22
	ctChangeCipher = 20
	ctAlert        = 21
	ctAppData      = 23
)

// helloRetryRequestRandom is the fixed ServerHello.random that marks a message as a
// HelloRetryRequest rather than a real ServerHello (RFC 8446 §4.1.3).
var helloRetryRequestRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// IsHelloRetryRandom reports whether a 32-byte ServerHello.random is the special value that
// distinguishes a HelloRetryRequest from a real ServerHello (RFC 8446 §4.1.3). Shared with
// the QUIC decoder, which sees the same TLS 1.3 handshake messages.
func IsHelloRetryRandom(random []byte) bool {
	return bytes.Equal(random, helloRetryRequestRandom)
}

// Negotiated protocol versions (ProtocolVersion on the wire).
const (
	vSSL30 = 0x0300
	vTLS10 = 0x0301
	vTLS11 = 0x0302
	vTLS12 = 0x0303
	vTLS13 = 0x0304
)

// isLegacyTLS reports whether a negotiated version uses the SSL 3.0 / TLS 1.0–1.2 record
// layer (cleartext handshake → ChangeCipherSpec → MAC/AEAD records), handled by handle12.
func isLegacyTLS(v uint16) bool {
	return v == vSSL30 || v == vTLS10 || v == vTLS11 || v == vTLS12
}

// dirState is one direction's record buffer + decryptor.
type dirState struct {
	label     string           // key-log label for this direction's app traffic secret (TLS 1.3)
	buf       []byte           // un-parsed record bytes
	dec       *recordDecryptor // TLS 1.3
	dec12     *tls12Decryptor  // TLS 1.2
	encrypted bool             // TLS 1.2: this direction's ChangeCipherSpec has been seen
}

type Conn struct {
	keylog *Keylog
	onApp  func(fromClient bool, data []byte)

	version      uint16 // negotiated version once the ServerHello is seen (0 until then)
	clientRandom []byte
	serverRandom []byte // TLS 1.2 key expansion needs both randoms
	sni          string
	chInfo       *ClientHelloInfo // parsed ClientHello (JA3/JA4 fingerprint), from the first CH
	clientHellos [][]byte         // every ClientHello handshake message (verbatim), in wire order
	hrrSeen      bool             // the server sent a HelloRetryRequest (⇒ a second ClientHello)
	suite        *suite           // TLS 1.3 suite
	suite12      *tls12Suite      // TLS 1.2 AEAD suite
	haveCH       bool
	haveSH       bool
	unsupported  bool   // ServerHello seen but not a supported version/suite
	unsupReason  string // human-readable reason, for diagnostics/logging

	dir [2]*dirState
}

// NewConn returns a decryptor that calls onApp with each decrypted application_data
// record (direction + plaintext), in stream order per direction.
func NewConn(keylog *Keylog, onApp func(fromClient bool, data []byte)) *Conn {
	return &Conn{
		keylog: keylog,
		onApp:  onApp,
		dir: [2]*dirState{
			{label: "CLIENT_TRAFFIC_SECRET_0"},
			{label: "SERVER_TRAFFIC_SECRET_0"},
		},
	}
}

func dirIdx(fromClient bool) int {
	if fromClient {
		return 0
	}
	return 1
}

// SNI returns the ClientHello server name (empty until the ClientHello is seen).
func (c *Conn) SNI() string { return c.sni }

// ClientHello returns the parsed ClientHello fingerprint (JA3/JA4, ALPN, …), or nil until
// the ClientHello is seen / if it couldn't be parsed. The fingerprint is from the first
// ClientHello (the one JA3/JA4 are defined over), even when a HelloRetryRequest prompts a
// second one.
func (c *Conn) ClientHello() *ClientHelloInfo { return c.chInfo }

// ClientHellos returns every ClientHello handshake message seen on the connection, verbatim
// and in wire order. There is more than one only when the server sent a HelloRetryRequest.
func (c *Conn) ClientHellos() [][]byte { return c.clientHellos }

// HRRSeen reports whether the server sent a HelloRetryRequest (RFC 8446 §4.1.4), which makes
// the client resend a second ClientHello on the same connection.
func (c *Conn) HRRSeen() bool { return c.hrrSeen }

// Unsupported reports that the ServerHello negotiated something this decryptor can't
// handle (an unknown version or suite) — the caller should stop and leave the stream to
// the batch tshark pass.
func (c *Conn) Unsupported() bool { return c.unsupported }

// UnsupportedReason returns a short human-readable explanation of why the connection is
// unsupported (empty until Unsupported reports true), for diagnostics/logging.
func (c *Conn) UnsupportedReason() string { return c.unsupReason }

// markUnsupported flags the connection unsupported, keeping the first reason recorded.
func (c *Conn) markUnsupported(reason string) {
	c.unsupported = true
	if c.unsupReason == "" {
		c.unsupReason = reason
	}
}

// versionName renders a negotiated version as a short label for diagnostics.
func versionName(v uint16) string {
	switch v {
	case vSSL30:
		return "SSL 3.0"
	case vTLS10:
		return "TLS 1.0"
	case vTLS11:
		return "TLS 1.1"
	case vTLS12:
		return "TLS 1.2"
	case vTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("version %#04x", v)
}

// Feed appends newly-reassembled record bytes for one direction and decrypts as far as
// it can. Both directions are drained in a loop until neither progresses, because a
// ServerHello (or a freshly-available key-log secret) in one direction can unblock
// application records buffered in the other regardless of arrival order.
func (c *Conn) Feed(fromClient bool, data []byte) {
	c.dir[dirIdx(fromClient)].buf = append(c.dir[dirIdx(fromClient)].buf, data...)
	for c.drain(true) || c.drain(false) {
	}
}

func (c *Conn) ready() bool { return c.clientRandom != nil && c.suite != nil }

// drain parses and processes complete records from one direction's buffer, stopping at
// the first record it can't yet handle (an application record before keys are available).
// It returns true if it consumed at least one record (so the caller can re-drain the
// other direction, which the just-parsed record may have unblocked).
func (c *Conn) drain(fromClient bool) bool {
	ds := c.dir[dirIdx(fromClient)]
	progressed := false
	for {
		if len(ds.buf) < recHeaderLen {
			return progressed
		}
		typ := ds.buf[0]
		length := int(ds.buf[3])<<8 | int(ds.buf[4])
		if length == 0 || len(ds.buf) < recHeaderLen+length {
			return progressed // incomplete record (or empty) — wait for more bytes
		}
		header := ds.buf[:recHeaderLen]
		frag := ds.buf[recHeaderLen : recHeaderLen+length]

		// handle* return false when the record can't be processed yet (keys/ServerHello
		// not available); leave it buffered and retry on a later Feed.
		var consumed bool
		if isLegacyTLS(c.version) {
			consumed = c.handle12(fromClient, ds, typ, header, frag)
		} else {
			// TLS 1.3, or version not yet known (only cleartext handshake matters until
			// the ServerHello sets the version). Unsupported versions (e.g. SSL 3.0) also
			// land here and simply drop through to the batch pass.
			consumed = c.handle13(fromClient, ds, typ, header, frag)
		}
		if !consumed {
			return progressed
		}
		ds.buf = ds.buf[recHeaderLen+length:]
		progressed = true
	}
}

// handle13 processes one TLS 1.3 record (or a pre-ServerHello cleartext handshake). It
// returns false if an application record can't be decrypted yet (keys not available).
func (c *Conn) handle13(fromClient bool, ds *dirState, typ byte, header, frag []byte) bool {
	switch typ {
	case ctHandshake: // cleartext ClientHello / ServerHello
		c.parseHandshake(fromClient, frag)
	case ctChangeCipher, ctAlert:
		// legacy ChangeCipherSpec / cleartext alert — ignore
	case ctAppData:
		if !c.ready() {
			return false // ServerHello not seen yet; retry on a later Feed
		}
		if !c.unsupported {
			if ds.dec == nil {
				secret, ok := c.keylog.Get(ds.label, c.clientRandom)
				if !ok {
					return false // secret not in the key-log yet; retry later
				}
				dec, err := newRecordDecryptor(c.suite, secret)
				if err != nil {
					c.markUnsupported(fmt.Sprintf("%s key setup failed: %v", versionName(c.version), err))
				} else {
					ds.dec = dec
				}
			}
			if ds.dec != nil {
				// On failure the record was a handshake-phase record under a
				// different key; skip it (open didn't advance the sequence number).
				if plain, ctype, ok := ds.dec.open(header, frag); ok {
					c.handleInner(fromClient, ds, ctype, plain)
				}
			}
		}
	}
	return true
}

// handle12 processes one TLS 1.2 record. Before this direction's ChangeCipherSpec the
// handshake is cleartext; after it every record (Finished, session tickets, application
// data, alerts) is AEAD-encrypted with a continuous sequence number that starts at 0. It
// returns false if an encrypted record can't be decrypted yet (master secret not in the
// key-log), leaving it buffered to retry.
func (c *Conn) handle12(fromClient bool, ds *dirState, typ byte, header, frag []byte) bool {
	if c.unsupported {
		return true // leave the connection to the batch pass; just consume + ignore
	}
	if !ds.encrypted {
		switch typ {
		case ctHandshake: // cleartext ClientHello / ServerHello / Certificate / ...
			c.parseHandshake(fromClient, frag)
		case ctChangeCipher:
			ds.encrypted = true // records after this point are encrypted
		case ctAlert:
			// cleartext warning/alert — ignore
		}
		return true
	}
	if ds.dec12 == nil {
		if c.suite12 == nil || c.serverRandom == nil || c.clientRandom == nil {
			return false // ServerHello not fully parsed yet (shouldn't happen post-CCS)
		}
		ms, ok := c.keylog.Get("CLIENT_RANDOM", c.clientRandom)
		if !ok {
			return false // master secret not in the key-log yet; retry on a later Feed
		}
		dec, err := newTLS12Decryptor(c.suite12, ms, c.clientRandom, c.serverRandom, fromClient, c.version)
		if err != nil {
			c.markUnsupported(fmt.Sprintf("%s key setup failed: %v", versionName(c.version), err))
			return true
		}
		ds.dec12 = dec
	}
	plain, ok := ds.dec12.open(header, frag)
	if !ok {
		// With the correct key an AEAD/MAC failure shouldn't happen; bail to the batch pass
		// rather than desynchronize the sequence number.
		c.markUnsupported(fmt.Sprintf("%s record decrypt/MAC failed", versionName(c.version)))
		return true
	}
	// The record's content type is the cleartext outer type; only application_data carries
	// payload we care about (Finished / tickets / alerts are decrypted only to keep seq).
	if typ == ctAppData && len(plain) > 0 && c.onApp != nil {
		c.onApp(fromClient, plain)
	}
	return true
}

// handleInner dispatches a decrypted record by its inner content type.
func (c *Conn) handleInner(fromClient bool, ds *dirState, ctype byte, plain []byte) {
	switch ctype {
	case ctAppData:
		if len(plain) > 0 && c.onApp != nil {
			c.onApp(fromClient, plain)
		}
	case ctHandshake:
		// Post-handshake message; rotate keys on key_update (RFC 8446 §4.6.3).
		if len(plain) >= 1 && plain[0] == 24 { // key_update
			_ = ds.dec.keyUpdate()
		}
	}
}

// parseHandshake extracts what we need from a cleartext handshake record: the
// client_random + SNI from ClientHello, the cipher suite from ServerHello.
func (c *Conn) parseHandshake(fromClient bool, frag []byte) {
	// handshake header: msg_type(1) length(3) body
	if len(frag) < 4 {
		return
	}
	msgType := frag[0]
	bodyLen := int(frag[1])<<16 | int(frag[2])<<8 | int(frag[3])
	if len(frag) < 4+bodyLen {
		return // ClientHello/ServerHello fits in one record in practice
	}
	body := frag[4 : 4+bodyLen]

	switch {
	case fromClient && msgType == 1: // ClientHello
		// Keep the ClientHello verbatim (handshake header + body), in wire order. There's
		// more than one only after a HelloRetryRequest; the first is the JA3/JA4 subject.
		c.clientHellos = append(c.clientHellos, append([]byte(nil), frag[:4+bodyLen]...))
		c.parseClientHello(body)
	case !fromClient && msgType == 2: // ServerHello / HelloRetryRequest
		c.parseServerHello(body)
	}
}

func (c *Conn) parseClientHello(b []byte) {
	// Full fingerprint (JA3/JA4, ALPN, …) — best-effort; nil on a malformed hello. JA3/JA4
	// are defined over the first ClientHello, so don't let a post-HRR retry overwrite it.
	if c.chInfo == nil {
		c.chInfo = parseClientHelloInfo(b)
	}
	// legacy_version(2) random(32) session_id<1> cipher_suites<2> compression<1> extensions<2>
	p := 2
	if len(b) < p+32 {
		return
	}
	c.clientRandom = append([]byte(nil), b[p:p+32]...)
	p += 32
	var ok bool
	if p, ok = skipVec8(b, p); !ok { // session_id
		c.haveCH = true
		return
	}
	if p, ok = skipVec16(b, p); !ok { // cipher_suites
		c.haveCH = true
		return
	}
	if p, ok = skipVec8(b, p); !ok { // compression_methods
		c.haveCH = true
		return
	}
	c.sni = parseSNI(b, p)
	c.haveCH = true
}

func (c *Conn) parseServerHello(b []byte) {
	// legacy_version(2) random(32) session_id<1> cipher_suite(2) compression(1) extensions<2>
	if len(b) < 2+32 {
		return
	}
	c.serverRandom = append([]byte(nil), b[2:2+32]...)
	// A HelloRetryRequest is a ServerHello carrying this fixed random; note it (the client
	// will follow with a second ClientHello) but otherwise parse it like a ServerHello.
	if IsHelloRetryRandom(c.serverRandom) {
		c.hrrSeen = true
	}
	legacy := uint16(b[0])<<8 | uint16(b[1])
	p := 2 + 32
	var ok bool
	if p, ok = skipVec8(b, p); !ok { // session_id
		return
	}
	if len(b) < p+3 {
		return
	}
	id := uint16(b[p])<<8 | uint16(b[p+1])
	p += 3 // cipher_suite(2) + compression_method(1)
	c.haveSH = true

	// TLS 1.3 pins legacy_version to 0x0303 and carries the real version in the
	// supported_versions extension; ≤1.2 uses legacy_version directly.
	c.version = legacy
	if v, found := shSupportedVersion(b, p); found {
		c.version = v
	}

	switch c.version {
	case vTLS13:
		if s, found := suiteByID(id); found {
			c.suite = s
		} else {
			c.markUnsupported(fmt.Sprintf("%s cipher %#04x not supported", versionName(c.version), id))
		}
	case vTLS12, vTLS11, vTLS10, vSSL30:
		s, found := tls12SuiteByID(id)
		switch {
		case !found:
			// e.g. 3DES/RC4, which we don't decrypt live (tshark handles them on close).
			c.markUnsupported(fmt.Sprintf("%s cipher %#04x not supported (3DES/RC4?)", versionName(c.version), id))
		case c.version < vTLS12 && !s.cbc:
			c.markUnsupported(fmt.Sprintf("%s with AEAD cipher %#04x (invalid)", versionName(c.version), id))
		default:
			c.suite12 = s
		}
	default:
		c.markUnsupported(versionName(c.version) + " not supported")
	}
}

// shSupportedVersion returns the version selected in a ServerHello supported_versions
// extension (type 43), scanning the extension block that starts at p.
func shSupportedVersion(b []byte, p int) (uint16, bool) {
	if len(b) < p+2 {
		return 0, false
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
			return 0, false
		}
		if etype == 43 && elen >= 2 { // supported_versions
			return uint16(b[p])<<8 | uint16(b[p+1]), true
		}
		p += elen
	}
	return 0, false
}

// parseSNI scans the ClientHello extensions starting at p for the host_name SNI.
func parseSNI(b []byte, p int) string {
	if len(b) < p+2 {
		return ""
	}
	extTotal := int(b[p])<<8 | int(b[p+1])
	p += 2
	end := p + extTotal
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
			// server_name_list<2>, entry: name_type(1) host_name<2>
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

// skipVec8/skipVec16 advance past a length-prefixed vector (1- or 2-byte length).
func skipVec8(b []byte, p int) (int, bool) {
	if len(b) < p+1 {
		return p, false
	}
	n := int(b[p])
	p += 1 + n
	return p, p <= len(b)
}

func skipVec16(b []byte, p int) (int, bool) {
	if len(b) < p+2 {
		return p, false
	}
	n := int(b[p])<<8 | int(b[p+1])
	p += 2 + n
	return p, p <= len(b)
}
