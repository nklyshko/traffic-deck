package decode

// Live HTTP/3-over-QUIC decode, fully in-process. internal/quicdecrypt turns a
// connection's UDP datagrams into reassembled QUIC streams (decrypting Initial with the
// version-derived keys and 1-RTT with the key-log secrets); here we parse the HTTP/3
// frame layer on each client-initiated bidirectional (request) stream, QPACK-decode the
// HEADERS (with dynamic-table support via internal/qpackdec, fed by the peer's QPACK
// encoder stream), and emit a Flow per request/response — like the H1/H2 live paths.
//
// Unlike TCP there is no assembler calling us back at end-of-capture, so close() is
// driven from LiveTCPDecode's teardown; see it for the ways an HTTP/3 connection can end
// up incomplete.

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nklyshko/traffic-deck/gateway/internal/qpackdec"
	"github.com/nklyshko/traffic-deck/gateway/internal/quicdecrypt"
)

// HTTP/3 frame types (RFC 9114 §7.2) we handle; others are skipped by length.
const (
	h3FrameData    = 0x00
	h3FrameHeaders = 0x01
)

// quicSession decodes one QUIC connection's HTTP/3 into Flows.
type quicSession struct {
	lt                                 *liveTCP
	conn                               *quicdecrypt.Conn
	connID                             string // this connection's id; goes on every flow it carries
	serverHost, serverPort, clientAddr string

	curTS       time.Time // capture time of the datagram being processed (QUIC decode is synchronous)
	mu          sync.Mutex
	streams     map[uint64]*h3Stream
	uni         map[uint64]*uniStream // unidirectional streams (control, QPACK enc/dec, push)
	qpack       [2]*qpackdec.Decoder  // QPACK dynamic tables: [0]=client (requests), [1]=server
	blocked     []blockedSection      // HEADERS awaiting more encoder-stream inserts
	decrypted   bool                  // any stream bytes ever came out — i.e. we had the keys
	loggedUnsup bool                  // logged the unsupported-suite diagnostic once
	loggedQPACK bool                  // logged a QPACK HEADERS decode failure once
	loggedEnc   bool                  // logged a QPACK encoder-stream failure once
	tally       connTally             // for its UndecodedConn, should it need one
}

// uniStream tracks one unidirectional QUIC stream until its type is known, then whether it
// is the peer's QPACK encoder stream (whose inserts drive our dynamic table).
type uniStream struct {
	typeKnown bool
	isEncoder bool
	pending   []byte // bytes buffered while the leading stream-type varint is incomplete
}

// blockedSection is a HEADERS field section that referenced dynamic entries not yet
// received on the encoder stream; retried as the encoder stream advances.
type blockedSection struct {
	st         *h3Stream
	fromClient bool
	payload    []byte
}

// h3Stream is one request stream: buffered bytes + parser state per direction, and the
// Flow the exchange maps to.
type h3Stream struct {
	buf  [2][]byte // accumulated HTTP/3 bytes per direction (0=client, 1=server)
	flow *Flow

	// An encoded response body (respEnc set from the response headers) accumulates here
	// in its wire form, because gzip can only be read from the start; the flow's own
	// ResponseBody holds the decoded bytes. respDecoded is how much of respRaw the last
	// decode covered — see decodeResp for why a stream can't just decode once at the end.
	respEnc     string
	respRaw     []byte
	respDecoded int
}

func newQUICSession(lt *liveTCP, connID, serverHost, serverPort, clientAddr string) *quicSession {
	s := &quicSession{
		lt: lt, connID: connID,
		serverHost: serverHost, serverPort: serverPort, clientAddr: clientAddr,
		streams: map[uint64]*h3Stream{},
		uni:     map[uint64]*uniStream{},
		qpack:   [2]*qpackdec.Decoder{qpackdec.New(), qpackdec.New()},
	}
	s.conn = quicdecrypt.NewConn(lt.keylog, s.onStream)
	s.conn.OnReset = s.onReset
	return s
}

// qdir maps a direction to the dynamic-table / buffer index (0=client, 1=server).
func qdir(fromClient bool) int {
	if fromClient {
		return 0
	}
	return 1
}

// close ends the connection at capture EOF. QUIC has no equivalent of the TCP
// assembler's ReassemblyComplete, so without this the two ways a connection can end up
// silently incomplete would never be reported: HEADERS still blocked on QPACK inserts
// that never arrived (those requests never become flows), and a connection whose
// key-log secrets never showed up (nothing decoded at all).
func (s *quicSession) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Last word on every stream still open: the connection is over, so what each
	// accumulated is all there will ever be (see decodeResp), and its bodies are final.
	for _, st := range s.streams {
		if !st.flow.BodyDone {
			s.end(st)
		}
	}
	if n := len(s.blocked); n > 0 {
		log.Printf("live decode: HTTP/3 %s (%s): %d HEADERS section(s) still blocked on QPACK "+
			"inserts that never arrived — %s",
			hostLabel(s.conn.SNI, s.serverHost), s.serverHost, n, partialFate)
		s.blocked = nil
	}
	// Never decrypted: the ClientHello (and so the SNI we log) rides the Initial packets,
	// which decrypt from the connection id alone — so we can name the host even here.
	if !s.decrypted && !s.conn.Unsupported() {
		log.Printf("live decode: HTTP/3 %s (%s) not decoded live: no QUIC key-log secret "+
			"(or incomplete handshake) — %s",
			hostLabel(s.conn.SNI, s.serverHost), s.serverHost, skippedFate)
		s.undecoded(UndecodedNoKey, "")
	}
	if s.conn.Unsupported() {
		s.undecoded(UndecodedUnsupported, s.conn.UnsupportedReason())
	}
}

// undecoded reports this QUIC connection to the undecoded index. QUIC cannot tell a
// missing secret from a handshake that never finished, so both read as no_key.
func (s *quicSession) undecoded(reason, detail string) {
	u := s.tally.record(s.connID, "udp", s.clientAddr, net.JoinHostPort(s.serverHost, s.serverPort), reason)
	u.Detail, u.SNI = detail, s.conn.SNI
	s.lt.reportUndecoded(u)
}

func (s *quicSession) feed(fromClient bool, datagram []byte, ts time.Time) {
	s.curTS = ts // times the flows this datagram produces (decode is synchronous, so no race)
	s.conn.Feed(fromClient, datagram)
	if !s.loggedUnsup && s.conn.Unsupported() {
		// Nothing on this connection decodes — whole-connection wording applies.
		log.Printf("live decode: not decoding HTTP/3 %s (%s) live: %s — %s",
			hostLabel(s.conn.SNI, s.serverHost), s.serverHost, s.conn.UnsupportedReason(),
			skippedFate)
		s.loggedUnsup = true
	}
}

// onStream receives in-order bytes for a QUIC stream. Client-initiated bidirectional
// streams (id&0x03==0) carry HTTP/3 requests/responses; unidirectional streams (bit 1 set)
// carry control / QPACK / push — we track only the QPACK encoder stream. Frames may span
// calls, so we buffer per direction and parse what's whole. ended marks the stream's FIN:
// on the server's half of a request stream, the response is complete.
func (s *quicSession) onStream(streamID uint64, fromClient bool, data []byte, ended bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decrypted = true // stream bytes at all means the key-log secrets were there
	if streamID&0x02 != 0 {
		s.onUni(streamID, fromClient, data)
		return
	}
	if streamID&0x03 != 0 {
		return // server-initiated bidirectional stream — not an HTTP/3 request
	}
	st := s.streams[streamID]
	if st == nil {
		st = &h3Stream{flow: s.newFlow(streamID)}
		s.streams[streamID] = st
	}
	d := qdir(fromClient)
	st.buf[d] = append(st.buf[d], data...)
	st.buf[d] = s.parseFrames(st, fromClient, st.buf[d])
	if ended && !fromClient && !st.flow.BodyDone {
		s.end(st)
	}
}

// h3NoError is H3_NO_ERROR (RFC 9114 §8.1): a reset that is not a failure.
const h3NoError = 0x100

// h3ErrorNames are the HTTP/3 error codes (RFC 9114 §8.1) a reset can carry.
var h3ErrorNames = map[uint64]string{
	0x100: "H3_NO_ERROR", 0x101: "H3_GENERAL_PROTOCOL_ERROR", 0x102: "H3_INTERNAL_ERROR",
	0x103: "H3_STREAM_CREATION_ERROR", 0x104: "H3_CLOSED_CRITICAL_STREAM",
	0x105: "H3_FRAME_UNEXPECTED", 0x106: "H3_FRAME_ERROR", 0x107: "H3_EXCESSIVE_LOAD",
	0x108: "H3_ID_ERROR", 0x109: "H3_SETTINGS_ERROR", 0x10a: "H3_MISSING_SETTINGS",
	0x10b: "H3_REQUEST_REJECTED", 0x10c: "H3_REQUEST_CANCELLED", 0x10d: "H3_REQUEST_INCOMPLETE",
	0x10e: "H3_MESSAGE_ERROR", 0x10f: "H3_CONNECT_ERROR", 0x110: "H3_VERSION_FALLBACK",
}

// onReset handles a RESET_STREAM. Only the server's matters here: it abandons the
// response, which is how HTTP/3 cancels one (the client asks with STOP_SENDING, the server
// answers with this) — so the response is over, and unless the code says no error, the
// flow says why. A client reset abandons just the request body; the response may still
// come, so it ends nothing.
func (s *quicSession) onReset(streamID uint64, fromClient bool, code uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.streams[streamID]
	if fromClient || st == nil || st.flow.BodyDone {
		return
	}
	if code != h3NoError && st.flow.Error == "" {
		name := h3ErrorNames[code]
		if name == "" {
			name = fmt.Sprintf("0x%x", code)
		}
		st.flow.Error = "HTTP/3 RESET_STREAM: " + name
		if st.flow.Status != 0 {
			st.flow.Error += " — response cut short"
		}
	}
	s.end(st)
}

// end closes a stream's response: decodes what an encoded body accumulated, marks the
// flow's bodies final and reports it. Caller holds mu.
func (s *quicSession) end(st *h3Stream) {
	st.decodeResp(true)
	st.flow.BodyDone = true
	s.emit(st)
}

// onUni handles a unidirectional stream: read the leading stream-type varint, then feed a
// QPACK encoder stream (type 0x02) into the matching direction's dynamic table. Other
// stream types (control 0x00, push 0x01, QPACK decoder 0x03, reserved) are ignored.
func (s *quicSession) onUni(streamID uint64, fromClient bool, data []byte) {
	u := s.uni[streamID]
	if u == nil {
		u = &uniStream{}
		s.uni[streamID] = u
	}
	if !u.typeKnown {
		u.pending = append(u.pending, data...)
		t, n := uvarint(u.pending)
		if n == 0 {
			return // stream-type varint not fully arrived yet
		}
		u.typeKnown = true
		u.isEncoder = t == 0x02 // QPACK encoder stream
		data = u.pending[n:]
		u.pending = nil
	}
	if !u.isEncoder || len(data) == 0 {
		return
	}
	if err := s.qpack[qdir(fromClient)].ReadEncoderStream(data); err != nil {
		// The dynamic table is cumulative, so a bad insert doesn't cost one section: every
		// later HEADERS on this direction that references a dynamic entry fails too. Say so
		// once rather than letting the connection quietly half-decode.
		if !s.loggedEnc {
			log.Printf("live decode: HTTP/3 %s (%s): QPACK encoder stream failed (%v) — "+
				"dynamic-table header decoding is broken for this direction from here on; %s",
				hostLabel(s.conn.SNI, s.serverHost), s.serverHost, err, partialFate)
			s.loggedEnc = true
		}
		return
	}
	s.retryBlocked() // new inserts may unblock buffered HEADERS
}

// parseFrames consumes whole HTTP/3 frames from buf, returning the unconsumed remainder.
func (s *quicSession) parseFrames(st *h3Stream, fromClient bool, buf []byte) []byte {
	i := 0
	for {
		t, n1 := uvarint(buf[i:])
		if n1 == 0 {
			break
		}
		ln, n2 := uvarint(buf[i+n1:])
		if n2 == 0 {
			break
		}
		hdr := n1 + n2
		if i+hdr+int(ln) > len(buf) {
			break // frame not fully arrived yet
		}
		payload := buf[i+hdr : i+hdr+int(ln)]
		switch t {
		case h3FrameHeaders:
			s.onHeaders(st, fromClient, payload)
		case h3FrameData:
			s.onData(st, fromClient, payload)
		}
		i += hdr + int(ln)
	}
	return buf[i:]
}

// onHeaders decodes a HEADERS field section with the direction's QPACK dynamic table. A
// section that references not-yet-inserted dynamic entries is buffered and retried as the
// encoder stream advances (retryBlocked).
func (s *quicSession) onHeaders(st *h3Stream, fromClient bool, payload []byte) {
	fields, blocked, err := s.qpack[qdir(fromClient)].DecodeFieldSection(payload)
	if blocked {
		s.blocked = append(s.blocked, blockedSection{st, fromClient, append([]byte(nil), payload...)})
		return
	}
	if err != nil {
		// One HEADERS section, not the connection: other streams here keep decoding, so this
		// costs individual requests.
		if !s.loggedQPACK {
			log.Printf("live decode: HTTP/3 %s (%s): QPACK HEADERS decode failed (%v) — %s",
				hostLabel(s.conn.SNI, s.serverHost), s.serverHost, err, partialFate)
			s.loggedQPACK = true
		}
		return
	}
	s.applyHeaders(st, fromClient, fields)
}

// retryBlocked re-attempts buffered HEADERS sections after the encoder stream advanced.
func (s *quicSession) retryBlocked() {
	if len(s.blocked) == 0 {
		return
	}
	kept := s.blocked[:0]
	for _, b := range s.blocked {
		fields, blocked, err := s.qpack[qdir(b.fromClient)].DecodeFieldSection(b.payload)
		switch {
		case blocked:
			kept = append(kept, b) // still waiting on more inserts
		case err == nil:
			s.applyHeaders(b.st, b.fromClient, fields)
		}
	}
	s.blocked = kept
}

// applyHeaders folds decoded header fields into the stream's Flow and emits it.
func (s *quicSession) applyHeaders(st *h3Stream, fromClient bool, fields []qpackdec.HeaderField) {
	f := st.flow
	if fromClient {
		for _, hf := range fields {
			// Pseudo-headers are recorded too, in their wire order — that order is a
			// client fingerprint, as on the tshark path (stitch.go zipHeaders). The
			// scalar fields below are for display.
			f.RequestHeaders = append(f.RequestHeaders, Header{Name: hf.Name, Value: hf.Value})
			switch hf.Name {
			case ":method":
				f.Method = hf.Value
			case ":authority":
				f.Authority = hf.Value
			case ":scheme":
				f.Scheme = hf.Value
			case ":path":
				path, query, _ := strings.Cut(hf.Value, "?")
				f.Path, f.Query = path, query
			default:
				if strings.EqualFold(hf.Name, "user-agent") {
					f.UserAgent = hf.Value
				}
			}
		}
	} else {
		for _, hf := range fields {
			f.ResponseHeaders = append(f.ResponseHeaders, Header{Name: hf.Name, Value: hf.Value})
			if hf.Name == ":status" {
				if code, e := strconv.Atoi(hf.Value); e == nil {
					f.Status = uint32(code)
					// Response headers mark completion — record request→response elapsed
					// from datagram capture time, as the H1/H2 live paths now do.
					f.DurationMicros = uint64(max(tsMicros(s.curTS)-f.TSUnixMicros, 0))
				}
			} else if !strings.HasPrefix(hf.Name, ":") {
				if strings.EqualFold(hf.Name, "content-type") {
					f.ContentType = hf.Value
				}
				if strings.EqualFold(hf.Name, "content-encoding") {
					st.setRespEnc(normalizeEncoding(hf.Value))
				}
			}
		}
	}
	s.emit(st)
}

func (s *quicSession) onData(st *h3Stream, fromClient bool, payload []byte) {
	f := st.flow
	switch {
	case fromClient:
		f.RequestBody = append(f.RequestBody, payload...)
		f.RequestBytes = uint64(len(f.RequestBody))
	case st.respEnc == "":
		f.ResponseBody = append(f.ResponseBody, payload...)
	default:
		st.respRaw = append(st.respRaw, payload...)
		st.decodeResp(false)
	}
	s.emit(st)
}

// decodeResp refreshes the flow's plain body from the accumulated wire bytes.
//
// HTTP/2 can decode once, at END_STREAM; QUIC gives this decoder no end-of-stream
// callback, and a capture can stop mid-response anyway, so the flow has to hold the best
// plain bytes available at every emit. Decoding is from the start each time (a gzip
// stream can only be read whole), so during capture it runs on a doubling schedule —
// amortized linear in the body's size rather than quadratic in its DATA frames — and
// `final` forces the last, authoritative pass when the connection ends.
func (st *h3Stream) decodeResp(final bool) {
	if st.respEnc == "" || len(st.respRaw) == 0 {
		return
	}
	if !final && len(st.respRaw) < 2*st.respDecoded {
		return
	}
	st.respDecoded = len(st.respRaw)
	st.flow.ResponseBodyEncoding = st.respEnc
	st.flow.ResponseBody = decodeFlowBody(st.flow, "response", st.respEnc, st.respRaw)
}

// setRespEnc records the response body's wire encoding, once its HEADERS are decoded.
// A QPACK-blocked HEADERS section is applied late (retryBlocked), possibly after DATA
// frames already arrived, so bytes taken as plain in the meantime move back to the wire
// buffer and are decoded from there.
func (st *h3Stream) setRespEnc(enc string) {
	if enc == "" || enc == st.respEnc {
		return
	}
	st.respEnc = enc
	if len(st.respRaw) == 0 && len(st.flow.ResponseBody) > 0 {
		st.respRaw = st.flow.ResponseBody
	}
	st.decodeResp(true)
}

func (s *quicSession) emit(st *h3Stream) {
	first := !st.flow.emitted
	st.flow.emitted = true
	s.lt.onFlow(st.flow, first)
}

func (s *quicSession) newFlow(streamID uint64) *Flow {
	host := s.conn.SNI
	if host == "" {
		host = s.serverHost
	}
	f := &Flow{
		ID:           uuid.NewString(),
		TSUnixMicros: tsMicros(s.curTS), // datagram capture time, not decode wall-clock
		Protocol:     "HTTP/3",
		Scheme:       "https",
		Authority:    host,
		SrcAddr:      s.clientAddr,
		DstAddr:      addr(s.serverHost, "", s.serverPort),
		TLSDecrypted: true,
		TCPStream:    s.connID,
		H2StreamID:   strconv.FormatUint(streamID, 10),
	}
	if ch := s.conn.ClientHello; ch != nil {
		f.JA3, f.JA4 = ch.JA3, ch.JA4
		text := ch.JA3Text
		if len(ch.ALPN) > 0 {
			text += " alpn=" + strings.Join(ch.ALPN, ",")
		}
		f.TLSClientHello = text
		f.ClientHellos = s.conn.ClientHellos
		f.TLSHRR = s.conn.HRRSeen
	}
	return f
}

// uvarint decodes a QUIC variable-length integer; n is 0 if truncated.
func uvarint(b []byte) (val uint64, n int) {
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
