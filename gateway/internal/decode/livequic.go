package decode

// Live HTTP/3-over-QUIC decode, fully in-process. internal/quicdecrypt turns a
// connection's UDP datagrams into reassembled QUIC streams (decrypting Initial with the
// version-derived keys and 1-RTT with the key-log secrets); here we parse the HTTP/3
// frame layer on each client-initiated bidirectional (request) stream, QPACK-decode the
// HEADERS, and emit a Flow per request/response — like the H1/H2 live paths. The batch
// tshark pass on close stays authoritative (and covers QPACK dynamic-table headers, which
// the quic-go/qpack decoder doesn't support live).

import (
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/quic-go/qpack"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/quicdecrypt"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

// HTTP/3 frame types (RFC 9114 §7.2) we handle; others are skipped by length.
const (
	h3FrameData    = 0x00
	h3FrameHeaders = 0x01
)

// quicSession decodes one QUIC connection's HTTP/3 into Flows.
type quicSession struct {
	onFlow                             func(*Flow, bool)
	conn                               *quicdecrypt.Conn
	serverHost, serverPort, clientAddr string

	mu          sync.Mutex
	streams     map[uint64]*h3Stream
	loggedUnsup bool // logged the unsupported-suite diagnostic once
	loggedQPACK bool // logged the QPACK-dynamic-table diagnostic once
}

// h3Stream is one request stream: buffered bytes + parser state per direction, and the
// Flow the exchange maps to.
type h3Stream struct {
	buf  [2][]byte // accumulated HTTP/3 bytes per direction (0=client, 1=server)
	flow *Flow
}

func newQUICSession(keylog *tlsdecrypt.Keylog, onFlow func(*Flow, bool), serverHost, serverPort, clientAddr string) *quicSession {
	s := &quicSession{
		onFlow: onFlow, serverHost: serverHost, serverPort: serverPort, clientAddr: clientAddr,
		streams: map[uint64]*h3Stream{},
	}
	s.conn = quicdecrypt.NewConn(keylog, s.onStream)
	return s
}

func (s *quicSession) feed(fromClient bool, datagram []byte) {
	s.conn.Feed(fromClient, datagram)
	if !s.loggedUnsup && s.conn.Unsupported() {
		log.Printf("live decode: not decoding HTTP/3 %s (%s) live: %s — deferred to batch pass on close",
			hostLabel(s.conn.SNI, s.serverHost), s.serverHost, s.conn.UnsupportedReason())
		s.loggedUnsup = true
	}
}

// onStream receives in-order bytes for a QUIC stream. Only client-initiated bidirectional
// streams (id&0x03==0) carry HTTP/3 requests/responses; the rest (control, QPACK, push)
// are ignored. Frames may span calls, so we buffer per direction and parse what's whole.
func (s *quicSession) onStream(streamID uint64, fromClient bool, data []byte) {
	if streamID&0x03 != 0 {
		return // not a client bidirectional request stream
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.streams[streamID]
	if st == nil {
		st = &h3Stream{flow: s.newFlow(streamID)}
		s.streams[streamID] = st
	}
	d := 0
	if !fromClient {
		d = 1
	}
	st.buf[d] = append(st.buf[d], data...)
	st.buf[d] = s.parseFrames(st, fromClient, st.buf[d])
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

func (s *quicSession) onHeaders(st *h3Stream, fromClient bool, payload []byte) {
	dec := qpack.NewDecoder(nil)
	fields, err := dec.DecodeFull(payload)
	if err != nil {
		// QPACK dynamic-table reference (unsupported live) or partial — leave to batch.
		if !s.loggedQPACK {
			log.Printf("live decode: HTTP/3 %s (%s): QPACK dynamic-table HEADERS not decodable live — deferred to batch pass on close",
				hostLabel(s.conn.SNI, s.serverHost), s.serverHost)
			s.loggedQPACK = true
		}
		return
	}
	f := st.flow
	if fromClient {
		for _, hf := range fields {
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
				if !strings.HasPrefix(hf.Name, ":") {
					f.RequestHeaders = append(f.RequestHeaders, Header{Name: hf.Name, Value: hf.Value})
					if strings.EqualFold(hf.Name, "user-agent") {
						f.UserAgent = hf.Value
					}
				}
			}
		}
	} else {
		for _, hf := range fields {
			if hf.Name == ":status" {
				if code, e := strconv.Atoi(hf.Value); e == nil {
					f.Status = uint32(code)
				}
			} else if !strings.HasPrefix(hf.Name, ":") {
				f.ResponseHeaders = append(f.ResponseHeaders, Header{Name: hf.Name, Value: hf.Value})
				if strings.EqualFold(hf.Name, "content-type") {
					f.ContentType = hf.Value
				}
			}
		}
	}
	s.emit(st)
}

func (s *quicSession) onData(st *h3Stream, fromClient bool, payload []byte) {
	f := st.flow
	if fromClient {
		f.RequestBody = appendCapped(f.RequestBody, payload)
		f.RequestBytes = uint64(len(f.RequestBody))
	} else {
		f.ResponseBody = appendCapped(f.ResponseBody, payload)
	}
	s.emit(st)
}

func (s *quicSession) emit(st *h3Stream) {
	first := !st.flow.emitted
	st.flow.emitted = true
	s.onFlow(st.flow, first)
}

func (s *quicSession) newFlow(streamID uint64) *Flow {
	host := s.conn.SNI
	if host == "" {
		host = s.serverHost
	}
	return &Flow{
		ID:           uuid.NewString(),
		TSUnixMicros: time.Now().UnixMicro(),
		Protocol:     "HTTP/3",
		Scheme:       "https",
		Authority:    host,
		SrcAddr:      s.clientAddr,
		DstAddr:      addr(s.serverHost, "", s.serverPort),
		TLSDecrypted: true,
		H2StreamID:   strconv.FormatUint(streamID, 10),
	}
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
