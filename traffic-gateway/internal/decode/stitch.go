package decode

import (
	"encoding/hex"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// stitcher correlates per-frame EK records into request/response flows.
type stitcher struct {
	ds         *Dataset
	byKey      map[string]*Flow   // HTTP/2: "tcpStream:streamID" -> flow
	h1pending  map[string][]*Flow // HTTP/1.1: tcpStream -> requests awaiting a response (FIFO)
	streamFlow map[string]*Flow   // tcpStream -> its HTTP/1.1 flow (the WebSocket Upgrade)

	// Per-TLS-stream metadata captured during the PDML pass, keyed by tcp.stream —
	// used to pick which streams to hand to custom raw-TCP decoders (plan §8). The
	// decoded bytes themselves are pulled via tshark `follow,tls,raw` (see streams.go),
	// since tshark only exposes decrypted undissected payloads through follow.
	// metaMu guards it because the live custom-decode poller reads it concurrently
	// with the PDML loop's addPacket writes.
	metaMu     sync.Mutex
	streamMeta map[string]*tlsStream

	// onChange, if set, fires after each flow is created (isNew=true) or updated.
	onChange func(f *Flow, isNew bool)
	// onMessage, if set, fires for each WebSocket frame as it's decoded (live path).
	onMessage func(m *WsMessage)
}

// tlsStream is the per-connection metadata captured from the ClientHello.
type tlsStream struct {
	tlsStreamIdx string // tls.stream index (the id `follow,tls,raw` uses)
	sni          string
	clientAddr   string // client ip:port
	serverHost   string // server ip
	serverPort   string
}

func newStitcher(ds *Dataset, onChange func(*Flow, bool)) *stitcher {
	return &stitcher{
		ds:         ds,
		byKey:      map[string]*Flow{},
		h1pending:  map[string][]*Flow{},
		streamFlow: map[string]*Flow{},
		streamMeta: map[string]*tlsStream{},
		onChange:   onChange,
	}
}

// addPacket records each TLS stream's ClientHello SNI + tls.stream index + endpoints,
// so decodeCustomStreams can decide which streams to decrypt-and-decode.
func (s *stitcher) addPacket(l layers) {
	tcp := l.first("tcp.stream")
	if tcp == "" {
		return
	}
	sni := l.first("tls.handshake.extensions_server_name")
	if sni == "" {
		return // only ClientHello packets carry the metadata we need
	}
	s.metaMu.Lock()
	s.streamMeta[tcp] = &tlsStream{
		tlsStreamIdx: l.first("tls.stream"),
		sni:          sni,
		clientAddr:   addr(l.first("ip.src"), l.first("ipv6.src"), l.first("tcp.srcport")),
		serverHost:   firstNonEmpty(l.first("ip.dst"), l.first("ipv6.dst")),
		serverPort:   l.first("tcp.dstport"),
	}
	s.metaMu.Unlock()
}

// snapshotMeta returns a copy of the per-stream metadata map for concurrent readers
// (the live poller). The *tlsStream values are written once in addPacket and not
// mutated after, so sharing the pointers is safe.
func (s *stitcher) snapshotMeta() map[string]*tlsStream {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()
	out := make(map[string]*tlsStream, len(s.streamMeta))
	for k, v := range s.streamMeta {
		out[k] = v
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (s *stitcher) emit(f *Flow, isNew bool) {
	if s.onChange != nil {
		s.onChange(f, isNew)
	}
}

func (s *stitcher) add(l layers) {
	tcp := l.first("tcp.stream")

	if op := l.first("websocket.opcode"); op != "" {
		s.addWebsocket(l, tcp, op)
		return
	}

	// HTTP/3 frames carry a quic.connection.number (merged from the quic layer) and a
	// per-frame http3.frame_streamid; key by (connection, stream) like HTTP/2.
	if conn := l.first("quic.connection.number"); conn != "" && l.first("http3.frame_streamid") != "" {
		s.addHTTP3(l, conn)
		return
	}

	sid := l.first("http2.streamid")

	method := l.first("http2.headers.method")
	if method == "" {
		method = l.first("http.request.method")
	}
	status := l.first("http2.headers.status")
	if status == "" {
		status = l.first("http.response.code")
	}
	isReq := method != ""
	isResp := status != ""
	body, reassembled := bodyBytes(l)
	if !isReq && !isResp && body == nil {
		return // a frame with neither headers nor body data; nothing to do
	}

	if sid != "" {
		key := tcp + ":" + sid
		f := s.byKey[key]
		created := f == nil
		if created {
			f = s.newFlow(l, tcp, sid)
			s.byKey[key] = f
			s.ds.Flows = append(s.ds.Flows, f)
		}
		if isReq {
			s.fillRequest(f, l, method)
		}
		if isResp {
			s.fillResponse(f, l, status)
		}
		if body != nil {
			attachBody(f, l, isReq, isResp, body, reassembled)
		}
		s.emit(f, created)
		return
	}

	// HTTP/1.1: no stream id — pair responses to requests FIFO per TCP stream.
	if isReq {
		f := s.newFlow(l, tcp, "")
		s.fillRequest(f, l, method)
		if body != nil {
			attachBody(f, l, true, false, body, reassembled)
		}
		s.ds.Flows = append(s.ds.Flows, f)
		s.h1pending[tcp] = append(s.h1pending[tcp], f)
		s.streamFlow[tcp] = f // a later WebSocket Upgrade rides this stream
		s.emit(f, true)
		return
	}
	// response or body-only frame on an HTTP/1.1 connection -> oldest pending req.
	var f *Flow
	created := false
	if q := s.h1pending[tcp]; len(q) > 0 {
		f = q[0]
		if isResp {
			s.h1pending[tcp] = q[1:]
		}
	} else {
		f = s.newFlow(l, tcp, "")
		created = true
		s.ds.Flows = append(s.ds.Flows, f)
	}
	if isResp {
		s.fillResponse(f, l, status)
	}
	if body != nil {
		attachBody(f, l, isReq, true, body, reassembled)
	}
	s.emit(f, created)
}

// addWebsocket records one WebSocket frame as a WsMessage on the Upgrade flow that
// owns this TCP stream. Frames whose stream has no known HTTP flow (e.g. the Upgrade
// handshake wasn't captured) are dropped.
func (s *stitcher) addWebsocket(l layers, tcp, opcode string) {
	f := s.streamFlow[tcp]
	if f == nil {
		return
	}
	f.Websocket = true
	f.WsMessageCount++
	src := addr(l.first("ip.src"), l.first("ipv6.src"), l.first("tcp.srcport"))
	msg := &WsMessage{
		ID:           uuid.NewString(),
		FlowID:       f.ID,
		FrameNumber:  parseUint(l.first("frame.number")),
		TSUnixMicros: epochToMicros(l.first("frame.time_epoch")),
		FromClient:   src != "" && src == f.SrcAddr,
		Opcode:       wsOpcodeName(opcode),
		Payload:      wsPayload(l),
	}
	s.ds.Messages = append(s.ds.Messages, msg)
	if s.onMessage != nil {
		s.onMessage(msg)
	}
	s.emit(f, false) // surface the ws flag/count change on the parent flow
}

// wsPayload returns a frame's application payload. With permessage-deflate
// (websocket.pmc=True) websocket.payload holds the still-compressed bytes, which
// render as undecodable binary; tshark inflates text frames into
// websocket.payload.text, so prefer that — making compressed text decode the way
// mitmproxy shows it. Uncompressed frames have no .text and fall back to the raw
// payload. (Compressed *binary* frames aren't inflated here — tshark exposes no
// text for them; that needs Go-side inflate with per-stream context-takeover.)
func wsPayload(l layers) []byte {
	if txt := l.first("websocket.payload.text"); txt != "" {
		return []byte(txt)
	}
	return hexBytes(l.first("websocket.payload"))
}

// addHTTP3 correlates HTTP/3 frames into flows, keyed by QUIC connection + stream id.
// A HEADERS frame sets request (method) or response (status); a DATA frame's http3.data
// appends to the matching side. Mirrors the HTTP/2 path but over QUIC/UDP (§8.6).
func (s *stitcher) addHTTP3(l layers, conn string) {
	sid := l.first("http3.frame_streamid")
	if sid == "" {
		return
	}
	method := l.first("http3.headers.method")
	status := l.first("http3.headers.status")
	body := hexBytes(l.first("http3.data"))
	if method == "" && status == "" && len(body) == 0 {
		return // control/QPACK frame — nothing to record
	}

	key := "quic:" + conn + ":" + sid
	f := s.byKey[key]
	created := f == nil
	if created {
		f = &Flow{
			ID:           uuid.NewString(),
			FrameNumber:  parseUint(l.first("frame.number")),
			TSUnixMicros: epochToMicros(l.first("frame.time_epoch")),
			Protocol:     "HTTP/3",
			TCPStream:    "quic:" + conn, // reuse the column for the QUIC connection id
			H2StreamID:   sid,
			SrcAddr:      addr(l.first("ip.src"), l.first("ipv6.src"), l.first("udp.srcport")),
			DstAddr:      addr(l.first("ip.dst"), l.first("ipv6.dst"), l.first("udp.dstport")),
			TLSDecrypted: true, // decoded h3 means QUIC/TLS was decrypted
		}
		s.byKey[key] = f
		s.ds.Flows = append(s.ds.Flows, f)
	}

	if method != "" {
		f.FrameNumber = parseUint(l.first("frame.number"))
		f.TSUnixMicros = epochToMicros(l.first("frame.time_epoch"))
		f.Method = method
		f.Scheme = l.first("http3.headers.scheme")
		f.Authority = l.first("http3.headers.authority")
		path := l.first("http3.headers.path")
		if i := strings.IndexByte(path, '?'); i >= 0 {
			f.Query = path[i+1:]
			path = path[:i]
		}
		f.Path = path
		f.RequestHeaders = zipHeaders(l.all("http3.header.header.name"), l.all("http3.headers.header.value"))
		f.UserAgent = pickHeader("", f.RequestHeaders, "user-agent")
		if f.ContentType == "" {
			f.ContentType = pickHeader("", f.RequestHeaders, "content-type")
		}
	}
	if status != "" {
		f.Status = uint32(parseUint(status))
		f.ResponseHeaders = zipHeaders(l.all("http3.header.header.name"), l.all("http3.headers.header.value"))
		if ct := pickHeader("", f.ResponseHeaders, "content-type"); ct != "" {
			f.ContentType = ct
		}
	}
	if len(body) > 0 {
		toRequest := method != ""
		if method == "" && status == "" { // DATA-only frame: direction by source
			src := addr(l.first("ip.src"), l.first("ipv6.src"), l.first("udp.srcport"))
			toRequest = src != "" && src == f.SrcAddr
		}
		if toRequest {
			f.RequestBody = append(f.RequestBody, body...)
		} else {
			f.ResponseBody = append(f.ResponseBody, body...)
		}
	}
	s.emit(f, created)
}

// wsOpcodeName maps a WebSocket opcode number (tshark `websocket.opcode` show value)
// to a human name (RFC 6455 §5.2).
func wsOpcodeName(op string) string {
	switch op {
	case "0":
		return "continuation"
	case "1":
		return "text"
	case "2":
		return "binary"
	case "8":
		return "close"
	case "9":
		return "ping"
	case "10":
		return "pong"
	default:
		return "opcode " + op
	}
}

func (s *stitcher) newFlow(l layers, tcp, sid string) *Flow {
	proto := "HTTP/1.1"
	if sid != "" {
		proto = "HTTP/2"
	}
	return &Flow{
		ID:           uuid.NewString(),
		FrameNumber:  parseUint(l.first("frame.number")),
		TSUnixMicros: epochToMicros(l.first("frame.time_epoch")),
		Protocol:     proto,
		TCPStream:    tcp,
		H2StreamID:   sid,
		SrcAddr:      addr(l.first("ip.src"), l.first("ipv6.src"), l.first("tcp.srcport")),
		DstAddr:      addr(l.first("ip.dst"), l.first("ipv6.dst"), l.first("tcp.dstport")),
		// If we can see HTTP inside a TLS stack, the TLS was decrypted (h1 or h2).
		TLSDecrypted: strings.Contains(l.first("frame.protocols"), "tls"),
	}
}

func (s *stitcher) fillRequest(f *Flow, l layers, method string) {
	// Prefer the request frame's timing/number for the flow.
	f.FrameNumber = parseUint(l.first("frame.number"))
	f.TSUnixMicros = epochToMicros(l.first("frame.time_epoch"))
	f.Method = method
	f.Scheme = l.first("http2.headers.scheme")

	authority := l.first("http2.headers.authority")
	if authority == "" {
		authority = l.first("http.host")
	}
	f.Authority = authority

	path := l.first("http2.headers.path")
	if path == "" {
		path = l.first("http.request.uri")
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		f.Query = path[i+1:]
		path = path[:i]
	}
	f.Path = path

	f.RequestHeaders = headersFor(l, true)
	f.UserAgent = pickHeader(l.first("http.user_agent"), f.RequestHeaders, "user-agent")
	if f.ContentType == "" {
		f.ContentType = pickHeader(l.first("http.content_type"), f.RequestHeaders, "content-type")
	}
}

func (s *stitcher) fillResponse(f *Flow, l layers, status string) {
	f.Status = uint32(parseUint(status))
	f.ResponseHeaders = headersFor(l, false)
	// Response content-type wins for the flow's content-type column.
	if ct := pickHeader(l.first("http.content_type"), f.ResponseHeaders, "content-type"); ct != "" {
		f.ContentType = ct
	}
}

// headersFor returns the HTTP headers for the current frame. For HTTP/2 it zips
// http2.header.name/value; for HTTP/1.1 it parses the raw header lines.
func headersFor(l layers, request bool) []Header {
	names := l.all("http2.header.name")
	vals := l.all("http2.header.value")
	if len(names) > 0 {
		return zipHeaders(names, vals)
	}
	field := "http.response.line"
	if request {
		field = "http.request.line"
	}
	var out []Header
	for _, line := range l.all(field) {
		line = strings.TrimRight(line, "\r\n")
		if i := strings.IndexByte(line, ':'); i >= 0 {
			out = append(out, Header{
				Name:  strings.TrimSpace(line[:i]),
				Value: strings.TrimSpace(line[i+1:]),
			})
		}
	}
	return out
}

func zipHeaders(names, vals []string) []Header {
	n := len(names)
	if len(vals) < n {
		n = len(vals)
	}
	out := make([]Header, 0, n)
	for i := 0; i < n; i++ {
		// Keep HTTP/2 pseudo-headers (:method/:authority/:scheme/:path/:status) in
		// their wire order — their ordering is a client fingerprint (compare, §7.5).
		// The dedicated Method/Path/… fields are still populated separately for display.
		out = append(out, Header{Name: names[i], Value: vals[i]})
	}
	return out
}

// pickHeader returns direct if set, else the named header's value (case-insensitive).
func pickHeader(direct string, headers []Header, name string) string {
	if direct != "" {
		return direct
	}
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func addr(ip4, ip6, port string) string {
	ip := ip4
	if ip == "" {
		ip = ip6
	}
	if ip == "" {
		return ""
	}
	if port == "" {
		return ip
	}
	return ip + ":" + port
}

func parseUint(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

// epochToMicros converts a tshark frame.time_epoch ("seconds.fraction") to micros.
func epochToMicros(s string) int64 {
	if s == "" {
		return 0
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return int64(f * 1e6)
}

// bodyBytes extracts a frame's body bytes, preferring the reassembled (complete)
// form over per-frame chunks. Returns (bytes, isReassembled). Full body, no cap —
// large bodies are spilled to files by the store (plan §6.4).
func bodyBytes(l layers) ([]byte, bool) {
	for _, c := range []struct {
		field string
		reass bool
	}{
		{"http2.body.reassembled.data", true},
		{"http.body.reassembled.data", true},
		{"http2.data.data", false},
		{"http.file_data", false},
	} {
		if v := l.first(c.field); v != "" {
			if b := hexBytes(v); b != nil {
				return b, c.reass
			}
		}
	}
	return nil, false
}

// hexBytes decodes tshark's hex byte field (continuous or colon-separated).
func hexBytes(s string) []byte {
	if strings.IndexByte(s, ':') >= 0 {
		s = strings.ReplaceAll(s, ":", "")
	}
	if len(s)%2 == 1 {
		s = s[:len(s)-1]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// attachBody attaches body bytes to the request or response side of f. Direction
// is taken from the frame's role (method/status) or, for body-only HTTP/2 DATA
// frames, from the source address vs the flow's client. The reassembled form
// (complete body) wins over accumulated per-frame chunks.
func attachBody(f *Flow, l layers, isReq, isResp bool, body []byte, reassembled bool) {
	toRequest := isReq
	if !isReq && !isResp {
		src := addr(l.first("ip.src"), l.first("ipv6.src"), l.first("tcp.srcport"))
		toRequest = src != "" && src == f.SrcAddr
	}

	if toRequest {
		if f.reqBodyFinal {
			return
		}
		if reassembled {
			f.RequestBody = body
			f.reqBodyFinal = true
		} else {
			f.RequestBody = append(f.RequestBody, body...)
		}
		return
	}
	if f.respBodyFinal {
		return
	}
	if reassembled {
		f.ResponseBody = body
		f.respBodyFinal = true
	} else {
		f.ResponseBody = append(f.ResponseBody, body...)
	}
}
