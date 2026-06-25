package decode

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"gitlab.com/nklyshko/traffic-deck/gateway/decoders"
)

// parseProxyAuth extracts credentials from a Proxy-Authorization: Basic header
// (base64 user:pass). Returns empty strings if absent or not decodable.
func parseProxyAuth(headers []Header) (user, pass string) {
	for _, h := range headers {
		if !strings.EqualFold(h.Name, "proxy-authorization") {
			continue
		}
		v := strings.TrimSpace(h.Value)
		if len(v) < 6 || !strings.EqualFold(v[:6], "Basic ") {
			return "", ""
		}
		dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[6:]))
		if err != nil {
			return "", ""
		}
		u, p, _ := strings.Cut(string(dec), ":")
		return u, p
	}
	return "", ""
}

// stitcher correlates per-frame EK records into request/response flows.
type stitcher struct {
	ds         *Dataset
	byKey      map[string]*Flow   // HTTP/2: "tcpStream:streamID" -> flow
	h1pending  map[string][]*Flow // HTTP/1.1: tcpStream -> requests awaiting a response (FIFO)
	streamFlow map[string]*Flow   // tcpStream -> its HTTP/1.1 flow (the WebSocket Upgrade)

	// Per-TLS-stream metadata captured during the PDML pass, keyed by tcp.stream —
	// used to pick which streams to hand to custom raw-TCP decoders. The
	// decoded bytes themselves are pulled via tshark `follow,tls,raw` (see streams.go),
	// since tshark only exposes decrypted undissected payloads through follow.
	streamMeta map[string]*tlsStream

	// proxyByStream records, per tcp.stream, the proxy a connection went through
	// (from a CONNECT or SOCKS handshake); attached to every flow on that stream.
	proxyByStream map[string]*FlowProxy

	// onChange, if set, fires after each flow is created (isNew=true) or updated.
	onChange func(f *Flow, isNew bool)
	// onMessage, if set, fires for each WebSocket frame as it's decoded (live path).
	onMessage func(m *WsMessage)

	// WebSocket binary decoders (e.g. MAX over WebSocket): per Upgrade flow, the
	// matched decoder (nil = none, cached) and its stateful framing session. Binary
	// frames on a matched connection are reframed into protocol messages instead of
	// being stored as raw bytes — the WebSocket analog of the raw-TCP decoder path.
	wsDec  map[string]decoders.WSDecoder
	wsSess map[string]decoders.Session
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
		ds:            ds,
		byKey:         map[string]*Flow{},
		h1pending:     map[string][]*Flow{},
		streamFlow:    map[string]*Flow{},
		streamMeta:    map[string]*tlsStream{},
		proxyByStream: map[string]*FlowProxy{},
		onChange:      onChange,
		wsDec:         map[string]decoders.WSDecoder{},
		wsSess:        map[string]decoders.Session{},
	}
}

// addPacket records per-connection packet-level metadata: each TLS stream's
// ClientHello SNI + tls.stream index (to pick streams for custom decoders), and any
// SOCKS proxy seen on the stream.
func (s *stitcher) addPacket(l layers) {
	tcp := l.first(fTCPStream)
	if tcp == "" {
		return
	}
	if sni := l.first(fTLSSNI); sni != "" {
		s.streamMeta[tcp] = &tlsStream{
			tlsStreamIdx: l.first(fTLSStream),
			sni:          sni,
			clientAddr:   addr(l.first(fIPSrc), l.first(fIP6Src), l.first(fTCPSrcPort)),
			serverHost:   firstNonEmpty(l.first(fIPDst), l.first(fIP6Dst)),
			serverPort:   l.first(fTCPDstPort),
		}
	}
	if l.first(fSocksVersion) != "" {
		s.noteSocksProxy(l, tcp)
	}
}

// noteSocksProxy merges SOCKS proxy details for a stream across its handshake packets.
// The proxy is the connection's server endpoint; client-originated packets (greeting,
// auth, connect) carry it as the destination, so prefer their dst.
func (s *stitcher) noteSocksProxy(l layers, tcp string) {
	p := s.proxyByStream[tcp]
	if p == nil {
		p = &FlowProxy{Type: "socks"}
		s.proxyByStream[tcp] = p
	}
	user, pass := l.first(fSocksUsername), l.first(fSocksPassword)
	if p.Addr == "" || user != "" { // client→proxy packet → dst is the proxy
		p.Addr = addr(l.first(fIPDst), l.first(fIP6Dst), l.first(fTCPDstPort))
	}
	if user != "" {
		p.Username = user
	}
	if pass != "" {
		p.Password = pass
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (s *stitcher) emit(f *Flow, isNew bool) {
	if f.Proxy == nil {
		if p := s.proxyByStream[f.TCPStream]; p != nil {
			f.Proxy = p // attach the connection's proxy to every flow on the stream
		}
	}
	if s.onChange != nil {
		s.onChange(f, isNew)
	}
}

// add dispatches one per-frame PDML record to the handler for its protocol.
func (s *stitcher) add(l layers) {
	tcp := l.first(fTCPStream)
	switch {
	case l.first(fWSOpcode) != "":
		s.addWebsocket(l, tcp, l.first(fWSOpcode))
	case l.first(fQUICConn) != "" && l.first(fH3StreamID) != "":
		s.addHTTP3(l, l.first(fQUICConn))
	case l.first(fH2StreamID) != "":
		s.addHTTP2(l, tcp, l.first(fH2StreamID))
	default:
		s.addHTTP1(l, tcp)
	}
}

// addHTTP2 correlates one HTTP/2 frame into its flow, keyed by TCP stream + stream id.
func (s *stitcher) addHTTP2(l layers, tcp, sid string) {
	method, status := l.first(fH2Method), l.first(fH2Status)
	body, reassembled := bodyBytes(l)
	if method == "" && status == "" && body == nil {
		return // not HEADERS or DATA — nothing to record
	}
	key := tcp + ":" + sid
	f := s.byKey[key]
	created := f == nil
	if created {
		f = s.newFlow(l, tcp, sid)
		s.byKey[key] = f
		s.ds.Flows = append(s.ds.Flows, f)
	}
	if method != "" {
		s.fillRequest(f, l, method)
	}
	if status != "" {
		s.fillResponse(f, l, status)
	}
	if body != nil {
		attachBody(f, l, method != "", status != "", body, reassembled)
	}
	s.emit(f, created)
}

// addHTTP1 correlates one HTTP/1.1 frame. With no stream id, responses pair to requests
// FIFO per TCP stream; the request flow also anchors a later WebSocket Upgrade.
func (s *stitcher) addHTTP1(l layers, tcp string) {
	method, status := l.first(fH1Method), l.first(fH1Status)
	body, reassembled := bodyBytes(l)
	if method == "" && status == "" && body == nil {
		return
	}

	if method != "" {
		f := s.newFlow(l, tcp, "")
		s.fillRequest(f, l, method)
		if method == "CONNECT" {
			// An HTTP proxy tunnel: the connection's peer is the proxy; subsequent
			// (decrypted) flows on this stream inherit it via emit.
			p := &FlowProxy{Addr: f.DstAddr, Type: "http"}
			p.Username, p.Password = parseProxyAuth(f.RequestHeaders)
			s.proxyByStream[tcp] = p
		}
		if body != nil {
			attachBody(f, l, true, false, body, reassembled)
		}
		s.ds.Flows = append(s.ds.Flows, f)
		s.h1pending[tcp] = append(s.h1pending[tcp], f)
		s.streamFlow[tcp] = f // a later WebSocket Upgrade rides this stream
		s.emit(f, true)
		return
	}

	// Response or body-only frame: attach to the oldest pending request on this stream.
	var f *Flow
	created := false
	if q := s.h1pending[tcp]; len(q) > 0 {
		f = q[0]
		if status != "" {
			s.h1pending[tcp] = q[1:]
		}
	} else {
		f = s.newFlow(l, tcp, "")
		created = true
		s.ds.Flows = append(s.ds.Flows, f)
	}
	if status != "" {
		s.fillResponse(f, l, status)
	}
	if body != nil {
		attachBody(f, l, false, true, body, reassembled)
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
	src := addr(l.first(fIPSrc), l.first(fIP6Src), l.first(fTCPSrcPort))
	fromClient := src != "" && src == f.SrcAddr
	frameNum := parseUint(l.first(fFrameNum))
	ts := epochToMicros(l.first(fFrameTime))
	opName := wsOpcodeName(opcode)
	payload := wsPayload(l)

	// A registered WebSocket binary decoder (e.g. MAX) reframes this connection's
	// binary payloads into protocol messages, mirroring the raw-TCP decoder path.
	// Non-binary frames (text/ping/pong/close) and unclaimed connections fall through.
	if opName == "binary" {
		if frames, ok := s.decodeWSBinary(f, fromClient, payload); ok {
			for _, fr := range frames {
				s.emitWsMessage(f, &WsMessage{
					ID:           uuid.NewString(),
					FlowID:       f.ID,
					FrameNumber:  frameNum,
					TSUnixMicros: ts,
					FromClient:   fr.FromClient,
					Opcode:       fr.Opcode,
					Payload:      fr.Payload,
				})
			}
			return // a partial frame buffered with no output is fine — a later frame completes it
		}
	}

	s.emitWsMessage(f, &WsMessage{
		ID:           uuid.NewString(),
		FlowID:       f.ID,
		FrameNumber:  frameNum,
		TSUnixMicros: ts,
		FromClient:   fromClient,
		Opcode:       opName,
		Payload:      payload,
	})
}

// emitWsMessage appends a WebSocket message to the dataset, bumps the parent flow's
// frame count, and fires the live callback + flow update.
func (s *stitcher) emitWsMessage(f *Flow, msg *WsMessage) {
	f.WsMessageCount++
	s.ds.Messages = append(s.ds.Messages, msg)
	if s.onMessage != nil {
		s.onMessage(msg)
	}
	s.emit(f, false) // surface the ws flag/count change on the parent flow
}

// decodeWSBinary frames a binary WebSocket payload through the WS decoder that claims
// this Upgrade flow, returning the completed protocol messages. ok=false means no
// decoder handles the connection (keep the raw binary frame); ok=true with an empty
// slice means the bytes were buffered as a partial frame.
func (s *stitcher) decodeWSBinary(f *Flow, fromClient bool, payload []byte) ([]decoders.Message, bool) {
	dec, seen := s.wsDec[f.ID]
	if !seen {
		if m := decoders.MatchWS(decoders.WSMeta{Host: f.Authority, Path: f.Path, SNI: f.Authority}); len(m) > 0 {
			dec = m[0]
		}
		s.wsDec[f.ID] = dec // cache the choice (may be nil)
	}
	if dec == nil {
		return nil, false
	}
	sess := s.wsSess[f.ID]
	if sess == nil {
		sess = dec.NewSession()
		s.wsSess[f.ID] = sess
	}
	return sess.Feed(fromClient, payload), true
}

// wsPayload returns a frame's application payload. With permessage-deflate
// (websocket.pmc=True) websocket.payload holds the still-compressed bytes, which
// render as undecodable binary; tshark inflates text frames into
// websocket.payload.text, so prefer that — making compressed text decode the way
// mitmproxy shows it. Uncompressed frames have no .text and fall back to the raw
// payload. (Compressed *binary* frames aren't inflated here — tshark exposes no
// text for them; that needs Go-side inflate with per-stream context-takeover.)
func wsPayload(l layers) []byte {
	if txt := l.first(fWSPayloadText); txt != "" {
		return []byte(txt)
	}
	return hexBytes(l.first(fWSPayload))
}

// addHTTP3 correlates HTTP/3 frames into flows, keyed by QUIC connection + stream id.
// A HEADERS frame sets request (method) or response (status); a DATA frame's http3.data
// appends to the matching side. Mirrors the HTTP/2 path but over QUIC/UDP.
func (s *stitcher) addHTTP3(l layers, conn string) {
	sid := l.first(fH3StreamID)
	if sid == "" {
		return
	}
	method := l.first(fH3Method)
	status := l.first(fH3Status)
	body := hexBytes(l.first(fH3Data))
	if method == "" && status == "" && len(body) == 0 {
		return // control/QPACK frame — nothing to record
	}

	key := "quic:" + conn + ":" + sid
	f := s.byKey[key]
	created := f == nil
	if created {
		f = &Flow{
			ID:           uuid.NewString(),
			FrameNumber:  parseUint(l.first(fFrameNum)),
			TSUnixMicros: epochToMicros(l.first(fFrameTime)),
			Protocol:     "HTTP/3",
			TCPStream:    "quic:" + conn, // reuse the column for the QUIC connection id
			H2StreamID:   sid,
			SrcAddr:      addr(l.first(fIPSrc), l.first(fIP6Src), l.first(fUDPSrcPort)),
			DstAddr:      addr(l.first(fIPDst), l.first(fIP6Dst), l.first(fUDPDstPort)),
			TLSDecrypted: true, // decoded h3 means QUIC/TLS was decrypted
		}
		s.byKey[key] = f
		s.ds.Flows = append(s.ds.Flows, f)
	}

	if method != "" {
		f.FrameNumber = parseUint(l.first(fFrameNum))
		f.TSUnixMicros = epochToMicros(l.first(fFrameTime))
		f.Method = method
		f.Scheme = l.first(fH3Scheme)
		f.Authority = l.first(fH3Authority)
		path := l.first(fH3Path)
		if i := strings.IndexByte(path, '?'); i >= 0 {
			f.Query = path[i+1:]
			path = path[:i]
		}
		f.Path = path
		f.RequestHeaders = zipHeaders(l.all(fH3HdrName), l.all(fH3HdrValue))
		f.UserAgent = pickHeader("", f.RequestHeaders, "user-agent")
		if f.ContentType == "" {
			f.ContentType = pickHeader("", f.RequestHeaders, "content-type")
		}
	}
	if status != "" {
		f.Status = uint32(parseUint(status))
		f.ResponseHeaders = zipHeaders(l.all(fH3HdrName), l.all(fH3HdrValue))
		if ct := pickHeader("", f.ResponseHeaders, "content-type"); ct != "" {
			f.ContentType = ct
		}
	}
	if len(body) > 0 {
		toRequest := method != ""
		if method == "" && status == "" { // DATA-only frame: direction by source
			src := addr(l.first(fIPSrc), l.first(fIP6Src), l.first(fUDPSrcPort))
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
		FrameNumber:  parseUint(l.first(fFrameNum)),
		TSUnixMicros: epochToMicros(l.first(fFrameTime)),
		Protocol:     proto,
		TCPStream:    tcp,
		H2StreamID:   sid,
		SrcAddr:      addr(l.first(fIPSrc), l.first(fIP6Src), l.first(fTCPSrcPort)),
		DstAddr:      addr(l.first(fIPDst), l.first(fIP6Dst), l.first(fTCPDstPort)),
		// If we can see HTTP inside a TLS stack, the TLS was decrypted (h1 or h2).
		TLSDecrypted: strings.Contains(l.first(fFrameProto), "tls"),
	}
}

func (s *stitcher) fillRequest(f *Flow, l layers, method string) {
	// Prefer the request frame's timing/number for the flow.
	f.FrameNumber = parseUint(l.first(fFrameNum))
	f.TSUnixMicros = epochToMicros(l.first(fFrameTime))
	f.Method = method
	f.Scheme = l.first(fH2Scheme)

	authority := l.first(fH2Authority)
	if authority == "" {
		authority = l.first(fH1Host)
	}
	f.Authority = authority

	path := l.first(fH2Path)
	if path == "" {
		path = l.first(fH1URI)
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		f.Query = path[i+1:]
		path = path[:i]
	}
	f.Path = path

	f.RequestHeaders = headersFor(l, true)
	f.UserAgent = pickHeader(l.first(fH1UserAgent), f.RequestHeaders, "user-agent")
	if f.ContentType == "" {
		f.ContentType = pickHeader(l.first(fH1ContentType), f.RequestHeaders, "content-type")
	}
}

func (s *stitcher) fillResponse(f *Flow, l layers, status string) {
	f.Status = uint32(parseUint(status))
	f.ResponseHeaders = headersFor(l, false)
	// Response content-type wins for the flow's content-type column.
	if ct := pickHeader(l.first(fH1ContentType), f.ResponseHeaders, "content-type"); ct != "" {
		f.ContentType = ct
	}
}

// headersFor returns the HTTP headers for the current frame. For HTTP/2 it zips
// http2.header.name/value; for HTTP/1.1 it parses the raw header lines.
func headersFor(l layers, request bool) []Header {
	names := l.all(fH2HdrName)
	vals := l.all(fH2HdrValue)
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
		// their wire order — their ordering is a client fingerprint.
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
// large bodies are spilled to files by the store.
func bodyBytes(l layers) ([]byte, bool) {
	for _, c := range []struct {
		field string
		reass bool
	}{
		{fH2BodyReassembled, true},
		{fH1BodyReassembled, true},
		{fH2Data, false},
		{fH1FileData, false},
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
		src := addr(l.first(fIPSrc), l.first(fIP6Src), l.first(fTCPSrcPort))
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
