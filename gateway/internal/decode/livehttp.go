package decode

// In-process live HTTP/1.1 decode over a TLS-decrypted connection. tshark can't decrypt
// a live capture whose key-log is still growing (it reads the key-log once, at the first
// TLS record, and never reloads), so the live path parses the bytes the in-process TLS
// layer (internal/tlsdecrypt) hands us, using the stdlib HTTP parsers, and emits Flow
// events in real time. Its flows are authoritative: no batch pass re-decodes a live
// capture on close (ADR-0009).

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nklyshko/traffic-deck/gateway/decoders"
)

// byteStream is an unbounded buffer whose Write never blocks and whose Read blocks until
// data or Close. The single reassembly loop Writes into it, so a stalled HTTP parse on
// one connection can't block decoding of the others (which a plain io.Pipe would).
//
// Each write carries the capture time of the packet the bytes came from, and LastTS reports
// the time of the most recently read byte. That is how the async parser recovers real
// request/response timing: measuring wall-clock across ReadRequest/ReadResponse gives ~0 when
// the bytes are already buffered (which they usually are — the packets, and often the whole
// exchange, arrive before the parser goroutine runs), so duration must come from packet time.
type byteStream struct {
	mu     sync.Mutex
	cond   *sync.Cond
	chunks []tsChunk
	off    int // read offset into chunks[0]
	closed bool
	lastTS time.Time // capture time of the most recently read byte
}

// tsChunk is one write's bytes with the capture time of the packet they came from.
type tsChunk struct {
	data []byte
	ts   time.Time
}

func newByteStream() *byteStream {
	b := &byteStream{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// WriteTS appends bytes captured at ts. A zero ts (bytes with no known capture time) leaves
// LastTS untouched, so a caller with real timestamps elsewhere still reports those.
func (b *byteStream) WriteTS(p []byte, ts time.Time) (int, error) {
	b.mu.Lock()
	b.chunks = append(b.chunks, tsChunk{append([]byte(nil), p...), ts})
	b.mu.Unlock()
	b.cond.Signal()
	return len(p), nil
}

// Write appends bytes with no capture time (used where timing doesn't matter).
func (b *byteStream) Write(p []byte) (int, error) { return b.WriteTS(p, time.Time{}) }

func (b *byteStream) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.chunks) == 0 && !b.closed {
		b.cond.Wait()
	}
	if len(b.chunks) == 0 && b.closed {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && len(b.chunks) > 0 {
		c := b.chunks[0]
		m := copy(p[n:], c.data[b.off:])
		n += m
		b.off += m
		if !c.ts.IsZero() {
			b.lastTS = c.ts
		}
		if b.off >= len(c.data) {
			b.chunks = b.chunks[1:]
			b.off = 0
		}
	}
	return n, nil
}

// LastTS is the capture time of the most recently read byte (zero until the first timed
// read). The parser reads it right after decoding a request/response to time that message.
func (b *byteStream) LastTS() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastTS
}

func (b *byteStream) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.cond.Broadcast()
	return nil
}

// tsMicros is the capture time in unix micros, falling back to wall-clock when unknown
// (bytes fed without a packet time — e.g. a unit test, or the rare untimed path).
func tsMicros(t time.Time) int64 {
	if t.IsZero() {
		return time.Now().UnixMicro()
	}
	return t.UnixMicro()
}

// httpStream decodes one TLS-decrypted connection as HTTP/1.1. A single goroutine reads
// a request from the client→server bytes then its response from the server→client bytes,
// in lockstep — HTTP/1.1 is strictly request→response on a kept-alive connection (no
// pipelining in practice), so this pairs them without a cross-goroutine race and lets
// ReadResponse use the request (HEAD/204/CONNECT have no body). Each exchange emits a
// Flow via onFlow: added when the request is seen, updated when the response completes.
type httpStream struct {
	owner  *tcpStream
	onFlow func(*Flow, bool)
	onMsg  func(*Message)
	req    *byteStream
	resp   *byteStream
	wsMu   sync.Mutex // guards the upgraded flow across the two WebSocket reader goroutines
}

func newHTTPStream(owner *tcpStream) *httpStream {
	h := &httpStream{
		owner:  owner,
		onFlow: owner.lt.onFlow,
		onMsg:  owner.lt.onMsg,
		req:    newByteStream(),
		resp:   newByteStream(),
	}
	owner.lt.goParse(h.run)
	return h
}

func (h *httpStream) feed(fromClient bool, data []byte) {
	ts := h.owner.curTS // capture time of the packet these bytes came from
	if fromClient {
		_, _ = h.req.WriteTS(data, ts)
	} else {
		_, _ = h.resp.WriteTS(data, ts)
	}
}

// close signals end-of-stream; run() finishes any buffered exchange, then exits on EOF.
// Not waited on (called from the reassembly loop).
func (h *httpStream) close() {
	h.req.Close()
	h.resp.Close()
}

func (h *httpStream) run() {
	reqBr := bufio.NewReader(h.req)
	respBr := bufio.NewReader(h.resp)
	for {
		req, err := http.ReadRequest(reqBr)
		if err != nil {
			return
		}
		reqBody := readBody(req.Body)
		f := h.owner.newHTTPFlow()
		// Time the request from the packet that carried its last byte, not wall-clock at
		// parse time — the parser reads already-buffered bytes, so wall-clock is meaningless.
		f.TSUnixMicros = tsMicros(h.req.LastTS())
		f.Method = req.Method
		if req.Host != "" {
			f.Authority = req.Host
		}
		f.Path = req.URL.Path
		f.Query = req.URL.RawQuery
		f.RequestHeaders = headersOf(req.Header)
		f.UserAgent = req.Header.Get("User-Agent")
		f.RequestBody = reqBody
		f.RequestBytes = uint64(len(reqBody))
		h.onFlow(f, true)

		resp, err := http.ReadResponse(respBr, req)
		if err != nil {
			// Request seen but no parseable response. A TCP reset explains the failure;
			// a clean close / capture end leaves it blank (may just be pending). Either
			// way this connection has nothing more to say about the flow.
			if h.owner.reset.Load() {
				f.Error = "connection reset (TCP RST)"
			}
			f.BodyDone = true
			h.onFlow(f, false)
			return
		}
		f.Status = uint32(resp.StatusCode)
		f.ResponseHeaders = headersOf(resp.Header)
		f.ContentType = resp.Header.Get("Content-Type")
		// Response time is the packet that carried the response's last-read byte, so the
		// duration is the real request→response latency from the capture, not decode timing.
		f.DurationMicros = uint64(max(tsMicros(h.resp.LastTS())-f.TSUnixMicros, 0))

		if isWSUpgrade(resp) {
			// The connection is now WebSocket; the "body" is RFC 6455 frames. Don't read
			// resp.Body (it would consume the frames). Mark the flow and hand both
			// directions (whatever the bufio readers buffered, then the byte streams) to
			// the frame parsers. HTTP/1.1 can't carry more requests after the upgrade.
			f.Websocket = true
			h.onFlow(f, false)
			h.startWebSocket(f, reqBr, respBr)
			return
		}

		wire := &wireBody{ReadCloser: resp.Body}
		resp.Body = wire
		var cut bool
		f.ResponseBody, f.ResponseBodyEncoding, cut = readRespBody(resp)
		if cut {
			noteBodyCut(f, "response")
		}
		if wire.err != nil {
			// The connection ended before the framing (Content-Length or chunked) said the
			// body did — e.g. Chrome dropping a media range read. Without this the flow reads
			// as a whole 200/206 holding part of a body.
			why := "connection closed"
			if h.owner.reset.Load() {
				why = "connection reset (TCP RST)"
			}
			f.Error = fmt.Sprintf("HTTP/1.1 %s mid-body after %s — response cut short",
				why, cutBytes(wire.n, resp.ContentLength))
		}
		f.BodyDone = true // the parser read the whole response before reporting it
		h.onFlow(f, false)
	}
}

// parseConnect reads a buffered CONNECT request header, returning the tunnel target
// (host:port), the request headers, and the User-Agent. Empty target on a parse failure.
func parseConnect(head []byte) (target string, headers []Header, ua string) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
	if err != nil {
		return "", nil, ""
	}
	target = req.Host // for CONNECT this is the authority-form target, e.g. "web.max.ru:443"
	if target == "" {
		target = req.RequestURI
	}
	return target, headersOf(req.Header), req.Header.Get("User-Agent")
}

func isWSUpgrade(resp *http.Response) bool {
	return resp.StatusCode == http.StatusSwitchingProtocols &&
		strings.EqualFold(resp.Header.Get("Upgrade"), "websocket")
}

// startWebSocket reads RFC 6455 frames from both directions of the upgraded connection,
// emitting a Message per frame and refreshing the flow's frame count. The two
// goroutines share the flow under wsMu; they exit when close() shuts the byte streams.
//
// If a registered WebSocket binary decoder claims this Upgrade (by host/path/SNI), its
// binary frames are reframed into protocol messages — the live counterpart of the batch
// stitcher's decodeWSBinary. Text/ping/pong/close and unclaimed connections pass through
// as raw frames.
func (h *httpStream) startWebSocket(f *Flow, reqBr, respBr *bufio.Reader) {
	var wsSess decoders.Session
	if m := decoders.MatchWS(decoders.WSMeta{Host: f.Authority, Path: f.Path, SNI: h.owner.conn.SNI()}); len(m) > 0 {
		wsSess = m[0].NewSession()
	}

	emitMsg := func(opcode string, fromClient bool, payload, raw []byte, fields map[string]string) {
		f.MessageCount++
		h.onMsg(&Message{
			ID:           uuid.NewString(),
			FlowID:       f.ID,
			TSUnixMicros: time.Now().UnixMicro(),
			FromClient:   fromClient,
			Opcode:       opcode,
			Payload:      payload,
			Raw:          raw,
			Metadata:     fields,
		})
	}
	emit := func(opcode string, fromClient bool, payload []byte) {
		h.wsMu.Lock()
		defer h.wsMu.Unlock()
		if opcode == "binary" && wsSess != nil {
			// Reframe the binary payload through the custom decoder (buffering partials),
			// carrying the raw frame bytes so the original remains queryable.
			for _, fr := range wsSess.Feed(fromClient, payload) {
				// opcode, not the decoder's label: the row keeps the WebSocket frame it
				// came in, and the protocol's own opcode stays in its fields.
				emitMsg(opcode, fr.FromClient, fr.Payload, payload, fr.Fields)
			}
		} else {
			emitMsg(opcode, fromClient, payload, nil, nil)
		}
		h.onFlow(f, false) // refresh the row's ⇅ count
	}
	h.owner.lt.goParse(func() { readWSFrames(reqBr, true, emit) })
	h.owner.lt.goParse(func() { readWSFrames(respBr, false, emit) })
}

// readBody reads a whole request body, which also leaves the next message on a
// kept-alive connection byte-aligned. (chunked transfer-encoding is undone by the stdlib
// body reader; gzip Content-Encoding is not — see readRespBody.)
func readBody(rc io.ReadCloser) []byte {
	if rc == nil {
		return nil
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	return data
}

// wireBody counts the body bytes the framing delivered and keeps the first error other
// than EOF — io.ErrUnexpectedEOF when the connection ended short of the Content-Length or
// the last chunk. It sits under the Content-Encoding decoder, so a corrupt gzip stream (a
// whole body that fails to inflate) is not mistaken for a cut one.
type wireBody struct {
	io.ReadCloser
	n   int64
	err error
}

func (b *wireBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n += int64(n)
	if err != nil && err != io.EOF && b.err == nil {
		b.err = err
	}
	return n, err
}

// cutBytes says how much of a cut body arrived: "N of M bytes" when the length was
// declared, "N bytes" for a chunked one.
func cutBytes(got, declared int64) string {
	if declared >= 0 {
		return fmt.Sprintf("%d of %d bytes", got, declared)
	}
	return fmt.Sprintf("%d bytes", got)
}

// readRespBody captures the response body, undoing its Content-Encoding so it is
// readable, and always drains the underlying body for keep-alive alignment. It also reports
// the encoding the bytes had on the wire ("" when they arrived plain, or when there are no
// bytes to describe), and whether the decoded body was cut at maxDecodedBytes.
func readRespBody(resp *http.Response) (body []byte, encoding string, cut bool) {
	defer resp.Body.Close()
	enc := normalizeEncoding(resp.Header.Get("Content-Encoding"))
	// Same encodings as the whole-body path (decodeBody), via decoderFor; streaming here,
	// because this one reads a live response rather than bytes already in hand. Only a
	// decoded body is capped: a plain one is no larger than the bytes captured, which is
	// how the HTTP/2 path treats it too.
	var dr io.ReadCloser
	if newReader := decoderFor(enc); newReader != nil {
		if r, err := newReader(resp.Body); err == nil {
			defer r.Close()
			dr = r
		}
	}
	var data []byte
	if dr != nil {
		data, cut, _ = readAllCapped(dr)
	} else {
		data, _ = io.ReadAll(resp.Body)
	}
	_, _ = io.Copy(io.Discard, resp.Body) // drain what a failed decode left unread
	if len(data) == 0 {
		enc = "" // the field describes body bytes; there are none
	}
	return data, enc, cut
}

func headersOf(h http.Header) []Header {
	out := make([]Header, 0, len(h))
	for k, vs := range h {
		for _, v := range vs {
			out = append(out, Header{Name: k, Value: v})
		}
	}
	return out
}

// newHTTPFlow seeds a Flow with this connection's TLS/addressing metadata; the caller
// fills request/response specifics. A cleartext connection has no SNI/TLS, so it is
// http:// and not marked decrypted (the Host header, filled by the caller, is authoritative).
func (s *tcpStream) newHTTPFlow() *Flow {
	if s.httpFlows != nil { // nil on a stream a test built by hand
		s.httpFlows.Add(1)
	}
	scheme, host := "https", s.conn.SNI()
	if s.plaintext {
		scheme, host = "http", ""
	}
	if host == "" {
		host = s.serverHost
	}
	f := &Flow{
		ID: uuid.NewString(),
		// TSUnixMicros is left 0 here and set by the caller from the message's own bytes:
		// run() and the h2 parser run in their own goroutines, so they must not read the
		// packet loop's s.curTS (a data race); they use the byteStream's per-message time.
		Protocol:     "HTTP/1.1",
		Scheme:       scheme,
		Authority:    host,
		SrcAddr:      s.clientAddr,
		DstAddr:      addr(s.serverHost, "", s.serverPort),
		TLSDecrypted: !s.plaintext,
		ConnectionID: s.connID,
		Proxy:        s.proxy, // set once a CONNECT tunnel is established; nil otherwise
	}
	s.applyTLSFingerprint(f)
	return f
}

// applyTLSFingerprint copies the connection's ClientHello fingerprint (JA3/JA4 + the
// readable ClientHello with offered ALPN) onto a decoded flow, when the TLS handshake was
// seen. No-op for a plaintext connection.
func (s *tcpStream) applyTLSFingerprint(f *Flow) {
	ch := s.conn.ClientHello()
	if ch == nil {
		return
	}
	f.JA3, f.JA4 = ch.JA3, ch.JA4
	text := ch.JA3Text
	if len(ch.ALPN) > 0 {
		text += " alpn=" + strings.Join(ch.ALPN, ",")
	}
	f.TLSClientHello = text
	f.ClientHellos = s.conn.ClientHellos()
	f.TLSHRR = s.conn.HRRSeen()
}
