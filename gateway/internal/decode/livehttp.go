package decode

// In-process live HTTP/1.1 decode over a TLS-decrypted connection. tshark can't decrypt
// a live capture whose key-log is still growing (it reads the key-log once, at the first
// TLS record, and never reloads), so HTTPS flows never appear live via the tshark path —
// only via the batch decode on close. Here we parse the bytes the in-process TLS layer
// (internal/tlsdecrypt) hands us, using the stdlib HTTP parsers, and emit Flow events in
// real time. The batch pass on close stays authoritative (full bodies, HTTP/2/3, WS).

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nklyshko/traffic-deck/gateway/decoders"
)

// maxLiveBody caps body bytes kept per live message; the batch decode on close has the
// full bodies. Live is a preview, so this also bounds memory under heavy traffic. It's a
// process-wide setting (SetUnlimitedLiveBodies) rather than a const so record-live mode —
// which persists the live flows as the authoritative record — can keep full bodies.
var maxLiveBody = 256 << 10

// SetUnlimitedLiveBodies removes the live body cap so the live decoders keep full bodies
// (for record-live mode). Call once at startup, before any decode runs.
func SetUnlimitedLiveBodies() { maxLiveBody = 1 << 62 }

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
	onMsg  func(*WsMessage)
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
		reqBody, reqTruncated := drainBody(req.Body)
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
		f.RequestBodyTruncated = reqTruncated
		f.RequestBytes = uint64(len(reqBody))
		h.onFlow(f, true)

		resp, err := http.ReadResponse(respBr, req)
		if err != nil {
			// Request seen but no parseable response. A TCP reset explains the failure;
			// a clean close / capture end leaves it blank (may just be pending).
			if h.owner.reset.Load() {
				f.Error = "connection reset (TCP RST)"
				h.onFlow(f, false)
			}
			return // no response
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

		f.ResponseBody, f.ResponseBodyTruncated, f.ResponseBodyEncoding = readRespBody(resp)
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
// emitting a WsMessage per frame and refreshing the flow's frame count. The two
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
		f.WsMessageCount++
		h.onMsg(&WsMessage{
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

// drainBody reads up to maxLiveBody bytes, then drains the rest so the next message on a
// kept-alive connection stays byte-aligned. Reports whether that drain threw anything
// away — i.e. whether the returned bytes are a prefix rather than the body. (chunked
// transfer-encoding is undone by the stdlib body reader; gzip Content-Encoding is not —
// see readRespBody.)
func drainBody(rc io.ReadCloser) ([]byte, bool) {
	if rc == nil {
		return nil, false
	}
	defer rc.Close()
	data, _ := io.ReadAll(io.LimitReader(rc, int64(maxLiveBody)))
	dropped, _ := io.Copy(io.Discard, rc)
	return data, dropped > 0
}

// readRespBody captures the response body, undoing a gzip Content-Encoding so the
// preview is readable, and always drains the underlying body for keep-alive alignment.
// It also reports whether the cap cut the body short, and the encoding the bytes had on
// the wire ("" when they arrived plain, or when there are no bytes to describe). The
// overflow is drained through the same (decoded) reader the capture used, so on a gzip
// body the truncation flag describes the decompressed bytes the viewer shows, not the
// compressed ones on the wire.
func readRespBody(resp *http.Response) (body []byte, truncated bool, encoding string) {
	defer resp.Body.Close()
	enc := normalizeEncoding(resp.Header.Get("Content-Encoding"))
	var r io.Reader = resp.Body
	if enc == "gzip" {
		if gz, err := gzip.NewReader(resp.Body); err == nil {
			defer gz.Close()
			r = gz
		}
	}
	data, _ := io.ReadAll(io.LimitReader(r, int64(maxLiveBody)))
	dropped, _ := io.Copy(io.Discard, r)
	_, _ = io.Copy(io.Discard, resp.Body) // drain remaining compressed/raw bytes
	if len(data) == 0 {
		enc = "" // the field describes body bytes; there are none
	}
	return data, dropped > 0, enc
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
		TCPStream:    s.connID,
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
