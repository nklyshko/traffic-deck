package decode

// In-process live HTTP/1.1 decode over a TLS-decrypted connection. tshark can't decrypt
// a live capture whose key-log is still growing (it reads the key-log once, at the first
// TLS record, and never reloads), so HTTPS flows never appear live via the tshark path —
// only via the batch decode on close. Here we parse the bytes the in-process TLS layer
// (internal/tlsdecrypt) hands us, using the stdlib HTTP parsers, and emit Flow events in
// real time. The batch pass on close stays authoritative (full bodies, HTTP/2/3, WS).

import (
	"bufio"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"gitlab.com/nklyshko/traffic-deck/gateway/decoders"
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
type byteStream struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	closed bool
}

func newByteStream() *byteStream {
	b := &byteStream{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *byteStream) Write(p []byte) (int, error) {
	b.mu.Lock()
	b.buf = append(b.buf, p...)
	b.mu.Unlock()
	b.cond.Signal()
	return len(p), nil
}

func (b *byteStream) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.buf) == 0 && !b.closed {
		b.cond.Wait()
	}
	if len(b.buf) == 0 && b.closed {
		return 0, io.EOF
	}
	n := copy(p, b.buf)
	b.buf = b.buf[n:]
	return n, nil
}

func (b *byteStream) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.cond.Broadcast()
	return nil
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
	go h.run()
	return h
}

func (h *httpStream) feed(fromClient bool, data []byte) {
	if fromClient {
		_, _ = h.req.Write(data)
	} else {
		_, _ = h.resp.Write(data)
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
		reqBody := drainBody(req.Body)
		f := h.owner.newHTTPFlow()
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
			return // request seen but no parseable response (capture ended / closed)
		}
		f.Status = uint32(resp.StatusCode)
		f.ResponseHeaders = headersOf(resp.Header)
		f.ContentType = resp.Header.Get("Content-Type")

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

		f.ResponseBody = readRespBody(resp)
		h.onFlow(f, false)
	}
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

	emitMsg := func(opcode string, fromClient bool, payload []byte) {
		f.WsMessageCount++
		h.onMsg(&WsMessage{
			ID:           uuid.NewString(),
			FlowID:       f.ID,
			TSUnixMicros: time.Now().UnixMicro(),
			FromClient:   fromClient,
			Opcode:       opcode,
			Payload:      payload,
		})
	}
	emit := func(opcode string, fromClient bool, payload []byte) {
		h.wsMu.Lock()
		defer h.wsMu.Unlock()
		if opcode == "binary" && wsSess != nil {
			// Keep the raw frame (original bytes) and also frame it through the custom
			// decoder (buffering partials), so both remain queryable.
			emitMsg("binary", fromClient, payload)
			for _, fr := range wsSess.Feed(fromClient, payload) {
				emitMsg(fr.Opcode, fr.FromClient, fr.Payload)
			}
		} else {
			emitMsg(opcode, fromClient, payload)
		}
		h.onFlow(f, false) // refresh the row's ⇅ count
	}
	go readWSFrames(reqBr, true, emit)
	go readWSFrames(respBr, false, emit)
}

// drainBody reads up to maxLiveBody bytes, then drains the rest so the next message on a
// kept-alive connection stays byte-aligned. (chunked transfer-encoding is undone by the
// stdlib body reader; gzip Content-Encoding is not — see readRespBody.)
func drainBody(rc io.ReadCloser) []byte {
	if rc == nil {
		return nil
	}
	defer rc.Close()
	data, _ := io.ReadAll(io.LimitReader(rc, int64(maxLiveBody)))
	_, _ = io.Copy(io.Discard, rc)
	return data
}

// readRespBody captures the response body, gunzipping a gzip Content-Encoding so the
// preview is readable, and always drains the underlying body for keep-alive alignment.
func readRespBody(resp *http.Response) []byte {
	defer resp.Body.Close()
	var r io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		if gz, err := gzip.NewReader(resp.Body); err == nil {
			defer gz.Close()
			r = gz
		}
	}
	data, _ := io.ReadAll(io.LimitReader(r, int64(maxLiveBody)))
	_, _ = io.Copy(io.Discard, resp.Body) // drain remaining compressed/raw bytes
	return data
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
// fills request/response specifics.
func (s *tcpStream) newHTTPFlow() *Flow {
	host := s.conn.SNI()
	if host == "" {
		host = s.serverHost
	}
	return &Flow{
		ID:           uuid.NewString(),
		TSUnixMicros: time.Now().UnixMicro(),
		Protocol:     "HTTP/1.1",
		Scheme:       "https",
		Authority:    host,
		SrcAddr:      s.clientAddr,
		DstAddr:      addr(s.serverHost, "", s.serverPort),
		TLSDecrypted: true,
	}
}
