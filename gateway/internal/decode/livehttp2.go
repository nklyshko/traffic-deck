package decode

// In-process live HTTP/2-over-TLS decode, the H2 counterpart to livehttp.go. The TLS
// layer (internal/tlsdecrypt) hands us each direction's decrypted bytes; we run an
// http2.Framer per direction (with an HPACK decoder, so CONTINUATION + dynamic-table
// state are handled) and reassemble per-stream requests/responses into Flows. As with
// the HTTP/1.1 path, the batch tshark pass on close stays authoritative.

import (
	"bytes"
	"compress/gzip"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const h2HeaderTableSize = 4096

// h2flow tracks one HTTP/2 stream's Flow plus the decode state the wire spreads across
// frames (added-yet, response gzip, accumulated bodies).
type h2flow struct {
	id       uint32
	flow     *Flow
	added    bool
	respGzip bool
}

// h2Stream decodes one TLS-decrypted connection as HTTP/2: a goroutine per direction
// reads frames; HEADERS populate a per-stream Flow, DATA accumulate bodies, END_STREAM
// finalizes. All flow mutation + emission happens under mu so the two goroutines never
// touch a Flow concurrently (onFlow converts to proto synchronously).
type h2Stream struct {
	owner  *tcpStream
	onFlow func(*Flow, bool)
	client *byteStream
	server *byteStream

	mu    sync.Mutex
	flows map[uint32]*h2flow

	// Stream-level failures the peer signalled. Recorded here (not just applied to the
	// flow) because the two directions decode concurrently, so a server RST_STREAM/GOAWAY
	// can arrive before the client's request HEADERS created the flow; emitLocked applies
	// them whenever the flow is (later) touched.
	pendingRST   map[uint32]string // stream id -> RST_STREAM reason (non-NO_ERROR only)
	goAwaySeen   bool
	goAwayLastID uint32
	goAwayErr    string
}

func newH2Stream(owner *tcpStream) *h2Stream {
	h := &h2Stream{
		owner:      owner,
		onFlow:     owner.lt.onFlow,
		client:     newByteStream(),
		server:     newByteStream(),
		flows:      map[uint32]*h2flow{},
		pendingRST: map[uint32]string{},
	}
	go h.read(h.client, true)
	go h.read(h.server, false)
	return h
}

func (h *h2Stream) feed(fromClient bool, data []byte) {
	if fromClient {
		_, _ = h.client.Write(data)
	} else {
		_, _ = h.server.Write(data)
	}
}

func (h *h2Stream) close() {
	h.client.Close()
	h.server.Close()
}

func (h *h2Stream) read(src *byteStream, fromClient bool) {
	if fromClient {
		// Consume the client connection preface before the first frame.
		pre := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(src, pre); err != nil || string(pre) != http2.ClientPreface {
			return
		}
	}
	fr := http2.NewFramer(io.Discard, src)
	fr.ReadMetaHeaders = hpack.NewDecoder(h2HeaderTableSize, nil)
	fr.MaxHeaderListSize = 1 << 20
	fr.SetMaxReadFrameSize(1 << 20)
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch frm := f.(type) {
		case *http2.MetaHeadersFrame:
			h.onHeaders(frm, fromClient)
		case *http2.DataFrame:
			h.onData(frm, fromClient)
		case *http2.RSTStreamFrame:
			h.onRSTStream(frm)
		case *http2.GoAwayFrame:
			h.onGoAway(frm)
		}
	}
}

// onRSTStream records a stream abort as its flow's failure reason. A NO_ERROR reset is a
// clean cancellation, not a failure, so it's ignored; other codes (REFUSED_STREAM, CANCEL,
// INTERNAL_ERROR, ENHANCE_YOUR_CALM, …) explain exactly why a request got no/partial
// response. Recorded even if the request HEADERS haven't been decoded yet (the directions
// race); emitLocked applies it when the flow appears.
func (h *h2Stream) onRSTStream(rf *http2.RSTStreamFrame) {
	if rf.ErrCode == http2.ErrCodeNo {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pendingRST[rf.StreamID] = "HTTP/2 RST_STREAM: " + rf.ErrCode.String()
	if hf := h.flows[rf.StreamID]; hf != nil {
		h.emitLocked(hf)
	}
}

// onGoAway records that the peer is shutting the connection down: any stream past
// LastStreamID was never processed, so a response-less flow there failed (the client would
// retry it on a new connection).
func (h *h2Stream) onGoAway(gf *http2.GoAwayFrame) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.goAwaySeen = true
	h.goAwayLastID = gf.LastStreamID
	h.goAwayErr = "HTTP/2 GOAWAY: " + gf.ErrCode.String() + " (stream not processed)"
	for _, hf := range h.flows {
		if hf.flow.Status == 0 {
			h.emitLocked(hf)
		}
	}
}

// getLocked returns (creating if needed) the stream's flow. Caller holds mu.
func (h *h2Stream) getLocked(id uint32) *h2flow {
	hf := h.flows[id]
	if hf == nil {
		f := h.owner.newHTTPFlow()
		f.Protocol = "HTTP/2"
		f.H2StreamID = strconv.FormatUint(uint64(id), 10)
		hf = &h2flow{id: id, flow: f}
		h.flows[id] = hf
	}
	return hf
}

// emitLocked publishes the flow (added on first emit, update after). Caller holds mu;
// onFlow converts to proto synchronously, so holding mu keeps the two directions from
// racing on the shared Flow. A stream-level failure recorded before the flow existed (a
// RST_STREAM/GOAWAY that raced ahead of the request HEADERS) is applied here.
func (h *h2Stream) emitLocked(hf *h2flow) {
	if hf.flow.Status == 0 && hf.flow.Error == "" {
		if r, ok := h.pendingRST[hf.id]; ok {
			hf.flow.Error = r
		} else if h.goAwaySeen && hf.id > h.goAwayLastID {
			hf.flow.Error = h.goAwayErr
		}
	}
	first := !hf.added
	hf.added = true
	h.onFlow(hf.flow, first)
}

func (h *h2Stream) onHeaders(mh *http2.MetaHeadersFrame, fromClient bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hf := h.getLocked(mh.StreamID)
	f := hf.flow
	if fromClient {
		if v := mh.PseudoValue("method"); v != "" {
			f.Method = v
		}
		if v := mh.PseudoValue("authority"); v != "" {
			f.Authority = v
		}
		if v := mh.PseudoValue("scheme"); v != "" {
			f.Scheme = v
		}
		if v := mh.PseudoValue("path"); v != "" {
			path, query, _ := strings.Cut(v, "?")
			f.Path, f.Query = path, query
		}
		for _, hd := range mh.RegularFields() {
			f.RequestHeaders = append(f.RequestHeaders, Header{Name: hd.Name, Value: hd.Value})
			if strings.EqualFold(hd.Name, "user-agent") {
				f.UserAgent = hd.Value
			}
		}
	} else {
		if v := mh.PseudoValue("status"); v != "" {
			if code, err := strconv.Atoi(v); err == nil {
				f.Status = uint32(code)
				f.DurationMicros = uint64(max(time.Now().UnixMicro()-f.TSUnixMicros, 0))
			}
		}
		for _, hd := range mh.RegularFields() {
			f.ResponseHeaders = append(f.ResponseHeaders, Header{Name: hd.Name, Value: hd.Value})
			if strings.EqualFold(hd.Name, "content-type") {
				f.ContentType = hd.Value
			}
			if strings.EqualFold(hd.Name, "content-encoding") && strings.EqualFold(hd.Value, "gzip") {
				hf.respGzip = true
			}
		}
	}
	h.emitLocked(hf)
}

func (h *h2Stream) onData(df *http2.DataFrame, fromClient bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hf := h.getLocked(df.Header().StreamID)
	f := hf.flow
	if fromClient {
		f.RequestBody = appendCapped(f.RequestBody, df.Data())
		f.RequestBytes = uint64(len(f.RequestBody))
	} else if !hf.respGzip {
		f.ResponseBody = appendCapped(f.ResponseBody, df.Data())
	} else {
		// gzip: keep the compressed bytes in ResponseBody until end-of-stream, then
		// gunzip in place (finalize). Capped to bound memory.
		f.ResponseBody = appendCapped(f.ResponseBody, df.Data())
	}
	if df.StreamEnded() {
		if !fromClient && hf.respGzip {
			f.ResponseBody = maybeGunzip(f.ResponseBody)
			hf.respGzip = false
		}
		h.emitLocked(hf)
	}
}

// appendCapped appends data to b, stopping at maxLiveBody (live is a preview; the batch
// pass on close has full bodies).
func appendCapped(b, data []byte) []byte {
	if len(b) >= maxLiveBody {
		return b
	}
	if room := maxLiveBody - len(b); len(data) > room {
		data = data[:room]
	}
	return append(b, data...)
}

func maybeGunzip(raw []byte) []byte {
	if len(raw) == 0 {
		return raw
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return raw // truncated/partial (capped) gzip — leave the raw bytes
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, int64(maxLiveBody)))
	if err != nil && len(out) == 0 {
		return raw
	}
	return out
}
