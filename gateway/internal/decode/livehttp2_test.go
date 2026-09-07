package decode

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

func h2encode(fields ...hpack.HeaderField) []byte {
	var b bytes.Buffer
	enc := hpack.NewEncoder(&b)
	for _, f := range fields {
		_ = enc.WriteField(f)
	}
	return b.Bytes()
}

// h2encodeTableSizeUpdate encodes header fields preceded by an HPACK dynamic table size
// update to size (RFC 7541 §6.3). The go hpack encoder only emits an update above the
// 4096 default once its limit is raised past it, so size must exceed 4096 to be a
// meaningful "large table" block.
func h2encodeTableSizeUpdate(size uint32, fields ...hpack.HeaderField) []byte {
	var b bytes.Buffer
	enc := hpack.NewEncoder(&b)
	enc.SetMaxDynamicTableSizeLimit(size)
	enc.SetMaxDynamicTableSize(size)
	for _, f := range fields {
		_ = enc.WriteField(f)
	}
	return b.Bytes()
}

// feedH2 drives one h2Stream with client/server byte streams and returns the final
// state of each emitted flow (keyed by id, last write wins), waiting for the last flow's
// response.
func feedH2(t *testing.T, client, server []byte) []*Flow {
	t.Helper()
	return feedH2Until(t, client, server, func(fs []*Flow) bool {
		return len(fs) > 0 && fs[len(fs)-1].Status != 0
	})
}

// feedH2Until is feedH2 with a custom readiness predicate over the flows so far — used to
// wait for a failure signal (RST_STREAM/GOAWAY set Error, not Status).
func feedH2Until(t *testing.T, client, server []byte, ready func([]*Flow) bool) []*Flow {
	t.Helper()
	var mu sync.Mutex
	latest := map[string]*Flow{}
	var order []string
	lt := &liveTCP{onFlow: func(f *Flow, isNew bool) {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := latest[f.ID]; !ok {
			order = append(order, f.ID)
		}
		latest[f.ID] = f
	}}
	s := &tcpStream{
		lt:         lt,
		connID:     "7",
		serverHost: "203.0.113.5",
		serverPort: "443",
		clientAddr: "198.51.100.2:51000",
		conn:       tlsdecrypt.NewConn(tlsdecrypt.NewKeylog(""), nil),
	}
	h := newH2Stream(s)
	h.feed(true, client)
	h.feed(false, server)
	h.close()

	snapshot := func() []*Flow {
		mu.Lock()
		defer mu.Unlock()
		out := make([]*Flow, 0, len(order))
		for _, id := range order {
			out = append(out, latest[id])
		}
		return out
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ready(snapshot()) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	return snapshot()
}

func TestLiveHTTP2RequestResponse(t *testing.T) {
	var cbuf bytes.Buffer
	cbuf.WriteString(http2.ClientPreface)
	cf := http2.NewFramer(&cbuf, nil)
	if err := cf.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := cf.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1,
		BlockFragment: h2encode(
			hpack.HeaderField{Name: ":method", Value: "GET"},
			hpack.HeaderField{Name: ":scheme", Value: "https"},
			hpack.HeaderField{Name: ":authority", Value: "example.com"},
			hpack.HeaderField{Name: ":path", Value: "/h2?x=1"},
			hpack.HeaderField{Name: "user-agent", Value: "probe/2"},
		),
		EndStream:  true,
		EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}

	var sbuf bytes.Buffer
	sf := http2.NewFramer(&sbuf, nil)
	if err := sf.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := sf.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1,
		BlockFragment: h2encode(
			hpack.HeaderField{Name: ":status", Value: "200"},
			hpack.HeaderField{Name: "content-type", Value: "application/json"},
		),
		EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sf.WriteData(1, true, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}

	flows := feedH2(t, cbuf.Bytes(), sbuf.Bytes())
	if len(flows) != 1 {
		t.Fatalf("got %d flows, want 1", len(flows))
	}
	f := flows[0]
	if f.Protocol != "HTTP/2" || f.H2StreamID != "1" {
		t.Errorf("proto=%q h2stream=%q", f.Protocol, f.H2StreamID)
	}
	if f.Method != "GET" || f.Path != "/h2" || f.Query != "x=1" || f.Authority != "example.com" {
		t.Errorf("req: method=%q path=%q query=%q authority=%q", f.Method, f.Path, f.Query, f.Authority)
	}
	if f.UserAgent != "probe/2" || !f.TLSDecrypted {
		t.Errorf("meta: ua=%q tls=%v", f.UserAgent, f.TLSDecrypted)
	}
	if f.Status != 200 || f.ContentType != "application/json" {
		t.Errorf("resp: status=%d ct=%q", f.Status, f.ContentType)
	}
	if string(f.ResponseBody) != `{"ok":true}` {
		t.Errorf("body=%q", f.ResponseBody)
	}
}

// TestLiveHTTP2DurationFromPacketTime: an h2 request whose whole exchange is already
// buffered when the parser runs (the common live case — the key-log lags, then a burst
// decrypts) must still get a real duration from packet capture time, not the ~0 that
// wall-clock at decode gives. Here the request and response frames carry capture times 30ms
// apart, so the flow's duration must be 30ms regardless of how fast decode ran.
func TestLiveHTTP2DurationFromPacketTime(t *testing.T) {
	var cbuf bytes.Buffer
	cbuf.WriteString(http2.ClientPreface)
	cf := http2.NewFramer(&cbuf, nil)
	if err := cf.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1,
		BlockFragment: h2encode(
			hpack.HeaderField{Name: ":method", Value: "GET"},
			hpack.HeaderField{Name: ":authority", Value: "example.com"},
			hpack.HeaderField{Name: ":path", Value: "/"},
		),
		EndStream: true, EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}
	var sbuf bytes.Buffer
	sf := http2.NewFramer(&sbuf, nil)
	if err := sf.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: h2encode(hpack.HeaderField{Name: ":status", Value: "200"}),
		EndStream:     true, EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	latest := map[string]*Flow{}
	var order []string
	lt := &liveTCP{onFlow: func(f *Flow, _ bool) {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := latest[f.ID]; !ok {
			order = append(order, f.ID)
		}
		latest[f.ID] = f
	}}
	s := &tcpStream{lt: lt, connID: "7", serverHost: "203.0.113.5", serverPort: "443",
		clientAddr: "198.51.100.2:51000", conn: tlsdecrypt.NewConn(tlsdecrypt.NewKeylog(""), nil)}
	h := newH2Stream(s)

	base := time.Unix(1_700_000_000, 0)
	s.curTS = base // the request frames' capture time
	h.feed(true, cbuf.Bytes())
	s.curTS = base.Add(30 * time.Millisecond) // the response arrived 30ms later
	h.feed(false, sbuf.Bytes())
	h.close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		// Wait for both directions to settle: the response emit sets Status, the request
		// emit pairs the times into DurationMicros (either goroutine may run first).
		done := len(order) > 0 && latest[order[0]].Status != 0 && latest[order[0]].DurationMicros != 0
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 1 {
		t.Fatalf("want 1 flow, got %d", len(order))
	}
	if f := latest[order[0]]; f.DurationMicros != 30_000 {
		t.Errorf("duration = %dµs, want 30000 (from packet timestamps, not decode time)", f.DurationMicros)
	}
}

// TestLiveHTTP2MultiplexedStreamsShareConnID covers the whole point of HTTP/2
// multiplexing being visible: two requests sent over one connection get one shared
// connection id and their own stream ids, so a viewer can group them.
func TestLiveHTTP2MultiplexedStreamsShareConnID(t *testing.T) {
	var cbuf bytes.Buffer
	cbuf.WriteString(http2.ClientPreface)
	cf := http2.NewFramer(&cbuf, nil)
	if err := cf.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	for _, sid := range []uint32{1, 3} { // client-initiated streams are odd
		if err := cf.WriteHeaders(http2.HeadersFrameParam{
			StreamID: sid,
			BlockFragment: h2encode(
				hpack.HeaderField{Name: ":method", Value: "GET"},
				hpack.HeaderField{Name: ":scheme", Value: "https"},
				hpack.HeaderField{Name: ":authority", Value: "example.com"},
				hpack.HeaderField{Name: ":path", Value: "/s"},
			),
			EndStream:  true,
			EndHeaders: true,
		}); err != nil {
			t.Fatal(err)
		}
	}

	var sbuf bytes.Buffer
	sf := http2.NewFramer(&sbuf, nil)
	if err := sf.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	for _, sid := range []uint32{1, 3} {
		if err := sf.WriteHeaders(http2.HeadersFrameParam{
			StreamID: sid,
			BlockFragment: h2encode(
				hpack.HeaderField{Name: ":status", Value: "200"},
			),
			EndStream:  true,
			EndHeaders: true,
		}); err != nil {
			t.Fatal(err)
		}
	}

	flows := feedH2Until(t, cbuf.Bytes(), sbuf.Bytes(), func(fs []*Flow) bool {
		if len(fs) < 2 {
			return false
		}
		for _, f := range fs {
			if f.Status == 0 {
				return false
			}
		}
		return true
	})
	if len(flows) != 2 {
		t.Fatalf("got %d flows, want 2", len(flows))
	}
	// One connection (the id feedH2Until gives its tcpStream), two distinct streams.
	for _, f := range flows {
		if f.TCPStream != "7" {
			t.Errorf("stream %q: conn=%q, want %q — multiplexed flows share a connection",
				f.H2StreamID, f.TCPStream, "7")
		}
	}
	if a, b := flows[0].H2StreamID, flows[1].H2StreamID; a != "1" || b != "3" {
		t.Errorf("h2 stream ids = %q,%q; want 1,3", a, b)
	}
}

// TestLiveHTTP2LargeHeaderTableSizeUpdate is the regression for browser-client responses
// being silently dropped. A browser advertises SETTINGS_HEADER_TABLE_SIZE=65536, so the
// server may grow its HPACK dynamic table past the 4096 default and open the response
// header block with a dynamic table size update above 4096. A decoder pinned at the 4096
// default rejects that update as a COMPRESSION_ERROR and the whole response direction dies
// — the flow keeps its request but never gets a status, headers or body. The decoder must
// accept a size update up to what the client advertised.
func TestLiveHTTP2LargeHeaderTableSizeUpdate(t *testing.T) {
	var cbuf bytes.Buffer
	cbuf.WriteString(http2.ClientPreface)
	cf := http2.NewFramer(&cbuf, nil)
	if err := cf.WriteSettings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536}); err != nil {
		t.Fatal(err)
	}
	if err := cf.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1,
		BlockFragment: h2encode(
			hpack.HeaderField{Name: ":method", Value: "GET"},
			hpack.HeaderField{Name: ":scheme", Value: "https"},
			hpack.HeaderField{Name: ":authority", Value: "example.com"},
			hpack.HeaderField{Name: ":path", Value: "/big-table"},
		),
		EndStream: true, EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}

	var sbuf bytes.Buffer
	sf := http2.NewFramer(&sbuf, nil)
	if err := sf.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	// The response header block opens with a dynamic table size update to 8192 (> the 4096
	// default), which a server encoding for a 64KB-table client legitimately may send.
	if err := sf.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1,
		BlockFragment: h2encodeTableSizeUpdate(8192,
			hpack.HeaderField{Name: ":status", Value: "200"},
			hpack.HeaderField{Name: "content-type", Value: "text/html"},
		),
		EndStream: true, EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}

	flows := feedH2(t, cbuf.Bytes(), sbuf.Bytes())
	if len(flows) != 1 {
		t.Fatalf("got %d flows, want 1", len(flows))
	}
	if flows[0].Status != 200 || flows[0].ContentType != "text/html" {
		t.Errorf("resp: status=%d ct=%q — response direction dropped (HPACK size update > 4096 rejected)?",
			flows[0].Status, flows[0].ContentType)
	}
}

func TestLiveHTTP2Fingerprint(t *testing.T) {
	// Client: preface + SETTINGS + connection WINDOW_UPDATE + a request whose pseudo
	// headers are in :method,:authority,:scheme,:path order.
	var cbuf bytes.Buffer
	cbuf.WriteString(http2.ClientPreface)
	cf := http2.NewFramer(&cbuf, nil)
	if err := cf.WriteSettings(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536},
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6291456},
	); err != nil {
		t.Fatal(err)
	}
	if err := cf.WriteWindowUpdate(0, 15663105); err != nil {
		t.Fatal(err)
	}
	if err := cf.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1,
		BlockFragment: h2encode(
			hpack.HeaderField{Name: ":method", Value: "GET"},
			hpack.HeaderField{Name: ":authority", Value: "example.com"},
			hpack.HeaderField{Name: ":scheme", Value: "https"},
			hpack.HeaderField{Name: ":path", Value: "/x"},
		),
		EndStream: true, EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}

	var sbuf bytes.Buffer
	sf := http2.NewFramer(&sbuf, nil)
	if err := sf.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := sf.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: h2encode(hpack.HeaderField{Name: ":status", Value: "200"}),
		EndStream: true, EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}

	flows := feedH2(t, cbuf.Bytes(), sbuf.Bytes())
	if len(flows) != 1 {
		t.Fatalf("got %d flows, want 1", len(flows))
	}
	want := "1:65536;3:1000;4:6291456|15663105|0|m,a,s,p"
	if flows[0].Http2Fingerprint != want {
		t.Errorf("fingerprint = %q, want %q", flows[0].Http2Fingerprint, want)
	}
}

// h2Request builds a client preface + SETTINGS + a HEADERS request on streamID.
func h2Request(t *testing.T, streamID uint32, path string) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&b, nil)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: streamID,
		BlockFragment: h2encode(
			hpack.HeaderField{Name: ":method", Value: "GET"},
			hpack.HeaderField{Name: ":authority", Value: "example.com"},
			hpack.HeaderField{Name: ":path", Value: path},
		),
		EndStream:  true,
		EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestLiveHTTP2RSTStream(t *testing.T) {
	client := h2Request(t, 1, "/x")
	var sbuf bytes.Buffer
	sf := http2.NewFramer(&sbuf, nil)
	if err := sf.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := sf.WriteRSTStream(1, http2.ErrCodeRefusedStream); err != nil {
		t.Fatal(err)
	}

	flows := feedH2Until(t, client, sbuf.Bytes(), func(fs []*Flow) bool {
		return len(fs) == 1 && fs[0].Error != ""
	})
	if len(flows) != 1 {
		t.Fatalf("got %d flows, want 1", len(flows))
	}
	if flows[0].Error != "HTTP/2 RST_STREAM: REFUSED_STREAM" {
		t.Errorf("error = %q, want RST_STREAM: REFUSED_STREAM", flows[0].Error)
	}
	if flows[0].Status != 0 || flows[0].Method != "GET" {
		t.Errorf("flow: status=%d method=%q", flows[0].Status, flows[0].Method)
	}
}

func TestLiveHTTP2RSTStreamNoErrorIgnored(t *testing.T) {
	// A NO_ERROR reset is a clean cancellation, not a failure — Error stays empty.
	client := h2Request(t, 1, "/x")
	var sbuf bytes.Buffer
	sf := http2.NewFramer(&sbuf, nil)
	if err := sf.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := sf.WriteRSTStream(1, http2.ErrCodeNo); err != nil {
		t.Fatal(err)
	}
	// The request HEADERS create the flow; wait for that, then assert no error was set.
	flows := feedH2Until(t, client, sbuf.Bytes(), func(fs []*Flow) bool { return len(fs) == 1 })
	if len(flows) != 1 || flows[0].Error != "" {
		t.Fatalf("flow = %+v; want no error", flows)
	}
}

func TestLiveHTTP2GoAwayFlagsUnprocessed(t *testing.T) {
	// Streams 1 and 3; server answers 1 (200) then GOAWAYs with LastStreamID=1, so stream
	// 3 was never processed and must be flagged, while stream 1 stays clean.
	client := append(h2Request(t, 1, "/a"), h2frames(t, 3, "/b")...)

	var sbuf bytes.Buffer
	sf := http2.NewFramer(&sbuf, nil)
	if err := sf.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := sf.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: h2encode(hpack.HeaderField{Name: ":status", Value: "200"}),
		EndStream:     true, EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sf.WriteGoAway(1, http2.ErrCodeNo, nil); err != nil {
		t.Fatal(err)
	}

	flows := feedH2Until(t, client, sbuf.Bytes(), func(fs []*Flow) bool {
		for _, f := range fs {
			if f.H2StreamID == "3" && f.Error != "" {
				return true
			}
		}
		return false
	})
	byStream := map[string]*Flow{}
	for _, f := range flows {
		byStream[f.H2StreamID] = f
	}
	if s1 := byStream["1"]; s1 == nil || s1.Status != 200 || s1.Error != "" {
		t.Errorf("stream 1 should be clean 200: %+v", s1)
	}
	if s3 := byStream["3"]; s3 == nil || s3.Error == "" || s3.Status != 0 {
		t.Errorf("stream 3 should be flagged unprocessed: %+v", s3)
	}
}

// h2frames builds just a HEADERS request on streamID (no preface/SETTINGS) — for a second
// request on an already-open connection.
func h2frames(t *testing.T, streamID uint32, path string) []byte {
	t.Helper()
	var b bytes.Buffer
	fr := http2.NewFramer(&b, nil)
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: streamID,
		BlockFragment: h2encode(
			hpack.HeaderField{Name: ":method", Value: "GET"},
			hpack.HeaderField{Name: ":authority", Value: "example.com"},
			hpack.HeaderField{Name: ":path", Value: path},
		),
		EndStream:  true,
		EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
