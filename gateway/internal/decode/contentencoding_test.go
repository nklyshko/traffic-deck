package decode

// Content-encoding handling across the decode paths: what a flow ends up holding when a
// body arrived compressed, and what it records about those bytes. Every path is covered
// because they disagreed before — h3 stored gzip wire bytes while h1/h2 stored plain, so
// a body search silently missed most of a Chrome capture's responses.

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"golang.org/x/net/http2"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

// gzipBytes returns s as a gzip stream, the way a server would send it.
func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// h3Layers builds the PDML record the stitcher sees for one HTTP/3 frame, addressed as
// the client or the server sent it — a body-only DATA frame takes its direction from
// the source address, so the fixtures have to be addressed like a real capture.
func h3Layers(fromClient bool, fields map[string][]string) layers {
	src, sport, dst, dport := "198.51.100.2", "50000", "203.0.113.5", "443"
	if !fromClient {
		src, sport, dst, dport = dst, dport, src, sport
	}
	l := layers{
		fFrameNum:   {"1"},
		fFrameTime:  {"1700000000.0"},
		fQUICConn:   {"0"},
		fH3StreamID: {"0"},
		fIPSrc:      {src},
		fUDPSrcPort: {sport},
		fIPDst:      {dst},
		fUDPDstPort: {dport},
	}
	for k, v := range fields {
		l[k] = v
	}
	return l
}

// h3Request is the request HEADERS frame every fixture opens with, so the flow knows
// which end is the client.
func h3Request() layers {
	return h3Layers(true, map[string][]string{
		fH3Method:   {"GET"},
		fH3Path:     {"/"},
		fH3HdrName:  {":method", ":path"},
		fH3HdrValue: {"GET", "/"},
	})
}

// TestStitchDecodesHTTP3GzipBody is the batch-decode half of the bug: tshark's HTTP/3
// dissector has no body-decompression preference, so http3.data reaches the stitcher as
// gzip wire bytes. What the flow keeps must be the plain page, labelled gzip.
func TestStitchDecodesHTTP3GzipBody(t *testing.T) {
	const page = "<html>searchable text</html>"
	ds := &Dataset{}
	st := newStitcher(ds, nil)

	st.addHTTP3(h3Request(), "0")
	st.addHTTP3(h3Layers(false, map[string][]string{
		fH3Status:   {"200"},
		fH3HdrName:  {"content-type", "content-encoding"},
		fH3HdrValue: {"text/html", "gzip"},
	}), "0")
	st.addHTTP3(h3Layers(false, map[string][]string{
		fH3Data: {hex.EncodeToString(gzipBytes(t, page))},
	}), "0")

	if len(ds.Flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(ds.Flows))
	}
	f := ds.Flows[0]
	if string(f.ResponseBody) == page {
		t.Fatal("body already plain before finish() — the fixture isn't exercising the decode")
	}

	st.finish()

	if string(f.ResponseBody) != page {
		t.Errorf("ResponseBody = %q, want the decompressed page %q", f.ResponseBody, page)
	}
	if f.ResponseBodyEncoding != "gzip" {
		t.Errorf("ResponseBodyEncoding = %q, want %q", f.ResponseBodyEncoding, "gzip")
	}
}

// A gzip body split across HTTP/3 DATA frames is one gzip stream cut in two; it decodes
// only once the frames are back together, which is why finish() runs after the last one.
func TestStitchDecodesHTTP3GzipAcrossFrames(t *testing.T) {
	const page = "chunked payload that spans two DATA frames"
	ds := &Dataset{}
	st := newStitcher(ds, nil)

	st.addHTTP3(h3Request(), "0")
	st.addHTTP3(h3Layers(false, map[string][]string{
		fH3Status:   {"200"},
		fH3HdrName:  {"content-encoding"},
		fH3HdrValue: {"gzip"},
	}), "0")
	raw := gzipBytes(t, page)
	half := len(raw) / 2
	st.addHTTP3(h3Layers(false, map[string][]string{fH3Data: {hex.EncodeToString(raw[:half])}}), "0")
	st.addHTTP3(h3Layers(false, map[string][]string{fH3Data: {hex.EncodeToString(raw[half:])}}), "0")

	st.finish()

	if got := string(ds.Flows[0].ResponseBody); got != page {
		t.Errorf("ResponseBody = %q, want %q", got, page)
	}
}

// A content-encoding header can lie: the body was sent plain. Decoding is then a no-op
// and the bytes stay as they came — but the encoding is still recorded, because the field
// reports what the wire said, and a consumer that trusts it must not be told "plain" by a
// decoder that merely failed to find gzip.
func TestStitchKeepsBodyWhenEncodingHeaderLies(t *testing.T) {
	const plain = "not actually compressed"
	ds := &Dataset{}
	st := newStitcher(ds, nil)

	st.addHTTP3(h3Request(), "0")
	st.addHTTP3(h3Layers(false, map[string][]string{
		fH3Status:   {"200"},
		fH3HdrName:  {"content-encoding"},
		fH3HdrValue: {"gzip"},
	}), "0")
	st.addHTTP3(h3Layers(false, map[string][]string{
		fH3Data: {hex.EncodeToString([]byte(plain))},
	}), "0")

	st.finish()

	f := ds.Flows[0]
	if string(f.ResponseBody) != plain {
		t.Errorf("ResponseBody = %q, want the bytes as sent %q", f.ResponseBody, plain)
	}
	if f.ResponseBodyEncoding != "gzip" {
		t.Errorf("ResponseBodyEncoding = %q, want %q — the wire named it", f.ResponseBodyEncoding, "gzip")
	}
}

// An encoding we can't undo (no brotli decoder) leaves the bytes compressed. That's the
// case the field exists for: without it a consumer has binary bytes and no idea why.
func TestStitchRecordsUndecodableEncoding(t *testing.T) {
	ds := &Dataset{}
	st := newStitcher(ds, nil)

	st.addHTTP3(h3Request(), "0")
	st.addHTTP3(h3Layers(false, map[string][]string{
		fH3Status:   {"200"},
		fH3HdrName:  {"content-encoding"},
		fH3HdrValue: {"br"},
	}), "0")
	st.addHTTP3(h3Layers(false, map[string][]string{fH3Data: {"cafebabe"}}), "0")

	st.finish()

	f := ds.Flows[0]
	if got := hex.EncodeToString(f.ResponseBody); got != "cafebabe" {
		t.Errorf("ResponseBody = %s, want the brotli bytes untouched", got)
	}
	if f.ResponseBodyEncoding != "br" {
		t.Errorf("ResponseBodyEncoding = %q, want %q", f.ResponseBodyEncoding, "br")
	}
}

// A plain body gets no encoding: the field means "these bytes arrived encoded", so
// setting it for every flow would make it useless.
func TestStitchLeavesPlainBodyUnlabelled(t *testing.T) {
	ds := &Dataset{}
	st := newStitcher(ds, nil)
	st.addHTTP3(h3Request(), "0")
	st.addHTTP3(h3Layers(false, map[string][]string{
		fH3Status:   {"200"},
		fH3HdrName:  {"content-type"},
		fH3HdrValue: {"text/plain"},
	}), "0")
	st.addHTTP3(h3Layers(false, map[string][]string{fH3Data: {hex.EncodeToString([]byte("hello"))}}), "0")

	st.finish()

	f := ds.Flows[0]
	if string(f.ResponseBody) != "hello" || f.ResponseBodyEncoding != "" {
		t.Errorf("body=%q encoding=%q, want the bytes unchanged and no encoding",
			f.ResponseBody, f.ResponseBodyEncoding)
	}
}

// A body tshark handed us reassembled has already been decompressed by it, so the flow
// keeps those bytes as they are — running gunzip again would unwrap a gzip *file* served
// under a gzip content-encoding. The encoding is still recorded: it describes what the
// bytes were on the wire, not who decoded them.
func TestStitchLeavesReassembledBodyDecoded(t *testing.T) {
	archive := gzipBytes(t, "a gzip file served with a gzip content-encoding")
	ds := &Dataset{}
	st := newStitcher(ds, nil)

	l := layers{
		fFrameNum:   {"1"},
		fFrameTime:  {"1700000000.0"},
		fH2StreamID: {"1"},
		fTCPStream:  {"3"},
		fIPSrc:      {"203.0.113.5"},
		fTCPSrcPort: {"443"},
		fIPDst:      {"198.51.100.2"},
		fTCPDstPort: {"50000"},
		fH2Status:   {"200"},
		fH2HdrName:  {"content-type", "content-encoding"},
		fH2HdrValue: {"application/gzip", "gzip"},
		// tshark's reassembled body: what it produced after undoing the content-encoding,
		// which here leaves the archive itself.
		fH2BodyReassembled: {hex.EncodeToString(archive)},
	}
	st.addHTTP2(l, "3", "1")

	st.finish()

	f := ds.Flows[0]
	if !bytes.Equal(f.ResponseBody, archive) {
		t.Errorf("ResponseBody = %.20q…, want the archive untouched", f.ResponseBody)
	}
	if f.ResponseBodyEncoding != "gzip" {
		t.Errorf("ResponseBodyEncoding = %q, want %q", f.ResponseBodyEncoding, "gzip")
	}
}

// TestLiveHTTP3GzipBody is the live half of the same bug: the QUIC decoder appended DATA
// payloads with no content-encoding awareness, so a gzip response reached the viewer (and
// the store, and body search) compressed.
func TestLiveHTTP3GzipBody(t *testing.T) {
	const page = "<html>live searchable text</html>"
	var mu sync.Mutex
	var flow *Flow
	s := newQUICSession(&liveTCP{
		keylog: tlsdecrypt.NewKeylog(""),
		onFlow: func(f *Flow, _ bool) { mu.Lock(); flow = f; mu.Unlock() },
	}, "quic:0", "203.0.113.5", "443", "198.51.100.2:50000")

	s.onStream(0, true, h3Frame(h3FrameHeaders, qpackSection(
		qpack.HeaderField{Name: ":method", Value: "GET"},
		qpack.HeaderField{Name: ":path", Value: "/"},
	)))
	s.onStream(0, false, h3Frame(h3FrameHeaders, qpackSection(
		qpack.HeaderField{Name: ":status", Value: "200"},
		qpack.HeaderField{Name: "content-type", Value: "text/html"},
		qpack.HeaderField{Name: "content-encoding", Value: "gzip"},
	)))
	raw := gzipBytes(t, page)
	half := len(raw) / 2
	s.onStream(0, false, h3Frame(h3FrameData, raw[:half]))
	s.onStream(0, false, h3Frame(h3FrameData, raw[half:]))
	s.close() // QUIC has no end-of-stream callback; teardown is the last word

	mu.Lock()
	defer mu.Unlock()
	if flow == nil {
		t.Fatal("no flow emitted")
	}
	if string(flow.ResponseBody) != page {
		t.Errorf("ResponseBody = %q, want the decompressed page %q", flow.ResponseBody, page)
	}
	if flow.ResponseBodyEncoding != "gzip" {
		t.Errorf("ResponseBodyEncoding = %q, want %q", flow.ResponseBodyEncoding, "gzip")
	}
}

// A QPACK-blocked response HEADERS is applied after its DATA frames have already arrived
// (retryBlocked), so the encoding is learnt late — the bytes taken as plain in the
// meantime still have to end up decoded.
func TestLiveHTTP3GzipEncodingLearntAfterData(t *testing.T) {
	const page = "headers decoded after the body arrived"
	st := &h3Stream{flow: &Flow{}}
	st.flow.appendRespBody(gzipBytes(t, page))

	st.setRespEnc("gzip")

	if string(st.flow.ResponseBody) != page {
		t.Errorf("ResponseBody = %q, want %q", st.flow.ResponseBody, page)
	}
	if st.flow.ResponseBodyEncoding != "gzip" {
		t.Errorf("ResponseBodyEncoding = %q, want %q", st.flow.ResponseBodyEncoding, "gzip")
	}
}

// The live HTTP/2 path already gunzipped at END_STREAM; it must now also say so, or a
// consumer can't tell a body that arrived plain from one that was decoded for it.
func TestLiveHTTP2RecordsGzipEncoding(t *testing.T) {
	const page = `{"h2":"gzipped"}`
	hf := &h2flow{id: 1, flow: &Flow{}}
	h := &h2Stream{
		onFlow:     func(*Flow, bool) {},
		flows:      map[uint32]*h2flow{1: hf},
		pendingRST: map[uint32]string{},
	}
	hf.respEnc = "gzip"

	raw := gzipBytes(t, page)
	h.onData(dataFrame(t, 1, raw[:len(raw)/2], false), false, time.Now())
	h.onData(dataFrame(t, 1, raw[len(raw)/2:], true), false, time.Now())

	if string(hf.flow.ResponseBody) != page {
		t.Errorf("ResponseBody = %q, want %q", hf.flow.ResponseBody, page)
	}
	if hf.flow.ResponseBodyEncoding != "gzip" {
		t.Errorf("ResponseBodyEncoding = %q, want %q", hf.flow.ResponseBodyEncoding, "gzip")
	}
}

// dataFrame builds one HTTP/2 DATA frame, read back through the framer so the test uses
// the same frame type the decoder does.
func dataFrame(t *testing.T, streamID uint32, data []byte, endStream bool) *http2.DataFrame {
	t.Helper()
	var buf bytes.Buffer
	fr := http2.NewFramer(&buf, &buf)
	if err := fr.WriteData(streamID, endStream, data); err != nil {
		t.Fatal(err)
	}
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	df, ok := f.(*http2.DataFrame)
	if !ok {
		t.Fatalf("read %T, want a DATA frame", f)
	}
	return df
}

// The HTTP/1.1 path decompresses while reading; it too must report the encoding it undid.
func TestLiveHTTP1RecordsGzipEncoding(t *testing.T) {
	const page = "plain after gunzip"
	resp := &http.Response{
		Header: http.Header{"Content-Encoding": {"gzip"}},
		Body:   io.NopCloser(bytes.NewReader(gzipBytes(t, page))),
	}

	body, truncated, enc := readRespBody(resp)

	if string(body) != page || truncated {
		t.Errorf("body = %q truncated=%v, want %q whole", body, truncated, page)
	}
	if enc != "gzip" {
		t.Errorf("encoding = %q, want %q", enc, "gzip")
	}
}

// An identity encoding is spelled-out absence, and a body of no bytes has no encoding to
// describe — neither should put a label on a flow.
func TestLiveHTTP1EncodingOmitted(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{"Content-Encoding": {"identity"}},
		Body:   io.NopCloser(strings.NewReader("plain")),
	}
	if _, _, enc := readRespBody(resp); enc != "" {
		t.Errorf("identity encoding = %q, want none", enc)
	}

	empty := &http.Response{
		Header: http.Header{"Content-Encoding": {"gzip"}},
		Body:   io.NopCloser(strings.NewReader("")),
	}
	if _, _, enc := readRespBody(empty); enc != "" {
		t.Errorf("empty body encoding = %q, want none — there are no bytes to describe", enc)
	}
}

// A gzip stream cut short (the live preview cap, a capture that ended mid-response)
// decompresses to as much as it has: a partial page beats no page.
func TestMaybeGunzipPartialStream(t *testing.T) {
	raw := gzipBytes(t, strings.Repeat("searchable ", 2000))
	got := maybeGunzip(raw[:len(raw)-20], noBodyLimit)
	if !strings.HasPrefix(string(got), "searchable searchable") {
		t.Errorf("partial gunzip = %.40q…, want the decompressed prefix", got)
	}
}
