package decode

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"testing"
)

func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

// A body past the decompression cap is cut there and the cut is reported; one that fits
// exactly is not called cut.
func TestDecodeBodyReportsACutAtTheCap(t *testing.T) {
	defer func(n int) { maxDecodedBytes = n }(maxDecodedBytes)
	maxDecodedBytes = 1000

	out, cut := decodeBody("gzip", gzipped(t, bytes.Repeat([]byte("z"), 5000)))
	if len(out) != 1000 || !cut {
		t.Fatalf("over the cap: got %d bytes, cut=%v; want 1000, true", len(out), cut)
	}
	out, cut = decodeBody("gzip", gzipped(t, bytes.Repeat([]byte("z"), 1000)))
	if len(out) != 1000 || cut {
		t.Fatalf("exactly the cap: got %d bytes, cut=%v; want 1000, false", len(out), cut)
	}
}

// The cut is named on the flow once per side, and the map a live snapshot already holds is
// never written into.
func TestNoteBodyCutNamesTheSideWithoutTouchingASnapshot(t *testing.T) {
	f := &Flow{Method: "GET", Authority: "example.com", Path: "/big",
		Metadata: map[string]string{"tls.sni": "example.com"}}
	snapshot := f.Metadata

	noteBodyCut(f, "response")
	noteBodyCut(f, "response")
	noteBodyCut(f, "request")

	if got := f.Metadata[BodyTruncatedKey]; got != "response,request" {
		t.Fatalf("%s = %q, want %q", BodyTruncatedKey, got, "response,request")
	}
	if f.Metadata["tls.sni"] != "example.com" {
		t.Fatal("the source's own metadata was lost")
	}
	if _, ok := snapshot[BodyTruncatedKey]; ok || len(snapshot) != 1 {
		t.Fatalf("the snapshot's map was written into: %v", snapshot)
	}
}

// The cap bounds decompression, not a body's own size: a plain HTTP/1.1 response past it is
// kept whole (it is no larger than the bytes captured), as on HTTP/2, while a gzip one that
// expands past it is cut.
func TestReadRespBodyCapsOnlyADecodedBody(t *testing.T) {
	defer func(n int) { maxDecodedBytes = n }(maxDecodedBytes)
	maxDecodedBytes = 1000
	plain := bytes.Repeat([]byte("p"), 5000)

	resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(plain))}
	if body, _, cut := readRespBody(resp); len(body) != len(plain) || cut {
		t.Fatalf("plain: %d bytes, cut=%v; want all %d, not cut", len(body), cut, len(plain))
	}
	resp = &http.Response{Header: http.Header{"Content-Encoding": {"gzip"}},
		Body: io.NopCloser(bytes.NewReader(gzipped(t, plain)))}
	if body, enc, cut := readRespBody(resp); len(body) != 1000 || !cut || enc != "gzip" {
		t.Fatalf("gzip: %d bytes, enc=%q, cut=%v; want 1000, gzip, cut", len(body), enc, cut)
	}
}
