package decode

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestSetUnlimitedLiveBodies checks the live body cap and its removal for record-live mode.
func TestSetUnlimitedLiveBodies(t *testing.T) {
	saved := maxLiveBody
	defer func() { maxLiveBody = saved }()

	maxLiveBody = 4
	if got := appendCapped(nil, []byte("hello")); string(got) != "hell" {
		t.Fatalf("capped append = %q, want %q", got, "hell")
	}

	SetUnlimitedLiveBodies()
	big := bytes.Repeat([]byte("x"), 1<<20)
	if got := appendCapped(nil, big); len(got) != len(big) {
		t.Fatalf("uncapped append = %d bytes, want %d", len(got), len(big))
	}
}

// TestAppendBodyMarksTruncation checks that the streaming appends flag a body the cap cut
// short — and only then. Without the flag a reader takes the prefix for the whole body.
func TestAppendBodyMarksTruncation(t *testing.T) {
	saved := maxLiveBody
	defer func() { maxLiveBody = saved }()
	maxLiveBody = 4

	var f Flow
	f.appendReqBody([]byte("abc"))
	if f.RequestBodyTruncated {
		t.Fatal("3 bytes under a 4-byte cap must not be flagged")
	}
	f.appendReqBody([]byte("de")) // one byte fits, one is dropped
	if string(f.RequestBody) != "abcd" || !f.RequestBodyTruncated {
		t.Fatalf("request body = %q truncated=%v, want %q flagged", f.RequestBody, f.RequestBodyTruncated, "abcd")
	}
	if f.ResponseBodyTruncated {
		t.Fatal("the response direction must be unaffected")
	}

	f.appendRespBody(bytes.Repeat([]byte("y"), 9))
	if string(f.ResponseBody) != "yyyy" || !f.ResponseBodyTruncated {
		t.Fatalf("response body = %q truncated=%v, want %q flagged", f.ResponseBody, f.ResponseBodyTruncated, "yyyy")
	}

	// Uncapped (record-live): whole bodies, nothing flagged.
	SetUnlimitedLiveBodies()
	var g Flow
	g.appendRespBody(bytes.Repeat([]byte("z"), 1<<20))
	if len(g.ResponseBody) != 1<<20 || g.ResponseBodyTruncated {
		t.Fatalf("uncapped body = %d bytes truncated=%v, want the lot unflagged",
			len(g.ResponseBody), g.ResponseBodyTruncated)
	}
}

// TestReadBodyMarksTruncation covers the HTTP/1.1 path, which caps with a LimitReader
// rather than appendCapped: the drained remainder is what says the body was cut short.
func TestReadBodyMarksTruncation(t *testing.T) {
	saved := maxLiveBody
	defer func() { maxLiveBody = saved }()
	maxLiveBody = 4

	data, truncated := drainBody(io.NopCloser(strings.NewReader("abcdefgh")))
	if string(data) != "abcd" || !truncated {
		t.Fatalf("drainBody = %q truncated=%v, want %q flagged", data, truncated, "abcd")
	}
	if data, truncated := drainBody(io.NopCloser(strings.NewReader("ab"))); string(data) != "ab" || truncated {
		t.Fatalf("drainBody (short) = %q truncated=%v, want %q unflagged", data, truncated, "ab")
	}
	if data, truncated := drainBody(nil); data != nil || truncated {
		t.Fatalf("drainBody (no body) = %q truncated=%v, want nothing unflagged", data, truncated)
	}

	resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader("abcdefgh"))}
	if data, truncated, _ := readRespBody(resp); string(data) != "abcd" || !truncated {
		t.Fatalf("readRespBody = %q truncated=%v, want %q flagged", data, truncated, "abcd")
	}
}
