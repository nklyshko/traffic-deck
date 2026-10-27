package decode

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

// reports records every onFlow call as the reader at that moment saw it, so a test can
// ask what a report said rather than only what the flow ended up as.
type reports struct {
	mu   sync.Mutex
	seen []Flow
}

func (r *reports) onFlow(f *Flow, _ bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, *f)
}

func (r *reports) waitFor(t *testing.T, what string, ok func(Flow) bool) Flow {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		r.mu.Lock()
		for _, f := range r.seen {
			if ok(f) {
				r.mu.Unlock()
				return f
			}
		}
		r.mu.Unlock()
	}
	t.Fatalf("no report %s", what)
	return Flow{}
}

func h2Conn(r *reports) *h2Stream {
	return newH2Stream(&tcpStream{
		lt: &liveTCP{onFlow: r.onFlow}, connID: "1",
		serverHost: "203.0.113.5", serverPort: "443", clientAddr: "198.51.100.2:51000",
		conn: tlsdecrypt.NewConn(tlsdecrypt.NewKeylog(""), nil),
	})
}

func h2ServerFrames(t *testing.T, write func(*http2.Framer)) []byte {
	t.Helper()
	var b bytes.Buffer
	f := http2.NewFramer(&b, nil)
	if err := f.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	write(f)
	return b.Bytes()
}

func h2Headers(t *testing.T, f *http2.Framer, end bool, fields ...hpack.HeaderField) {
	t.Helper()
	if err := f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: h2encode(fields...),
		EndStream: end, EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
}

// HTTP/2 reports a flow on its response HEADERS and is silent through the DATA frames, so
// that report must not claim the body is finished — persistence would store it empty.
func TestH2BodyIsDoneOnlyAtEndOfStream(t *testing.T) {
	r := &reports{}
	h := h2Conn(r)
	h.feed(true, h2Request(t, 1, "/big"))
	h.feed(false, h2ServerFrames(t, func(f *http2.Framer) {
		h2Headers(t, f, false, hpack.HeaderField{Name: ":status", Value: "200"})
	}))
	if head := r.waitFor(t, "with the status", func(f Flow) bool { return f.Status == 200 }); head.BodyDone {
		t.Fatal("the HEADERS report said the body was done")
	}

	var data bytes.Buffer
	if err := http2.NewFramer(&data, nil).WriteData(1, true, []byte("the whole body")); err != nil {
		t.Fatal(err)
	}
	h.feed(false, data.Bytes())
	end := r.waitFor(t, "with the body done", func(f Flow) bool { return f.BodyDone })
	if string(end.ResponseBody) != "the whole body" {
		t.Fatalf("done report body = %q", end.ResponseBody)
	}
	h.close()
}

// Trailers end the stream on a HEADERS frame, after the DATA: the body is done there, and
// one still in its wire encoding has to be decoded there too, since no DATA frame will.
func TestH2TrailersEndTheBodyAndDecodeIt(t *testing.T) {
	r := &reports{}
	h := h2Conn(r)
	h.feed(true, h2Request(t, 1, "/gz"))
	h.feed(false, h2ServerFrames(t, func(f *http2.Framer) {
		h2Headers(t, f, false, hpack.HeaderField{Name: ":status", Value: "200"},
			hpack.HeaderField{Name: "content-encoding", Value: "gzip"})
		if err := f.WriteData(1, false, gzipBytes(t, "decoded at the trailers")); err != nil {
			t.Fatal(err)
		}
		h2Headers(t, f, true, hpack.HeaderField{Name: "grpc-status", Value: "0"})
	}))
	end := r.waitFor(t, "with the body done", func(f Flow) bool { return f.BodyDone })
	if string(end.ResponseBody) != "decoded at the trailers" {
		t.Fatalf("body = %q, want it decoded", end.ResponseBody)
	}
	h.close()
}

// A connection that ends mid-response leaves no frame to say so; its end does. Whatever
// each open stream has is all it will get.
func TestH2ConnectionEndFinishesOpenBodies(t *testing.T) {
	r := &reports{}
	h := h2Conn(r)
	h.feed(true, h2Request(t, 1, "/cut"))
	h.feed(false, h2ServerFrames(t, func(f *http2.Framer) {
		h2Headers(t, f, false, hpack.HeaderField{Name: ":status", Value: "200"})
		if err := f.WriteData(1, false, []byte("cut short")); err != nil {
			t.Fatal(err)
		}
	}))
	r.waitFor(t, "with the status", func(f Flow) bool { return f.Status == 200 })
	h.close()
	if end := r.waitFor(t, "with the body done", func(f Flow) bool { return f.BodyDone }); string(end.ResponseBody) != "cut short" {
		t.Fatalf("body = %q", end.ResponseBody)
	}
}

// HTTP/3 reports a flow on every DATA frame, so a pause between frames used to look like
// the end. Only the FIN on the server's half of the stream — or the connection ending —
// says the response is complete.
func TestH3BodyIsDoneAtTheServersFIN(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(s *quicSession)
	}{
		{"FIN", func(s *quicSession) { s.onStream(0, false, nil, true) }},
		{"connection close", func(s *quicSession) { s.close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &reports{}
			s := newQUICSession(&liveTCP{keylog: tlsdecrypt.NewKeylog(""), onFlow: r.onFlow},
				"quic:0", "203.0.113.5", "443", "198.51.100.2:50000")
			s.onStream(0, true, h3Frame(h3FrameHeaders, qpackSection(
				qpack.HeaderField{Name: ":method", Value: "GET"},
				qpack.HeaderField{Name: ":path", Value: "/big"},
			)), true)
			s.onStream(0, false, h3Frame(h3FrameHeaders, qpackSection(
				qpack.HeaderField{Name: ":status", Value: "200"},
			)), false)
			s.onStream(0, false, h3Frame(h3FrameData, []byte("first part")), false)
			r.waitFor(t, "with the first DATA", func(f Flow) bool { return len(f.ResponseBody) > 0 })
			for _, f := range r.seen {
				if f.BodyDone {
					t.Fatalf("a report before the end said the body was done (%q)", f.ResponseBody)
				}
			}

			tc.end(s)
			if end := r.waitFor(t, "with the body done", func(f Flow) bool { return f.BodyDone }); string(end.ResponseBody) != "first part" {
				t.Fatalf("done report body = %q", end.ResponseBody)
			}
		})
	}
}

// HTTP/1.1 reports a flow when its request is read and again once the whole response
// body is: only the second report is final. A request whose connection ends without a
// response is final too — that connection has nothing more to say about it.
func TestH1BodyIsDoneWithTheResponseOrTheConnection(t *testing.T) {
	newConn := func(r *reports) *httpStream {
		return newHTTPStream(&tcpStream{lt: &liveTCP{onFlow: r.onFlow},
			serverHost: "203.0.113.5", serverPort: "80", clientAddr: "198.51.100.2:51000",
			conn: tlsdecrypt.NewConn(tlsdecrypt.NewKeylog(""), nil)})
	}

	r := &reports{}
	h := newConn(r)
	h.feed(true, []byte("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	h.feed(false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
	end := r.waitFor(t, "with the body done", func(f Flow) bool { return f.BodyDone })
	if end.Status != 200 || string(end.ResponseBody) != "hello" {
		t.Fatalf("done report = status %d body %q", end.Status, end.ResponseBody)
	}
	if first := r.seen[0]; first.BodyDone {
		t.Fatal("the request-time report said the body was done")
	}
	h.close()

	r = &reports{}
	h = newConn(r)
	h.feed(true, []byte("GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	r.waitFor(t, "for the request", func(f Flow) bool { return f.Path == "/b" })
	h.close()
	if end := r.waitFor(t, "with the body done", func(f Flow) bool { return f.BodyDone }); end.Status != 0 {
		t.Fatalf("response-less flow got status %d", end.Status)
	}
}

// A stream reset after the response began leaves part of a body. The flow must say so,
// or it reads as a whole 200 response; a reset after the response ended changes nothing.
// The reset rides the server's byte stream right after the DATA, so the two are parsed in
// that order — a client reset would race the DATA on the other direction's goroutine.
func TestH2ResetAfterHeadersMarksTheBodyCut(t *testing.T) {
	for _, tc := range []struct {
		name      string
		endStream bool
		wantErr   string
	}{
		{"mid-body", false, "HTTP/2 RST_STREAM: INTERNAL_ERROR — response cut short"},
		{"after the end", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &reports{}
			h := h2Conn(r)
			h.feed(true, h2Request(t, 1, "/img.jpg"))
			h.feed(false, h2ServerFrames(t, func(f *http2.Framer) {
				h2Headers(t, f, false, hpack.HeaderField{Name: ":status", Value: "200"})
				if err := f.WriteData(1, tc.endStream, []byte("first 3 KB")); err != nil {
					t.Fatal(err)
				}
				if err := f.WriteRSTStream(1, http2.ErrCodeInternal); err != nil {
					t.Fatal(err)
				}
				if err := f.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, // a marker: all of the above is parsed
					BlockFragment: h2encode(hpack.HeaderField{Name: ":status", Value: "204"}),
					EndStream:     true, EndHeaders: true}); err != nil {
					t.Fatal(err)
				}
			}))
			r.waitFor(t, "for the marker stream", func(f Flow) bool { return f.Status == 204 })
			r.mu.Lock()
			var last Flow
			for _, f := range r.seen {
				if f.Status == 200 {
					last = f
				}
			}
			r.mu.Unlock()
			if !last.BodyDone || last.Error != tc.wantErr || string(last.ResponseBody) != "first 3 KB" {
				t.Fatalf("flow = done %v error %q body %q, want done, error %q",
					last.BodyDone, last.Error, last.ResponseBody, tc.wantErr)
			}
			h.close()
		})
	}
}

// HTTP/3 cancels a response with the server's RESET_STREAM (after the client's
// STOP_SENDING). The response is over at that point, and the flow says why — with "cut
// short" once a status was in; H3_NO_ERROR ends it quietly; a client reset abandons only
// the request body and ends nothing.
func TestH3ResetEndsTheResponseAndSaysWhy(t *testing.T) {
	for _, tc := range []struct {
		name       string
		withStatus bool
		fromClient bool
		code       uint64
		wantDone   bool
		wantErr    string
	}{
		{"cancelled mid-body", true, false, 0x10c, true, "HTTP/3 RESET_STREAM: H3_REQUEST_CANCELLED — response cut short"},
		{"rejected before a response", false, false, 0x10b, true, "HTTP/3 RESET_STREAM: H3_REQUEST_REJECTED"},
		{"no error", true, false, 0x100, true, ""},
		{"client reset", true, true, 0x10c, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &reports{}
			s := newQUICSession(&liveTCP{keylog: tlsdecrypt.NewKeylog(""), onFlow: r.onFlow},
				"quic:0", "203.0.113.5", "443", "198.51.100.2:50000")
			if s.conn.OnReset == nil {
				t.Fatal("the session does not hear resets from the QUIC layer")
			}
			s.onStream(0, true, h3Frame(h3FrameHeaders, qpackSection(
				qpack.HeaderField{Name: ":method", Value: "GET"},
				qpack.HeaderField{Name: ":path", Value: "/img.jpg"},
			)), false)
			if tc.withStatus {
				s.onStream(0, false, h3Frame(h3FrameHeaders, qpackSection(
					qpack.HeaderField{Name: ":status", Value: "200"},
				)), false)
				s.onStream(0, false, h3Frame(h3FrameData, []byte("first 3 KB")), false)
			}
			s.onReset(0, tc.fromClient, tc.code)

			r.mu.Lock()
			last := r.seen[len(r.seen)-1]
			r.mu.Unlock()
			if last.BodyDone != tc.wantDone || last.Error != tc.wantErr {
				t.Fatalf("flow = done %v error %q, want done %v error %q",
					last.BodyDone, last.Error, tc.wantDone, tc.wantErr)
			}
		})
	}
}
