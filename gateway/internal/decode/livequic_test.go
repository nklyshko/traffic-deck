package decode

import (
	"bytes"
	"sync"
	"testing"

	"github.com/quic-go/qpack"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

// putUvarint encodes a QUIC varint (1-byte form is enough for our small test frames).
func putUvarint(v uint64) []byte {
	if v < 64 {
		return []byte{byte(v)}
	}
	return []byte{0x40 | byte(v>>8), byte(v)} // 2-byte form
}

func qpackSection(fields ...qpack.HeaderField) []byte {
	var b bytes.Buffer
	enc := qpack.NewEncoder(&b)
	for _, f := range fields {
		_ = enc.WriteField(f)
	}
	return b.Bytes()
}

func h3Frame(t uint64, payload []byte) []byte {
	out := append([]byte(nil), putUvarint(t)...)
	out = append(out, putUvarint(uint64(len(payload)))...)
	return append(out, payload...)
}

func TestLiveHTTP3RequestResponse(t *testing.T) {
	var mu sync.Mutex
	var flow *Flow
	onFlow := func(f *Flow, _ bool) { mu.Lock(); flow = f; mu.Unlock() }
	s := newQUICSession(tlsdecrypt.NewKeylog(""), onFlow, "203.0.113.5", "443", "198.51.100.2:50000")

	// Request stream 0 (client bidirectional): HEADERS then DATA.
	reqHdr := h3Frame(h3FrameHeaders, qpackSection(
		qpack.HeaderField{Name: ":method", Value: "GET"},
		qpack.HeaderField{Name: ":scheme", Value: "https"},
		qpack.HeaderField{Name: ":authority", Value: "example.com"},
		qpack.HeaderField{Name: ":path", Value: "/h3?q=1"},
		qpack.HeaderField{Name: "user-agent", Value: "probe/3"},
	))
	s.onStream(0, true, reqHdr)

	respHdr := h3Frame(h3FrameHeaders, qpackSection(
		qpack.HeaderField{Name: ":status", Value: "200"},
		qpack.HeaderField{Name: "content-type", Value: "application/json"},
	))
	s.onStream(0, false, respHdr)
	s.onStream(0, false, h3Frame(h3FrameData, []byte(`{"ok":true}`)))

	mu.Lock()
	defer mu.Unlock()
	if flow == nil {
		t.Fatal("no flow emitted")
	}
	if flow.Protocol != "HTTP/3" || flow.H2StreamID != "0" {
		t.Errorf("proto=%q stream=%q", flow.Protocol, flow.H2StreamID)
	}
	if flow.Method != "GET" || flow.Path != "/h3" || flow.Query != "q=1" || flow.Authority != "example.com" {
		t.Errorf("req: method=%q path=%q query=%q authority=%q", flow.Method, flow.Path, flow.Query, flow.Authority)
	}
	if flow.UserAgent != "probe/3" || !flow.TLSDecrypted {
		t.Errorf("meta: ua=%q tls=%v", flow.UserAgent, flow.TLSDecrypted)
	}
	if flow.Status != 200 || flow.ContentType != "application/json" {
		t.Errorf("resp: status=%d ct=%q", flow.Status, flow.ContentType)
	}
	if string(flow.ResponseBody) != `{"ok":true}` {
		t.Errorf("body=%q", flow.ResponseBody)
	}
}
