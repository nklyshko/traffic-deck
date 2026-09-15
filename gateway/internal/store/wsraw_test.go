package store

import (
	"context"
	"testing"

	"github.com/google/uuid"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// TestWsMessageRawRoundTrip checks that a WebSocket message's original (undecoded) bytes
// persist in the raw field and are retrievable via ListMessages + GetWsMessageBody(raw).
func TestWsMessageRawRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	sid := uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{
		ID: sid, Source: "import",
		Status: trafficv1.SessionStatus_SESSION_STATUS_DECODING,
	}); err != nil {
		t.Fatal(err)
	}
	aid := uuid.NewString()
	if err := st.CreateAnalysis(ctx, NewAnalysis{ID: aid, SessionID: sid, Engine: "live"}); err != nil {
		t.Fatal(err)
	}
	fid := uuid.NewString()
	if _, err := st.InsertFlows(ctx, sid, aid, []*decode.Flow{
		{ID: fid, Protocol: "MAX", Websocket: true},
	}); err != nil {
		t.Fatal(err)
	}

	decodedID := uuid.NewString()
	if _, err := st.InsertWsMessages(ctx, sid, []*decode.WsMessage{
		// decoder-produced: decoded Payload + original Raw
		{ID: decodedID, FlowID: fid, TSUnixMicros: 100, FromClient: true, Opcode: "cmd", Payload: []byte("decoded"), Raw: []byte("RAWBYTES")},
		// plain frame: no Raw
		{ID: uuid.NewString(), FlowID: fid, TSUnixMicros: 200, FromClient: false, Opcode: "text", Payload: []byte("hi")},
	}); err != nil {
		t.Fatal(err)
	}

	msgs, err := st.ListMessages(ctx, sid, fid)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("list: n=%d err=%v", len(msgs), err)
	}
	if string(msgs[0].GetPayload().GetInline()) != "decoded" {
		t.Errorf("decoded payload = %q", msgs[0].GetPayload().GetInline())
	}
	if string(msgs[0].GetRaw().GetInline()) != "RAWBYTES" {
		t.Errorf("raw inline = %q, want RAWBYTES", msgs[0].GetRaw().GetInline())
	}
	if msgs[1].GetRaw() != nil {
		t.Errorf("plain frame should have no raw: %+v", msgs[1].GetRaw())
	}

	// GetWsMessageBody: decoded vs raw.
	if b, err := st.GetWsMessageBody(ctx, sid, decodedID, false); err != nil || string(b) != "decoded" {
		t.Fatalf("get decoded = %q err=%v", b, err)
	}
	if b, err := st.GetWsMessageBody(ctx, sid, decodedID, true); err != nil || string(b) != "RAWBYTES" {
		t.Fatalf("get raw = %q err=%v", b, err)
	}
}
