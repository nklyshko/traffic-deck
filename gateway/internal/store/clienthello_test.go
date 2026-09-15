package store

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// TestClientHelloRoundTrip checks that a flow's raw ClientHello handshake messages and the
// HelloRetryRequest flag persist verbatim and come back in wire order via GetFlow.
func TestClientHelloRoundTrip(t *testing.T) {
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

	// Two ClientHellos (as after a HelloRetryRequest), with a NUL byte to prove BLOB fidelity.
	ch1 := []byte{0x01, 0x00, 0x00, 0x03, 0x03, 0x00, 0xAA}
	ch2 := []byte{0x01, 0x00, 0x00, 0x02, 0x03, 0x03}
	fid := uuid.NewString()
	if _, err := st.InsertFlows(ctx, sid, aid, []*decode.Flow{{
		ID: fid, Method: "GET", Authority: "x", Protocol: "HTTP/2", Status: 200,
		TLSDecrypted: true, ClientHellos: [][]byte{ch1, ch2}, TLSHRR: true,
	}}); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetFlow(ctx, sid, fid)
	if err != nil {
		t.Fatal(err)
	}
	if !got.GetTlsHrr() {
		t.Error("tls_hrr = false, want true")
	}
	chs := got.GetClientHellos()
	if len(chs) != 2 {
		t.Fatalf("client_hellos n=%d, want 2", len(chs))
	}
	if !bytes.Equal(chs[0], ch1) || !bytes.Equal(chs[1], ch2) {
		t.Errorf("client_hellos = %x, %x; want %x, %x", chs[0], chs[1], ch1, ch2)
	}
}

// TestClientHelloUpsertReplaces checks that re-inserting a flow (the mitmproxy request-then-
// response upsert) replaces its ClientHello rows instead of duplicating them.
func TestClientHelloUpsertReplaces(t *testing.T) {
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
	base := &decode.Flow{ID: fid, Method: "GET", Authority: "x", Protocol: "HTTP/2",
		TLSDecrypted: true, ClientHellos: [][]byte{{0x01, 0x00, 0x00, 0x01, 0x03}}}
	if _, err := st.InsertFlows(ctx, sid, aid, []*decode.Flow{base}); err != nil {
		t.Fatal(err)
	}
	base.Status = 200 // re-push on response
	if _, err := st.InsertFlows(ctx, sid, aid, []*decode.Flow{base}); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetFlow(ctx, sid, fid)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(got.GetClientHellos()); n != 1 {
		t.Fatalf("after re-push client_hellos n=%d, want 1 (no duplication)", n)
	}
}
