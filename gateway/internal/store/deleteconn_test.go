package store

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// TestDeleteFlowsByConnection covers narrowing a flow list by the connections a
// per-process capture proved belonged to another process.
//
// Three things have to hold, and each has a way of failing silently: a connection matches
// whichever way round the flow names its endpoints, a tunnelled flow is matched by the
// proxy it actually talked to rather than the target it records, and a flow on no listed
// connection is never touched.
func TestDeleteFlowsByConnection(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	sid := uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{ID: sid, Source: "pktap"}); err != nil {
		t.Fatal(err)
	}
	aid := uuid.NewString()
	if err := st.CreateAnalysis(ctx, NewAnalysis{ID: aid, SessionID: sid, Engine: "live"}); err != nil {
		t.Fatal(err)
	}

	mine := &decode.Flow{
		ID: "mine", Authority: "ours.example", SrcAddr: "192.168.1.240:49152",
		DstAddr: "93.184.216.34:443",
	}
	theirs := &decode.Flow{
		ID: "theirs", Authority: "speedtest.example", SrcAddr: "192.168.1.240:50000",
		DstAddr: "1.1.1.1:443",
	}
	// The same connection, named the other way round by the decoder.
	reversed := &decode.Flow{
		ID: "reversed", Authority: "speedtest.example", SrcAddr: "1.1.1.1:443",
		DstAddr: "192.168.1.240:50000",
	}
	// Tunnelled: dst_addr is the *target*, and only proxy_addr names the endpoint any
	// packet on the wire actually carried.
	tunnelled := &decode.Flow{
		ID: "tunnelled", Authority: "speedtest.example", SrcAddr: "192.168.1.240:50002",
		DstAddr: "203.0.113.9:443",
		Proxy:   &decode.FlowProxy{Addr: "176.12.75.158:9675", Type: "http"},
	}
	if _, err := st.InsertFlows(ctx, sid, aid, []*decode.Flow{mine, theirs, reversed, tunnelled}); err != nil {
		t.Fatal(err)
	}

	n, err := st.DeleteFlowsByConnection(ctx, sid, [][2]string{
		{"192.168.1.240:50000", "1.1.1.1:443"},
		{"176.12.75.158:9675", "192.168.1.240:50002"}, // given proxy-first, to check ordering
	})
	if err != nil {
		t.Fatalf("DeleteFlowsByConnection: %v", err)
	}
	if n != 3 {
		t.Errorf("deleted %d flows, want 3 (both directions plus the tunnelled one)", n)
	}

	left, err := st.ListFlows(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 || left[0].GetId() != "mine" {
		ids := make([]string, len(left))
		for i, f := range left {
			ids[i] = f.GetId()
		}
		t.Errorf("remaining flows = %v, want just [mine]", ids)
	}
}

// TestDeleteFlowsByConnectionIgnoresAnEmptyList is the no-op guard: a capture with
// nothing to narrow must not have a query run against it that could match everything.
func TestDeleteFlowsByConnectionIgnoresAnEmptyList(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	sid := uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{ID: sid, Source: "chrome"}); err != nil {
		t.Fatal(err)
	}
	aid := uuid.NewString()
	if err := st.CreateAnalysis(ctx, NewAnalysis{ID: aid, SessionID: sid, Engine: "live"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertFlows(ctx, sid, aid, []*decode.Flow{
		{ID: "a", SrcAddr: "10.0.0.1:1", DstAddr: "10.0.0.2:443"},
	}); err != nil {
		t.Fatal(err)
	}

	n, err := st.DeleteFlowsByConnection(ctx, sid, nil)
	if err != nil || n != 0 {
		t.Fatalf("DeleteFlowsByConnection(nil) = %d, %v; want 0, nil", n, err)
	}
	left, err := st.ListFlows(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 {
		t.Errorf("an empty connection list removed %d flows", 1-len(left))
	}
}
