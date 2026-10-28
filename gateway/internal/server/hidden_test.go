package server

import (
	"context"
	"testing"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// DNS lookups and connections nothing decoded are recorded but hidden by default: a page
// leaves them out and says how many it left out — from the bundle and from an open
// session's unflushed tail alike — and include_hidden brings them back. A raw TCP stream
// nothing claimed is not hidden: its payload is there to read.
func TestHiddenFlowsAreCountedNotShown(t *testing.T) {
	ctx := context.Background()
	st, sid := queryTestStore(t)
	defer st.Close()

	if _, err := st.InsertFlows(ctx, sid, "a1", []*decode.Flow{
		{ID: "http", Method: "GET", Authority: "api.example.com", Protocol: "HTTP/2", Status: 200, TSUnixMicros: 1},
		{ID: "dns", Method: "A", Authority: "api.example.com", Protocol: "DNS", TSUnixMicros: 2},
		{ID: "pinned", Authority: "pinned.example.com", Protocol: "TCP", TSUnixMicros: 3,
			Metadata: map[string]string{"conn.outcome": "tls_rejected"}},
		{ID: "raw", Authority: "mtalk.google.com", Protocol: "TCP", TSUnixMicros: 4,
			Metadata: map[string]string{"conn.outcome": "tcp_passthrough"}},
	}); err != nil {
		t.Fatal(err)
	}
	hub := newLiveHub()
	ls := hub.startPassive(sid)
	ls.publish(&trafficv1.Flow{Id: "udp", Authority: "stun.example.com", Protocol: "UDP", TsUnixMicros: 5,
		Metadata: map[string]string{"conn.outcome": "udp_undecoded"}}, true)
	v := NewViewer(st, hub)

	page, err := v.QueryFlows(ctx, &trafficv1.QueryFlowsRequest{SessionId: sid, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := pageIDs(page); len(got) != 2 || got[0] != "http" || got[1] != "raw" {
		t.Fatalf("default page = %v, want the HTTP flow and the raw TCP stream", got)
	}
	if page.GetMatched() != 2 || page.GetHiddenMatched() != 3 {
		t.Fatalf("matched %d hidden %d, want 2 and 3", page.GetMatched(), page.GetHiddenMatched())
	}

	// A filter narrows the hidden count too, so a reader learns what *its* query left out.
	page, err = v.QueryFlows(ctx, &trafficv1.QueryFlowsRequest{SessionId: sid, Limit: 10, Filter: "~d api"})
	if err != nil {
		t.Fatal(err)
	}
	if page.GetMatched() != 1 || page.GetHiddenMatched() != 1 {
		t.Fatalf("~d api: matched %d hidden %d, want 1 and 1", page.GetMatched(), page.GetHiddenMatched())
	}

	page, err = v.QueryFlows(ctx, &trafficv1.QueryFlowsRequest{SessionId: sid, Limit: 10, IncludeHidden: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := pageIDs(page); len(got) != 5 || page.GetHiddenMatched() != 0 {
		t.Fatalf("include_hidden page = %v (hidden %d), want all five and nothing hidden", got, page.GetHiddenMatched())
	}

	page, err = v.QueryFlows(ctx, &trafficv1.QueryFlowsRequest{SessionId: sid, Limit: 10,
		IncludeHidden: true, Filter: "!~proto ^DNS$"})
	if err != nil {
		t.Fatal(err)
	}
	if got := pageIDs(page); len(got) != 4 {
		t.Fatalf("!~proto ^DNS$ = %v, want everything but the lookup", got)
	}
}

func TestStreamFlowsLeavesHiddenFlowsOutUnlessAsked(t *testing.T) {
	for _, include := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		st, sid := queryTestStore(t)
		hub := newLiveHub()
		ls := hub.startPassive(sid)
		v := NewViewer(st, hub)
		s := &collectStream{ctx: ctx}
		done := make(chan error, 1)
		go func() {
			done <- v.StreamFlows(&trafficv1.StreamFlowsRequest{SessionId: sid, Follow: true, IncludeHidden: include}, s)
		}()
		waitForSubscriber(t, ls)
		ls.publish(&trafficv1.Flow{Id: "dns", Protocol: "DNS", Authority: "a.example", TsUnixMicros: 1}, true)
		ls.publish(&trafficv1.Flow{Id: "http", Protocol: "HTTP/1.1", Method: "GET", Authority: "a.example", TsUnixMicros: 2}, true)
		want := 1
		if include {
			want = 2
		}
		waitFor(t, func() bool { return s.flowCount() >= want })
		got := s.kinds()
		if len(got) != want || got[len(got)-1] != "added:http" {
			t.Fatalf("include_hidden=%v streamed %v", include, got)
		}
		cancel()
		<-done
		st.Close()
	}
}

func pageIDs(p *trafficv1.FlowPage) []string {
	var out []string
	for _, f := range p.GetFlows() {
		out = append(out, f.GetId())
	}
	return out
}
