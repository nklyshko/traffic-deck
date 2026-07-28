package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// TestInsertHeadersChunking checks that a flow with more headers than fit in one
// multi-row INSERT still round-trips every header, in order, on both directions —
// the chunk boundary (headerChunk) is otherwise invisible.
func TestInsertHeadersChunking(t *testing.T) {
	// Sizes either side of the chunk boundary, including an exact multiple.
	for _, n := range []int{1, headerChunk - 1, headerChunk, headerChunk + 1, 2*headerChunk + 5} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			ctx := context.Background()
			st, err := Open(ctx, t.TempDir())
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer st.Close()

			sid, aid := uuid.NewString(), uuid.NewString()
			if err := st.CreateSession(ctx, NewSession{ID: sid}); err != nil {
				t.Fatalf("create session: %v", err)
			}
			if err := st.CreateAnalysis(ctx, NewAnalysis{ID: aid, SessionID: sid, Engine: "live"}); err != nil {
				t.Fatalf("create analysis: %v", err)
			}

			f := &decode.Flow{ID: "f1", Method: "GET", Authority: "example.com", Path: "/"}
			for i := range n {
				f.RequestHeaders = append(f.RequestHeaders, decode.Header{
					Name: fmt.Sprintf("x-req-%03d", i), Value: fmt.Sprintf("v%d", i)})
				f.ResponseHeaders = append(f.ResponseHeaders, decode.Header{
					Name: fmt.Sprintf("x-resp-%03d", i), Value: fmt.Sprintf("w%d", i)})
			}
			if _, err := st.InsertFlows(ctx, sid, aid, []*decode.Flow{f}); err != nil {
				t.Fatalf("insert flows: %v", err)
			}

			got, err := st.GetFlow(ctx, sid, "f1")
			if err != nil {
				t.Fatalf("get flow: %v", err)
			}
			if len(got.RequestHeaders) != n || len(got.ResponseHeaders) != n {
				t.Fatalf("header counts: req=%d resp=%d, want %d each",
					len(got.RequestHeaders), len(got.ResponseHeaders), n)
			}
			for i := range n {
				if h := got.RequestHeaders[i]; h.Name != fmt.Sprintf("x-req-%03d", i) || h.Value != fmt.Sprintf("v%d", i) {
					t.Fatalf("request header %d: got %s=%s", i, h.Name, h.Value)
				}
				if h := got.ResponseHeaders[i]; h.Name != fmt.Sprintf("x-resp-%03d", i) || h.Value != fmt.Sprintf("w%d", i) {
					t.Fatalf("response header %d: got %s=%s", i, h.Name, h.Value)
				}
			}
		})
	}
}

// TestInsertFlowsReplacesHeaders checks the re-insert path: a flow inserted twice (the
// mitmproxy push pattern — request first, then again with the response) ends up with
// only the second insert's headers, not both sets appended.
func TestInsertFlowsReplacesHeaders(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	sid, aid := uuid.NewString(), uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{ID: sid}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := st.CreateAnalysis(ctx, NewAnalysis{ID: aid, SessionID: sid, Engine: "live"}); err != nil {
		t.Fatalf("create analysis: %v", err)
	}

	first := &decode.Flow{ID: "f1", Method: "GET", Authority: "example.com", Path: "/",
		RequestHeaders: []decode.Header{{Name: "accept", Value: "*/*"}}}
	if _, err := st.InsertFlows(ctx, sid, aid, []*decode.Flow{first}); err != nil {
		t.Fatalf("insert 1: %v", err)
	}

	second := &decode.Flow{ID: "f1", Method: "GET", Authority: "example.com", Path: "/", Status: 200,
		RequestHeaders:  []decode.Header{{Name: "accept", Value: "*/*"}, {Name: "user-agent", Value: "probe"}},
		ResponseHeaders: []decode.Header{{Name: "content-type", Value: "text/html"}}}
	if _, err := st.InsertFlows(ctx, sid, aid, []*decode.Flow{second}); err != nil {
		t.Fatalf("insert 2: %v", err)
	}

	got, err := st.GetFlow(ctx, sid, "f1")
	if err != nil {
		t.Fatalf("get flow: %v", err)
	}
	if len(got.RequestHeaders) != 2 || len(got.ResponseHeaders) != 1 {
		t.Fatalf("headers after re-insert: req=%d resp=%d, want 2 and 1",
			len(got.RequestHeaders), len(got.ResponseHeaders))
	}
	if got.Status != 200 {
		t.Fatalf("status: got %d, want 200", got.Status)
	}
}
