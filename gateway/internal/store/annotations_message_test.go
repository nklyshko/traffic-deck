package store

import (
	"context"
	"testing"

	"github.com/google/uuid"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// TestMessageAnnotations checks that a WebSocket/parsed message is annotatable like a flow:
// marks/tags/comments keyed on the message id round-trip through GetMessage and ListMessages.
func TestMessageAnnotations(t *testing.T) {
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
	m1, m2 := uuid.NewString(), uuid.NewString()
	if _, err := st.InsertWsMessages(ctx, sid, []*decode.WsMessage{
		{ID: m1, FlowID: fid, TSUnixMicros: 100, FromClient: true, Opcode: "text", Payload: []byte("a")},
		{ID: m2, FlowID: fid, TSUnixMicros: 200, FromClient: false, Opcode: "text", Payload: []byte("b")},
	}); err != nil {
		t.Fatal(err)
	}

	// Mark m1, tag both, comment on m1 — using the same record-keyed store APIs as flows.
	if err := st.SetMark(ctx, sid, []string{m1}, "red"); err != nil {
		t.Fatal(err)
	}
	tag, err := st.CreateTag(ctx, "ws-tag", "green")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetTags(ctx, sid, []string{m1, m2}, []string{tag.Id}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddComment(ctx, sid, m1, "first frame"); err != nil {
		t.Fatal(err)
	}

	// GetMessage attaches the annotations.
	got, err := st.GetMessage(ctx, sid, m1)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetMarkColor() != "red" {
		t.Errorf("m1 mark = %q, want red", got.GetMarkColor())
	}
	if len(got.GetTagIds()) != 1 || got.GetTagIds()[0] != tag.Id {
		t.Errorf("m1 tags = %v, want [%s]", got.GetTagIds(), tag.Id)
	}
	if len(got.GetComments()) != 1 || got.GetComments()[0].GetBody() != "first frame" {
		t.Errorf("m1 comments = %v", got.GetComments())
	}

	// ListMessages attaches them too, and only the marked message is marked.
	msgs, err := st.ListMessages(ctx, sid, fid)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("list: n=%d err=%v", len(msgs), err)
	}
	byID := map[string]*trafficv1.WsMessage{msgs[0].Id: msgs[0], msgs[1].Id: msgs[1]}
	if byID[m1].GetMarkColor() != "red" || byID[m2].GetMarkColor() != "" {
		t.Errorf("marks: m1=%q m2=%q", byID[m1].GetMarkColor(), byID[m2].GetMarkColor())
	}
	if len(byID[m2].GetTagIds()) != 1 {
		t.Errorf("m2 tags = %v, want the shared tag", byID[m2].GetTagIds())
	}
	if len(byID[m2].GetComments()) != 0 {
		t.Errorf("m2 should have no comments: %v", byID[m2].GetComments())
	}
}
