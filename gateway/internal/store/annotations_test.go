package store

import (
	"context"
	"testing"

	"github.com/google/uuid"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// seedFlows creates a session with n flows and returns (sessionID, flowIDs).
func seedFlows(t *testing.T, st *Store, n int) (string, []string) {
	t.Helper()
	ctx := context.Background()
	sid := uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{
		ID: sid, SourceKind: trafficv1.SourceKind_SOURCE_KIND_GENERIC,
		Status: trafficv1.SessionStatus_SESSION_STATUS_DECODING,
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	aid := uuid.NewString()
	if err := st.CreateAnalysis(ctx, NewAnalysis{ID: aid, SessionID: sid, Engine: "tshark"}); err != nil {
		t.Fatalf("create analysis: %v", err)
	}
	flows := make([]*decode.Flow, n)
	ids := make([]string, n)
	for i := range flows {
		ids[i] = uuid.NewString()
		flows[i] = &decode.Flow{ID: ids[i], FrameNumber: uint64(i + 1), Method: "GET",
			Authority: "example.com", Path: "/", Protocol: "HTTP/2"}
	}
	if _, err := st.InsertFlows(ctx, sid, aid, flows); err != nil {
		t.Fatalf("insert flows: %v", err)
	}
	return sid, ids
}

func getFlow(t *testing.T, st *Store, sid, fid string) *trafficv1.Flow {
	t.Helper()
	f, err := st.GetFlow(context.Background(), sid, fid)
	if err != nil {
		t.Fatalf("get flow: %v", err)
	}
	return f
}

func TestAnnotations(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	sid, ids := seedFlows(t, st, 3)

	// Tags: create + bulk-assign to two records; verify mirror + read-back.
	tag, err := st.CreateTag(ctx, "auth", "red")
	if err != nil {
		t.Fatalf("create tag: %v", err)
	}
	if err := st.SetTags(ctx, sid, ids[:2], []string{tag.Id}, nil); err != nil {
		t.Fatalf("set tags: %v", err)
	}
	if f := getFlow(t, st, sid, ids[0]); len(f.TagIds) != 1 || f.TagIds[0] != tag.Id {
		t.Fatalf("flow0 tags = %v, want [%s]", f.TagIds, tag.Id)
	}
	if f := getFlow(t, st, sid, ids[2]); len(f.TagIds) != 0 {
		t.Fatalf("flow2 unexpectedly tagged: %v", f.TagIds)
	}
	// Remove on a subset.
	if err := st.SetTags(ctx, sid, []string{ids[0]}, nil, []string{tag.Id}); err != nil {
		t.Fatalf("untag: %v", err)
	}
	if f := getFlow(t, st, sid, ids[0]); len(f.TagIds) != 0 {
		t.Fatalf("flow0 still tagged: %v", f.TagIds)
	}

	// Favorite: toggle on (adds) then off (removes) for the same selection.
	if err := st.ToggleFavorite(ctx, sid, ids[:2]); err != nil {
		t.Fatalf("favorite on: %v", err)
	}
	if f := getFlow(t, st, sid, ids[0]); !f.Favorite {
		t.Fatal("flow0 not favorite after toggle on")
	}
	if err := st.ToggleFavorite(ctx, sid, ids[:2]); err != nil {
		t.Fatalf("favorite off: %v", err)
	}
	if f := getFlow(t, st, sid, ids[0]); f.Favorite {
		t.Fatal("flow0 still favorite after toggle off")
	}

	// Marks: set then clear.
	if err := st.SetMark(ctx, sid, []string{ids[1]}, "red"); err != nil {
		t.Fatalf("set mark: %v", err)
	}
	if f := getFlow(t, st, sid, ids[1]); f.MarkColor != "red" {
		t.Fatalf("mark = %q, want red", f.MarkColor)
	}
	if err := st.ClearMark(ctx, sid, []string{ids[1]}); err != nil {
		t.Fatalf("clear mark: %v", err)
	}
	if f := getFlow(t, st, sid, ids[1]); f.MarkColor != "" {
		t.Fatalf("mark = %q, want cleared", f.MarkColor)
	}

	// Comments: add, edit, delete.
	cm, err := st.AddComment(ctx, sid, ids[0], "looks suspicious")
	if err != nil {
		t.Fatalf("add comment: %v", err)
	}
	if f := getFlow(t, st, sid, ids[0]); len(f.Comments) != 1 || f.Comments[0].Body != "looks suspicious" {
		t.Fatalf("comments = %v", f.Comments)
	}
	if _, err := st.EditComment(ctx, sid, cm.Id, "benign"); err != nil {
		t.Fatalf("edit comment: %v", err)
	}
	if f := getFlow(t, st, sid, ids[0]); f.Comments[0].Body != "benign" {
		t.Fatalf("comment not edited: %q", f.Comments[0].Body)
	}
	if err := st.DeleteComment(ctx, sid, cm.Id); err != nil {
		t.Fatalf("delete comment: %v", err)
	}
	if f := getFlow(t, st, sid, ids[0]); len(f.Comments) != 0 {
		t.Fatalf("comment not deleted: %v", f.Comments)
	}

	// Groups: create + assign membership (multi-record).
	g, err := st.CreateGroup(ctx, "login flow", "blue", "")
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := st.SetGroups(ctx, sid, ids, []string{g.Id}, nil); err != nil {
		t.Fatalf("set groups: %v", err)
	}
	if f := getFlow(t, st, sid, ids[2]); len(f.GroupIds) != 1 || f.GroupIds[0] != g.Id {
		t.Fatalf("flow2 groups = %v, want [%s]", f.GroupIds, g.Id)
	}

	// ListFlows must carry summary annotations too.
	flows, err := st.ListFlows(ctx, sid)
	if err != nil {
		t.Fatalf("list flows: %v", err)
	}
	for _, f := range flows {
		if len(f.GroupIds) != 1 {
			t.Fatalf("list flow %s missing group: %v", f.Id, f.GroupIds)
		}
	}

	// ListTags includes the seeded Favorite + the created tag.
	tags, err := st.ListTags(ctx)
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}
	var sawFav, sawAuth bool
	for _, tg := range tags {
		sawFav = sawFav || (tg.Id == FavoriteTagID && tg.IsFavorite)
		sawAuth = sawAuth || tg.Id == tag.Id
	}
	if !sawFav || !sawAuth {
		t.Fatalf("list tags missing seeded/created: fav=%v auth=%v (%d tags)", sawFav, sawAuth, len(tags))
	}

	// Favorite tag is protected from deletion.
	if err := st.DeleteTag(ctx, FavoriteTagID); err != ErrProtected {
		t.Fatalf("delete favorite err = %v, want ErrProtected", err)
	}
}

func TestWsMessagesRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	sid, ids := seedFlows(t, st, 2)
	fid := ids[0]

	msgs := []*decode.WsMessage{
		{ID: uuid.NewString(), FlowID: fid, FrameNumber: 10, TSUnixMicros: 100, FromClient: true, Opcode: "text", Payload: []byte("hello")},
		{ID: uuid.NewString(), FlowID: fid, FrameNumber: 11, TSUnixMicros: 200, FromClient: false, Opcode: "binary", Payload: []byte("world")},
	}
	if n, err := st.InsertWsMessages(ctx, sid, msgs); err != nil || n != 2 {
		t.Fatalf("insert ws: n=%d err=%v", n, err)
	}

	got, err := st.ListMessages(ctx, sid, fid)
	if err != nil || len(got) != 2 {
		t.Fatalf("list ws: n=%d err=%v", len(got), err)
	}
	if got[0].Opcode != "text" || !got[0].FromClient || string(got[0].Payload.GetInline()) != "hello" {
		t.Fatalf("msg0 = %+v", got[0])
	}
	if got[1].Opcode != "binary" || got[1].FromClient {
		t.Fatalf("msg1 = %+v", got[1])
	}

	body, err := st.GetWsMessageBody(ctx, sid, msgs[1].ID, false)
	if err != nil || string(body) != "world" {
		t.Fatalf("get ws body = %q err=%v", body, err)
	}

	// Flow summaries carry the websocket flag + count.
	f, err := st.GetFlow(ctx, sid, fid)
	if err != nil {
		t.Fatalf("get flow: %v", err)
	}
	if !f.Websocket || f.WsMessageCount != 2 {
		t.Fatalf("flow ws=%v count=%d", f.Websocket, f.WsMessageCount)
	}
}
