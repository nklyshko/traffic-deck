package bundle_test

import (
	"bytes"
	"context"
	"testing"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/bundle"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// seed creates a session with one flow (inline + spilled bodies), a tag def, and a
// tag assignment, returning the session id. dataRoot/st belong to the caller.
func seed(t *testing.T, st *store.Store, dataRoot string) string {
	t.Helper()
	ctx := context.Background()
	const sid = "sess-export-1"
	if err := st.CreateSession(ctx, store.NewSession{
		ID: sid, Label: "orig", Source: "chrome",
		Status: trafficv1.SessionStatus_SESSION_STATUS_CLOSED,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAnalysis(ctx, store.NewAnalysis{ID: "an-1", SessionID: sid, Engine: "tshark"}); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("x"), store.InlineBlobMax+10) // forces a spilled blob file
	flow := &decode.Flow{
		ID: "flow-1", Method: "POST", Authority: "api.example.com", Path: "/v1",
		Protocol: "HTTP/2", Status: 200,
		RequestHeaders:  []decode.Header{{Name: "content-type", Value: "application/json"}},
		ResponseHeaders: []decode.Header{{Name: "content-type", Value: "text/plain"}},
		RequestBody:     []byte(`{"hello":"world"}`),
		ResponseBody:    big,
	}
	if _, err := st.InsertFlows(ctx, sid, "an-1", []*decode.Flow{flow}); err != nil {
		t.Fatal(err)
	}
	tag, err := st.CreateTag(ctx, "auth", "red")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetTags(ctx, sid, []string{"flow-1"}, []string{tag.Id}, nil); err != nil {
		t.Fatal(err)
	}
	return sid
}

func TestExportImportRoundTrip(t *testing.T) {
	ctx := context.Background()

	srcRoot := t.TempDir()
	srcSt, err := store.Open(ctx, srcRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer srcSt.Close()
	sid := seed(t, srcSt, srcRoot)

	var buf bytes.Buffer
	if err := bundle.Export(ctx, srcSt, srcRoot, sid, &buf); err != nil {
		t.Fatalf("export: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty export")
	}

	// Import into a fresh data root + catalog, keeping the original id.
	dstRoot := t.TempDir()
	dstSt, err := store.Open(ctx, dstRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer dstSt.Close()

	gotID, err := bundle.Import(ctx, dstSt, dstRoot, bytes.NewReader(buf.Bytes()), bundle.ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if gotID != sid {
		t.Fatalf("import id = %q, want %q", gotID, sid)
	}

	sess, err := dstSt.GetSession(ctx, sid)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sess.Label != "orig" {
		t.Fatalf("label = %q, want orig", sess.Label)
	}

	f, err := dstSt.GetFlow(ctx, sid, "flow-1")
	if err != nil {
		t.Fatalf("get flow: %v", err)
	}
	if f.Method != "POST" || f.Authority != "api.example.com" {
		t.Fatalf("flow mismatch: %+v", f)
	}
	// Inline request body survives.
	if got := string(f.RequestBody.GetInline()); got != `{"hello":"world"}` {
		t.Fatalf("request body = %q", got)
	}
	// Spilled response blob survives as an external file → readable via GetBodyBytes.
	body, _, err := dstSt.GetBodyBytes(ctx, sid, "flow-1", true)
	if err != nil {
		t.Fatalf("get response body: %v", err)
	}
	if len(body) != store.InlineBlobMax+10 {
		t.Fatalf("response body len = %d", len(body))
	}
	// Tag assignment survives and the def merged into the new catalog.
	if len(f.TagIds) != 1 {
		t.Fatalf("tag ids = %v", f.TagIds)
	}
	tags, err := dstSt.ListTags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tg := range tags {
		if tg.Name == "auth" {
			found = true
		}
	}
	if !found {
		t.Fatal("tag def 'auth' not merged into catalog")
	}
}

func TestImportCollisionAndNewID(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	st, err := store.Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sid := seed(t, st, root)

	var buf bytes.Buffer
	if err := bundle.Export(ctx, st, root, sid, &buf); err != nil {
		t.Fatalf("export: %v", err)
	}

	// Re-importing the same id into the same catalog must fail.
	if _, err := bundle.Import(ctx, st, root, bytes.NewReader(buf.Bytes()), bundle.ImportOptions{}); err == nil {
		t.Fatal("expected collision error, got nil")
	}

	// --new-id imports a copy under a fresh id, with the flow rebound + readable.
	newID, err := bundle.Import(ctx, st, root, bytes.NewReader(buf.Bytes()), bundle.ImportOptions{NewID: true, Label: "copy"})
	if err != nil {
		t.Fatalf("import --new-id: %v", err)
	}
	if newID == sid {
		t.Fatal("new-id import reused the original id")
	}
	sess, err := st.GetSession(ctx, newID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sess.Label != "copy" {
		t.Fatalf("label = %q, want copy", sess.Label)
	}
	f, err := st.GetFlow(ctx, newID, "flow-1")
	if err != nil {
		t.Fatalf("get flow: %v", err)
	}
	if f.SessionId != newID {
		t.Fatalf("flow session_id = %q, want %q (rebind failed)", f.SessionId, newID)
	}
	// The spilled blob's external_path was rewritten to the new dir → still readable.
	body, _, err := st.GetBodyBytes(ctx, newID, "flow-1", true)
	if err != nil {
		t.Fatalf("get response body after new-id: %v", err)
	}
	if len(body) != store.InlineBlobMax+10 {
		t.Fatalf("response body len = %d", len(body))
	}
}
