package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// toOldNames rewrites a current bundle into what a gateway before the rename wrote:
// the old names, index names included, and no schema version.
func toOldNames(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := []string{`DROP INDEX messages_flow_idx`, `DROP INDEX message_metadata_msg_idx`}
	for _, r := range sessionColumnRenames {
		stmts = append(stmts, `ALTER TABLE `+r[0]+` RENAME COLUMN `+r[2]+` TO `+r[1])
	}
	for _, r := range sessionTableRenames {
		stmts = append(stmts, `ALTER TABLE `+r[1]+` RENAME TO `+r[0])
	}
	stmts = append(stmts,
		`CREATE INDEX ws_messages_flow_idx ON ws_messages (flow_id, ts_micros, frame_number)`,
		`CREATE INDEX ws_message_metadata_msg_idx ON ws_message_metadata (message_id)`,
		`PRAGMA user_version = 0`)
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

func TestABundleUnderTheOldNamesIsRenamedWhenOpened(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	sid, aid := uuid.NewString(), uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{ID: sid, Label: "old"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAnalysis(ctx, NewAnalysis{ID: aid, SessionID: sid, Engine: "native"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertFlows(ctx, sid, aid, []*decode.Flow{{
		FrameNumber: 1, Method: "GET", Authority: "example.com", Protocol: "HTTP/2",
		ConnectionID: "quic:3", StreamID: "5", Http2Fingerprint: "1:65536|0|0|m,a,s,p",
		RequestHeaders:  []decode.Header{{Name: "user-agent", Value: "probe"}},
		ResponseHeaders: []decode.Header{{Name: "server", Value: "edge"}},
	}}); err != nil {
		t.Fatal(err)
	}
	flows, err := st.ListFlows(ctx, sid)
	if err != nil || len(flows) != 1 {
		t.Fatalf("list: %v %d", err, len(flows))
	}
	fid := flows[0].GetId()
	if _, err := st.InsertMessages(ctx, sid, []*decode.Message{{
		ID: "m1", FlowID: fid, FromClient: true, Opcode: "text", Payload: []byte("hi"),
		Metadata: map[string]string{"max.cmd": "7"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertUndecoded(ctx, sid, []*decode.UndecodedConn{{
		ConnectionID: "9", Transport: "tcp", Client: "10.0.0.1:1", Server: "10.0.0.2:443",
		Reason: "no_key", FirstTSMicros: 10, LastTSMicros: 20, PcapOffset: -1,
	}}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	toOldNames(t, filepath.Join(dir, "sessions", sid, "flows.sqlite"))

	st, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	// The read-only path first: it must see the new names without anything else having
	// opened the bundle.
	res, err := st.QuerySQL(ctx, sid,
		`SELECT f.connection_id, f.stream_id, f.http2_fingerprint,
		        (SELECT COUNT(*) FROM messages), (SELECT COUNT(*) FROM message_metadata),
		        (SELECT first_ts_micros FROM undecoded_connections WHERE connection_id = '9'),
		        (SELECT COUNT(*) FROM flow_headers WHERE response = 1)
		 FROM flows f`, nil, 0)
	if err != nil {
		t.Fatalf("query after rename: %v", err)
	}
	if want := `"quic:3"`; len(res.RowsJSON) != 1 || !strings.Contains(res.RowsJSON[0], want) {
		t.Fatalf("rows = %v", res.RowsJSON)
	}
	for _, want := range []string{`"stream_id":"5"`, `"(SELECT COUNT(*) FROM messages)":1`,
		`"(SELECT COUNT(*) FROM message_metadata)":1`, `:10`, `"(SELECT COUNT(*) FROM flow_headers WHERE response = 1)":1`} {
		if !strings.Contains(res.RowsJSON[0], want) {
			t.Fatalf("row %s lacks %s", res.RowsJSON[0], want)
		}
	}

	f, err := st.GetFlow(ctx, sid, fid)
	if err != nil {
		t.Fatal(err)
	}
	if f.GetConnectionId() != "quic:3" || f.GetStreamId() != "5" || f.GetHttp2Fingerprint() == "" {
		t.Fatalf("flow = %v", f)
	}
	if len(f.GetRequestHeaders()) != 1 || f.GetResponseHeaders()[0].GetValue() != "edge" {
		t.Fatalf("headers = %v / %v", f.GetRequestHeaders(), f.GetResponseHeaders())
	}
	msgs, err := st.ListMessages(ctx, sid, fid)
	if err != nil || len(msgs) != 1 || msgs[0].GetMetadata()["max.cmd"] != "7" {
		t.Fatalf("messages = %v %v", msgs, err)
	}
	und, err := st.ListUndecoded(ctx, sid)
	if err != nil || len(und) != 1 || und[0].ConnectionID != "9" || und[0].LastTSMicros != 20 {
		t.Fatalf("undecoded = %v %v", und, err)
	}

	// No table is left under an old name, and the indexes exist under the new ones.
	rows, err := st.QuerySQL(ctx, sid, `SELECT name FROM sqlite_master ORDER BY name`, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(rows.RowsJSON, " ")
	for _, gone := range []string{"ws_message", "undecoded_conns"} {
		if strings.Contains(all, gone) {
			t.Fatalf("%s still present: %s", gone, all)
		}
	}
	for _, idx := range []string{"messages_flow_idx", "message_metadata_msg_idx"} {
		if !strings.Contains(all, idx) {
			t.Fatalf("%s missing: %s", idx, all)
		}
	}
}
