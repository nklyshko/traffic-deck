package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func query(t *testing.T, st *Store, sid, sql string, params ...string) *SQLResult {
	t.Helper()
	res, err := st.QuerySQL(context.Background(), sid, sql, params, 0)
	if err != nil {
		t.Fatalf("QuerySQL %q: %v", sql, err)
	}
	return res
}

func TestQuerySQLReadsFlowsAndBindsParams(t *testing.T) {
	st, sid := seedQuerySession(t, 6)
	defer st.Close()

	res := query(t, st, sid, `SELECT method, COUNT(*) AS n FROM flows GROUP BY method ORDER BY method`)
	if got, want := res.Columns, []string{"method", "n"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("columns = %v, want %v", got, want)
	}
	if len(res.RowsJSON) != 2 {
		t.Fatalf("rows = %v, want 2 (GET, POST)", res.RowsJSON)
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(res.RowsJSON[0]), &row); err != nil {
		t.Fatal(err)
	}
	if row["method"] != "GET" || row["n"].(float64) != 3 {
		t.Fatalf("first row = %v, want 3 GETs", row)
	}

	// A text param compares equal to an INTEGER column (SQLite column affinity), which is
	// what lets every parameter travel over the wire as a string.
	res = query(t, st, sid, `SELECT COUNT(*) AS n FROM flows WHERE status = ?`, "200")
	if !strings.Contains(res.RowsJSON[0], `"n":6`) {
		t.Fatalf("status param row = %v, want 6", res.RowsJSON[0])
	}

	// The empty session id is the catalog, not an error.
	res = query(t, st, "", `SELECT id FROM sessions`)
	if len(res.RowsJSON) != 1 || !strings.Contains(res.RowsJSON[0], sid) {
		t.Fatalf("catalog rows = %v, want the one session", res.RowsJSON)
	}
}

func TestQuerySQLRefusesEveryWrite(t *testing.T) {
	st, sid := seedQuerySession(t, 2)
	defer st.Close()

	// The point of the read-only DSN: SQLite refuses these, so nothing has to be parsed
	// out of the statement.
	for _, sql := range []string{
		`DELETE FROM flows`,
		`UPDATE flows SET method = 'nope'`,
		`INSERT INTO flows (id, session_id, analysis_id) VALUES ('x','y','z')`,
		`DROP TABLE flows`,
	} {
		if _, err := st.QuerySQL(context.Background(), sid, sql, nil, 0); err == nil {
			t.Errorf("%q was accepted, want a read-only refusal", sql)
		}
	}
	if n := len(query(t, st, sid, `SELECT id FROM flows`).RowsJSON); n != 2 {
		t.Fatalf("flows after the write attempts = %d, want 2", n)
	}
}

func TestQuerySQLCannotAttachAnotherFile(t *testing.T) {
	st, sid := seedQuerySession(t, 1)
	defer st.Close()

	// ATTACH is the way out of a read-only connection: the write to the attached database
	// fails on query_only, but ATTACH itself creates the file it names — so a read-only
	// query could drop files anywhere the gateway can write. It has to fail *before* that.
	other := filepath.Join(t.TempDir(), "elsewhere.sqlite")
	_, err := st.QuerySQL(context.Background(), sid,
		`ATTACH DATABASE '`+other+`' AS other; CREATE TABLE other.t (a)`, nil, 0)
	if err == nil {
		t.Fatal("ATTACH was accepted")
	}
	if _, statErr := os.Stat(other); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("%s exists after a refused ATTACH (err was %v)", other, err)
	}
}

func TestQuerySQLLimitAndErrors(t *testing.T) {
	st, sid := seedQuerySession(t, 10)
	defer st.Close()
	ctx := context.Background()

	res, err := st.QuerySQL(ctx, sid, `SELECT id FROM flows`, nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RowsJSON) != 4 || !res.Truncated {
		t.Fatalf("limit 4 gave %d rows, truncated=%v", len(res.RowsJSON), res.Truncated)
	}
	if res, err := st.QuerySQL(ctx, sid, `SELECT id FROM flows`, nil, 10); err != nil || res.Truncated {
		t.Fatalf("a limit that exactly fits must not report truncated: %v %v", res.Truncated, err)
	}

	if _, err := st.QuerySQL(ctx, "no-such-session", `SELECT 1`, nil, 0); err != ErrNotFound {
		t.Fatalf("unknown session = %v, want ErrNotFound", err)
	}
	if _, err := st.QuerySQL(ctx, sid, `SELECT * FROM nope`, nil, 0); err == nil {
		t.Fatal("a bad table name must be an error, not an empty result")
	}
}
