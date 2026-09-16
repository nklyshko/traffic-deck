package store

// Ad-hoc read-only SQL over a bundle (ViewerService.QuerySQL). The filter DSL answers
// "which flows match", deliberately and cheaply; this answers the questions it does not
// express — GROUP BY, joins onto flow_headers/ws_messages, "how many distinct
// authorities". It lives in the store because the store owns the files and the only safe
// way to run someone else's SQL against them: a *separate* connection opened read-only,
// never the pooled read/write handle the decode path is using.

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	sqlitedriver "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// SQLResult is one page of a QuerySQL answer: the statement's columns in their own order
// plus a JSON object per row (see QuerySQLResponse for why JSON).
type SQLResult struct {
	Columns   []string
	RowsJSON  []string
	Truncated bool
}

// SQL row/byte budgets. The row cap keeps a `SELECT *` on a 273k-flow bundle from being
// an accident; the byte budget keeps a query that selects a blob column (bodies and raw
// ClientHellos live in this schema) from building a response gRPC then refuses to send.
const (
	SQLDefaultLimit = 200
	SQLMaxLimit     = 2000
	sqlMaxBytes     = 1 << 20
)

// readOnlyDSN opens a bundle with writes refused by SQLite itself.
//
// Both flags are needed, and one is not a belt for the other's braces: mode=ro alone
// still allows ATTACH of a second file followed by CREATE TABLE *in that file*, so a
// read-only connection could write elsewhere on disk. query_only closes that, being a
// property of the connection rather than of one file. In the DSN rather than a PRAGMA
// Exec so it holds for every connection database/sql pools, not just the first.
func readOnlyDSN(path string) string {
	return path + "?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)"
}

// readOnlyConn takes a single connection out of db and forbids ATTACH on it. query_only
// already makes a write to an attached database fail, but ATTACH itself *creates* the
// file it names, so without this a read-only query could still drop empty files
// anywhere the gateway can write. A limit of zero attached databases makes the statement
// an error before it opens anything. Limits are per-connection, which is why the query
// runs on this one rather than on the pool.
func readOnlyConn(ctx context.Context, db *sql.DB) (*sql.Conn, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := sqlitedriver.Limit(conn, sqlite3.SQLITE_LIMIT_ATTACHED, 0); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// dbPath resolves which file a session id names: the per-session bundle, or the global
// catalog for the empty id. ErrNotFound when it isn't there — a mistyped id has to fail
// loudly rather than come back as an empty result set.
func (s *Store) dbPath(sessionID string) (string, error) {
	path := filepath.Join(s.dataRoot, "catalog.sqlite")
	if sessionID != "" {
		path = filepath.Join(s.dataRoot, "sessions", sessionID, "flows.sqlite")
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", err
	}
	return path, nil
}

// QuerySQL runs one read-only statement against a session bundle (or the catalog when
// sessionID is empty) and returns up to limit rows. Params bind the statement's `?`
// placeholders; they are passed as text and SQLite applies column affinity, so "429"
// compares equal to an INTEGER 429.
//
// A write is refused by SQLite, not by pattern-matching the statement — see readOnlyDSN.
// Cancel ctx (the caller sets the deadline) to abandon a query that runs long.
func (s *Store) QuerySQL(ctx context.Context, sessionID, query string, params []string, limit int) (*SQLResult, error) {
	if limit <= 0 {
		limit = SQLDefaultLimit
	}
	if limit > SQLMaxLimit {
		limit = SQLMaxLimit
	}
	path, err := s.dbPath(sessionID)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", readOnlyDSN(path))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	conn, err := readOnlyConn(ctx, db)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	args := make([]any, len(params))
	for i, p := range params {
		args[i] = p
	}
	rows, err := conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := &SQLResult{Columns: cols, RowsJSON: []string{}}
	cells := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range cells {
		ptrs[i] = &cells[i]
	}
	bytesUsed := 0
	for rows.Next() {
		// One row past the limit is fetched, not returned: that is how `truncated` can be
		// the truth instead of "the page happened to be full".
		if len(out.RowsJSON) >= limit || bytesUsed >= sqlMaxBytes {
			out.Truncated = true
			break
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			row[c] = sqlValue(cells[i])
		}
		enc, err := json.Marshal(row)
		if err != nil {
			return nil, fmt.Errorf("encode row: %w", err)
		}
		out.RowsJSON = append(out.RowsJSON, string(enc))
		bytesUsed += len(enc)
	}
	return out, rows.Err()
}

// sqlValue turns a scanned SQLite value into something json.Marshal renders usefully.
// A BLOB becomes base64 — it is bodies and raw handshake bytes in this schema, not text.
func sqlValue(v any) any {
	switch t := v.(type) {
	case []byte:
		return base64.StdEncoding.EncodeToString(t)
	case time.Time:
		return t.Format(time.RFC3339Nano)
	default:
		return v
	}
}
