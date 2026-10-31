package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// A database's schema version is SQLite's user_version: the number of migrations in its
// list that have been applied. A new database gets the schema as it stands and the
// latest version without running any; an existing one runs the migrations past its
// version, then the schema (whose CREATE ... IF NOT EXISTS adds any new table or index),
// all in one transaction.
//
// To change the schema of existing databases, append a migration to the list and change
// the schema file to the result. Never edit or reorder an applied migration: a database
// that ran it will not run it again.
type migration func(ctx context.Context, tx *sql.Tx) error

var (
	catalogMigrations = []migration{catalogBaseline}
	sessionMigrations = []migration{sessionBaseline}
)

// ErrSchemaNewer is returned for a database written by a gateway newer than this one.
// Reading it could misread data it does not know about, so it is refused instead.
var ErrSchemaNewer = errors.New("written by a newer gateway — upgrade this gateway to open it")

// openVersioned opens path and brings it to the latest version of steps.
func openVersioned(ctx context.Context, path, schema string, steps []migration) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+dsnPragmas)
	if err != nil {
		return nil, err
	}
	if err := migrate(ctx, db, schema, steps); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return db, nil
}

func migrate(ctx context.Context, db *sql.DB, schema string, steps []migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > len(steps) {
		return fmt.Errorf("%w (schema version %d, this gateway knows up to %d)", ErrSchemaNewer, version, len(steps))
	}
	if version == len(steps) {
		// Already current. The schema still runs, cheaply, so a table or index it lost is
		// recreated; there is nothing to commit otherwise.
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return err
		}
		return tx.Commit()
	}
	tables, err := tableNames(ctx, tx)
	if err != nil {
		return err
	}
	if len(tables) > 0 {
		for _, step := range steps[version:] {
			if err := step(ctx, tx); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return err
	}
	// PRAGMA takes no bound parameters; len(steps) is ours, not input.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, len(steps))); err != nil {
		return err
	}
	return tx.Commit()
}

func tableNames(ctx context.Context, tx *sql.Tx) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tables := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables[name] = true
	}
	return tables, rows.Err()
}

func hasColumn(ctx context.Context, tx *sql.Tx, table, column string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n)
	return n > 0, err
}

// addColumn adds a column unless the table already has it or does not exist.
func addColumn(ctx context.Context, tx *sql.Tx, tables map[string]bool, table, column, decl string) error {
	if !tables[table] {
		return nil
	}
	if has, err := hasColumn(ctx, tx, table, column); err != nil || has {
		return err
	}
	_, err := tx.ExecContext(ctx, `ALTER TABLE "`+table+`" ADD COLUMN "`+column+`" `+decl)
	return err
}

// The baselines take a database from version 0 — anything a gateway wrote before
// versioning, in whichever of its shapes — to version 1. So unlike a later migration,
// which knows the exact schema it starts from, they check before each change.

func catalogBaseline(ctx context.Context, tx *sql.Tx) error {
	tables, err := tableNames(ctx, tx)
	if err != nil {
		return err
	}
	return addColumn(ctx, tx, tables, "sessions", "session_group", `TEXT NOT NULL DEFAULT ''`)
}

// Tables and columns renamed to the names the API uses.
var (
	sessionTableRenames = [][2]string{
		{"ws_messages", "messages"},
		{"ws_message_metadata", "message_metadata"},
		{"undecoded_conns", "undecoded_connections"},
	}
	sessionColumnRenames = [][3]string{
		{"flows", "tcp_stream", "connection_id"},
		{"flows", "h2_stream_id", "stream_id"},
		{"flows", "h2_fingerprint", "http2_fingerprint"},
		{"flow_headers", "direction", "response"},
		{"undecoded_connections", "conn_id", "connection_id"},
		{"undecoded_connections", "first_ts", "first_ts_micros"},
		{"undecoded_connections", "last_ts", "last_ts_micros"},
	}
	// Indexes named after a renamed table. SQLite cannot rename an index, so they are
	// dropped and the schema creates them again under the new name.
	sessionStaleIndexes = []string{"ws_messages_flow_idx", "ws_message_metadata_msg_idx"}
)

// sessionBaseline renames what older gateways wrote under other names and adds the body
// content-encoding columns. The renames run before the schema, whose CREATE TABLE IF NOT
// EXISTS would otherwise add an empty table under the new name beside the old one;
// SQLite's RENAME keeps the data and rewrites the indexes that use the column.
//
// The content-encoding columns are empty in an older bundle, which reads as "no encoding
// recorded" — its bodies are whatever that gateway stored; re-import to have them
// decoded. A column the read path cannot do without is not added here but listed in
// requiredFlowColumns, which refuses the bundle (ErrSchemaOutdated).
func sessionBaseline(ctx context.Context, tx *sql.Tx) error {
	tables, err := tableNames(ctx, tx)
	if err != nil {
		return err
	}
	for _, r := range sessionTableRenames {
		if tables[r[0]] && !tables[r[1]] {
			if _, err := tx.ExecContext(ctx, `ALTER TABLE "`+r[0]+`" RENAME TO "`+r[1]+`"`); err != nil {
				return err
			}
			delete(tables, r[0])
			tables[r[1]] = true
		}
	}
	for _, idx := range sessionStaleIndexes {
		if _, err := tx.ExecContext(ctx, `DROP INDEX IF EXISTS "`+idx+`"`); err != nil {
			return err
		}
	}
	for _, r := range sessionColumnRenames {
		if !tables[r[0]] {
			continue
		}
		hasOld, err := hasColumn(ctx, tx, r[0], r[1])
		if err != nil {
			return err
		}
		hasNew, err := hasColumn(ctx, tx, r[0], r[2])
		if err != nil {
			return err
		}
		if hasOld && !hasNew {
			if _, err := tx.ExecContext(ctx, `ALTER TABLE "`+r[0]+`" RENAME COLUMN "`+r[1]+`" TO "`+r[2]+`"`); err != nil {
				return err
			}
		}
	}
	for _, col := range []string{"req_content_encoding", "resp_content_encoding"} {
		if err := addColumn(ctx, tx, tables, "flows", col, `TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}
