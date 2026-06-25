package store

// Session export/import support. A session bundle is already
// self-contained on disk (sessions/<id>/{flows.sqlite,capture.pcap,key.log,blobs/})
// with tag/group defs mirrored into flows.sqlite; the only external state is the
// catalog row. These helpers expose that row and let the bundle package snapshot the
// per-session DB, re-insert the row on import, and fold any mirrored tag/group defs
// back into the catalog so an imported session's annotations stay selectable.

import (
	"context"
	"database/sql"
	"errors"
)

// SessionRow is the catalog row for one session, carried in an export manifest.
type SessionRow struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	SourceKind  string `json:"source_kind"`
	Status      string `json:"status"`
	CreatedAt   int64  `json:"created_at"`
	ClosedAt    *int64 `json:"closed_at,omitempty"`
	PcapBytes   int64  `json:"pcap_bytes"`
	KeylogBytes int64  `json:"keylog_bytes"`
	FlowCount   int64  `json:"flow_count"`
}

// ExportSessionRow returns the catalog row for a session (ErrNotFound if absent).
func (s *Store) ExportSessionRow(ctx context.Context, id string) (*SessionRow, error) {
	var r SessionRow
	var closed sql.NullInt64
	err := s.catalog.QueryRowContext(ctx,
		`SELECT id, label, source_kind, status, created_at, closed_at, pcap_bytes, keylog_bytes, flow_count
		 FROM sessions WHERE id=?`, id).
		Scan(&r.ID, &r.Label, &r.SourceKind, &r.Status, &r.CreatedAt, &closed,
			&r.PcapBytes, &r.KeylogBytes, &r.FlowCount)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if closed.Valid {
		r.ClosedAt = &closed.Int64
	}
	return &r, nil
}

// ImportSessionRow inserts a session row into the catalog (the imported bundle's
// own flows.sqlite already exists on disk under sessions/<id>/). It does not open or
// create the per-session DB. Errors if the id already exists.
func (s *Store) ImportSessionRow(ctx context.Context, r *SessionRow) error {
	var closed any
	if r.ClosedAt != nil {
		closed = *r.ClosedAt
	}
	_, err := s.catalog.ExecContext(ctx, `
		INSERT INTO sessions (id, label, source_kind, status, created_at, closed_at, pcap_bytes, keylog_bytes, flow_count)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		r.ID, r.Label, r.SourceKind, r.Status, r.CreatedAt, closed, r.PcapBytes, r.KeylogBytes, r.FlowCount)
	return err
}

// SessionExists reports whether a session id is present in the catalog.
func (s *Store) SessionExists(ctx context.Context, id string) (bool, error) {
	var n int
	err := s.catalog.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE id=?`, id).Scan(&n)
	return n > 0, err
}

// SnapshotSessionDB writes a consistent single-file copy of a session's flows.sqlite
// to dest via VACUUM INTO — capturing committed WAL contents and excluding the
// -wal/-shm sidecars, so the export is a clean point-in-time snapshot even while the
// gateway holds the DB open. dest must not already exist (VACUUM INTO requirement).
func (s *Store) SnapshotSessionDB(ctx context.Context, sessionID, dest string) error {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `VACUUM INTO ?`, dest)
	return err
}

// MergeBundleDefsIntoCatalog copies the tag/group definitions mirrored in a session's
// flows.sqlite into the global catalog (INSERT OR IGNORE), so an imported session's
// tags/groups remain selectable alongside the rest. Existing catalog defs win.
func (s *Store) MergeBundleDefsIntoCatalog(ctx context.Context, sessionID string) error {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return err
	}
	if err := copyDefs(ctx, db, s.catalog,
		`SELECT id, name, color, is_favorite, created_at FROM tags`,
		`INSERT OR IGNORE INTO tags (id, name, color, is_favorite, created_at) VALUES (?,?,?,?,?)`,
		5); err != nil {
		return err
	}
	return copyDefs(ctx, db, s.catalog,
		`SELECT id, name, color, parent_id, created_at FROM groups`,
		`INSERT OR IGNORE INTO groups (id, name, color, parent_id, created_at) VALUES (?,?,?,?,?)`,
		5)
}

// copyDefs streams rows from src to dst, scanning ncol generic columns per row.
func copyDefs(ctx context.Context, src, dst *sql.DB, query, insert string, ncol int) error {
	rows, err := src.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		vals := make([]any, ncol)
		ptrs := make([]any, ncol)
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		if _, err := dst.ExecContext(ctx, insert, vals...); err != nil {
			return err
		}
	}
	return rows.Err()
}

// RewriteSessionID rebinds an imported bundle's flows.sqlite to a new session id:
// the session_id columns and any spilled-blob external_path prefixes still point at
// the old id. dbPath is the extracted flows.sqlite; it must not be an already-open
// store DB. Called only on the --new-id import path.
func RewriteSessionID(ctx context.Context, dbPath, oldID, newID string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	stmts := []struct {
		q    string
		args []any
	}{
		{`UPDATE flows SET session_id=?`, []any{newID}},
		{`UPDATE analyses SET session_id=?`, []any{newID}},
		{`UPDATE blobs SET external_path=REPLACE(external_path, ?, ?) WHERE external_path IS NOT NULL`,
			[]any{"sessions/" + oldID + "/", "sessions/" + newID + "/"}},
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s.q, s.args...); err != nil {
			return err
		}
	}
	return nil
}
