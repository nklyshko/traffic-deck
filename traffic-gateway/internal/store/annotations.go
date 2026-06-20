package store

// Annotations (plan §12): tags, comments, color marks, and groups.
//
// Tag and group *definitions* are canonical in the global catalog (so they are
// consistent and selectable across sessions) and mirrored into each session
// bundle that uses them (so the bundle stays self-contained/portable).
// Assignments, comments, and marks live only in the bundle.

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	trafficv1 "github.com/nikitak/parsing/traffic-gateway/gen/traffic/v1"
)

// FavoriteTagID is the fixed id of the seeded built-in Favorite tag (catalog.sql).
const FavoriteTagID = "__favorite__"

// ErrProtected is returned when a write targets a protected object (the Favorite tag).
var ErrProtected = errors.New("store: protected object")

// --- tag definitions (catalog) -------------------------------------------

func (s *Store) CreateTag(ctx context.Context, name, color string) (*trafficv1.Tag, error) {
	t := &trafficv1.Tag{Id: uuid.NewString(), Name: name, Color: color, CreatedAtUnixMs: time.Now().UnixMilli()}
	_, err := s.catalog.ExecContext(ctx,
		`INSERT INTO tags (id, name, color, is_favorite, created_at) VALUES (?,?,?,0,?)`,
		t.Id, t.Name, t.Color, t.CreatedAtUnixMs)
	return t, err
}

func (s *Store) DeleteTag(ctx context.Context, id string) error {
	if id == FavoriteTagID {
		return ErrProtected
	}
	_, err := s.catalog.ExecContext(ctx, `DELETE FROM tags WHERE id=?`, id)
	return err
}

func (s *Store) ListTags(ctx context.Context) ([]*trafficv1.Tag, error) {
	rows, err := s.catalog.QueryContext(ctx,
		`SELECT id, name, color, is_favorite, created_at FROM tags ORDER BY is_favorite DESC, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*trafficv1.Tag
	for rows.Next() {
		var t trafficv1.Tag
		var fav int
		if err := rows.Scan(&t.Id, &t.Name, &t.Color, &fav, &t.CreatedAtUnixMs); err != nil {
			return nil, err
		}
		t.IsFavorite = fav != 0
		out = append(out, &t)
	}
	return out, rows.Err()
}

// --- group definitions (catalog) -----------------------------------------

func (s *Store) CreateGroup(ctx context.Context, name, color, parentID string) (*trafficv1.Group, error) {
	g := &trafficv1.Group{Id: uuid.NewString(), Name: name, Color: color, ParentId: parentID, CreatedAtUnixMs: time.Now().UnixMilli()}
	_, err := s.catalog.ExecContext(ctx,
		`INSERT INTO groups (id, name, color, parent_id, created_at) VALUES (?,?,?,?,?)`,
		g.Id, g.Name, g.Color, nullIfEmpty(parentID), g.CreatedAtUnixMs)
	return g, err
}

func (s *Store) UpdateGroup(ctx context.Context, id, name, color, parentID string) (*trafficv1.Group, error) {
	_, err := s.catalog.ExecContext(ctx,
		`UPDATE groups SET name=?, color=?, parent_id=? WHERE id=?`,
		name, color, nullIfEmpty(parentID), id)
	if err != nil {
		return nil, err
	}
	return &trafficv1.Group{Id: id, Name: name, Color: color, ParentId: parentID}, nil
}

func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	_, err := s.catalog.ExecContext(ctx, `DELETE FROM groups WHERE id=?`, id)
	return err
}

func (s *Store) ListGroups(ctx context.Context) ([]*trafficv1.Group, error) {
	rows, err := s.catalog.QueryContext(ctx,
		`SELECT id, name, color, parent_id, created_at FROM groups ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*trafficv1.Group
	for rows.Next() {
		var g trafficv1.Group
		var parent sql.NullString
		if err := rows.Scan(&g.Id, &g.Name, &g.Color, &parent, &g.CreatedAtUnixMs); err != nil {
			return nil, err
		}
		g.ParentId = parent.String
		out = append(out, &g)
	}
	return out, rows.Err()
}

// --- mirroring defs into a bundle ----------------------------------------

// mirrorTag copies a catalog tag def into the session bundle so the bundle is
// self-contained (its rows render with name/color even detached from the catalog).
func (s *Store) mirrorTag(ctx context.Context, db *sql.DB, tagID string) error {
	var name, color string
	var fav int
	var created int64
	err := s.catalog.QueryRowContext(ctx,
		`SELECT name, color, is_favorite, created_at FROM tags WHERE id=?`, tagID).
		Scan(&name, &color, &fav, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx,
		`INSERT OR REPLACE INTO tags (id, name, color, is_favorite, created_at) VALUES (?,?,?,?,?)`,
		tagID, name, color, fav, created)
	return err
}

func (s *Store) mirrorGroup(ctx context.Context, db *sql.DB, groupID string) error {
	var name, color string
	var parent sql.NullString
	var created int64
	err := s.catalog.QueryRowContext(ctx,
		`SELECT name, color, parent_id, created_at FROM groups WHERE id=?`, groupID).
		Scan(&name, &color, &parent, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx,
		`INSERT OR REPLACE INTO groups (id, name, color, parent_id, created_at) VALUES (?,?,?,?,?)`,
		groupID, name, color, parent, created)
	return err
}

// --- tag assignments (bundle) --------------------------------------------

func (s *Store) SetTags(ctx context.Context, sessionID string, recordIDs, addIDs, removeIDs []string) error {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return err
	}
	for _, tid := range addIDs {
		if err := s.mirrorTag(ctx, db, tid); err != nil {
			return err
		}
	}
	return inTx(ctx, db, func(tx *sql.Tx) error {
		for _, rid := range recordIDs {
			for _, tid := range addIDs {
				if _, err := tx.ExecContext(ctx,
					`INSERT OR IGNORE INTO record_tags (record_id, tag_id) VALUES (?,?)`, rid, tid); err != nil {
					return err
				}
			}
			for _, tid := range removeIDs {
				if _, err := tx.ExecContext(ctx,
					`DELETE FROM record_tags WHERE record_id=? AND tag_id=?`, rid, tid); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ToggleFavorite adds the Favorite tag to the records if any lacks it, else removes
// it from all (bulk toggle keyed off the current selection state).
func (s *Store) ToggleFavorite(ctx context.Context, sessionID string, recordIDs []string) error {
	if len(recordIDs) == 0 {
		return nil
	}
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return err
	}
	if err := s.mirrorTag(ctx, db, FavoriteTagID); err != nil {
		return err
	}
	allFav := true
	for _, rid := range recordIDs {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM record_tags WHERE record_id=? AND tag_id=?`, rid, FavoriteTagID).
			Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			allFav = false
			break
		}
	}
	if allFav {
		return s.SetTags(ctx, sessionID, recordIDs, nil, []string{FavoriteTagID})
	}
	return s.SetTags(ctx, sessionID, recordIDs, []string{FavoriteTagID}, nil)
}

// --- comments (bundle) ----------------------------------------------------

func (s *Store) AddComment(ctx context.Context, sessionID, recordID, body string) (*trafficv1.Comment, error) {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	c := &trafficv1.Comment{Id: uuid.NewString(), RecordId: recordID, Body: body, CreatedAtUnixMs: now, UpdatedAtUnixMs: now}
	_, err = db.ExecContext(ctx,
		`INSERT INTO comments (id, record_id, body, created_at, updated_at) VALUES (?,?,?,?,?)`,
		c.Id, c.RecordId, c.Body, now, now)
	return c, err
}

func (s *Store) EditComment(ctx context.Context, sessionID, id, body string) (*trafficv1.Comment, error) {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	if _, err := db.ExecContext(ctx,
		`UPDATE comments SET body=?, updated_at=? WHERE id=?`, body, now, id); err != nil {
		return nil, err
	}
	var c trafficv1.Comment
	err = db.QueryRowContext(ctx,
		`SELECT id, record_id, body, created_at, updated_at FROM comments WHERE id=?`, id).
		Scan(&c.Id, &c.RecordId, &c.Body, &c.CreatedAtUnixMs, &c.UpdatedAtUnixMs)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &c, err
}

func (s *Store) DeleteComment(ctx context.Context, sessionID, id string) error {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `DELETE FROM comments WHERE id=?`, id)
	return err
}

// --- color marks (bundle) -------------------------------------------------

func (s *Store) SetMark(ctx context.Context, sessionID string, recordIDs []string, color string) error {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return err
	}
	return inTx(ctx, db, func(tx *sql.Tx) error {
		for _, rid := range recordIDs {
			if _, err := tx.ExecContext(ctx,
				`INSERT OR REPLACE INTO record_marks (record_id, color) VALUES (?,?)`, rid, color); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) ClearMark(ctx context.Context, sessionID string, recordIDs []string) error {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return err
	}
	return inTx(ctx, db, func(tx *sql.Tx) error {
		for _, rid := range recordIDs {
			if _, err := tx.ExecContext(ctx, `DELETE FROM record_marks WHERE record_id=?`, rid); err != nil {
				return err
			}
		}
		return nil
	})
}

// --- group membership (bundle) -------------------------------------------

func (s *Store) SetGroups(ctx context.Context, sessionID string, recordIDs, addIDs, removeIDs []string) error {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return err
	}
	for _, gid := range addIDs {
		if err := s.mirrorGroup(ctx, db, gid); err != nil {
			return err
		}
	}
	return inTx(ctx, db, func(tx *sql.Tx) error {
		for _, rid := range recordIDs {
			for _, gid := range addIDs {
				if _, err := tx.ExecContext(ctx,
					`INSERT OR IGNORE INTO group_members (group_id, record_id) VALUES (?,?)`, gid, rid); err != nil {
					return err
				}
			}
			for _, gid := range removeIDs {
				if _, err := tx.ExecContext(ctx,
					`DELETE FROM group_members WHERE group_id=? AND record_id=?`, gid, rid); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// --- read attach ----------------------------------------------------------

// attachAnnotations fills the annotation fields (tag_ids, favorite, mark_color,
// group_ids, comments) on the given flows, keyed by id. Whole-table scans are fine
// for a single session's bundle; callers pass the subset they care about.
func (s *Store) attachAnnotations(ctx context.Context, db *sql.DB, flows map[string]*trafficv1.Flow) error {
	if len(flows) == 0 {
		return nil
	}
	favTags := map[string]bool{}
	if rows, err := db.QueryContext(ctx, `SELECT id FROM tags WHERE is_favorite=1`); err == nil {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			favTags[id] = true
		}
		rows.Close()
	} else {
		return err
	}

	if err := scanPairs(ctx, db, `SELECT record_id, tag_id FROM record_tags`,
		func(rid, tid string) {
			if f := flows[rid]; f != nil {
				f.TagIds = append(f.TagIds, tid)
				if favTags[tid] {
					f.Favorite = true
				}
			}
		}); err != nil {
		return err
	}
	if err := scanPairs(ctx, db, `SELECT record_id, color FROM record_marks`,
		func(rid, color string) {
			if f := flows[rid]; f != nil {
				f.MarkColor = color
			}
		}); err != nil {
		return err
	}
	if err := scanPairs(ctx, db, `SELECT record_id, group_id FROM group_members`,
		func(rid, gid string) {
			if f := flows[rid]; f != nil {
				f.GroupIds = append(f.GroupIds, gid)
			}
		}); err != nil {
		return err
	}

	rows, err := db.QueryContext(ctx,
		`SELECT id, record_id, body, created_at, updated_at FROM comments ORDER BY created_at`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var c trafficv1.Comment
		if err := rows.Scan(&c.Id, &c.RecordId, &c.Body, &c.CreatedAtUnixMs, &c.UpdatedAtUnixMs); err != nil {
			return err
		}
		if f := flows[c.RecordId]; f != nil {
			f.Comments = append(f.Comments, &c)
		}
	}
	return rows.Err()
}

// scanPairs runs a two-string-column query and calls fn for each row.
func scanPairs(ctx context.Context, db *sql.DB, query string, fn func(a, b string)) error {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var a, b string
		if err := rows.Scan(&a, &b); err != nil {
			return err
		}
		fn(a, b)
	}
	return rows.Err()
}

// inTx runs fn inside a transaction, committing on success.
func inTx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
