package store

// Server-side flow querying (ADR-0012): one page of a session's flows, filtered by a
// predicate the gateway evaluates.
//
// The predicate is the semantics and the scan is how it is applied — rows stream out of
// SQLite in key order and are tested one at a time, stopping when the page fills. That is
// affordable: a full scan of 100k rows matching a regex over a composed URL measures
// ~143ms, roughly 20x cheaper per row than ListFlows, which builds a proto and runs three
// attach passes for every row in the session.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/filter"
)

// DefaultScanCap bounds how many rows one query examines. A filter matching very little
// would otherwise walk the whole session; the page reports when this applied so a viewer
// can say "500+ matching" rather than a number that is quietly wrong.
const DefaultScanCap = 20000

// Cursor is a position in a session's timeline — the sort key of a row, not an offset. A
// live session grows while it is read, so an offset would shift rows under the reader.
type Cursor struct {
	TSMicros    int64
	FrameNumber uint64
}

// FlowQuery is one page request.
type FlowQuery struct {
	Filter *filter.Predicate
	Limit  int
	// At most one of After/Before, or neither for the first page. Last starts at the end
	// of the list, which is how "jump to the end" works without knowing the total.
	After   *Cursor
	Before  *Cursor
	Last    bool
	ScanCap int
	// Request-time bounds in unix micros; 0 is unbounded. Applied in SQL rather than by
	// the predicate: this is a range on the paging key, which flows_ts_idx already covers,
	// so bounding a window costs the scan nothing instead of a test per row.
	SinceMicros int64
	UntilMicros int64
}

// FlowPage is one page plus what a viewer needs to navigate and describe it.
type FlowPage struct {
	Flows       []*trafficv1.Flow
	Next, Prev  *Cursor
	Matched     uint64
	CountCapped bool
	Scanned     uint64
}

// queryCols are the columns the predicate can see. Deliberately narrow: this is the scan
// that runs for every row, and hydrating a full flow happens only for the page.
const queryCols = `id, ts_micros, frame_number, scheme, method, authority, path, query,
	status, content_type, tcp_stream, h2_stream_id, req_body_ref, resp_body_ref`

type scanRow struct {
	id                  string
	ts                  int64
	frame               uint64
	reqBodyRef, respRef string
	f                   filter.Flow
}

// QueryFlows returns one page of a session's flows matching q.
func (s *Store) QueryFlows(ctx context.Context, sessionID string, q FlowQuery) (*FlowPage, error) {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.ScanCap <= 0 {
		q.ScanCap = DefaultScanCap
	}

	ann, err := s.loadAnnotationIndex(ctx, db)
	if err != nil {
		return nil, err
	}
	meta, err := loadMetadataIndex(ctx, db)
	if err != nil {
		return nil, err
	}

	// Walking backwards — paging up, or starting from the end — scans in descending key
	// order and the page is reversed before returning, so the caller always sees timeline
	// order regardless of which way it was gathered.
	backwards := q.Before != nil || q.Last
	where, args := whereClause(q)
	order := "ASC"
	if backwards {
		order = "DESC"
	}
	rows, err := db.QueryContext(ctx, fmt.Sprintf(
		`SELECT %s FROM flows %s ORDER BY ts_micros %s, frame_number %s`,
		queryCols, where, order, order), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	page := &FlowPage{}
	var ids []string
	// Whether the scan saw a matching row past this page, in the direction it walked. It is
	// the only thing that justifies a cursor that way: a page filled exactly to the limit
	// with nothing after it is still the end of the list, and a cursor there would step a
	// caller onto an empty page (the "phantom last page" a viewer scrolls into).
	overflow := false
	for rows.Next() {
		if page.Scanned >= uint64(q.ScanCap) {
			page.CountCapped = true
			break
		}
		r, err := scanQueryRow(rows)
		if err != nil {
			return nil, err
		}
		page.Scanned++
		ann.apply(r.id, &r.f)
		r.f.Metadata = meta[r.id]
		if q.Filter.ReadsHeaders() {
			r.f.Headers = headerLoader(ctx, db, r.id)
		}
		if q.Filter.ReadsBodies() {
			r.f.Body = s.bodyLoader(ctx, db, r.reqBodyRef, r.respRef)
		}
		if !q.Filter.Match(&r.f) {
			continue
		}
		page.Matched++
		if len(ids) < q.Limit {
			ids = append(ids, r.id)
			page.Next = &Cursor{TSMicros: r.ts, FrameNumber: r.frame}
			if len(ids) == 1 {
				page.Prev = &Cursor{TSMicros: r.ts, FrameNumber: r.frame}
			}
		} else {
			// A match beyond the page: the cursor on the last kept row leads somewhere. The
			// scan keeps going anyway — a filtered query still has to count every match.
			overflow = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// With no filter and no window every row matches, so the total is a cheap COUNT rather
	// than a scan the cap might have truncated — the common case gets an exact number.
	if q.Filter == nil && q.SinceMicros == 0 && q.UntilMicros == 0 {
		n, err := s.CountFlows(ctx, sessionID)
		if err != nil {
			return nil, err
		}
		page.Matched, page.CountCapped = uint64(n), false
	}

	if backwards {
		reverse(ids)
		page.Next, page.Prev = page.Prev, page.Next
	}
	if page.Flows, err = s.hydrateFlows(ctx, sessionID, ids); err != nil {
		return nil, err
	}
	if len(ids) < q.Limit || (!overflow && !page.CountCapped) {
		// Nothing further in the walk direction: the page either ran out before the limit,
		// or filled exactly to it with no matching row seen beyond. Either way a cursor that
		// way would offer a step into an empty page. (When the scan cap cut the walk short at
		// a full page we cannot rule out more, so the cursor stays rather than strand rows.)
		if backwards {
			page.Prev = nil
		} else {
			page.Next = nil
		}
	}
	// Being *at* an end is the other way to have nothing further, and it holds however
	// full the page is: the first page has nothing before it, and a page taken from the
	// end of the list has nothing after it.
	if q.After == nil && q.Before == nil && !q.Last {
		page.Prev = nil
	}
	if q.Last {
		page.Next = nil
	}
	return page, nil
}

// whereClause builds the keyset predicate and the time window. Row-value comparison gives
// the "strictly after this (ts, frame)" ordering directly, so paging never revisits or
// skips a row even when several share a timestamp.
func whereClause(q FlowQuery) (string, []any) {
	var conds []string
	var args []any
	switch {
	case q.After != nil:
		conds = append(conds, `(ts_micros, frame_number) > (?, ?)`)
		args = append(args, q.After.TSMicros, int64(q.After.FrameNumber))
	case q.Before != nil:
		conds = append(conds, `(ts_micros, frame_number) < (?, ?)`)
		args = append(args, q.Before.TSMicros, int64(q.Before.FrameNumber))
	}
	if q.SinceMicros > 0 {
		conds = append(conds, `ts_micros >= ?`)
		args = append(args, q.SinceMicros)
	}
	if q.UntilMicros > 0 {
		conds = append(conds, `ts_micros <= ?`)
		args = append(args, q.UntilMicros)
	}
	if len(conds) == 0 {
		return "", nil // first page, or (with backwards) the last
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func scanQueryRow(rows *sql.Rows) (*scanRow, error) {
	var r scanRow
	var scheme, method, authority, path, query, contentType, tcpStream, h2 sql.NullString
	var reqRef, respRef sql.NullString
	var status sql.NullInt64
	if err := rows.Scan(&r.id, &r.ts, &r.frame, &scheme, &method, &authority, &path, &query,
		&status, &contentType, &tcpStream, &h2, &reqRef, &respRef); err != nil {
		return nil, err
	}
	r.reqBodyRef, r.respRef = reqRef.String, respRef.String
	r.f = filter.Flow{
		Scheme: scheme.String, Method: method.String, Authority: authority.String,
		Path: path.String, Query: query.String, Status: uint32(status.Int64),
		ContentTyp: contentType.String, TCPStream: tcpStream.String, H2StreamID: h2.String,
	}
	return &r, nil
}

// bodyLoader returns a lazy reader for a row's bodies. Body terms sort last in the
// predicate, so this is only called for a row that already passed every cheaper term.
func (s *Store) bodyLoader(ctx context.Context, db *sql.DB, reqRef, respRef string) func(filter.Direction) string {
	return func(d filter.Direction) string {
		ref := reqRef
		if d == filter.Response {
			ref = respRef
		}
		if ref == "" {
			return ""
		}
		if b := s.loadBlobBytes(ctx, db, ref); b != nil {
			return string(b)
		}
		return ""
	}
}

// headerLoader returns a lazy reader for one row's headers, as the "name: value" lines a
// header term matches against. Read per row rather than bulk-loaded like the annotation
// maps: flow_headers runs to roughly a dozen rows per flow, so a large session's headers
// are millions of rows — pre-loading them would recreate the memory problem this design
// exists to remove. flow_headers_flow_idx makes the per-row read cheap.
func headerLoader(ctx context.Context, db *sql.DB, flowID string) func(filter.Direction) string {
	var cache [2]*string
	return func(d filter.Direction) string {
		if cache[d] != nil {
			return *cache[d]
		}
		dir := 0
		if d == filter.Response {
			dir = 1
		}
		var b strings.Builder
		rows, err := db.QueryContext(ctx,
			`SELECT name, value FROM flow_headers WHERE flow_id=? AND direction=? ORDER BY ord`,
			flowID, dir)
		if err == nil {
			for rows.Next() {
				var name, value string
				if err := rows.Scan(&name, &value); err != nil {
					break
				}
				b.WriteString(name)
				b.WriteString(": ")
				b.WriteString(value)
				b.WriteByte('\n')
			}
			rows.Close()
		}
		out := b.String()
		cache[d] = &out
		return out
	}
}

// hydrateFlows loads one page's flows in timeline order, as *summaries* — the same shape
// ListFlows returned, with annotations, metadata and WebSocket counts but no headers and
// no bodies.
//
// Not GetFlow per row, which is the detail path: it inlines bodies, so a page of a few
// hundred flows became tens of megabytes in one response and blew past the gRPC message
// limit. A table row needs none of it, and a viewer that opens a flow fetches the detail
// then.
func (s *Store) hydrateFlows(ctx context.Context, sessionID string, ids []string) ([]*trafficv1.Flow, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	q := `SELECT ` + flowCols + ` FROM flows WHERE id IN (?` +
		strings.Repeat(",?", len(ids)-1) + `)`
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byID := make(map[string]*trafficv1.Flow, len(ids))
	for rows.Next() {
		f, err := scanFlow(rows)
		if err != nil {
			return nil, err
		}
		byID[f.Id] = f
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.attachAnnotations(ctx, db, flowRecords(byID)); err != nil {
		return nil, err
	}
	if err := s.attachWsCounts(ctx, db, byID); err != nil {
		return nil, err
	}
	if err := s.attachMetadata(ctx, db, byID); err != nil {
		return nil, err
	}
	// IN (...) does not preserve order, so the page is reassembled from the id list the
	// scan produced — which is already in timeline order.
	out := make([]*trafficv1.Flow, 0, len(ids))
	for _, id := range ids {
		if f := byID[id]; f != nil {
			out = append(out, f)
		}
	}
	// linkRedirects is deliberately not run here: it correlates a redirect with its target
	// across the whole session, and a page cannot see outside itself. Redirect chains are
	// a detail-view concern, and GetFlow still resolves them.
	return out, nil
}

func reverse[T any](s []T) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// annotationIndex is every annotation in a bundle, keyed by record id. Loaded once per
// query with one whole-table read each — the pattern attachAnnotations already uses —
// so the scan consults maps instead of joining per row.
type annotationIndex struct {
	tags     map[string][]string
	groups   map[string][]string
	marks    map[string]string
	comments map[string][]string
	favorite map[string]bool
	tagNames map[string]string
	grpNames map[string]string
}

func (a *annotationIndex) apply(id string, f *filter.Flow) {
	f.TagNames = a.tags[id]
	f.GroupNames = a.groups[id]
	f.MarkColor = a.marks[id]
	f.Comments = a.comments[id]
	f.Favorite = a.favorite[id]
}

// Names returns the id→name maps the predicate needs, since ~tag and ~group match what
// the user sees rather than an internal id.
func (a *annotationIndex) Names() (tags, groups map[string]string) {
	return a.tagNames, a.grpNames
}

func (s *Store) loadAnnotationIndex(ctx context.Context, db *sql.DB) (*annotationIndex, error) {
	a := &annotationIndex{
		tags: map[string][]string{}, groups: map[string][]string{},
		marks: map[string]string{}, comments: map[string][]string{},
		favorite: map[string]bool{},
		tagNames: map[string]string{}, grpNames: map[string]string{},
	}
	favTags := map[string]bool{}
	rows, err := db.QueryContext(ctx, `SELECT id, name, is_favorite FROM tags`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, name string
		var fav int
		if err := rows.Scan(&id, &name, &fav); err != nil {
			rows.Close()
			return nil, err
		}
		a.tagNames[id] = name
		if fav != 0 {
			favTags[id] = true
		}
	}
	rows.Close()

	if err := scanPairs(ctx, db, `SELECT id, name FROM groups`, func(id, name string) {
		a.grpNames[id] = name
	}); err != nil {
		return nil, err
	}
	if err := scanPairs(ctx, db, `SELECT record_id, tag_id FROM record_tags`, func(rid, tid string) {
		a.tags[rid] = append(a.tags[rid], tid)
		if favTags[tid] {
			a.favorite[rid] = true
		}
	}); err != nil {
		return nil, err
	}
	if err := scanPairs(ctx, db, `SELECT record_id, group_id FROM group_members`, func(rid, gid string) {
		a.groups[rid] = append(a.groups[rid], gid)
	}); err != nil {
		return nil, err
	}
	if err := scanPairs(ctx, db, `SELECT record_id, color FROM record_marks`, func(rid, c string) {
		a.marks[rid] = c
	}); err != nil {
		return nil, err
	}
	if err := scanPairs(ctx, db, `SELECT record_id, body FROM comments`, func(rid, body string) {
		a.comments[rid] = append(a.comments[rid], body)
	}); err != nil {
		return nil, err
	}
	return a, nil
}

func loadMetadataIndex(ctx context.Context, db *sql.DB) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	rows, err := db.QueryContext(ctx, `SELECT flow_id, key, value FROM flow_metadata`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var fid, k, v string
		if err := rows.Scan(&fid, &k, &v); err != nil {
			return nil, err
		}
		if out[fid] == nil {
			out[fid] = map[string]string{}
		}
		out[fid][k] = v
	}
	return out, rows.Err()
}

// loadBlobBytes reads a content-addressed blob, inline or spilled. Returns nil rather
// than an error when it cannot be read: a body that will not load is a body that does not
// match, which is how the pre-existing content search behaved too.
func (s *Store) loadBlobBytes(ctx context.Context, db *sql.DB, sha string) []byte {
	var b []byte
	var ext sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT bytes, external_path FROM blobs WHERE sha256=?`, sha).Scan(&b, &ext); err != nil {
		return nil
	}
	if ext.Valid && ext.String != "" {
		data, err := os.ReadFile(filepath.Join(s.dataRoot, ext.String))
		if err != nil {
			return nil
		}
		return data
	}
	return b
}

// AnnotationNames returns the bundle's tag and group id→name maps. A filter needs these
// before it can be compiled, because ~tag and ~group match the names a user sees rather
// than internal ids — and the names live in the bundle, which mirrors them so it stays
// self-contained.
func (s *Store) AnnotationNames(ctx context.Context, sessionID string) (tags, groups map[string]string, err error) {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return nil, nil, err
	}
	a, err := s.loadAnnotationIndex(ctx, db)
	if err != nil {
		return nil, nil, err
	}
	tags, groups = a.Names()
	return tags, groups, nil
}
