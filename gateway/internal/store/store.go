// Package store is the gateway's SQLite persistence layer.
//
// Per-session bundles: each session has its own sessions/<id>/flows.sqlite holding
// that capture's flows; a global catalog.sqlite holds the session list. Inserts
// accept decode.Flow; reads return proto types to keep the ViewerService path thin.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrSchemaOutdated is returned when a session bundle's flows.sqlite was written by
// an older gateway and is missing columns the current read path needs. The session
// schema uses CREATE TABLE IF NOT EXISTS, which never alters an existing table, so
// such bundles cannot be migrated in place — they must be re-imported. The error
// message names the missing columns and is safe to surface to clients.
var ErrSchemaOutdated = errors.New("session bundle schema is outdated — re-import this session")

// requiredFlowColumns are the flows-table columns the read/serialize path depends on.
// Bundles predating any of these (e.g. the proxy_* columns) trip ErrSchemaOutdated.
var requiredFlowColumns = []string{
	"id", "session_id", "analysis_id", "frame_number", "ts_micros", "method", "scheme",
	"authority", "path", "query", "protocol", "status", "src_addr", "dst_addr",
	"user_agent", "content_type", "request_bytes", "tls_decrypted", "tcp_stream",
	"h2_stream_id", "req_body_ref", "resp_body_ref", "proxy_addr", "proxy_type",
	"proxy_user", "proxy_pass",
}

const pragmas = `PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=NORMAL;`

type Store struct {
	dataRoot string
	catalog  *sql.DB

	mu       sync.Mutex
	sessions map[string]*sql.DB // open per-session DBs, keyed by session id
}

// Open creates/opens the catalog under dataRoot and prepares the store.
func Open(ctx context.Context, dataRoot string) (*Store, error) {
	if err := os.MkdirAll(dataRoot, 0o755); err != nil {
		return nil, err
	}
	cat, err := openDB(ctx, filepath.Join(dataRoot, "catalog.sqlite"), catalogSchema)
	if err != nil {
		return nil, err
	}
	return &Store{dataRoot: dataRoot, catalog: cat, sessions: map[string]*sql.DB{}}, nil
}

func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, db := range s.sessions {
		_ = db.Close()
	}
	_ = s.catalog.Close()
}

// openDB opens a SQLite file, applies pragmas and the (idempotent) schema.
func openDB(ctx context.Context, path, schema string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, pragmas); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// sessionDB returns the (cached) DB for a session, creating the bundle dir + file.
func (s *Store) sessionDB(ctx context.Context, sessionID string) (*sql.DB, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if db, ok := s.sessions[sessionID]; ok {
		return db, nil
	}
	dir := filepath.Join(s.dataRoot, "sessions", sessionID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	db, err := openDB(ctx, filepath.Join(dir, "flows.sqlite"), sessionSchema)
	if err != nil {
		return nil, err
	}
	// Reject bundles older than the current flows schema up front, so every read/write
	// path gets a single, actionable ErrSchemaOutdated instead of a raw "no such
	// column" SQL error deep in a query. A freshly created DB has the current schema
	// and passes; only pre-existing older bundles fail.
	if err := validateSessionSchema(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	s.sessions[sessionID] = db
	return db, nil
}

// validateSessionSchema verifies the flows table has every column the read path needs.
// Returns an ErrSchemaOutdated wrapping the list of missing columns when it doesn't.
func validateSessionSchema(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(flows)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	have := make(map[string]bool)
	for rows.Next() {
		var (
			cid, notnull, pk int
			name, typ        string
			dflt             sql.NullString
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return err
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var missing []string
	for _, c := range requiredFlowColumns {
		if !have[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w (flows table missing columns: %s)", ErrSchemaOutdated, strings.Join(missing, ", "))
	}
	return nil
}

// --- writes ---------------------------------------------------------------

type NewSession struct {
	ID          string
	Label       string
	SourceKind  trafficv1.SourceKind
	Status      trafficv1.SessionStatus
	PcapBytes   int64
	KeylogBytes int64
}

func (s *Store) CreateSession(ctx context.Context, ns NewSession) error {
	if _, err := s.catalog.ExecContext(ctx, `
		INSERT INTO sessions (id, label, source_kind, status, created_at, pcap_bytes, keylog_bytes)
		VALUES (?,?,?,?,?,?,?)`,
		ns.ID, ns.Label, ns.SourceKind.String(), ns.Status.String(),
		time.Now().UnixMilli(), ns.PcapBytes, ns.KeylogBytes); err != nil {
		return err
	}
	// Materialize the per-session bundle DB up front.
	_, err := s.sessionDB(ctx, ns.ID)
	return err
}

// FinishSession sets the terminal status, closed_at, and flow_count in the catalog.
func (s *Store) FinishSession(ctx context.Context, sessionID string, status trafficv1.SessionStatus, flowCount int) error {
	var closed any
	if status == trafficv1.SessionStatus_SESSION_STATUS_CLOSED || status == trafficv1.SessionStatus_SESSION_STATUS_ERROR {
		closed = time.Now().UnixMilli()
	}
	_, err := s.catalog.ExecContext(ctx,
		`UPDATE sessions SET status=?, closed_at=?, flow_count=? WHERE id=?`,
		status.String(), closed, flowCount, sessionID)
	return err
}

type NewAnalysis struct {
	ID            string
	SessionID     string
	Engine        string
	TLSKeyLogUsed bool
}

func (s *Store) CreateAnalysis(ctx context.Context, na NewAnalysis) error {
	db, err := s.sessionDB(ctx, na.SessionID)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO analyses (id, session_id, engine, tls_key_log_used, created_at)
		VALUES (?,?,?,?,?)`,
		na.ID, na.SessionID, na.Engine, boolToInt(na.TLSKeyLogUsed), time.Now().UnixMilli())
	return err
}

// InsertFlows writes flows and their headers into the session bundle in one tx.
func (s *Store) InsertFlows(ctx context.Context, sessionID, analysisID string, flows []*decode.Flow) (int, error) {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return 0, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	for _, f := range flows {
		id := f.ID
		if id == "" {
			id = uuid.NewString()
		}
		reqRef, err := s.storeBlob(ctx, tx, sessionID, f.RequestBody, ctFromHeaders(f.RequestHeaders))
		if err != nil {
			return 0, err
		}
		respRef, err := s.storeBlob(ctx, tx, sessionID, f.ResponseBody, ctFromHeaders(f.ResponseHeaders))
		if err != nil {
			return 0, err
		}
		var pAddr, pType, pUser, pPass string
		if f.Proxy != nil {
			pAddr, pType, pUser, pPass = f.Proxy.Addr, f.Proxy.Type, f.Proxy.Username, f.Proxy.Password
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO flows (id, session_id, analysis_id, frame_number, ts_micros,
			    method, scheme, authority, path, query, protocol, status,
			    src_addr, dst_addr, user_agent, content_type, request_bytes,
			    tls_decrypted, tcp_stream, h2_stream_id, req_body_ref, resp_body_ref,
			    proxy_addr, proxy_type, proxy_user, proxy_pass)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			id, sessionID, analysisID, int64(f.FrameNumber), f.TSUnixMicros,
			f.Method, f.Scheme, f.Authority, f.Path, f.Query, f.Protocol, int64(f.Status),
			f.SrcAddr, f.DstAddr, f.UserAgent, f.ContentType, int64(f.RequestBytes),
			boolToInt(f.TLSDecrypted), f.TCPStream, f.H2StreamID,
			nullIfEmpty(reqRef), nullIfEmpty(respRef),
			nullIfEmpty(pAddr), nullIfEmpty(pType), nullIfEmpty(pUser), nullIfEmpty(pPass)); err != nil {
			return 0, err
		}
		if err := insertHeaders(ctx, tx, id, 0, f.RequestHeaders); err != nil {
			return 0, err
		}
		if err := insertHeaders(ctx, tx, id, 1, f.ResponseHeaders); err != nil {
			return 0, err
		}
		if err := insertMetadata(ctx, tx, id, f.Metadata); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(flows), nil
}

// insertMetadata writes a flow's opaque source-supplied key/value metadata.
func insertMetadata(ctx context.Context, tx *sql.Tx, flowID string, md map[string]string) error {
	for k, v := range md {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO flow_metadata (flow_id, key, value) VALUES (?,?,?)`,
			flowID, k, v); err != nil {
			return err
		}
	}
	return nil
}

func insertHeaders(ctx context.Context, tx *sql.Tx, flowID string, dir int, hs []decode.Header) error {
	for i, h := range hs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO flow_headers (flow_id, direction, ord, name, value) VALUES (?,?,?,?,?)`,
			flowID, dir, i, h.Name, h.Value); err != nil {
			return err
		}
	}
	return nil
}

// InlineBlobMax is the size threshold: bodies at or below it are stored
// inline in SQLite; larger bodies spill to a file under the session bundle.
const InlineBlobMax = 1 << 20 // 1 MiB

// storeBlob content-addresses a body and returns its sha256 ("" if empty). Small
// bodies go inline; large bodies spill to sessions/<id>/blobs/<sha256>.
func (s *Store) storeBlob(ctx context.Context, tx *sql.Tx, sessionID string, body []byte, contentType string) (string, error) {
	if len(body) == 0 {
		return "", nil
	}
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])

	if len(body) <= InlineBlobMax {
		_, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO blobs (sha256, size, content_type, bytes) VALUES (?,?,?,?)`,
			sha, len(body), contentType, body)
		return sha, err
	}

	rel := filepath.Join("sessions", sessionID, "blobs", sha)
	abs := filepath.Join(s.dataRoot, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(abs, body, 0o644); err != nil {
		return "", err
	}
	_, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO blobs (sha256, size, content_type, external_path) VALUES (?,?,?,?)`,
		sha, len(body), contentType, rel)
	return sha, err
}

func ctFromHeaders(hs []decode.Header) string {
	for _, h := range hs {
		if strings.EqualFold(h.Name, "content-type") {
			return h.Value
		}
	}
	return ""
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// --- reads ----------------------------------------------------------------

func (s *Store) ListSessions(ctx context.Context, limit, offset int) ([]*trafficv1.Session, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.catalog.QueryContext(ctx, `
		SELECT id, label, source_kind, status, created_at, closed_at,
		       pcap_bytes, keylog_bytes, flow_count
		FROM sessions ORDER BY created_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*trafficv1.Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

const sessionCols = `id, label, source_kind, status, created_at, closed_at, pcap_bytes, keylog_bytes, flow_count`

func scanSession(row scannable) (*trafficv1.Session, error) {
	var (
		id, label, srcKind, status string
		createdAt                  int64
		closedAt                   sql.NullInt64
		pcapBytes, keylogBytes     int64
		flowCount                  int64
	)
	if err := row.Scan(&id, &label, &srcKind, &status, &createdAt, &closedAt,
		&pcapBytes, &keylogBytes, &flowCount); err != nil {
		return nil, err
	}
	return &trafficv1.Session{
		Id:              id,
		Label:           label,
		SourceKind:      trafficv1.SourceKind(trafficv1.SourceKind_value[srcKind]),
		Status:          trafficv1.SessionStatus(trafficv1.SessionStatus_value[status]),
		CreatedAtUnixMs: createdAt,
		ClosedAtUnixMs:  closedAt.Int64,
		PcapBytes:       uint64(pcapBytes),
		KeylogBytes:     uint64(keylogBytes),
		FlowCount:       uint32(flowCount),
	}, nil
}

// GetSession returns a single session from the catalog.
func (s *Store) GetSession(ctx context.Context, id string) (*trafficv1.Session, error) {
	sess, err := scanSession(s.catalog.QueryRowContext(ctx,
		`SELECT `+sessionCols+` FROM sessions WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sess, err
}

// SetSessionBytes records the captured pcap/key.log sizes in the catalog.
func (s *Store) SetSessionBytes(ctx context.Context, id string, pcapBytes, keylogBytes int64) error {
	_, err := s.catalog.ExecContext(ctx,
		`UPDATE sessions SET pcap_bytes=?, keylog_bytes=? WHERE id=?`, pcapBytes, keylogBytes, id)
	return err
}

const flowCols = `id, session_id, analysis_id, frame_number, ts_micros, method, scheme,
	authority, path, query, protocol, status, src_addr, dst_addr,
	user_agent, content_type, request_bytes, tls_decrypted, tcp_stream, h2_stream_id,
	proxy_addr, proxy_type, proxy_user, proxy_pass`

// ListFlows returns flow summaries (no headers/bodies) for backfill.
func (s *Store) ListFlows(ctx context.Context, sessionID string) ([]*trafficv1.Flow, error) {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx,
		`SELECT `+flowCols+` FROM flows ORDER BY ts_micros, frame_number`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*trafficv1.Flow
	byID := map[string]*trafficv1.Flow{}
	for rows.Next() {
		f, err := scanFlow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
		byID[f.Id] = f
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.attachAnnotations(ctx, db, byID); err != nil {
		return nil, err
	}
	if err := s.attachWsCounts(ctx, db, byID); err != nil {
		return nil, err
	}
	if err := s.attachMetadata(ctx, db, byID); err != nil {
		return nil, err
	}
	return out, nil
}

// attachMetadata fills each flow's Metadata map from the flow_metadata side table.
func (s *Store) attachMetadata(ctx context.Context, db *sql.DB, flows map[string]*trafficv1.Flow) error {
	if len(flows) == 0 {
		return nil
	}
	rows, err := db.QueryContext(ctx, `SELECT flow_id, key, value FROM flow_metadata`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var fid, k, v string
		if err := rows.Scan(&fid, &k, &v); err != nil {
			return err
		}
		f := flows[fid]
		if f == nil {
			continue
		}
		if f.Metadata == nil {
			f.Metadata = map[string]string{}
		}
		f.Metadata[k] = v
	}
	return rows.Err()
}

// CountFlows returns the number of flows stored in a session's bundle. Used to
// finalize supplied (pushed) sessions that have no pcap to re-decode.
func (s *Store) CountFlows(ctx context.Context, sessionID string) (int, error) {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return 0, err
	}
	var n int
	err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM flows`).Scan(&n)
	return n, err
}

// GetFlow returns a single flow (with headers) from the given session's bundle.
func (s *Store) GetFlow(ctx context.Context, sessionID, flowID string) (*trafficv1.Flow, error) {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	f, err := scanFlow(db.QueryRowContext(ctx, `SELECT `+flowCols+` FROM flows WHERE id=?`, flowID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	hrows, err := db.QueryContext(ctx,
		`SELECT direction, name, value FROM flow_headers WHERE flow_id=? ORDER BY direction, ord`, flowID)
	if err != nil {
		return nil, err
	}
	defer hrows.Close()
	for hrows.Next() {
		var dir int
		var name, value string
		if err := hrows.Scan(&dir, &name, &value); err != nil {
			return nil, err
		}
		h := &trafficv1.Header{Name: name, Value: value}
		if dir == 0 {
			f.RequestHeaders = append(f.RequestHeaders, h)
		} else {
			f.ResponseHeaders = append(f.ResponseHeaders, h)
		}
	}
	if err := hrows.Err(); err != nil {
		return nil, err
	}

	// Attach bodies (inlined; capped at decode.MaxBodyBytes).
	var reqRef, respRef sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT req_body_ref, resp_body_ref FROM flows WHERE id=?`, flowID).
		Scan(&reqRef, &respRef); err == nil {
		f.RequestBody = s.loadBody(ctx, db, reqRef.String)
		f.ResponseBody = s.loadBody(ctx, db, respRef.String)
	}
	single := map[string]*trafficv1.Flow{f.Id: f}
	if err := s.attachAnnotations(ctx, db, single); err != nil {
		return nil, err
	}
	if err := s.attachWsCounts(ctx, db, single); err != nil {
		return nil, err
	}
	if err := s.attachMetadata(ctx, db, single); err != nil {
		return nil, err
	}
	return f, nil
}

// loadBody returns body metadata for GetFlow: small bodies inline, large bodies
// as an object_ref (sha256) to be fetched in full via GetBody.
func (s *Store) loadBody(ctx context.Context, db *sql.DB, sha string) *trafficv1.Body {
	if sha == "" {
		return nil
	}
	var size int64
	var ct string
	var b []byte
	var ext sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT size, content_type, bytes, external_path FROM blobs WHERE sha256=?`, sha).
		Scan(&size, &ct, &b, &ext); err != nil {
		return nil
	}
	body := &trafficv1.Body{Size: uint64(size), ContentType: ct}
	if ext.Valid && ext.String != "" {
		body.Content = &trafficv1.Body_ObjectRef{ObjectRef: sha}
	} else {
		body.Content = &trafficv1.Body_Inline{Inline: b}
	}
	return body
}

// GetBodyBytes returns the raw body bytes + content-type for a flow direction.
func (s *Store) GetBodyBytes(ctx context.Context, sessionID, flowID string, response bool) ([]byte, string, error) {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return nil, "", err
	}
	col := "req_body_ref"
	if response {
		col = "resp_body_ref"
	}
	var ref sql.NullString
	switch err := db.QueryRowContext(ctx, `SELECT `+col+` FROM flows WHERE id=?`, flowID).Scan(&ref); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, "", ErrNotFound
	case err != nil:
		return nil, "", err
	}
	if !ref.Valid || ref.String == "" {
		return nil, "", ErrNotFound
	}
	var b []byte
	var ct string
	var ext sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT bytes, content_type, external_path FROM blobs WHERE sha256=?`, ref.String).
		Scan(&b, &ct, &ext); err != nil {
		return nil, "", err
	}
	if ext.Valid && ext.String != "" {
		data, err := os.ReadFile(filepath.Join(s.dataRoot, ext.String))
		if err != nil {
			return nil, "", err
		}
		return data, ct, nil
	}
	return b, ct, nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanFlow(row scannable) (*trafficv1.Flow, error) {
	var (
		id, sessionID, analysisID                                  string
		frameNumber, tsMicros, requestBytes, status                int64
		method, scheme, authority, path, query, protocol           sql.NullString
		srcAddr, dstAddr, userAgent, contentType, tcpStream, h2sid sql.NullString
		proxyAddr, proxyType, proxyUser, proxyPass                 sql.NullString
		tlsDecrypted                                               int64
	)
	if err := row.Scan(&id, &sessionID, &analysisID, &frameNumber, &tsMicros, &method, &scheme,
		&authority, &path, &query, &protocol, &status, &srcAddr, &dstAddr,
		&userAgent, &contentType, &requestBytes, &tlsDecrypted, &tcpStream, &h2sid,
		&proxyAddr, &proxyType, &proxyUser, &proxyPass); err != nil {
		return nil, err
	}
	f := &trafficv1.Flow{
		Id:           id,
		SessionId:    sessionID,
		AnalysisId:   analysisID,
		FrameNumber:  uint64(frameNumber),
		TsUnixMicros: tsMicros,
		Method:       method.String,
		Scheme:       scheme.String,
		Authority:    authority.String,
		Path:         path.String,
		Query:        query.String,
		Protocol:     protocol.String,
		Status:       uint32(status),
		SrcAddr:      srcAddr.String,
		DstAddr:      dstAddr.String,
		UserAgent:    userAgent.String,
		ContentType:  contentType.String,
		RequestBytes: uint64(requestBytes),
		TlsDecrypted: tlsDecrypted != 0,
		TcpStream:    tcpStream.String,
		H2StreamId:   h2sid.String,
	}
	if proxyAddr.String != "" {
		f.Proxy = &trafficv1.Proxy{
			Addr: proxyAddr.String, Type: proxyType.String,
			Username: proxyUser.String, Password: proxyPass.String,
		}
	}
	return f, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
