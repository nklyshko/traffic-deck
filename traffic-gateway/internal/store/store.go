// Package store is the gateway's SQLite persistence layer (plan §6).
//
// Per-session bundles: each session has its own sessions/<id>/flows.sqlite holding
// that capture's flows; a global catalog.sqlite holds the session list. Inserts
// accept decode.Flow; reads return proto types to keep the ViewerService path thin.
package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	trafficv1 "github.com/nikitak/parsing/traffic-gateway/gen/traffic/v1"
	"github.com/nikitak/parsing/traffic-gateway/internal/decode"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("store: not found")

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
	s.sessions[sessionID] = db
	return db, nil
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
		id := uuid.NewString()
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO flows (id, session_id, analysis_id, frame_number, ts_micros,
			    method, scheme, authority, path, query, protocol, status,
			    src_addr, dst_addr, user_agent, content_type, request_bytes,
			    tls_decrypted, tcp_stream, h2_stream_id)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			id, sessionID, analysisID, int64(f.FrameNumber), f.TSUnixMicros,
			f.Method, f.Scheme, f.Authority, f.Path, f.Query, f.Protocol, int64(f.Status),
			f.SrcAddr, f.DstAddr, f.UserAgent, f.ContentType, int64(f.RequestBytes),
			boolToInt(f.TLSDecrypted), f.TCPStream, f.H2StreamID); err != nil {
			return 0, err
		}
		if err := insertHeaders(ctx, tx, id, 0, f.RequestHeaders); err != nil {
			return 0, err
		}
		if err := insertHeaders(ctx, tx, id, 1, f.ResponseHeaders); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(flows), nil
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
		var (
			id, label, srcKind, status string
			createdAt                  int64
			closedAt                   sql.NullInt64
			pcapBytes, keylogBytes     int64
			flowCount                  int64
		)
		if err := rows.Scan(&id, &label, &srcKind, &status, &createdAt, &closedAt,
			&pcapBytes, &keylogBytes, &flowCount); err != nil {
			return nil, err
		}
		out = append(out, &trafficv1.Session{
			Id:              id,
			Label:           label,
			SourceKind:      trafficv1.SourceKind(trafficv1.SourceKind_value[srcKind]),
			Status:          trafficv1.SessionStatus(trafficv1.SessionStatus_value[status]),
			CreatedAtUnixMs: createdAt,
			ClosedAtUnixMs:  closedAt.Int64,
			PcapBytes:       uint64(pcapBytes),
			KeylogBytes:     uint64(keylogBytes),
			FlowCount:       uint32(flowCount),
		})
	}
	return out, rows.Err()
}

const flowCols = `id, session_id, analysis_id, frame_number, ts_micros, method, scheme,
	authority, path, query, protocol, status, src_addr, dst_addr,
	user_agent, content_type, request_bytes, tls_decrypted, tcp_stream, h2_stream_id`

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
	for rows.Next() {
		f, err := scanFlow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
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
	return f, hrows.Err()
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
		tlsDecrypted                                               int64
	)
	if err := row.Scan(&id, &sessionID, &analysisID, &frameNumber, &tsMicros, &method, &scheme,
		&authority, &path, &query, &protocol, &status, &srcAddr, &dstAddr,
		&userAgent, &contentType, &requestBytes, &tlsDecrypted, &tcpStream, &h2sid); err != nil {
		return nil, err
	}
	return &trafficv1.Flow{
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
	}, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
