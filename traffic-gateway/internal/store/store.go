// Package store is the gateway's Postgres persistence layer (plan §6.1).
//
// Inserts accept decode.Flow (decoder output); reads return proto types directly
// to keep the read path thin for the ViewerService.
package store

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	trafficv1 "github.com/nikitak/parsing/traffic-gateway/gen/traffic/v1"
	"github.com/nikitak/parsing/traffic-gateway/internal/decode"
)

type Store struct {
	pool *pgxpool.Pool
}

// Open connects to Postgres and verifies connectivity.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

// Migrate applies embedded migrations using a single dedicated connection.
func (s *Store) Migrate(ctx context.Context, fsys fs.FS) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	return Migrate(ctx, conn.Conn(), fsys)
}

// --- writes ---------------------------------------------------------------

type NewSession struct {
	ID          string
	Label       string
	SourceKind  trafficv1.SourceKind
	Status      trafficv1.SessionStatus
	PcapKey     string
	KeylogKey   string
	PcapngKey   string
	PcapBytes   int64
	KeylogBytes int64
}

func (s *Store) CreateSession(ctx context.Context, ns NewSession) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (id, label, source_kind, status,
		    pcap_object_key, keylog_object_key, pcapng_object_key, pcap_bytes, keylog_bytes)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9)`,
		ns.ID, ns.Label, ns.SourceKind.String(), ns.Status.String(),
		ns.PcapKey, ns.KeylogKey, ns.PcapngKey, ns.PcapBytes, ns.KeylogBytes)
	return err
}

// SetSessionStatus updates status and, for terminal states, closed_at.
func (s *Store) SetSessionStatus(ctx context.Context, sessionID string, status trafficv1.SessionStatus) error {
	closed := status == trafficv1.SessionStatus_SESSION_STATUS_CLOSED || status == trafficv1.SessionStatus_SESSION_STATUS_ERROR
	_, err := s.pool.Exec(ctx, `
		UPDATE sessions SET status=$2, closed_at = CASE WHEN $3 THEN now() ELSE closed_at END
		WHERE id=$1`, sessionID, status.String(), closed)
	return err
}

type NewAnalysis struct {
	ID                string
	SessionID         string
	Engine            string
	TLSKeyLogUsed     bool
	PlaintextFallback bool
	DatasetKey        string
}

func (s *Store) CreateAnalysis(ctx context.Context, na NewAnalysis) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO analyses (id, session_id, engine, tls_key_log_used, plaintext_fallback, dataset_object_key)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,''))`,
		na.ID, na.SessionID, na.Engine, na.TLSKeyLogUsed, na.PlaintextFallback, na.DatasetKey)
	return err
}

// InsertFlows writes flows and their headers in one transaction; returns count.
func (s *Store) InsertFlows(ctx context.Context, sessionID, analysisID string, flows []*decode.Flow) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	for _, f := range flows {
		id := uuid.NewString()
		if _, err := tx.Exec(ctx, `
			INSERT INTO flows (id, session_id, analysis_id, frame_number, ts_micros,
			    method, scheme, authority, path, query, protocol, status,
			    src_addr, dst_addr, user_agent, content_type, request_bytes,
			    tls_decrypted, tcp_stream, h2_stream_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
			id, sessionID, analysisID, int64(f.FrameNumber), f.TSUnixMicros,
			f.Method, f.Scheme, f.Authority, f.Path, f.Query, f.Protocol, int32(f.Status),
			f.SrcAddr, f.DstAddr, f.UserAgent, f.ContentType, int64(f.RequestBytes),
			f.TLSDecrypted, f.TCPStream, f.H2StreamID); err != nil {
			return 0, err
		}
		if err := insertHeaders(ctx, tx, id, 0, f.RequestHeaders); err != nil {
			return 0, err
		}
		if err := insertHeaders(ctx, tx, id, 1, f.ResponseHeaders); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(flows), nil
}

func insertHeaders(ctx context.Context, tx pgx.Tx, flowID string, dir int, hs []decode.Header) error {
	for i, h := range hs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO flow_headers (flow_id, direction, ord, name, value) VALUES ($1,$2,$3,$4,$5)`,
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
	rows, err := s.pool.Query(ctx, `
		SELECT s.id, s.label, s.source_kind, s.status, s.created_at, s.closed_at,
		       s.pcap_bytes, s.keylog_bytes,
		       (SELECT count(*) FROM flows f WHERE f.session_id = s.id) AS flow_count
		FROM sessions s
		ORDER BY s.created_at DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*trafficv1.Session
	for rows.Next() {
		var (
			id, label, srcKind, status string
			createdAt                  time.Time
			closedAt                   *time.Time
			pcapBytes, keylogBytes     int64
			flowCount                  int64
		)
		if err := rows.Scan(&id, &label, &srcKind, &status, &createdAt, &closedAt,
			&pcapBytes, &keylogBytes, &flowCount); err != nil {
			return nil, err
		}
		out = append(out, &trafficv1.Session{
			Id:             id,
			Label:          label,
			SourceKind:     trafficv1.SourceKind(trafficv1.SourceKind_value[srcKind]),
			Status:         trafficv1.SessionStatus(trafficv1.SessionStatus_value[status]),
			CreatedAtUnixMs: createdAt.UnixMilli(),
			ClosedAtUnixMs:  unixMilliPtr(closedAt),
			PcapBytes:      uint64(pcapBytes),
			KeylogBytes:    uint64(keylogBytes),
			FlowCount:      uint32(flowCount),
		})
	}
	return out, rows.Err()
}

// ListFlows returns flow summaries (no headers/bodies) for backfill.
func (s *Store) ListFlows(ctx context.Context, sessionID string) ([]*trafficv1.Flow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, session_id, analysis_id, frame_number, ts_micros, method, scheme,
		       authority, path, query, protocol, status, src_addr, dst_addr,
		       user_agent, content_type, request_bytes, tls_decrypted, tcp_stream, h2_stream_id
		FROM flows WHERE session_id=$1 ORDER BY ts_micros, frame_number`, sessionID)
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

// GetFlow returns a single flow with its headers.
func (s *Store) GetFlow(ctx context.Context, flowID string) (*trafficv1.Flow, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, session_id, analysis_id, frame_number, ts_micros, method, scheme,
		       authority, path, query, protocol, status, src_addr, dst_addr,
		       user_agent, content_type, request_bytes, tls_decrypted, tcp_stream, h2_stream_id
		FROM flows WHERE id=$1`, flowID)
	f, err := scanFlow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	hrows, err := s.pool.Query(ctx,
		`SELECT direction, name, value FROM flow_headers WHERE flow_id=$1 ORDER BY direction, ord`, flowID)
	if err != nil {
		return nil, err
	}
	defer hrows.Close()
	for hrows.Next() {
		var dir int16
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

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("store: not found")

type scannable interface {
	Scan(dest ...any) error
}

func scanFlow(row scannable) (*trafficv1.Flow, error) {
	var (
		id, sessionID, analysisID                                  string
		frameNumber, tsMicros, requestBytes                        int64
		method, scheme, authority, path, query, protocol           string
		status                                                     int32
		srcAddr, dstAddr, userAgent, contentType, tcpStream, h2sid string
		tlsDecrypted                                               bool
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
		Method:       method,
		Scheme:       scheme,
		Authority:    authority,
		Path:         path,
		Query:        query,
		Protocol:     protocol,
		Status:       uint32(status),
		SrcAddr:      srcAddr,
		DstAddr:      dstAddr,
		UserAgent:    userAgent,
		ContentType:  contentType,
		RequestBytes: uint64(requestBytes),
		TlsDecrypted: tlsDecrypted,
		TcpStream:    tcpStream,
		H2StreamId:   h2sid,
	}, nil
}

func unixMilliPtr(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.UnixMilli()
}
