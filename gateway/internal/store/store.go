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
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
	"github.com/nklyshko/traffic-deck/gateway/internal/tlsfp"
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
	"proxy_user", "proxy_pass", "error", "duration_micros", "h2_fingerprint",
	"ja3", "ja4", "tls_client_hello", "redirect_location", "tls_hrr",
}

// dsnPragmas are applied to every pooled connection (unlike `PRAGMA` run via Exec, which
// only affects the one connection it ran on). busy_timeout on all connections makes
// concurrent writers wait for the lock instead of failing with SQLITE_BUSY — important
// under many concurrent writers (e.g. the mitmproxy push path opening a stream per frame).
const dsnPragmas = "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)" +
	"&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"

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
	if err := migrateCatalog(ctx, cat); err != nil {
		cat.Close()
		return nil, err
	}
	return &Store{dataRoot: dataRoot, catalog: cat, sessions: map[string]*sql.DB{}}, nil
}

// migrateCatalog applies additive column migrations to an existing catalog — CREATE TABLE
// IF NOT EXISTS never alters a table, so columns added over time need ALTER. Each is
// idempotent: a duplicate-column error means it's already present.
func migrateCatalog(ctx context.Context, db *sql.DB) error {
	for _, stmt := range []string{
		`ALTER TABLE sessions ADD COLUMN session_group TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
	}
	return nil
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
	db, err := sql.Open("sqlite", path+dsnPragmas)
	if err != nil {
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
	if err := migrateSession(ctx, db); err != nil {
		db.Close()
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

// requiredWsMessageColumns are the ws_messages columns the read path depends on. Bundles
// predating raw_ref trip ErrSchemaOutdated (re-import to get the raw-bytes column).
var requiredWsMessageColumns = []string{
	"id", "flow_id", "frame_number", "ts_micros", "from_client", "opcode",
	"payload_ref", "raw_ref",
}

// migrateSession applies additive column migrations to an existing session bundle —
// CREATE TABLE IF NOT EXISTS never alters a table. Used where a bundle written by an
// older gateway stays readable without the new column's data: the body content-encoding
// columns are empty for such a bundle, which reads as "no encoding recorded" — the
// bodies in it are whatever that gateway stored. Re-import to have them decoded.
// A column the read path cannot do without belongs in requiredFlowColumns instead, which
// rejects the bundle outright (ErrSchemaOutdated). Each statement is idempotent: a
// duplicate-column error means it is already applied.
func migrateSession(ctx context.Context, db *sql.DB) error {
	for _, stmt := range []string{
		`ALTER TABLE flows ADD COLUMN req_content_encoding TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE flows ADD COLUMN resp_content_encoding TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
	}
	return nil
}

// validateSessionSchema verifies the flows + ws_messages tables have every column the read
// path needs. Returns an ErrSchemaOutdated wrapping the missing columns when they don't.
func validateSessionSchema(ctx context.Context, db *sql.DB) error {
	if missing, err := missingColumns(ctx, db, "flows", requiredFlowColumns); err != nil {
		return err
	} else if len(missing) > 0 {
		return fmt.Errorf("%w (flows table missing columns: %s)", ErrSchemaOutdated, strings.Join(missing, ", "))
	}
	if missing, err := missingColumns(ctx, db, "ws_messages", requiredWsMessageColumns); err != nil {
		return err
	} else if len(missing) > 0 {
		return fmt.Errorf("%w (ws_messages table missing columns: %s)", ErrSchemaOutdated, strings.Join(missing, ", "))
	}
	return nil
}

// missingColumns returns which of `required` are absent from `table`.
func missingColumns(ctx context.Context, db *sql.DB, table string, required []string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	have := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var missing []string
	for _, c := range required {
		if !have[c] {
			missing = append(missing, c)
		}
	}
	return missing, nil
}

// --- writes ---------------------------------------------------------------

type NewSession struct {
	ID          string
	Label       string
	Source      string // producing tool: "chrome", "mitmproxy", "import", a module name
	Status      trafficv1.SessionStatus
	PcapBytes   int64
	KeylogBytes int64
	Metadata    map[string]string // opaque source-supplied metadata (e.g. viewer.columns)
}

func (s *Store) CreateSession(ctx context.Context, ns NewSession) error {
	if _, err := s.catalog.ExecContext(ctx, `
		INSERT INTO sessions (id, label, source_kind, status, created_at, pcap_bytes, keylog_bytes)
		VALUES (?,?,?,?,?,?,?)`,
		ns.ID, ns.Label, ns.Source, ns.Status.String(),
		time.Now().UnixMilli(), ns.PcapBytes, ns.KeylogBytes); err != nil {
		return err
	}
	for k, v := range ns.Metadata {
		if _, err := s.catalog.ExecContext(ctx,
			`INSERT OR REPLACE INTO session_metadata (session_id, key, value) VALUES (?,?,?)`,
			ns.ID, k, v); err != nil {
			return err
		}
	}
	// Materialize the per-session bundle DB up front.
	_, err := s.sessionDB(ctx, ns.ID)
	return err
}

// SetSessionMetadata merges keys into a session's metadata, overwriting any that already
// exist. Used when a source reports at CloseSession what it only learned while capturing
// (see CloseSessionRequest.metadata), so the finalization that follows — and anyone
// reading the session later — sees it alongside the metadata supplied at open.
func (s *Store) SetSessionMetadata(ctx context.Context, sessionID string, md map[string]string) error {
	for k, v := range md {
		if _, err := s.catalog.ExecContext(ctx,
			`INSERT OR REPLACE INTO session_metadata (session_id, key, value) VALUES (?,?,?)`,
			sessionID, k, v); err != nil {
			return err
		}
	}
	return nil
}

// attachSessionMetadata fills each session's Metadata map from the session_metadata table.
func (s *Store) attachSessionMetadata(ctx context.Context, sessions map[string]*trafficv1.Session) error {
	if len(sessions) == 0 {
		return nil
	}
	rows, err := s.catalog.QueryContext(ctx, `SELECT session_id, key, value FROM session_metadata`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var sid, k, v string
		if err := rows.Scan(&sid, &k, &v); err != nil {
			return err
		}
		if ss := sessions[sid]; ss != nil {
			if ss.Metadata == nil {
				ss.Metadata = map[string]string{}
			}
			ss.Metadata[k] = v
		}
	}
	return rows.Err()
}

// FinishSession sets the terminal status, closed_at, and flow_count in the catalog, and
// checkpoints the session's write-ahead log now that nothing more will be written to it.
func (s *Store) FinishSession(ctx context.Context, sessionID string, status trafficv1.SessionStatus, flowCount int) error {
	var closed any
	terminal := status == trafficv1.SessionStatus_SESSION_STATUS_CLOSED ||
		status == trafficv1.SessionStatus_SESSION_STATUS_ERROR
	if terminal {
		closed = time.Now().UnixMilli()
	}
	if _, err := s.catalog.ExecContext(ctx,
		`UPDATE sessions SET status=?, closed_at=?, flow_count=? WHERE id=?`,
		status.String(), closed, flowCount, sessionID); err != nil {
		return err
	}
	if terminal {
		s.checkpointSession(ctx, sessionID)
	}
	return nil
}

// checkpointSession folds a finalized session's WAL back into its bundle and truncates it.
// The handle stays in the pool — a viewer may still be reading the session — but no
// further writes are coming, so from here the log is pure overhead. Without this it
// survives for the life of the gateway process, one WAL per session ever captured:
// a two-minute capture left 4.8 MB beside a 6 MB bundle, reclaimed only on shutdown.
//
// Best-effort by design. A checkpoint that cannot run yet (a reader still holding the
// log) is reported as busy rather than failing, and the next one will pick it up; nothing
// about the session's correctness depends on it.
func (s *Store) checkpointSession(ctx context.Context, sessionID string) {
	s.mu.Lock()
	db, open := s.sessions[sessionID]
	s.mu.Unlock()
	if !open {
		return // never opened, so there is no log to fold in
	}
	var busy, logFrames, checkpointed int
	if err := db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).
		Scan(&busy, &logFrames, &checkpointed); err != nil {
		log.Printf("store: WAL checkpoint for session %s: %v", sessionID, err)
		return
	}
	if busy != 0 {
		log.Printf("store: WAL checkpoint for session %s deferred; readers still active", sessionID)
	}
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

// BodyDisposition says how a flow's body bytes should be treated when it is written.
type BodyDisposition int

const (
	// BodiesFinal stores the flow's body bytes and sets its refs. The default, and what
	// every non-live path uses: a batch decode and a pushed flow both arrive complete.
	BodiesFinal BodyDisposition = iota
	// BodiesPending leaves the body refs NULL because the body is still arriving. Writing
	// it now would content-address a prefix and strand that blob when the body grows
	// (ADR-0011 §3b) — blobs are never deleted, so the only safe move is not to write one.
	BodiesPending
	// BodiesStored reuses refs written by an earlier flush, for a flow whose bytes have
	// since been released from memory. Without this a re-flush would null the refs and
	// orphan the body it already wrote.
	BodiesStored
)

// FlowWrite is one flow to persist plus how to treat its bodies. On return from
// InsertFlowWrites, ReqRef/RespRef hold the refs actually written, so a caller that
// releases the bytes afterwards can quote them back with BodiesStored.
type FlowWrite struct {
	Flow    *decode.Flow
	Bodies  BodyDisposition
	ReqRef  string
	RespRef string
}

// InsertFlows writes flows and their headers into the session bundle in one tx, storing
// each flow's bodies. For the live path, which writes a flow before its body is complete,
// see InsertFlowWrites.
func (s *Store) InsertFlows(ctx context.Context, sessionID, analysisID string, flows []*decode.Flow) (int, error) {
	writes := make([]FlowWrite, len(flows))
	for i, f := range flows {
		writes[i] = FlowWrite{Flow: f, Bodies: BodiesFinal}
	}
	return s.InsertFlowWrites(ctx, sessionID, analysisID, writes)
}

// InsertFlowWrites writes flows and their headers in one tx, honouring each write's body
// disposition. It updates writes[i].ReqRef/RespRef with the refs written.
func (s *Store) InsertFlowWrites(ctx context.Context, sessionID, analysisID string, writes []FlowWrite) (int, error) {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return 0, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	// One prepared statement per distinct query, reused across every flow — a large
	// session issues millions of these and re-parsing them dominates otherwise.
	stmts := newTxStmts(ctx, tx)
	defer stmts.close()

	for wi := range writes {
		w := &writes[wi]
		f := w.Flow
		id := f.ID
		if id == "" {
			id = uuid.NewString()
		}
		var reqRef, respRef string
		switch w.Bodies {
		case BodiesPending:
			// Refs stay NULL; the bytes are still in the hub and are written once final.
		case BodiesStored:
			reqRef, respRef = w.ReqRef, w.RespRef
		default:
			if reqRef, err = s.storeBlob(stmts, sessionID, f.RequestBody, ctFromHeaders(f.RequestHeaders)); err != nil {
				return 0, err
			}
			if respRef, err = s.storeBlob(stmts, sessionID, f.ResponseBody, ctFromHeaders(f.ResponseHeaders)); err != nil {
				return 0, err
			}
		}
		w.ReqRef, w.RespRef = reqRef, respRef
		var pAddr, pType, pUser, pPass string
		if f.Proxy != nil {
			pAddr, pType, pUser, pPass = f.Proxy.Addr, f.Proxy.Type, f.Proxy.Username, f.Proxy.Password
		}
		// INSERT OR REPLACE (not plain INSERT) so a flow re-pushed as it progresses — the
		// mitmproxy path pushes it request-first, then again on response — upserts to its
		// latest state instead of hitting the primary-key. The side tables aren't
		// FK-cascaded, so clear their old rows first (headers have no key; metadata does).
		if err := stmts.exec(`DELETE FROM flow_headers WHERE flow_id=?`, id); err != nil {
			return 0, err
		}
		if err := stmts.exec(`DELETE FROM flow_metadata WHERE flow_id=?`, id); err != nil {
			return 0, err
		}
		if err := stmts.exec(`DELETE FROM flow_client_hellos WHERE flow_id=?`, id); err != nil {
			return 0, err
		}
		if err := stmts.exec(`
			INSERT OR REPLACE INTO flows (id, session_id, analysis_id, frame_number, ts_micros,
			    method, scheme, authority, path, query, protocol, status,
			    src_addr, dst_addr, user_agent, content_type, request_bytes,
			    tls_decrypted, tcp_stream, h2_stream_id, req_body_ref, resp_body_ref,
			    proxy_addr, proxy_type, proxy_user, proxy_pass, error, duration_micros, h2_fingerprint,
			    ja3, ja4, tls_client_hello, redirect_location, tls_hrr,
			    req_content_encoding, resp_content_encoding)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			id, sessionID, analysisID, int64(f.FrameNumber), f.TSUnixMicros,
			f.Method, f.Scheme, f.Authority, f.Path, f.Query, f.Protocol, int64(f.Status),
			f.SrcAddr, f.DstAddr, f.UserAgent, f.ContentType, int64(f.RequestBytes),
			boolToInt(f.TLSDecrypted), f.TCPStream, f.H2StreamID,
			nullIfEmpty(reqRef), nullIfEmpty(respRef),
			nullIfEmpty(pAddr), nullIfEmpty(pType), nullIfEmpty(pUser), nullIfEmpty(pPass),
			f.Error, int64(f.DurationMicros), f.Http2Fingerprint,
			f.JA3, f.JA4, f.TLSClientHello, resolveRedirect(f), boolToInt(f.TLSHRR),
			f.RequestBodyEncoding, f.ResponseBodyEncoding); err != nil {
			return 0, err
		}
		if err := insertClientHellos(stmts, id, f.ClientHellos); err != nil {
			return 0, err
		}
		if err := insertHeaders(stmts, id, 0, f.RequestHeaders); err != nil {
			return 0, err
		}
		if err := insertHeaders(stmts, id, 1, f.ResponseHeaders); err != nil {
			return 0, err
		}
		if err := insertMetadata(stmts, id, f.Metadata); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(writes), nil
}

// insertMetadata writes a flow's opaque source-supplied key/value metadata.
func insertMetadata(stmts *txStmts, flowID string, md map[string]string) error {
	for k, v := range md {
		if err := stmts.exec(
			`INSERT OR REPLACE INTO flow_metadata (flow_id, key, value) VALUES (?,?,?)`,
			flowID, k, v); err != nil {
			return err
		}
	}
	return nil
}

// insertClientHellos writes a flow's raw ClientHello handshake messages in wire order.
func insertClientHellos(stmts *txStmts, flowID string, hellos [][]byte) error {
	for i, raw := range hellos {
		if err := stmts.exec(
			`INSERT OR REPLACE INTO flow_client_hellos (flow_id, ord, raw) VALUES (?,?,?)`,
			flowID, i, raw); err != nil {
			return err
		}
	}
	return nil
}

// insertHeaders writes one direction's headers as multi-row INSERTs of up to
// headerChunk rows — headers are the highest-volume side table, and one statement per
// header row is what makes persisting a large session slow. ord stays the header's
// absolute position, so chunking doesn't disturb wire order.
func insertHeaders(stmts *txStmts, flowID string, dir int, hs []decode.Header) error {
	for start := 0; start < len(hs); start += headerChunk {
		end := min(start+headerChunk, len(hs))
		args := make([]any, 0, (end-start)*5)
		for i := start; i < end; i++ {
			args = append(args, flowID, dir, i, hs[i].Name, hs[i].Value)
		}
		if err := stmts.exec(headerInsertSQL[end-start], args...); err != nil {
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
func (s *Store) storeBlob(stmts *txStmts, sessionID string, body []byte, contentType string) (string, error) {
	if len(body) == 0 {
		return "", nil
	}
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])

	if len(body) <= InlineBlobMax {
		err := stmts.exec(
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
	err := stmts.exec(
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
		SELECT `+sessionCols+`
		FROM sessions ORDER BY created_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*trafficv1.Session
	byID := map[string]*trafficv1.Session{}
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
		byID[sess.Id] = sess
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.attachSessionMetadata(ctx, byID); err != nil {
		return nil, err
	}
	return out, nil
}

// The sessions.source_kind column holds the producing tool's name ("chrome", "import",
// a module's name). Before that it held a SourceKind enum name, and those values reach
// us from two directions — a catalog written by an older build, and a bundle exported by
// one and imported at any time since (ImportSessionRow writes the manifest's string
// verbatim). So the translation lives on the read path rather than in a one-shot
// migration, which would only ever fix the first.
var legacySourceNames = map[string]string{
	"SOURCE_KIND_CHROME":           "chrome",
	"SOURCE_KIND_MITMPROXY":        "mitmproxy",
	"SOURCE_KIND_ANDROID_EMULATOR": "android",
	"SOURCE_KIND_ANDROID_DEVICE":   "android",
	"SOURCE_KIND_GENERIC":          "import",
	"SOURCE_KIND_UNSPECIFIED":      "",
}

// sourceName maps a stored source_kind cell to a tool name, translating the legacy enum
// names. An unrecognized SOURCE_KIND_* value (a kind this build never knew) becomes ""
// rather than being shown raw.
func sourceName(stored string) string {
	if name, ok := legacySourceNames[stored]; ok {
		return name
	}
	if strings.HasPrefix(stored, "SOURCE_KIND_") {
		return ""
	}
	return stored
}

const sessionCols = `id, label, source_kind, status, created_at, closed_at, pcap_bytes, keylog_bytes, flow_count, session_group`

func scanSession(row scannable) (*trafficv1.Session, error) {
	var (
		id, label, source, status string
		createdAt                 int64
		closedAt                  sql.NullInt64
		pcapBytes, keylogBytes    int64
		flowCount                 int64
		group                     sql.NullString
	)
	if err := row.Scan(&id, &label, &source, &status, &createdAt, &closedAt,
		&pcapBytes, &keylogBytes, &flowCount, &group); err != nil {
		return nil, err
	}
	return &trafficv1.Session{
		Id:              id,
		Label:           label,
		Source:          sourceName(source),
		Status:          trafficv1.SessionStatus(trafficv1.SessionStatus_value[status]),
		CreatedAtUnixMs: createdAt,
		ClosedAtUnixMs:  closedAt.Int64,
		PcapBytes:       uint64(pcapBytes),
		KeylogBytes:     uint64(keylogBytes),
		FlowCount:       uint32(flowCount),
		Group:           group.String,
	}, nil
}

// SetSessionGroup sets (or clears, with "") a session's free-text group label.
func (s *Store) SetSessionGroup(ctx context.Context, sessionID, group string) error {
	_, err := s.catalog.ExecContext(ctx,
		`UPDATE sessions SET session_group=? WHERE id=?`, group, sessionID)
	return err
}

// SetSessionLabel renames a session.
func (s *Store) SetSessionLabel(ctx context.Context, sessionID, label string) error {
	res, err := s.catalog.ExecContext(ctx,
		`UPDATE sessions SET label=? WHERE id=?`, label, sessionID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSession permanently removes a session: its catalog row and its whole bundle dir
// (flows.sqlite, pcap/key.log, spilled blobs). Refused while the session is still open
// (capturing) — stop it first. All per-session data lives in the bundle, so there's no
// other catalog table to clean.
func (s *Store) DeleteSession(ctx context.Context, sessionID string) error {
	var status string
	err := s.catalog.QueryRowContext(ctx, `SELECT status FROM sessions WHERE id=?`, sessionID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status == trafficv1.SessionStatus_SESSION_STATUS_OPEN.String() {
		return fmt.Errorf("session is still open (capturing) — stop it before deleting")
	}
	// Drop the cached bundle DB handle so the file can be removed.
	s.mu.Lock()
	if db, ok := s.sessions[sessionID]; ok {
		db.Close()
		delete(s.sessions, sessionID)
	}
	s.mu.Unlock()
	if _, err := s.catalog.ExecContext(ctx, `DELETE FROM sessions WHERE id=?`, sessionID); err != nil {
		return err
	}
	if _, err := s.catalog.ExecContext(ctx, `DELETE FROM session_metadata WHERE session_id=?`, sessionID); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(s.dataRoot, "sessions", sessionID))
}

// GetSession returns a single session from the catalog.
func (s *Store) GetSession(ctx context.Context, id string) (*trafficv1.Session, error) {
	sess, err := scanSession(s.catalog.QueryRowContext(ctx,
		`SELECT `+sessionCols+` FROM sessions WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := s.attachSessionMetadata(ctx, map[string]*trafficv1.Session{sess.Id: sess}); err != nil {
		return nil, err
	}
	return sess, nil
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
	proxy_addr, proxy_type, proxy_user, proxy_pass, error, duration_micros, h2_fingerprint,
	ja3, ja4, tls_client_hello, redirect_location, tls_hrr`

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
	if err := s.attachAnnotations(ctx, db, flowRecords(byID)); err != nil {
		return nil, err
	}
	if err := s.attachWsCounts(ctx, db, byID); err != nil {
		return nil, err
	}
	if err := s.attachMetadata(ctx, db, byID); err != nil {
		return nil, err
	}
	linkRedirects(out)
	return out, nil
}

// linkRedirects sets redirected_from_id on each flow whose request URL is the target of an
// earlier flow's redirect_location — so a redirect chain can be traced across the session.
func linkRedirects(flows []*trafficv1.Flow) {
	source := map[string]string{} // absolute redirect target URL -> the redirecting flow id
	for _, f := range flows {
		if loc := f.GetRedirectLocation(); loc != "" {
			if _, ok := source[loc]; !ok { // first redirect to this URL wins
				source[loc] = f.GetId()
			}
		}
	}
	for _, f := range flows {
		if src, ok := source[flowURL(f)]; ok && src != f.GetId() {
			f.RedirectedFromId = src
		}
	}
}

// flowURL is a flow's absolute request URL (scheme://authority/path?query).
func flowURL(f *trafficv1.Flow) string {
	scheme := f.GetScheme()
	if scheme == "" {
		scheme = "https"
	}
	u := scheme + "://" + f.GetAuthority() + f.GetPath()
	if f.GetQuery() != "" {
		u += "?" + f.GetQuery()
	}
	return u
}

// resolveRedirect returns the absolute Location URL a 3xx response redirects to, resolved
// against the request URL; "" for non-redirects or when there's no Location.
func resolveRedirect(f *decode.Flow) string {
	if f.Status < 300 || f.Status >= 400 {
		return ""
	}
	var loc string
	for _, h := range f.ResponseHeaders {
		if strings.EqualFold(h.Name, "location") {
			loc = h.Value
			break
		}
	}
	if loc == "" {
		return ""
	}
	scheme := f.Scheme
	if scheme == "" {
		scheme = "https"
	}
	base := &url.URL{Scheme: scheme, Host: f.Authority, Path: f.Path}
	ref, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	return base.ResolveReference(ref).String()
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

	// Raw ClientHello handshake messages (for export/replay), in wire order.
	chrows, err := db.QueryContext(ctx,
		`SELECT raw FROM flow_client_hellos WHERE flow_id=? ORDER BY ord`, flowID)
	if err != nil {
		return nil, err
	}
	defer chrows.Close()
	for chrows.Next() {
		var raw []byte
		if err := chrows.Scan(&raw); err != nil {
			return nil, err
		}
		f.ClientHellos = append(f.ClientHellos, raw)
	}
	if err := chrows.Err(); err != nil {
		return nil, err
	}

	// Attach bodies (inlined; capped at decode.MaxBodyBytes).
	var reqRef, respRef sql.NullString
	var reqEnc, respEnc string
	if err := db.QueryRowContext(ctx,
		`SELECT req_body_ref, resp_body_ref, req_content_encoding, resp_content_encoding
		 FROM flows WHERE id=?`, flowID).
		Scan(&reqRef, &respRef, &reqEnc, &respEnc); err == nil {
		f.RequestBody = s.loadBody(ctx, db, reqRef.String, reqEnc)
		f.ResponseBody = s.loadBody(ctx, db, respRef.String, respEnc)
	}
	single := map[string]*trafficv1.Flow{f.Id: f}
	if err := s.attachAnnotations(ctx, db, flowRecords(single)); err != nil {
		return nil, err
	}
	if err := s.attachWsCounts(ctx, db, single); err != nil {
		return nil, err
	}
	if err := s.attachMetadata(ctx, db, single); err != nil {
		return nil, err
	}
	attachCookies(f)
	// Link the redirect chain: which flow (if any) redirected to this one.
	var srcID string
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM flows WHERE redirect_location=? AND id!=? LIMIT 1`, flowURL(f), f.Id).
		Scan(&srcID); err == nil {
		f.RedirectedFromId = srcID
	}
	return f, nil
}

// attachCookies derives the request/response cookies from the flow's headers: bare
// name=value from the Cookie request header, and full Set-Cookie attributes (domain,
// path, expiry, secure, httpOnly, sameSite) for responses. Header names are lower-case
// on the HTTP/2/3 paths, so canonicalize via http.Header before parsing.
func attachCookies(f *trafficv1.Flow) {
	reqHdr := http.Header{}
	for _, h := range f.RequestHeaders {
		reqHdr.Add(h.Name, h.Value)
	}
	for _, c := range (&http.Request{Header: reqHdr}).Cookies() {
		f.RequestCookies = append(f.RequestCookies, &trafficv1.Cookie{Name: c.Name, Value: c.Value})
	}
	respHdr := http.Header{}
	for _, h := range f.ResponseHeaders {
		respHdr.Add(h.Name, h.Value)
	}
	for _, c := range (&http.Response{Header: respHdr}).Cookies() {
		f.ResponseCookies = append(f.ResponseCookies, cookieToProto(c))
	}
}

func cookieToProto(c *http.Cookie) *trafficv1.Cookie {
	ss := ""
	switch c.SameSite {
	case http.SameSiteLaxMode:
		ss = "Lax"
	case http.SameSiteStrictMode:
		ss = "Strict"
	case http.SameSiteNoneMode:
		ss = "None"
	}
	return &trafficv1.Cookie{
		Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
		Expires: c.RawExpires, MaxAge: int64(c.MaxAge),
		Secure: c.Secure, HttpOnly: c.HttpOnly, SameSite: ss,
	}
}

// loadBody returns body metadata for GetFlow: small bodies inline, large bodies
// as an object_ref (sha256) to be fetched in full via GetBody. enc is the transport
// encoding the bytes had on the wire, which the stored bytes are decoded from where the
// decoder supports it — reported so a consumer knows what it is holding.
func (s *Store) loadBody(ctx context.Context, db *sql.DB, sha, enc string) *trafficv1.Body {
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
	body := &trafficv1.Body{Size: uint64(size), ContentType: ct, ContentEncoding: enc}
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
		durationMicros                                             int64
		method, scheme, authority, path, query, protocol           sql.NullString
		srcAddr, dstAddr, userAgent, contentType, tcpStream, h2sid sql.NullString
		proxyAddr, proxyType, proxyUser, proxyPass, flowError      sql.NullString
		h2Fingerprint, ja3, ja4, tlsClientHello, redirectLocation  sql.NullString
		tlsDecrypted, tlsHRR                                       int64
	)
	if err := row.Scan(&id, &sessionID, &analysisID, &frameNumber, &tsMicros, &method, &scheme,
		&authority, &path, &query, &protocol, &status, &srcAddr, &dstAddr,
		&userAgent, &contentType, &requestBytes, &tlsDecrypted, &tcpStream, &h2sid,
		&proxyAddr, &proxyType, &proxyUser, &proxyPass, &flowError, &durationMicros, &h2Fingerprint,
		&ja3, &ja4, &tlsClientHello, &redirectLocation, &tlsHRR); err != nil {
		return nil, err
	}
	f := &trafficv1.Flow{
		Id:               id,
		SessionId:        sessionID,
		AnalysisId:       analysisID,
		FrameNumber:      uint64(frameNumber),
		TsUnixMicros:     tsMicros,
		Method:           method.String,
		Scheme:           scheme.String,
		Authority:        authority.String,
		Path:             path.String,
		Query:            query.String,
		Protocol:         protocol.String,
		Status:           uint32(status),
		SrcAddr:          srcAddr.String,
		DstAddr:          dstAddr.String,
		UserAgent:        userAgent.String,
		ContentType:      contentType.String,
		RequestBytes:     uint64(requestBytes),
		TlsDecrypted:     tlsDecrypted != 0,
		TcpStream:        tcpStream.String,
		H2StreamId:       h2sid.String,
		Error:            flowError.String,
		DurationMicros:   uint64(durationMicros),
		Http2Fingerprint: h2Fingerprint.String,
		Ja3:              ja3.String,
		Ja4:              ja4.String,
		TlsClientHello:   tlsClientHello.String,
		RedirectLocation: redirectLocation.String,
		TlsHrr:           tlsHRR != 0,
	}
	if proxyAddr.String != "" {
		f.Proxy = &trafficv1.Proxy{
			Addr: proxyAddr.String, Type: proxyType.String,
			Username: proxyUser.String, Password: proxyPass.String,
		}
	}
	f.TlsClientName = tlsfp.Name(tlsfp.Fingerprint{JA4: f.Ja4, JA3: f.Ja3, SNI: f.Authority})
	return f, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
