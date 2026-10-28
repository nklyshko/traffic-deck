package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// InsertUndecoded records connections a capture carried that produced no flow. A
// connection already recorded is replaced, so a re-run over the same capture converges.
func (s *Store) InsertUndecoded(ctx context.Context, sessionID string, conns []*decode.UndecodedConn) error {
	if len(conns) == 0 {
		return nil
	}
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck — a no-op once committed
	stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO undecoded_conns
		(conn_id, transport, client, server, sni, ja4, reason, detail, bytes_up, bytes_down,
		 first_ts, last_ts, pcap_offset) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, c := range conns {
		if _, err := stmt.ExecContext(ctx, c.ConnID, c.Transport, c.Client, c.Server, c.SNI, c.JA4,
			c.Reason, c.Detail, int64(c.BytesUp), int64(c.BytesDown), c.FirstTS, c.LastTS, c.PcapOffset); err != nil {
			return fmt.Errorf("insert undecoded %s: %w", c.ConnID, err)
		}
	}
	return tx.Commit()
}

// ListUndecoded returns a session's undecoded connections, the largest first — volume is
// what tells an app's own traffic from a stray probe.
func (s *Store) ListUndecoded(ctx context.Context, sessionID string) ([]*decode.UndecodedConn, error) {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT conn_id, transport, client, server, sni, ja4,
		reason, detail, bytes_up, bytes_down, first_ts, last_ts, pcap_offset
		FROM undecoded_conns ORDER BY bytes_up + bytes_down DESC, first_ts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*decode.UndecodedConn
	for rows.Next() {
		c, err := scanUndecoded(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func scanUndecoded(rows *sql.Rows) (*decode.UndecodedConn, error) {
	var c decode.UndecodedConn
	var up, down int64
	err := rows.Scan(&c.ConnID, &c.Transport, &c.Client, &c.Server, &c.SNI, &c.JA4, &c.Reason,
		&c.Detail, &up, &down, &c.FirstTS, &c.LastTS, &c.PcapOffset)
	c.BytesUp, c.BytesDown = uint64(up), uint64(down)
	return &c, err
}

// RecordUndecoded stores a capture's undecoded-connection index and summarises it in the
// session's metadata — undecoded.<reason> counts, every reason present, 0 included, since
// an absent key would read as "not counted" — so a session list can say how much went
// undecoded without opening the bundle.
func (s *Store) RecordUndecoded(ctx context.Context, sessionID string, conns []*decode.UndecodedConn) error {
	if err := s.InsertUndecoded(ctx, sessionID, conns); err != nil {
		return err
	}
	return s.SetSessionMetadata(ctx, sessionID, UndecodedCounts(conns))
}

// UndecodedCounts is the undecoded.<reason> summary of an index.
func UndecodedCounts(conns []*decode.UndecodedConn) map[string]string {
	n := map[string]int{}
	for _, c := range conns {
		n[c.Reason]++
	}
	md := map[string]string{}
	for _, r := range []string{decode.UndecodedNoKey, decode.UndecodedHandshake,
		decode.UndecodedUnsupported, decode.UndecodedUnparsed, decode.UndecodedNotQUIC} {
		md["undecoded."+r] = strconv.Itoa(n[r])
	}
	return md
}
