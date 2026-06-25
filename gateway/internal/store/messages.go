package store

// WebSocket messages: message-shaped records belonging to an Upgrade
// flow. Payloads are content-addressed blobs, reusing the body blob policy.

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// InsertWsMessages writes a session's decoded WebSocket frames into the bundle.
func (s *Store) InsertWsMessages(ctx context.Context, sessionID string, msgs []*decode.WsMessage) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return 0, err
	}
	err = inTx(ctx, db, func(tx *sql.Tx) error {
		for _, m := range msgs {
			ref, err := s.storeBlob(ctx, tx, sessionID, m.Payload, "")
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO ws_messages (id, flow_id, frame_number, ts_micros,
				    from_client, opcode, payload_len, payload_ref)
				VALUES (?,?,?,?,?,?,?,?)`,
				m.ID, m.FlowID, int64(m.FrameNumber), m.TSUnixMicros,
				boolToInt(m.FromClient), m.Opcode, int64(len(m.Payload)), nullIfEmpty(ref)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(msgs), nil
}

// ListMessages returns the WebSocket frames of an Upgrade flow in timeline order,
// with small payloads inline and large payloads as object_refs (fetch via GetMessageBody).
func (s *Store) ListMessages(ctx context.Context, sessionID, flowID string) ([]*trafficv1.WsMessage, error) {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, flow_id, frame_number, ts_micros, from_client, opcode, payload_ref
		FROM ws_messages WHERE flow_id=? ORDER BY ts_micros, frame_number`, flowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*trafficv1.WsMessage
	for rows.Next() {
		var (
			id, flow        string
			frameNumber, ts int64
			fromClient      int64
			opcode          sql.NullString
			payloadRef      sql.NullString
		)
		if err := rows.Scan(&id, &flow, &frameNumber, &ts, &fromClient, &opcode, &payloadRef); err != nil {
			return nil, err
		}
		out = append(out, &trafficv1.WsMessage{
			Id:           id,
			SessionId:    sessionID,
			FlowId:       flow,
			FrameNumber:  uint64(frameNumber),
			TsUnixMicros: ts,
			FromClient:   fromClient != 0,
			Opcode:       opcode.String,
			Payload:      s.loadBody(ctx, db, payloadRef.String),
		})
	}
	return out, rows.Err()
}

// GetWsMessageBody returns the full payload bytes of one WebSocket message.
func (s *Store) GetWsMessageBody(ctx context.Context, sessionID, messageID string) ([]byte, error) {
	db, err := s.sessionDB(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	var ref sql.NullString
	switch err := db.QueryRowContext(ctx,
		`SELECT payload_ref FROM ws_messages WHERE id=?`, messageID).Scan(&ref); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrNotFound
	case err != nil:
		return nil, err
	}
	if !ref.Valid || ref.String == "" {
		return nil, ErrNotFound
	}
	var b []byte
	var ct string
	var ext sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT bytes, content_type, external_path FROM blobs WHERE sha256=?`, ref.String).
		Scan(&b, &ct, &ext); err != nil {
		return nil, err
	}
	if ext.Valid && ext.String != "" {
		return os.ReadFile(filepath.Join(s.dataRoot, ext.String))
	}
	return b, nil
}

// attachWsCounts sets Websocket + WsMessageCount on the given flows from one grouped
// scan over ws_messages (cheap; the bundle is one session).
func (s *Store) attachWsCounts(ctx context.Context, db *sql.DB, flows map[string]*trafficv1.Flow) error {
	if len(flows) == 0 {
		return nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT flow_id, COUNT(*) FROM ws_messages GROUP BY flow_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var fid string
		var n int64
		if err := rows.Scan(&fid, &n); err != nil {
			return err
		}
		if f := flows[fid]; f != nil {
			f.Websocket = true
			f.WsMessageCount = uint32(n)
		}
	}
	return rows.Err()
}
