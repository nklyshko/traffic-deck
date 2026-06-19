// Package importer implements the Phase 1 "import a pre-captured pcap + key.log"
// flow (plan §9): copy the artifacts into the session bundle, batch-decode them with
// tshark, and persist the session/analysis/flows to the per-session SQLite DB.
package importer

import (
	"context"
	"fmt"
	"os"
	"path"

	"github.com/google/uuid"

	trafficv1 "github.com/nikitak/parsing/traffic-gateway/gen/traffic/v1"
	"github.com/nikitak/parsing/traffic-gateway/internal/decode"
	"github.com/nikitak/parsing/traffic-gateway/internal/objstore"
	"github.com/nikitak/parsing/traffic-gateway/internal/store"
)

type Options struct {
	PcapPath   string
	KeylogPath string // optional
	Label      string
	TsharkPath string
}

type Result struct {
	SessionID string
	FlowCount int
}

// Import copies the capture into the session bundle, decodes it, and persists flows.
// The raw pcap + key.log are the canonical inputs (plan §6).
func Import(ctx context.Context, st *store.Store, obj objstore.Store, opts Options) (*Result, error) {
	sessionID := uuid.NewString()
	pcapKey := path.Join("sessions", sessionID, "capture.pcap")
	keylogKey := path.Join("sessions", sessionID, "key.log")

	pcapBytes, err := copyIn(obj, pcapKey, opts.PcapPath)
	if err != nil {
		return nil, fmt.Errorf("store pcap: %w", err)
	}
	var keylogBytes int64
	hasKeylog := opts.KeylogPath != ""
	if hasKeylog {
		if keylogBytes, err = copyIn(obj, keylogKey, opts.KeylogPath); err != nil {
			return nil, fmt.Errorf("store key.log: %w", err)
		}
	}

	if err := st.CreateSession(ctx, store.NewSession{
		ID:          sessionID,
		Label:       opts.Label,
		SourceKind:  trafficv1.SourceKind_SOURCE_KIND_GENERIC,
		Status:      trafficv1.SessionStatus_SESSION_STATUS_DECODING,
		PcapBytes:   pcapBytes,
		KeylogBytes: keylogBytes,
	}); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// Decode from the stored canonical copies (fall back to inputs if non-local).
	pcapLocal := localOr(obj, pcapKey, opts.PcapPath)
	keylogLocal := ""
	if hasKeylog {
		keylogLocal = localOr(obj, keylogKey, opts.KeylogPath)
	}

	ds, err := decode.Decode(ctx, opts.TsharkPath, pcapLocal, keylogLocal)
	if err != nil {
		_ = st.FinishSession(ctx, sessionID, trafficv1.SessionStatus_SESSION_STATUS_ERROR, 0)
		return nil, fmt.Errorf("decode: %w", err)
	}

	analysisID := uuid.NewString()
	if err := st.CreateAnalysis(ctx, store.NewAnalysis{
		ID:            analysisID,
		SessionID:     sessionID,
		Engine:        ds.Engine,
		TLSKeyLogUsed: ds.TLSKeyLogUsed,
	}); err != nil {
		return nil, fmt.Errorf("create analysis: %w", err)
	}

	n, err := st.InsertFlows(ctx, sessionID, analysisID, ds.Flows)
	if err != nil {
		_ = st.FinishSession(ctx, sessionID, trafficv1.SessionStatus_SESSION_STATUS_ERROR, 0)
		return nil, fmt.Errorf("insert flows: %w", err)
	}

	if err := st.FinishSession(ctx, sessionID, trafficv1.SessionStatus_SESSION_STATUS_CLOSED, n); err != nil {
		return nil, err
	}
	return &Result{SessionID: sessionID, FlowCount: n}, nil
}

func copyIn(obj objstore.Store, key, srcPath string) (int64, error) {
	f, err := os.Open(srcPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return obj.Put(key, f)
}

func localOr(obj objstore.Store, key, fallback string) string {
	if p, ok := obj.LocalPath(key); ok {
		return p
	}
	return fallback
}
