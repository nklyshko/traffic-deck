// Package importer implements the "import a pre-captured pcap + key.log" flow:
// copy the artifacts into the session bundle, batch-decode them with tshark, and
// persist the session/analysis/flows to the per-session SQLite DB.
package importer

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/google/uuid"

	"gitlab.com/nklyshko/traffic-deck/gateway/decoders"
	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/objstore"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

type Options struct {
	PcapPath   string
	KeylogPath string // optional
	Label      string
	TsharkPath string
	// Engine selects the batch decoder: decode.EngineTshark (default) orchestrates tshark;
	// decode.EngineNative runs the in-process Go pipeline. "" means tshark.
	Engine string
}

type Result struct {
	SessionID string
	FlowCount int
}

// Import copies the capture into the session bundle, decodes it, and persists flows.
// The raw pcap + key.log are the canonical inputs.
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
	return Finalize(ctx, st, opts.Engine, opts.TsharkPath, sessionID, pcapLocal, keylogLocal)
}

// Finalize batch-decodes a session's already-stored pcap (+ optional key.log) with the
// named engine (decode.EngineTshark or decode.EngineNative; "" = tshark), persists the
// analysis + flows, and marks the session closed. Shared by the `import` CLI and
// IngestService.CloseSession.
func Finalize(ctx context.Context, st *store.Store, engine, tsharkPath, sessionID, pcapPath, keylogPath string) (*Result, error) {
	ds, err := decodeBatch(ctx, engine, tsharkPath, pcapPath, keylogPath)
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

	if _, err := st.InsertWsMessages(ctx, sessionID, ds.Messages); err != nil {
		_ = st.FinishSession(ctx, sessionID, trafficv1.SessionStatus_SESSION_STATUS_ERROR, 0)
		return nil, fmt.Errorf("insert ws messages: %w", err)
	}

	if err := st.FinishSession(ctx, sessionID, trafficv1.SessionStatus_SESSION_STATUS_CLOSED, n); err != nil {
		return nil, err
	}
	return &Result{SessionID: sessionID, FlowCount: n}, nil
}

// RedecodeCustom re-runs decode over a stored capture and inserts ONLY the custom
// (non-HTTP) decoder output — synthetic protocol flows + their messages — as a new
// analysis. Lets an already-captured session be decoded by a newly added decoder
// without re-importing (and without duplicating the HTTP flows). Re-running appends
// again, so it's a one-shot per added decoder.
func RedecodeCustom(ctx context.Context, st *store.Store, tsharkPath, sessionID, pcapPath, keylogPath string) (int, error) {
	ds, err := decode.Decode(ctx, tsharkPath, pcapPath, keylogPath)
	if err != nil {
		return 0, fmt.Errorf("decode: %w", err)
	}
	custom := map[string]bool{}
	for _, d := range decoders.All() {
		custom[strings.ToUpper(d.Name())] = true
	}
	var flows []*decode.Flow
	keep := map[string]bool{}
	for _, f := range ds.Flows {
		if custom[f.Protocol] {
			flows = append(flows, f)
			keep[f.ID] = true
		}
	}
	var msgs []*decode.WsMessage
	for _, m := range ds.Messages {
		if keep[m.FlowID] {
			msgs = append(msgs, m)
		}
	}
	if len(flows) == 0 {
		return 0, nil
	}
	analysisID := uuid.NewString()
	if err := st.CreateAnalysis(ctx, store.NewAnalysis{ID: analysisID, SessionID: sessionID, Engine: "decoders"}); err != nil {
		return 0, fmt.Errorf("create analysis: %w", err)
	}
	if _, err := st.InsertFlows(ctx, sessionID, analysisID, flows); err != nil {
		return 0, fmt.Errorf("insert flows: %w", err)
	}
	if _, err := st.InsertWsMessages(ctx, sessionID, msgs); err != nil {
		return 0, fmt.Errorf("insert ws messages: %w", err)
	}
	return len(flows), nil
}

// decodeBatch runs a whole-pcap decode with the selected engine. tsharkPath is used only
// by the tshark engine; native reads the file entirely in-process.
func decodeBatch(ctx context.Context, engine, tsharkPath, pcapPath, keylogPath string) (*decode.Dataset, error) {
	switch engine {
	case decode.EngineNative:
		return decode.DecodeNative(ctx, pcapPath, keylogPath)
	case decode.EngineTshark, "":
		return decode.Decode(ctx, tsharkPath, pcapPath, keylogPath)
	default:
		return nil, fmt.Errorf("unknown decode engine %q (want %q or %q)", engine, decode.EngineTshark, decode.EngineNative)
	}
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
