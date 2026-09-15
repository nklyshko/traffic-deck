package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"path"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nklyshko/traffic-deck/gateway/decoders"
	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
	"github.com/nklyshko/traffic-deck/gateway/internal/importer"
	"github.com/nklyshko/traffic-deck/gateway/internal/objstore"
	"github.com/nklyshko/traffic-deck/gateway/internal/store"
)

const maxChunkBytes = 1 << 20 // advertised upload chunk size

// Ingest implements trafficv1.IngestServiceServer: streamed capture upload (decoded
// live and/or on close) and the pushed-flow path for already-decoded sources.
type Ingest struct {
	trafficv1.UnimplementedIngestServiceServer
	st           *store.Store
	obj          objstore.Store
	tshark       string
	hub          *liveHub
	liveDecode   bool // when false, streaming uploads are archived and decoded only on close
	recordLive   bool // when true, persist the live-decoded flows on close instead of batch decode
	tsharkVerify bool // when true, compare live flows vs a tshark decode on close and log differences

	// pushAnalyses gives each pushed (mitmproxy) session a single analysis, shared across
	// its many PushFlows streams — the addon opens one stream per flow/message.
	// liveAnalyses is the record-live counterpart, created at session start because rows
	// reference it throughout the capture now, not only at close (ADR-0011 §7).
	pushMu       sync.Mutex
	pushAnalyses map[string]string // sessionID -> analysisID
	liveAnalyses map[string]string // sessionID -> analysisID

	// stopCapture ends the capture feeding a session, for when its flush fails and the
	// session can no longer be recorded (ADR-0011 §5). Set by Register; nil in tests.
	stopCapture func(ctx context.Context, sessionID string) error

	// wsStates runs custom WebSocket decoders over pushed binary frames (the push path
	// bypasses the tshark/Go decoders), keyed by the parent flow id.
	wsDecMu  sync.Mutex
	wsStates map[string]*wsPushState
}

// wsPushState is one pushed WebSocket flow's decoder framing state.
type wsPushState struct {
	meta    decoders.WSMeta
	decided bool
	dec     decoders.WSDecoder // nil once decided if none claims the connection
	sess    decoders.Session
}

func NewIngest(st *store.Store, obj objstore.Store, tshark string, hub *liveHub, liveDecode, recordLive, tsharkVerify bool) *Ingest {
	return &Ingest{
		st: st, obj: obj, tshark: tshark, hub: hub,
		liveDecode: liveDecode, recordLive: recordLive, tsharkVerify: tsharkVerify,
		pushAnalyses: map[string]string{},
		liveAnalyses: map[string]string{},
	}
}

// liveAnalysis returns a record-live session's analysis, creating it on first use. The
// flusher needs it from the first written row, so unlike the old close-time path this
// runs at session start (ADR-0011 §7).
func (i *Ingest) liveAnalysis(sid string) (string, error) {
	i.pushMu.Lock()
	defer i.pushMu.Unlock()
	if i.liveAnalyses == nil {
		i.liveAnalyses = map[string]string{}
	}
	if aid, ok := i.liveAnalyses[sid]; ok {
		return aid, nil
	}
	aid := uuid.NewString()
	if err := i.st.CreateAnalysis(context.Background(), store.NewAnalysis{
		ID: aid, SessionID: sid, Engine: "live", TLSKeyLogUsed: true,
	}); err != nil {
		return "", err
	}
	i.liveAnalyses[sid] = aid
	return aid, nil
}

// onFlushError ends a session whose incremental flush failed. Its record is no longer
// being written, so the capture must not keep running: mark the session errored and stop
// the source. Everything flushed before the failure stays readable in the bundle, which
// is what makes stopping the recoverable choice (ADR-0011 §5).
func (i *Ingest) onFlushError(sid string, ferr error) {
	ctx := context.Background()
	n, err := i.st.CountFlows(ctx, sid)
	if err != nil {
		log.Printf("session %s: counting flows after flush failure: %v", sid, err)
	}
	if err := i.st.FinishSession(ctx, sid, trafficv1.SessionStatus_SESSION_STATUS_ERROR, n); err != nil {
		log.Printf("session %s: marking errored after flush failure: %v", sid, err)
	}
	if i.stopCapture != nil {
		if err := i.stopCapture(ctx, sid); err != nil {
			log.Printf("session %s: stopping capture after flush failure: %v", sid, err)
		}
	}
}

// pushAnalysis returns the session's push analysis id, creating it once. Shared across the
// addon's many concurrent PushFlows streams so they don't each create an analysis.
func (i *Ingest) pushAnalysis(ctx context.Context, sid string) (string, error) {
	i.pushMu.Lock()
	defer i.pushMu.Unlock()
	if i.pushAnalyses == nil {
		i.pushAnalyses = map[string]string{}
	}
	if aid, ok := i.pushAnalyses[sid]; ok {
		return aid, nil
	}
	aid := uuid.NewString()
	if err := i.st.CreateAnalysis(ctx, store.NewAnalysis{ID: aid, SessionID: sid, Engine: "mitmproxy"}); err != nil {
		return "", err
	}
	i.pushAnalyses[sid] = aid
	return aid, nil
}

// recordWSMeta remembers a pushed WebSocket upgrade flow's host/path so a WSDecoder can be
// matched for its binary frames. Raw-TCP flows (protocol "TCP") are left to store as-is.
func (i *Ingest) recordWSMeta(pf *trafficv1.Flow) {
	if !pf.GetWebsocket() || pf.GetProtocol() == "TCP" {
		return
	}
	i.wsDecMu.Lock()
	defer i.wsDecMu.Unlock()
	if i.wsStates == nil {
		i.wsStates = map[string]*wsPushState{}
	}
	if _, ok := i.wsStates[pf.GetId()]; !ok {
		i.wsStates[pf.GetId()] = &wsPushState{meta: decoders.WSMeta{Host: pf.GetAuthority(), Path: pf.GetPath()}}
	}
}

// decodePushedWSBinary frames a pushed binary WebSocket payload through the WSDecoder that
// claims its flow. ok=false means no decoder handles it (store the raw frame). The addon
// awaits each push, so frames for a flow arrive in order — the stateful session stays synced.
func (i *Ingest) decodePushedWSBinary(flowID string, fromClient bool, payload []byte) ([]decoders.Message, bool) {
	i.wsDecMu.Lock()
	defer i.wsDecMu.Unlock()
	st := i.wsStates[flowID]
	if st == nil {
		return nil, false
	}
	if !st.decided {
		if m := decoders.MatchWS(st.meta); len(m) > 0 {
			st.dec = m[0]
		}
		st.decided = true
	}
	if st.dec == nil {
		return nil, false
	}
	if st.sess == nil {
		st.sess = st.dec.NewSession()
	}
	return st.sess.Feed(fromClient, payload), true
}

func pcapKey(sid string) string   { return path.Join("sessions", sid, "capture.pcap") }
func keylogKey(sid string) string { return path.Join("sessions", sid, "key.log") }

func (i *Ingest) OpenSession(ctx context.Context, req *trafficv1.OpenSessionRequest) (*trafficv1.SessionHandle, error) {
	sid := uuid.NewString()
	if err := i.st.CreateSession(ctx, store.NewSession{
		ID:       sid,
		Label:    req.GetLabel(),
		Source:   req.GetSource(),
		Status:   trafficv1.SessionStatus_SESSION_STATUS_OPEN,
		Metadata: req.GetMetadata(),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "create session: %v", err)
	}
	// A pushed source has no UploadBegin to start a live session, so register a passive
	// one now — viewers can follow from the moment it exists. PushFlows registers it too
	// (idempotent); doing it here just closes the window before the first flow arrives.
	if req.GetShape() == trafficv1.SourceShape_SOURCE_SHAPE_FLOWS {
		i.hub.startPassive(sid)
	}
	return &trafficv1.SessionHandle{SessionId: sid, MaxChunkBytes: maxChunkBytes}, nil
}

// UploadCapture streams pcap + key.log chunks into the session bundle, writing
// each at its byte offset (ordered, resumable). Decode happens on CloseSession.
func (i *Ingest) UploadCapture(stream grpc.ClientStreamingServer[trafficv1.CaptureChunk, trafficv1.UploadAck]) error {
	var sid, uploadID string
	var pcapN, keylogN uint64
	var live bool

	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch m := msg.GetMsg().(type) {
		case *trafficv1.CaptureChunk_Begin:
			sid = m.Begin.GetSessionId()
			uploadID = m.Begin.GetUploadId()
			if m.Begin.GetMode() == trafficv1.CaptureMode_CAPTURE_MODE_STREAMING_LIVE && i.liveDecode {
				live = true
				// Ensure the key.log exists so tshark can watch it, then start live decode.
				_ = i.obj.WriteAt(keylogKey(sid), nil, 0)
				keylogLocal, _ := i.obj.LocalPath(keylogKey(sid))
				i.hub.start(sid, keylogLocal)
			}
		case *trafficv1.CaptureChunk_Data:
			if sid == "" {
				return status.Error(codes.InvalidArgument, "UploadBegin must precede data chunks")
			}
			key, dir := pcapKey(sid), m.Data.GetKind()
			if dir == trafficv1.FileKind_FILE_KIND_KEYLOG {
				key = keylogKey(sid)
			}
			if err := i.obj.WriteAt(key, m.Data.GetPayload(), int64(m.Data.GetOffset())); err != nil {
				return status.Errorf(codes.Internal, "write chunk: %v", err)
			}
			n := uint64(len(m.Data.GetPayload()))
			if dir == trafficv1.FileKind_FILE_KIND_KEYLOG {
				keylogN += n
			} else {
				pcapN += n
				if live { // tee the pcap bytes to the live decoder
					i.hub.write(sid, m.Data.GetPayload())
				}
			}
		case *trafficv1.CaptureChunk_End:
		}
	}
	return stream.SendAndClose(&trafficv1.UploadAck{
		UploadId: uploadID, PcapReceived: pcapN, KeylogReceived: keylogN,
	})
}

// PushFlows ingests already-decoded flows (the mitmproxy/supplied path):
// each batch is persisted to the session bundle and live-published to viewers. No
// pcap/tshark is involved; the session is a tshark-less ("passive") live session.
func (i *Ingest) PushFlows(stream grpc.ClientStreamingServer[trafficv1.FlowBatch, trafficv1.PushAck]) error {
	ctx := stream.Context()
	var accepted uint32

	for {
		batch, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		sid := batch.GetSessionId()
		if sid == "" {
			return status.Error(codes.InvalidArgument, "FlowBatch.session_id required")
		}
		ls := i.hub.startPassive(sid)

		aid, err := i.pushAnalysis(ctx, sid) // one analysis per session, across all streams
		if err != nil {
			return status.Errorf(codes.Internal, "create analysis: %v", err)
		}

		flows := batch.GetFlows()
		dflows := make([]*decode.Flow, 0, len(flows))
		for _, pf := range flows {
			if pf.GetId() == "" {
				pf.Id = uuid.NewString() // keep persisted + live ids in sync
			}
			dflows = append(dflows, protoToDecodeFlow(pf))
		}
		if _, err := i.st.InsertFlows(ctx, sid, aid, dflows); err != nil {
			return status.Errorf(codes.Internal, "insert flows: %v", err)
		}
		for _, pf := range flows {
			ls.publish(pf, true)
			i.recordWSMeta(pf) // remember host/path so a WSDecoder can claim its frames
		}

		// WebSocket / raw-TCP frames: their flow_id references a flow pushed earlier
		// (same or prior batch), so the parent flow is already persisted. A registered
		// WSDecoder reframes binary frames into protocol messages (carrying the original
		// bytes in Raw); unclaimed frames are stored as-is.
		msgs := batch.GetMessages()
		var store []*decode.WsMessage
		var pub []*trafficv1.WsMessage
		for _, pm := range msgs {
			if pm.GetId() == "" {
				pm.Id = uuid.NewString()
			}
			payload := pm.GetPayload().GetInline()
			if pm.GetOpcode() == "binary" {
				if frames, ok := i.decodePushedWSBinary(pm.GetFlowId(), pm.GetFromClient(), payload); ok {
					for _, fr := range frames {
						dm := &decode.WsMessage{
							ID: uuid.NewString(), FlowID: pm.GetFlowId(),
							// The WebSocket opcode the protocol frame arrived in ("binary"),
							// not the protocol's own — that is in Metadata, which this path
							// was dropping outright.
							FromClient: fr.FromClient, Opcode: pm.GetOpcode(),
							TSUnixMicros: pm.GetTsUnixMicros(), Payload: fr.Payload, Raw: payload,
							Metadata: fr.Fields,
						}
						store = append(store, dm)
						pub = append(pub, wsMsgToProto(dm))
					}
					continue
				}
			}
			store = append(store, protoToDecodeWsMessage(pm))
			pub = append(pub, pm)
		}
		if len(store) > 0 {
			if _, err := i.st.InsertWsMessages(ctx, sid, store); err != nil {
				return status.Errorf(codes.Internal, "insert ws messages: %v", err)
			}
			for _, pm := range pub {
				ls.publishMessage(pm)
			}
		}
		accepted += uint32(len(flows)) + uint32(len(msgs))
	}
	return stream.SendAndClose(&trafficv1.PushAck{Accepted: accepted})
}

// protoToDecodeFlow converts a pushed proto Flow to the decode.Flow the store
// persists (extracting inline body bytes; pushed bodies are inline).
func protoToDecodeFlow(pf *trafficv1.Flow) *decode.Flow {
	df := &decode.Flow{
		ID:           pf.GetId(),
		FrameNumber:  pf.GetFrameNumber(),
		TSUnixMicros: pf.GetTsUnixMicros(),
		Method:       pf.GetMethod(),
		Scheme:       pf.GetScheme(),
		Authority:    pf.GetAuthority(),
		Path:         pf.GetPath(),
		Query:        pf.GetQuery(),
		Protocol:     pf.GetProtocol(),
		Status:       pf.GetStatus(),
		SrcAddr:      pf.GetSrcAddr(),
		DstAddr:      pf.GetDstAddr(),
		UserAgent:    pf.GetUserAgent(),
		ContentType:  pf.GetContentType(),
		RequestBytes: pf.GetRequestBytes(),
		TLSDecrypted: pf.GetTlsDecrypted(),
		TCPStream:    pf.GetTcpStream(),
		H2StreamID:   pf.GetH2StreamId(),
		RequestBody:  pf.GetRequestBody().GetInline(),
		ResponseBody: pf.GetResponseBody().GetInline(),
		// What the source says the bytes it pushed were encoded as on the wire (it did
		// its own decoding, so we take its word); "" when they arrived plain.
		RequestBodyEncoding:  pf.GetRequestBody().GetContentEncoding(),
		ResponseBodyEncoding: pf.GetResponseBody().GetContentEncoding(),
		Metadata:             pf.GetMetadata(),
		Error:                pf.GetError(),
		DurationMicros:       pf.GetDurationMicros(),
		Http2Fingerprint:     pf.GetHttp2Fingerprint(),
		JA3:                  pf.GetJa3(),
		JA4:                  pf.GetJa4(),
		TLSClientHello:       pf.GetTlsClientHello(),
	}
	// Proxy metadata a source stamped (e.g. mitmproxy's SocksUpstreamLayer): carry it
	// across so the viewer can show which proxy a tunnelled flow rode. Unlike Websocket,
	// nothing on the store side re-derives this, so a drop here loses it for good.
	if p := pf.GetProxy(); p != nil {
		df.Proxy = &decode.FlowProxy{
			Addr:     p.GetAddr(),
			Type:     p.GetType(),
			Username: p.GetUsername(),
			Password: p.GetPassword(),
		}
	}
	for _, h := range pf.GetRequestHeaders() {
		df.RequestHeaders = append(df.RequestHeaders, decode.Header{Name: h.GetName(), Value: h.GetValue()})
	}
	for _, h := range pf.GetResponseHeaders() {
		df.ResponseHeaders = append(df.ResponseHeaders, decode.Header{Name: h.GetName(), Value: h.GetValue()})
	}
	return df
}

// CloseSession finalizes a session: record sizes, batch-decode the bundle, and
// return the closed session summary.
func (i *Ingest) CloseSession(ctx context.Context, req *trafficv1.CloseSessionRequest) (*trafficv1.SessionSummary, error) {
	return i.finalizeSession(ctx, req.GetSessionId())
}

// ForceCloseSession finalizes a session that's stuck open — a capture that died without
// sending CloseSession leaves the session OPEN forever. It runs the same finalization
// (decode/persist whatever was captured) and marks it closed, refusing a session that's
// already terminal.
func (i *Ingest) ForceCloseSession(ctx context.Context, req *trafficv1.CloseSessionRequest) (*trafficv1.SessionSummary, error) {
	sid := req.GetSessionId()
	sess, err := i.st.GetSession(ctx, sid)
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Error(codes.NotFound, "force close: session not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "force close: %v", err)
	}
	if s := sess.GetStatus(); s == trafficv1.SessionStatus_SESSION_STATUS_CLOSED ||
		s == trafficv1.SessionStatus_SESSION_STATUS_ERROR {
		return nil, status.Errorf(codes.FailedPrecondition, "session already finalized (%s)", s)
	}

	// Try the normal finalization (decode/persist whatever was captured). If it fails —
	// e.g. the bundle has an outdated schema (an old stale session), or a partial/corrupt
	// pcap — force-close must still unstick the session, so fall back to marking it closed
	// in the catalog only (which doesn't touch the bundle DB). Live decode was already
	// stopped inside finalizeSession.
	if summary, err := i.finalizeSession(ctx, sid); err == nil {
		return summary, nil
	} else {
		log.Printf("force close %s: finalize failed (%v); marking closed in the catalog", sid, err)
	}
	if err := i.st.FinishSession(ctx, sid, trafficv1.SessionStatus_SESSION_STATUS_CLOSED, int(sess.GetFlowCount())); err != nil {
		return nil, status.Errorf(codes.Internal, "force close: mark closed: %v", err)
	}
	closed, err := i.st.GetSession(ctx, sid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "force close: %v", err)
	}
	return &trafficv1.SessionSummary{Session: closed}, nil
}

func (i *Ingest) finalizeSession(ctx context.Context, sid string) (*trafficv1.SessionSummary, error) {
	// Stop live decode (if any); ls holds the accumulated live flows for record-live mode.
	ls := i.hub.stop(sid)

	var pcapBytes, keylogBytes int64
	if fi, err := i.obj.Stat(pcapKey(sid)); err == nil {
		pcapBytes = fi.Size
	}
	keylogLocal := ""
	if fi, err := i.obj.Stat(keylogKey(sid)); err == nil && fi.Size > 0 {
		keylogBytes = fi.Size
		keylogLocal, _ = i.obj.LocalPath(keylogKey(sid))
	}
	if err := i.st.SetSessionBytes(ctx, sid, pcapBytes, keylogBytes); err != nil {
		return nil, status.Errorf(codes.Internal, "set sizes: %v", err)
	}

	switch {
	case i.recordLive && ls != nil && pcapBytes > 0:
		// RECORD-LIVE: persist the flows the live decoder already produced; skip the batch
		// tshark re-decode. Bodies are the live previews (capped at maxLiveBody).
		if err := i.persistLive(ctx, sid, ls); err != nil {
			return nil, status.Errorf(codes.Internal, "persist live: %v", err)
		}
		if i.tsharkVerify {
			// Diagnostic tshark decode (not persisted) to check the recorded live flows.
			i.verifyRecordedLive(ctx, sid, ls, keylogLocal)
		}
	case pcapBytes > 0:
		// PACKET source: authoritative batch decode over the finalized pcap.
		pcapLocal, _ := i.obj.LocalPath(pcapKey(sid))
		if _, err := importer.Finalize(ctx, i.st, decode.EngineTshark, i.tshark, sid, pcapLocal, keylogLocal); err != nil {
			return nil, status.Errorf(codes.Internal, "finalize: %v", err)
		}
		if i.tsharkVerify && ls != nil {
			// Compare the live decode against the just-persisted tshark flows and log diffs.
			if batch, err := i.st.ListFlows(ctx, sid); err == nil {
				verifyLiveVsTshark(sid, ls.protoFlows(), batch)
			} else {
				log.Printf("verify %s: cannot list tshark flows: %v", sid, err)
			}
		}
	default:
		// Supplied/pushed source (PushFlows): flows were persisted incrementally;
		// there's nothing to decode — just mark the session closed with its count.
		n, err := i.st.CountFlows(ctx, sid)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "count flows: %v", err)
		}
		if err := i.st.FinishSession(ctx, sid, trafficv1.SessionStatus_SESSION_STATUS_CLOSED, n); err != nil {
			return nil, status.Errorf(codes.Internal, "finish session: %v", err)
		}
	}

	sess, err := i.st.GetSession(ctx, sid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get session: %v", err)
	}
	return &trafficv1.SessionSummary{Session: sess}, nil
}

// persistLive records the flows + WebSocket messages produced by the live decoder as a
// "live" analysis, then finishes the session — the record-live alternative to the batch
// tshark pass. The flows are the live path's final state (bodies capped at maxLiveBody).
func (i *Ingest) persistLive(ctx context.Context, sid string, ls *liveSession) error {
	if ls.sink != nil {
		// The flusher has been writing throughout the capture, so closing is a final
		// flush of the unwritten tail rather than a transaction over the whole session
		// (ADR-0011 §7). The count comes from the bundle, which now holds every flow.
		if err := ls.flush(ctx, true); err != nil {
			return fmt.Errorf("final flush: %w", err)
		}
		n, err := i.st.CountFlows(ctx, sid)
		if err != nil {
			return fmt.Errorf("count flows: %w", err)
		}
		return i.st.FinishSession(ctx, sid, trafficv1.SessionStatus_SESSION_STATUS_CLOSED, n)
	}

	// No flusher ran (its analysis could not be created), so the session accumulated in
	// memory as it used to: write it in one pass.
	flows, msgs := ls.snapshotForRecord()
	aid, err := i.liveAnalysis(sid)
	if err != nil {
		return fmt.Errorf("create analysis: %w", err)
	}
	n, err := i.st.InsertFlows(ctx, sid, aid, flows)
	if err != nil {
		return fmt.Errorf("insert flows: %w", err)
	}
	if _, err := i.st.InsertWsMessages(ctx, sid, msgs); err != nil {
		return fmt.Errorf("insert ws messages: %w", err)
	}
	return i.st.FinishSession(ctx, sid, trafficv1.SessionStatus_SESSION_STATUS_CLOSED, n)
}

// protoToDecodeWsMessage converts a live proto WebSocket frame to the decode type the
// store persists (payloads are inline on the live path).
func protoToDecodeWsMessage(pm *trafficv1.WsMessage) *decode.WsMessage {
	return &decode.WsMessage{
		ID:           pm.GetId(),
		FlowID:       pm.GetFlowId(),
		FrameNumber:  pm.GetFrameNumber(),
		TSUnixMicros: pm.GetTsUnixMicros(),
		FromClient:   pm.GetFromClient(),
		Opcode:       pm.GetOpcode(),
		Payload:      pm.GetPayload().GetInline(),
		Raw:          pm.GetRaw().GetInline(),
		// The decoder's header fields, which every live frame reaches the bundle through:
		// the flusher converts back to the decode type to write, so a field dropped here is
		// a field the session never gets. The batch path writes decode.WsMessage directly
		// and so never showed it — a live capture came out with named opcodes and no
		// columns at all.
		Metadata: pm.GetMetadata(),
	}
}
