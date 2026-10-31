package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nklyshko/traffic-deck/gateway/decoders"
	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
	"github.com/nklyshko/traffic-deck/gateway/internal/filter"
	"github.com/nklyshko/traffic-deck/gateway/internal/importer"
	"github.com/nklyshko/traffic-deck/gateway/internal/objstore"
	"github.com/nklyshko/traffic-deck/gateway/internal/store"
)

const maxChunkBytes = 1 << 20 // advertised upload chunk size

// maxSessionFileBytes bounds where a client may write within a session's pcap or key.log.
// The write offset arrives on the wire, so this is what stops a crafted offset from
// creating an enormous sparse file that a later full read would allocate in memory (and
// from wrapping negative in WriteAt past 2^63). It is far above any real capture.
const maxSessionFileBytes = 64 << 30 // 64 GiB

// pidsCaptureKey is reported at CloseSession by the macOS per-process source: the pids its
// browser's network process used while the capture ran, comma-separated. Mirrors
// capture/capture_pktap/capture_pktap/pktap.py.
//
// It arrives at close rather than at open because it cannot be known earlier — the browser
// has not been launched when the session opens, and the set can still grow if Chrome
// replaces its network process midway. The kernel filter makes the cheap cut during the
// capture; this makes the exact one afterwards.
const pidsCaptureKey = "capture.pids"

// Ingest implements trafficv1.IngestServiceServer: streamed capture upload (decoded
// live and/or on close) and the pushed-flow path for already-decoded sources.
type Ingest struct {
	trafficv1.UnimplementedIngestServiceServer
	st           *store.Store
	obj          objstore.Store
	tshark       string
	hub          *liveHub
	liveDecode   bool // when false, streaming uploads are archived and decoded only on close
	tsharkVerify bool // when true, compare live flows vs a tshark decode on close and log differences

	// pushAnalyses gives each pushed (mitmproxy) session a single analysis, shared across
	// its many PushFlows streams — the addon opens one stream per flow/message.
	// liveAnalyses is the live-decode counterpart, created at session start because rows
	// reference it throughout the capture now, not only at close (ADR-0011 §7).
	pushMu       sync.Mutex
	pushAnalyses map[string]string // sessionID -> analysisID
	liveAnalyses map[string]string // sessionID -> analysisID

	// stopCapture ends the capture feeding a session, for when its flush fails and the
	// session can no longer be recorded (ADR-0011 §5). Set by Register; nil in tests.
	stopCapture func(ctx context.Context, sessionID string) error

	// finalizing holds the sessions a finalizeSession call is working on. A close can race
	// an upload stream that breaks right after it (the client cancels the stream once it
	// has closed the session), and a second finalize of a session the first one closed
	// would run a whole tshark batch decode and store a second analysis.
	finalizeMu sync.Mutex
	finalizing map[string]bool

	// wsStates runs custom WebSocket decoders over pushed binary frames (the push path
	// bypasses the tshark/Go decoders), keyed by the parent flow id.
	wsDecMu  sync.Mutex
	wsStates map[string]*wsPushState

	// tcpStates is the raw-TCP counterpart: a pushed connection a custom decoder claims
	// (MAX's mobile transport through mitmproxy) is framed as on the pcap path, keyed by
	// the flow id.
	tcpDecMu  sync.Mutex
	tcpStates map[string]*tcpPushState
}

// tcpPushState is one pushed raw-TCP flow's decoder, chosen at its first push.
type tcpPushState struct {
	dec  decoders.Decoder // nil if none claims the connection
	sess decoders.Session
}

// wsPushState is one pushed WebSocket flow's decoder framing state.
type wsPushState struct {
	meta    decoders.WSMeta
	decided bool
	dec     decoders.WSDecoder // nil once decided if none claims the connection
	sess    decoders.Session
}

func NewIngest(st *store.Store, obj objstore.Store, tshark string, hub *liveHub, liveDecode, tsharkVerify bool) *Ingest {
	return &Ingest{
		st: st, obj: obj, tshark: tshark, hub: hub,
		liveDecode: liveDecode, tsharkVerify: tsharkVerify,
		pushAnalyses: map[string]string{},
		liveAnalyses: map[string]string{},
	}
}

// liveAnalysis returns a live-decoded session's analysis, creating it on first use. The
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
		i.wsStates[pf.GetId()] = &wsPushState{meta: decoders.WSMeta{
			Host: pf.GetAuthority(), Path: pf.GetPath(), SNI: pf.GetMetadata()[tlsSNIKey]}}
	}
}

// Keys a capture source sets on a pushed flow's metadata (capture/capture_mitmproxy):
// the TLS SNI the client sent, where the flow's authority came from, and — for a
// connection nothing decoded — why.
const (
	tlsSNIKey         = "tls.sni"
	hostnameSourceKey = "hostname.source"
	connOutcomeKey    = filter.ConnOutcomeKey
)

// claimPushedTCP lets a custom decoder claim a pushed raw-TCP connection, as the pcap path
// does for one it decrypted: matched on the SNI, the best name the source had for the
// server, and the address dialled. The decision is made on the connection's first push
// and re-applied to every later one (the source re-pushes it when it closes), so the flow
// keeps the protocol's name and loses its "undecoded" outcome for good.
func (i *Ingest) claimPushedTCP(pf *trafficv1.Flow) {
	if pf.GetProtocol() != "TCP" {
		return
	}
	i.tcpDecMu.Lock()
	defer i.tcpDecMu.Unlock()
	if i.tcpStates == nil {
		i.tcpStates = map[string]*tcpPushState{}
	}
	st, ok := i.tcpStates[pf.GetId()]
	if !ok {
		st = &tcpPushState{}
		if m := decoders.Match(pushedStreamMeta(pf)); len(m) > 0 {
			st.dec, st.sess = m[0], m[0].NewSession()
		}
		i.tcpStates[pf.GetId()] = st
	}
	if st.dec == nil {
		return
	}
	pf.Protocol = strings.ToUpper(st.dec.Name())
	delete(pf.Metadata, connOutcomeKey)
}

// pushedStreamMeta describes a pushed raw-TCP flow to the decoder registry. Its authority
// is a name only when the source says one named it; a bare address is ServerHost alone.
func pushedStreamMeta(pf *trafficv1.Flow) decoders.StreamMeta {
	m := decoders.StreamMeta{ConnectionID: pf.GetConnectionId(), SNI: pf.GetMetadata()[tlsSNIKey]}
	if host, port, err := net.SplitHostPort(pf.GetDstAddr()); err == nil {
		m.ServerHost, m.ServerPort = host, port
	}
	if src := pf.GetMetadata()[hostnameSourceKey]; src != "" && src != "ip" {
		host := pf.GetAuthority()
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		m.Host = host
	}
	return m
}

// decodePushedTCP frames a pushed raw-TCP chunk through the decoder that claimed its flow,
// returning the decoder's name for the messages' opcode (as the pcap path records them).
// ok=false means no decoder handles the flow (store the chunk as-is). The source awaits
// each push, so a flow's chunks arrive in order and the session's framing stays in sync.
func (i *Ingest) decodePushedTCP(flowID string, fromClient bool, payload []byte) ([]decoders.Message, string, bool) {
	i.tcpDecMu.Lock()
	defer i.tcpDecMu.Unlock()
	st := i.tcpStates[flowID]
	if st == nil || st.dec == nil {
		return nil, "", false
	}
	return st.sess.Feed(fromClient, payload), st.dec.Name(), true
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
// each at its byte offset (ordered, resumable). A live-decoded upload is also teed to the
// live decoder; otherwise decode happens on CloseSession.
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
			// The upload stream broke before the client finished it — the source process
			// died, or the connection dropped — and the CloseSession that normally
			// finalizes the capture will never arrive. Left alone the session stays OPEN
			// forever and, for a live capture, its decode goroutine and reassembly buffers
			// leak until the gateway restarts (the manual escape hatch is ForceCloseSession).
			// Reclaim it: finalize what was captured, on a fresh context since the stream's
			// is already cancelled. The real capture clients do not resume a dropped upload,
			// so there is nothing being truncated here. A client that closed the session and
			// then dropped the stream lands here too; finalizeSession refuses that one.
			if sid != "" {
				_, ferr := i.finalizeSession(context.Background(), sid)
				switch {
				case ferr == nil:
					log.Printf("upload %s broke (%v); finalized what was captured", sid, err)
				case errors.Is(ferr, errFinalizing), status.Code(ferr) == codes.FailedPrecondition:
					// Closed, or being closed, by CloseSession: nothing to reclaim.
				default:
					log.Printf("upload %s broke (%v); auto-finalize failed too: %v", sid, err, ferr)
				}
			}
			return err
		}
		switch m := msg.GetMsg().(type) {
		case *trafficv1.CaptureChunk_Begin:
			sid = m.Begin.GetSessionId()
			uploadID = m.Begin.GetUploadId()
			if m.Begin.GetMode() == trafficv1.CaptureMode_CAPTURE_MODE_STREAMING_LIVE && i.liveDecode {
				live = true
				// Ensure the key.log exists so the in-process decoder can tail it, then start live decode.
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
			off := m.Data.GetOffset()
			if off > maxSessionFileBytes || off+uint64(len(m.Data.GetPayload())) > maxSessionFileBytes {
				return status.Errorf(codes.InvalidArgument,
					"chunk offset %d beyond the %d-byte per-file ceiling", off, maxSessionFileBytes)
			}
			if err := i.obj.WriteAt(key, m.Data.GetPayload(), int64(off)); err != nil {
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
			i.claimPushedTCP(pf) // before it is stored: a claimed stream is stored as its protocol
			dflows = append(dflows, protoToDecodeFlow(pf))
		}
		if _, err := i.st.InsertFlows(ctx, sid, aid, dflows); err != nil {
			return status.Errorf(codes.Internal, "insert flows: %v", err)
		}
		for _, pf := range flows {
			ls.publish(pf, true)
			i.recordWSMeta(pf)
		}

		// WebSocket / raw-TCP frames: their flow_id references a flow pushed earlier
		// (same or prior batch), so the parent flow is already persisted. A registered
		// WSDecoder reframes binary frames into protocol messages (carrying the original
		// bytes in Raw); unclaimed frames are stored as-is.
		msgs := batch.GetMessages()
		var store []*decode.Message
		var pub []*trafficv1.Message
		for _, pm := range msgs {
			if pm.GetId() == "" {
				pm.Id = uuid.NewString()
			}
			payload := pm.GetPayload().GetInline()
			if pm.GetOpcode() == "binary" {
				if frames, name, ok := i.decodePushedTCP(pm.GetFlowId(), pm.GetFromClient(), payload); ok {
					for _, fr := range frames {
						dm := &decode.Message{
							ID: uuid.NewString(), FlowID: pm.GetFlowId(),
							// A raw stream has no frame types of its own, so the transport's
							// opcode is the decoder's name — as the pcap path records it.
							FromClient: fr.FromClient, Opcode: name,
							TSUnixMicros: pm.GetTsUnixMicros(), Payload: fr.Payload, Raw: payload,
							Metadata: fr.Fields,
						}
						store = append(store, dm)
						pub = append(pub, wsMsgToProto(dm))
					}
					continue
				}
				if frames, ok := i.decodePushedWSBinary(pm.GetFlowId(), pm.GetFromClient(), payload); ok {
					for _, fr := range frames {
						dm := &decode.Message{
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
			store = append(store, protoToDecodeMessage(pm))
			pub = append(pub, pm)
		}
		if len(store) > 0 {
			if _, err := i.st.InsertMessages(ctx, sid, store); err != nil {
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
		ConnectionID: pf.GetConnectionId(),
		StreamID:     pf.GetStreamId(),
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

// CloseSession finalizes a session: record sizes, persist the live decode's flows (or
// batch-decode the pcap when live decode was off), and return the closed session summary.
//
// Any metadata the source reports here is merged into the session first, so finalization
// and anyone reading the session later see it alongside what was supplied at open.
func (i *Ingest) CloseSession(ctx context.Context, req *trafficv1.CloseSessionRequest) (*trafficv1.SessionSummary, error) {
	if md := req.GetMetadata(); len(md) > 0 {
		if err := i.st.SetSessionMetadata(ctx, req.GetSessionId(), md); err != nil {
			// Not fatal: the capture is already recorded, and losing this only means a
			// narrowing doesn't happen. Failing the close would strand the session open.
			log.Printf("close %s: session metadata: %v", req.GetSessionId(), err)
		}
	}
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
	if s := sess.GetStatus(); finalized(s) {
		return nil, status.Errorf(codes.FailedPrecondition, "session already finalized (%s)", s)
	}

	// Try the normal finalization (decode/persist whatever was captured). If it fails —
	// e.g. the bundle has an outdated schema (an old stale session), or a partial/corrupt
	// pcap — force-close must still unstick the session, so fall back to marking it closed
	// in the catalog only (which doesn't touch the bundle DB). Live decode was already
	// stopped inside finalizeSession. Not when another call is finalizing it right now:
	// marking it closed under that call would cut its persist short.
	summary, err := i.finalizeSession(ctx, sid)
	if err == nil || errors.Is(err, errFinalizing) {
		return summary, err
	}
	log.Printf("force close %s: finalize failed (%v); marking closed in the catalog", sid, err)
	if err := i.st.FinishSession(ctx, sid, trafficv1.SessionStatus_SESSION_STATUS_CLOSED, int(sess.GetFlowCount())); err != nil {
		return nil, status.Errorf(codes.Internal, "force close: mark closed: %v", err)
	}
	closed, err := i.st.GetSession(ctx, sid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "force close: %v", err)
	}
	return &trafficv1.SessionSummary{Session: closed}, nil
}

// errFinalizing refuses a finalize while another call is finalizing the same session.
var errFinalizing = status.Error(codes.Aborted, "session is already being finalized")

func finalized(s trafficv1.SessionStatus) bool {
	return s == trafficv1.SessionStatus_SESSION_STATUS_CLOSED || s == trafficv1.SessionStatus_SESSION_STATUS_ERROR
}

func (i *Ingest) finalizeSession(ctx context.Context, sid string) (*trafficv1.SessionSummary, error) {
	i.finalizeMu.Lock()
	if i.finalizing[sid] {
		i.finalizeMu.Unlock()
		return nil, errFinalizing
	}
	if i.finalizing == nil {
		i.finalizing = map[string]bool{}
	}
	i.finalizing[sid] = true
	i.finalizeMu.Unlock()
	defer func() {
		i.finalizeMu.Lock()
		delete(i.finalizing, sid)
		i.finalizeMu.Unlock()
	}()
	if sess, err := i.st.GetSession(ctx, sid); err == nil && finalized(sess.GetStatus()) {
		return nil, status.Errorf(codes.FailedPrecondition, "session already finalized (%s)", sess.GetStatus())
	}

	// Stop live decode (if any); ls holds the live flows not yet persisted.
	ls := i.hub.stop(sid)

	// Narrow a per-process capture to the browser that was launched. This runs before the
	// size is recorded and before any batch decode, so the stored pcap, the size reported
	// for it and the flows decoded from it all describe the same packets.
	//
	// foreign is the connections it proved belonged to another process. The batch path
	// needs nothing further — tshark decodes the pruned pcap — but the live decode ran
	// while the capture did, so its flows are narrowed separately below.
	foreign := i.pruneToCapturePIDs(ctx, sid)

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
	case ls != nil && pcapBytes > 0:
		// LIVE: persist the flows the live decoder already produced; it is authoritative,
		// so no batch re-decode runs (ADR-0009).
		if err := i.persistLive(ctx, sid, ls, foreign); err != nil {
			return nil, status.Errorf(codes.Internal, "persist live: %v", err)
		}
		if i.tsharkVerify {
			// Diagnostic tshark decode (not persisted) to check the recorded live flows.
			i.verifyRecordedLive(ctx, sid, ls, keylogLocal)
		}
	case pcapBytes > 0:
		// PACKET source with live decode off (GATEWAY_LIVE_DECODE=false): the batch decode
		// over the finalized pcap is the only one.
		pcapLocal, _ := i.obj.LocalPath(pcapKey(sid))
		if _, err := importer.Finalize(ctx, i.st, decode.EngineTshark, i.tshark, sid, pcapLocal, keylogLocal); err != nil {
			return nil, status.Errorf(codes.Internal, "finalize: %v", err)
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

// pruneToCapturePIDs cuts a PKTAP capture down to the packets owned by the pids the
// source reported, and is a no-op for every other session — a source that said nothing
// gets nothing done to its capture. It returns the connections it proved belonged to
// another process, so the flow list can be narrowed by the same evidence.
//
// Every failure here is logged and swallowed. The capture is already recorded and a
// session that cannot be narrowed is still a good session; failing the close instead
// would leave it stuck open, which is strictly worse than a bundle that is larger than
// the user asked for.
func (i *Ingest) pruneToCapturePIDs(ctx context.Context, sid string) map[decode.ConnKey]bool {
	sess, err := i.st.GetSession(ctx, sid)
	if err != nil {
		return nil
	}
	keep := parseCapturePIDs(sess.GetMetadata()[pidsCaptureKey])
	if len(keep) == 0 {
		return nil
	}
	// A session with no capture (or an empty one) is not a failure to narrow; there is
	// simply nothing to narrow. Checked before opening so it stays silent.
	if fi, err := i.obj.Stat(pcapKey(sid)); err != nil || fi.Size == 0 {
		return nil
	}
	pcapLocal, ok := i.obj.LocalPath(pcapKey(sid))
	if !ok || pcapLocal == "" {
		return nil
	}
	res, err := decode.PrunePcapngByPID(pcapLocal, keep)
	if err != nil {
		// ErrNoProcessInfo is the ordinary case of a source reporting pids for a capture
		// that carries no per-packet process; it is worth one line, not an alarm.
		log.Printf("prune %s: %v", sid, err)
		return nil
	}
	log.Printf("prune %s: kept %d of %d packets, %d -> %d bytes; wanted pids %v, capture held %v",
		sid, res.PacketsKept, res.PacketsIn, res.Before, res.After,
		sortedPIDs(keep), sortedPIDs(res.PIDsSeen))
	if res.PacketsUnknown > 0 {
		log.Printf("prune %s: %d packets kept because their pktap header could not be read",
			sid, res.PacketsUnknown)
	}
	return res.ForeignConns()
}

// parseCapturePIDs reads the comma-separated pid list a source reports. Anything
// unparseable is skipped rather than failing the whole list: a partial set still narrows
// the capture, and the alternative is to narrow nothing.
func parseCapturePIDs(s string) map[int32]bool {
	if s == "" {
		return nil
	}
	pids := map[int32]bool{}
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.ParseInt(strings.TrimSpace(part), 10, 32)
		if err != nil || n <= 0 {
			continue
		}
		pids[int32(n)] = true
	}
	return pids
}

func sortedPIDs(keep map[int32]bool) []int32 {
	out := make([]int32, 0, len(keep))
	for p := range keep {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// persistLive records the flows + WebSocket messages produced by the live decoder as a
// "live" analysis, then finishes the session. The flows are the live path's final state,
// bodies whole.
//
// foreign names connections a per-process capture proved belonged to another process. The
// live decoder saw them because the kernel filter could not exclude them, so they are
// dropped here — after everything is in the bundle and before the count is taken, so the
// session's flow count describes what the session actually holds.
func (i *Ingest) persistLive(ctx context.Context, sid string, ls *liveSession, foreign map[decode.ConnKey]bool) error {
	// The undecoded index is evidence, not the record: a failure to keep it is logged and
	// the session still closes.
	if err := i.st.RecordUndecoded(ctx, sid, ls.undecodedSnapshot(foreign)); err != nil {
		log.Printf("session %s: undecoded connections not recorded: %v", sid, err)
	}
	if ls.sink != nil {
		// The flusher has been writing throughout the capture, so closing is a final
		// flush of the unwritten tail rather than a transaction over the whole session
		// (ADR-0011 §7). The count comes from the bundle, which now holds every flow.
		if err := ls.flush(ctx, true); err != nil {
			return fmt.Errorf("final flush: %w", err)
		}
		i.dropForeignFlows(ctx, sid, foreign)
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
	if _, err := i.st.InsertFlows(ctx, sid, aid, flows); err != nil {
		return fmt.Errorf("insert flows: %w", err)
	}
	if _, err := i.st.InsertMessages(ctx, sid, msgs); err != nil {
		return fmt.Errorf("insert ws messages: %w", err)
	}
	i.dropForeignFlows(ctx, sid, foreign)
	// Counted from the bundle rather than from what was just inserted, so the number
	// still holds after the drop above removed some of it.
	n, err := i.st.CountFlows(ctx, sid)
	if err != nil {
		return fmt.Errorf("count flows: %w", err)
	}
	return i.st.FinishSession(ctx, sid, trafficv1.SessionStatus_SESSION_STATUS_CLOSED, n)
}

// dropForeignFlows removes the flows on connections that belonged to another process.
// Best-effort: a session whose flow list could not be narrowed is still a good session,
// and the packets have already been pruned either way.
func (i *Ingest) dropForeignFlows(ctx context.Context, sid string, foreign map[decode.ConnKey]bool) {
	if len(foreign) == 0 {
		return
	}
	conns := make([][2]string, 0, len(foreign))
	for c := range foreign {
		conns = append(conns, [2]string{c.A, c.B})
	}
	n, err := i.st.DeleteFlowsByConnection(ctx, sid, conns)
	if err != nil {
		log.Printf("prune %s: drop foreign flows: %v", sid, err)
		return
	}
	if n > 0 {
		log.Printf("prune %s: dropped %d flows on %d connections owned by other processes",
			sid, n, len(conns))
	}
}

// protoToDecodeMessage converts a live proto WebSocket frame to the decode type the
// store persists (payloads are inline on the live path).
func protoToDecodeMessage(pm *trafficv1.Message) *decode.Message {
	return &decode.Message{
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
		// a field the session never gets. The batch path writes decode.Message directly
		// and so never showed it — a live capture came out with named opcodes and no
		// columns at all.
		Metadata: pm.GetMetadata(),
	}
}
