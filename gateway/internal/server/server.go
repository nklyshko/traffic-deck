// Package server wires the gRPC services onto the gateway's dependencies:
// the read-side ViewerService and the IngestService (capture upload).
package server

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/objstore"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/sourcemgr"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// Viewer implements trafficv1.ViewerServiceServer backed by the store + live hub.
type Viewer struct {
	trafficv1.UnimplementedViewerServiceServer
	st  *store.Store
	hub *liveHub
}

func NewViewer(st *store.Store, hub *liveHub) *Viewer { return &Viewer{st: st, hub: hub} }

// storeStatus maps a store error to a gRPC status. ErrSchemaOutdated becomes
// FailedPrecondition carrying the re-import message, so any client can tell a stale
// bundle (fix: re-import the session) apart from a transient server fault; everything
// else is Internal. Callers handle ErrNotFound first when they want a specific message.
func storeStatus(err error, action string) error {
	if errors.Is(err, store.ErrSchemaOutdated) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	return status.Errorf(codes.Internal, "%s: %v", action, err)
}

func (v *Viewer) ListSessions(ctx context.Context, req *trafficv1.ListSessionsRequest) (*trafficv1.SessionList, error) {
	sessions, err := v.st.ListSessions(ctx, int(req.GetLimit()), int(req.GetOffset()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list sessions: %v", err)
	}
	// The catalog's flow_count is only written on close, so a still-open session would
	// report a stale 0. Surface the live hub's running count for open sessions instead,
	// so the count grows as flows arrive (notably the pushed mitmproxy path).
	for _, s := range sessions {
		if s.GetStatus() != trafficv1.SessionStatus_SESSION_STATUS_OPEN {
			continue
		}
		if n, ok := v.hub.liveFlowCount(s.GetId()); ok {
			s.FlowCount = uint32(n)
		}
	}
	return &trafficv1.SessionList{Sessions: sessions}, nil
}

func (v *Viewer) GetFlow(ctx context.Context, req *trafficv1.GetFlowRequest) (*trafficv1.Flow, error) {
	f, err := v.st.GetFlow(ctx, req.GetSessionId(), req.GetFlowId())
	if errors.Is(err, store.ErrNotFound) {
		// A live native-decode flow isn't persisted to the store until the session closes,
		// so serve it from the hub with the bundle's annotations attached — otherwise an
		// annotation set during capture (a comment, mark, tag) wouldn't be visible until
		// the session is closed and reopened.
		if lf := v.liveFlow(ctx, req.GetSessionId(), req.GetFlowId()); lf != nil {
			return lf, nil
		}
		return nil, status.Error(codes.NotFound, "flow not found")
	}
	if err != nil {
		return nil, storeStatus(err, "get flow")
	}
	return f, nil
}

// liveFlow returns the in-progress (unpersisted) flow from the live hub with the session
// bundle's annotations folded in, or nil if it isn't live. Annotation attach is best-effort:
// the flow itself is still worth returning if that read fails.
func (v *Viewer) liveFlow(ctx context.Context, sessionID, flowID string) *trafficv1.Flow {
	ls := v.hub.get(sessionID)
	if ls == nil {
		return nil
	}
	f := ls.flow(flowID)
	if f == nil {
		return nil
	}
	_ = v.st.AttachFlowAnnotations(ctx, sessionID, f)
	return f
}

// StreamFlows replays stored flows (backfill), then — if follow is set and the
// session is live — streams a snapshot + subsequent live flow events until the
// session closes or the client disconnects.
func (v *Viewer) StreamFlows(req *trafficv1.StreamFlowsRequest, srv grpc.ServerStreamingServer[trafficv1.FlowEvent]) error {
	flows, err := v.st.ListFlows(srv.Context(), req.GetSessionId())
	if err != nil {
		return storeStatus(err, "list flows")
	}
	sent := make(map[string]bool, len(flows))
	for _, f := range flows {
		if err := srv.Send(&trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_FlowAdded{FlowAdded: f}}); err != nil {
			return err
		}
		sent[f.GetId()] = true
	}

	if !req.GetFollow() {
		// The live decode paths persist nothing until close, so a non-following reader
		// (the MCP server, a script) would see an open session as empty. Serve the hub's
		// flows too — skipping ids the backfill already covered, since the pushed
		// (mitmproxy) path persists incrementally and so appears in both.
		return v.sendLiveFlows(srv, req.GetSessionId(), sent)
	}
	ls := v.waitForLive(srv.Context(), req.GetSessionId())
	if ls == nil {
		return nil // not a live session; backfill is all there is
	}
	snapshot, ch, cancel := ls.subscribe()
	defer cancel()
	for _, ev := range snapshot {
		if err := srv.Send(ev); err != nil {
			return err
		}
	}
	for {
		select {
		case <-srv.Context().Done():
			return nil
		case ev, ok := <-ch:
			if !ok {
				return nil // session closed
			}
			if err := srv.Send(ev); err != nil {
				return err
			}
		}
	}
}

// sendLiveFlows sends the in-progress (unpersisted) flows of an open session as
// flow_added events, skipping ids already sent from the store, with the bundle's
// annotations folded in. A no-op when the session isn't live. Annotation attach is
// best-effort: the flows are still worth sending if that read fails.
func (v *Viewer) sendLiveFlows(srv grpc.ServerStreamingServer[trafficv1.FlowEvent], sessionID string, sent map[string]bool) error {
	ls := v.hub.get(sessionID)
	if ls == nil {
		return nil
	}
	var live []*trafficv1.Flow
	for _, f := range ls.liveFlows() {
		if !sent[f.GetId()] {
			live = append(live, f)
		}
	}
	_ = v.st.AttachFlowAnnotations(srv.Context(), sessionID, live...)
	for _, f := range live {
		if err := srv.Send(&trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_FlowAdded{FlowAdded: f}}); err != nil {
			return err
		}
	}
	return nil
}

// waitForLive returns the live-hub session for sessionID, briefly waiting out the race
// between OpenSession (the session row is created) and the first UploadBegin (which
// registers the hub session and starts live decode). Without this, a viewer that
// subscribes in that window sees hub.get==nil and gets only backfill — no live flows —
// even though the session is live. Returns nil if the session is already closed, gone,
// or stays open without ever registering a live decode (e.g. live decode disabled).
func (v *Viewer) waitForLive(ctx context.Context, sessionID string) *liveSession {
	const poll = 50 * time.Millisecond
	deadline := time.Now().Add(5 * time.Second)
	for {
		if ls := v.hub.get(sessionID); ls != nil {
			return ls
		}
		// Stop waiting once the session is no longer open (it won't become live) or gone.
		s, err := v.st.GetSession(ctx, sessionID)
		if err != nil || s.GetStatus() != trafficv1.SessionStatus_SESSION_STATUS_OPEN {
			return nil
		}
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(poll):
		}
	}
}

func (v *Viewer) GetBody(req *trafficv1.GetBodyRequest, srv grpc.ServerStreamingServer[trafficv1.BodyChunk]) error {
	body, _, err := v.st.GetBodyBytes(srv.Context(), req.GetSessionId(), req.GetFlowId(), req.GetResponse())
	if errors.Is(err, store.ErrNotFound) {
		// Like GetFlow: an unpersisted live flow's body is served from the hub. Whatever
		// the live decode kept is streamed, flagged truncated when that is only the start
		// of the body — so a caller can't read a prefix as if it were the whole thing.
		if ls := v.hub.get(req.GetSessionId()); ls != nil {
			if data, truncated, ok := ls.bodyBytes(req.GetFlowId(), req.GetResponse()); ok {
				return streamBytes(srv, data, truncated)
			}
		}
		return status.Error(codes.NotFound, "body not found")
	}
	if err != nil {
		return storeStatus(err, "get body")
	}
	return streamBytes(srv, body, false)
}

func (v *Viewer) ListMessages(ctx context.Context, req *trafficv1.ListMessagesRequest) (*trafficv1.MessageList, error) {
	msgs, err := v.st.ListMessages(ctx, req.GetSessionId(), req.GetFlowId())
	if err != nil {
		return nil, storeStatus(err, "list messages")
	}
	if len(msgs) == 0 {
		// Nothing stored: the frames of an open session live only in the hub until close,
		// so serve those (with their annotations) — otherwise a live WebSocket timeline
		// reads as empty. GetMessage/StreamMessages already have this fallback.
		if ls := v.hub.get(req.GetSessionId()); ls != nil {
			msgs = ls.messagesForFlow(req.GetFlowId())
			_ = v.st.AttachMessageAnnotations(ctx, req.GetSessionId(), msgs...)
		}
	}
	return &trafficv1.MessageList{Messages: msgs}, nil
}

func (v *Viewer) GetMessage(ctx context.Context, req *trafficv1.GetMessageRequest) (*trafficv1.WsMessage, error) {
	m, err := v.st.GetMessage(ctx, req.GetSessionId(), req.GetMessageId())
	if errors.Is(err, store.ErrNotFound) {
		// Like GetFlow: a live WebSocket/parsed message isn't persisted until close, so
		// serve it from the hub with its annotations attached — so an annotation set on a
		// message during capture reflects immediately in the message timeline.
		if lm := v.liveMessage(ctx, req.GetSessionId(), req.GetMessageId()); lm != nil {
			return lm, nil
		}
		return nil, status.Error(codes.NotFound, "message not found")
	}
	if err != nil {
		return nil, storeStatus(err, "get message")
	}
	return m, nil
}

// liveMessage is the message-side counterpart of liveFlow: the in-progress message from the
// live hub with the bundle's annotations folded in, or nil if it isn't live.
func (v *Viewer) liveMessage(ctx context.Context, sessionID, messageID string) *trafficv1.WsMessage {
	ls := v.hub.get(sessionID)
	if ls == nil {
		return nil
	}
	m := ls.message(messageID)
	if m == nil {
		return nil
	}
	_ = v.st.AttachMessageAnnotations(ctx, sessionID, m)
	return m
}

// StreamMessages replays an Upgrade flow's stored frames, then — if follow is set and
// the session is live — streams newly decoded frames until the session closes or the
// client disconnects (the live WebSocket timeline, mirroring StreamFlows;).
func (v *Viewer) StreamMessages(req *trafficv1.StreamMessagesRequest, srv grpc.ServerStreamingServer[trafficv1.MessageEvent]) error {
	send := func(m *trafficv1.WsMessage) error {
		return srv.Send(&trafficv1.MessageEvent{Event: &trafficv1.MessageEvent_MessageAdded{MessageAdded: m}})
	}

	// Subscribe *before* reading the store, so a frame the flusher moves from the hub to
	// the bundle mid-read lands in one of the two rather than falling between them. The
	// cost is that a frame can appear in both, which the id set below drops — a duplicate
	// is recoverable, a gap in a live timeline is not.
	var (
		ls       *liveSession
		snapshot []*trafficv1.WsMessage
		ch       chan *trafficv1.WsMessage
	)
	if req.GetFollow() {
		if ls = v.waitForLive(srv.Context(), req.GetSessionId()); ls != nil {
			var cancel func()
			snapshot, ch, cancel = ls.subscribeMessages(req.GetFlowId())
			defer cancel()
		}
	}

	// Backfill from the store: everything already flushed, plus the whole session once
	// it is closed.
	stored, err := v.st.ListMessages(srv.Context(), req.GetSessionId(), req.GetFlowId())
	if err != nil {
		return storeStatus(err, "list messages")
	}
	sent := make(map[string]bool, len(stored))
	for _, m := range stored {
		if err := send(m); err != nil {
			return err
		}
		sent[m.GetId()] = true
	}

	if !req.GetFollow() || ls == nil {
		return nil // not live; the backfill is all there is
	}
	for _, m := range snapshot {
		if sent[m.GetId()] {
			continue // already served from the bundle
		}
		if err := send(m); err != nil {
			return err
		}
		sent[m.GetId()] = true
	}
	for {
		select {
		case <-srv.Context().Done():
			return nil
		case m, ok := <-ch:
			if !ok {
				// Session closed: signal end of the live stream and finish.
				_ = srv.Send(&trafficv1.MessageEvent{Event: &trafficv1.MessageEvent_SessionEvent{
					SessionEvent: &trafficv1.SessionEvent{
						SessionId: req.GetSessionId(),
						Status:    trafficv1.SessionStatus_SESSION_STATUS_CLOSED,
					}}})
				return nil
			}
			if m.GetFlowId() != req.GetFlowId() {
				continue // other flows share the channel; only forward this flow's frames
			}
			if sent[m.GetId()] {
				continue // already served from the bundle or the snapshot
			}
			if err := send(m); err != nil {
				return err
			}
			sent[m.GetId()] = true
		}
	}
}

func (v *Viewer) GetMessageBody(req *trafficv1.GetMessageBodyRequest, srv grpc.ServerStreamingServer[trafficv1.BodyChunk]) error {
	body, err := v.st.GetWsMessageBody(srv.Context(), req.GetSessionId(), req.GetMessageId(), req.GetRaw())
	if errors.Is(err, store.ErrNotFound) {
		// Unpersisted live frame: its payload (and raw bytes) are inline in the hub. Frames
		// are small and kept whole, so nothing here is ever a prefix.
		if ls := v.hub.get(req.GetSessionId()); ls != nil {
			if data, ok := ls.messageBody(req.GetMessageId(), req.GetRaw()); ok {
				return streamBytes(srv, data, false)
			}
		}
		return status.Error(codes.NotFound, "message body not found")
	}
	if err != nil {
		return storeStatus(err, "get message body")
	}
	return streamBytes(srv, body, false)
}

// streamBytes sends a byte slice as BodyChunks over a server stream. truncated marks the
// bytes as a prefix of a longer body; it rides on every chunk, and forces one empty chunk
// when there are no bytes at all, so the flag can't be lost to an empty stream.
func streamBytes(srv grpc.ServerStreamingServer[trafficv1.BodyChunk], body []byte, truncated bool) error {
	const chunk = 64 << 10
	if len(body) == 0 && truncated {
		return srv.Send(&trafficv1.BodyChunk{Truncated: true})
	}
	for off := 0; off < len(body); off += chunk {
		end := min(off+chunk, len(body))
		if err := srv.Send(&trafficv1.BodyChunk{Payload: body[off:end], Truncated: truncated}); err != nil {
			return err
		}
	}
	return nil
}

// Register attaches all implemented services to s, sharing one live hub between the ingest
// (producer) and viewer (subscriber) sides. gatewayAddr is where spawned capture sources
// connect back for ingest. Returns the source manager so the caller can reap it on shutdown.
func Register(s *grpc.Server, st *store.Store, obj objstore.Store, tshark, gatewayAddr string, liveDecode, recordLive, tsharkVerify bool) (*sourcemgr.Manager, *sourcemgr.Services) {
	if recordLive {
		// The persisted record is the live decode, so keep full bodies (not previews).
		decode.SetUnlimitedLiveBodies()
	}
	hub := newLiveHub(recordLive)
	dataRoot, _ := obj.LocalPath("") // FSStore root; session bundles live here
	// Built-in registries, then merge in any third-party modules from plugins/ (their
	// processes become auto-start services; a [control] block a dial-only capture source).
	srcSpecs := sourcemgr.DefaultSpecs()
	svcSpecs := sourcemgr.DefaultServices()
	sourcemgr.ApplyManifests(sourcemgr.PluginsDir(), srcSpecs, svcSpecs)
	mgr := sourcemgr.New(gatewayAddr, srcSpecs)
	svcs := sourcemgr.NewServices(gatewayAddr, svcSpecs)
	// A module's processes (adapter, web UI) start on first use of its capture source, not
	// now; only services with no owning capture type auto-start at launch.
	mgr.SetModuleStarter(svcs.StartModule)
	svcs.StartAuto()
	ingest := NewIngest(st, obj, tshark, hub, liveDecode, recordLive, tsharkVerify)
	// Incremental persistence (ADR-0011): the hub's flushers write through the store,
	// take their analysis from the ingest side, and end the capture if a write fails.
	ingest.stopCapture = mgr.StopCapture
	hub.setPersistence(st, ingest.liveAnalysis, ingest.onFlushError)
	trafficv1.RegisterViewerServiceServer(s, NewViewer(st, hub))
	trafficv1.RegisterIngestServiceServer(s, ingest)
	trafficv1.RegisterControlServiceServer(s, NewControl(st, obj, dataRoot, tshark, mgr, svcs))
	return mgr, svcs
}
