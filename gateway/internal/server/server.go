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
		return nil, status.Error(codes.NotFound, "flow not found")
	}
	if err != nil {
		return nil, storeStatus(err, "get flow")
	}
	return f, nil
}

// StreamFlows replays stored flows (backfill), then — if follow is set and the
// session is live — streams a snapshot + subsequent live flow events until the
// session closes or the client disconnects.
func (v *Viewer) StreamFlows(req *trafficv1.StreamFlowsRequest, srv grpc.ServerStreamingServer[trafficv1.FlowEvent]) error {
	flows, err := v.st.ListFlows(srv.Context(), req.GetSessionId())
	if err != nil {
		return storeStatus(err, "list flows")
	}
	for _, f := range flows {
		if err := srv.Send(&trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_FlowAdded{FlowAdded: f}}); err != nil {
			return err
		}
	}

	if !req.GetFollow() {
		return nil
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
		return status.Error(codes.NotFound, "body not found")
	}
	if err != nil {
		return storeStatus(err, "get body")
	}
	return streamBytes(srv, body)
}

func (v *Viewer) ListMessages(ctx context.Context, req *trafficv1.ListMessagesRequest) (*trafficv1.MessageList, error) {
	msgs, err := v.st.ListMessages(ctx, req.GetSessionId(), req.GetFlowId())
	if err != nil {
		return nil, storeStatus(err, "list messages")
	}
	return &trafficv1.MessageList{Messages: msgs}, nil
}

// StreamMessages replays an Upgrade flow's stored frames, then — if follow is set and
// the session is live — streams newly decoded frames until the session closes or the
// client disconnects (the live WebSocket timeline, mirroring StreamFlows;).
func (v *Viewer) StreamMessages(req *trafficv1.StreamMessagesRequest, srv grpc.ServerStreamingServer[trafficv1.MessageEvent]) error {
	send := func(m *trafficv1.WsMessage) error {
		return srv.Send(&trafficv1.MessageEvent{Event: &trafficv1.MessageEvent_MessageAdded{MessageAdded: m}})
	}

	// Backfill from the store (populated once the session is persisted on close).
	stored, err := v.st.ListMessages(srv.Context(), req.GetSessionId(), req.GetFlowId())
	if err != nil {
		return storeStatus(err, "list messages")
	}
	for _, m := range stored {
		if err := send(m); err != nil {
			return err
		}
	}

	if !req.GetFollow() {
		return nil
	}
	ls := v.waitForLive(srv.Context(), req.GetSessionId())
	if ls == nil {
		return nil // not live; the backfill is all there is
	}
	snapshot, ch, cancel := ls.subscribeMessages(req.GetFlowId())
	defer cancel()
	for _, m := range snapshot {
		if err := send(m); err != nil {
			return err
		}
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
			if err := send(m); err != nil {
				return err
			}
		}
	}
}

func (v *Viewer) GetMessageBody(req *trafficv1.GetMessageBodyRequest, srv grpc.ServerStreamingServer[trafficv1.BodyChunk]) error {
	body, err := v.st.GetWsMessageBody(srv.Context(), req.GetSessionId(), req.GetMessageId(), req.GetRaw())
	if errors.Is(err, store.ErrNotFound) {
		return status.Error(codes.NotFound, "message body not found")
	}
	if err != nil {
		return storeStatus(err, "get message body")
	}
	return streamBytes(srv, body)
}

// streamBytes sends a byte slice as BodyChunks over a server stream.
func streamBytes(srv grpc.ServerStreamingServer[trafficv1.BodyChunk], body []byte) error {
	const chunk = 64 << 10
	for off := 0; off < len(body); off += chunk {
		end := min(off+chunk, len(body))
		if err := srv.Send(&trafficv1.BodyChunk{Payload: body[off:end]}); err != nil {
			return err
		}
	}
	return nil
}

// Register attaches all implemented services to s, sharing one live hub between
// the ingest (producer) and viewer (subscriber) sides.
func Register(s *grpc.Server, st *store.Store, obj objstore.Store, tshark string, liveDecode, recordLive, verifyLive bool) {
	if recordLive {
		// The persisted record is the live decode, so keep full bodies (not previews).
		decode.SetUnlimitedLiveBodies()
	}
	hub := newLiveHub(recordLive)
	dataRoot, _ := obj.LocalPath("") // FSStore root; session bundles live here
	trafficv1.RegisterViewerServiceServer(s, NewViewer(st, hub))
	trafficv1.RegisterIngestServiceServer(s, NewIngest(st, obj, tshark, hub, liveDecode, recordLive, verifyLive))
	trafficv1.RegisterControlServiceServer(s, NewControl(st, dataRoot))
}
