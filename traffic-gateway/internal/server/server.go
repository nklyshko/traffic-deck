// Package server wires the gRPC services onto the gateway's dependencies:
// the read-side ViewerService and the IngestService (capture upload).
package server

import (
	"context"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "github.com/nikitak/parsing/traffic-gateway/gen/traffic/v1"
	"github.com/nikitak/parsing/traffic-gateway/internal/objstore"
	"github.com/nikitak/parsing/traffic-gateway/internal/store"
)

// Viewer implements trafficv1.ViewerServiceServer backed by the store + live hub.
type Viewer struct {
	trafficv1.UnimplementedViewerServiceServer
	st  *store.Store
	hub *liveHub
}

func NewViewer(st *store.Store, hub *liveHub) *Viewer { return &Viewer{st: st, hub: hub} }

func (v *Viewer) ListSessions(ctx context.Context, req *trafficv1.ListSessionsRequest) (*trafficv1.SessionList, error) {
	sessions, err := v.st.ListSessions(ctx, int(req.GetLimit()), int(req.GetOffset()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list sessions: %v", err)
	}
	return &trafficv1.SessionList{Sessions: sessions}, nil
}

func (v *Viewer) GetFlow(ctx context.Context, req *trafficv1.GetFlowRequest) (*trafficv1.Flow, error) {
	f, err := v.st.GetFlow(ctx, req.GetSessionId(), req.GetFlowId())
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Error(codes.NotFound, "flow not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get flow: %v", err)
	}
	return f, nil
}

// StreamFlows replays stored flows (backfill), then — if follow is set and the
// session is live — streams a snapshot + subsequent live flow events until the
// session closes or the client disconnects (plan §8.2).
func (v *Viewer) StreamFlows(req *trafficv1.StreamFlowsRequest, srv grpc.ServerStreamingServer[trafficv1.FlowEvent]) error {
	flows, err := v.st.ListFlows(srv.Context(), req.GetSessionId())
	if err != nil {
		return status.Errorf(codes.Internal, "list flows: %v", err)
	}
	for _, f := range flows {
		if err := srv.Send(&trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_FlowAdded{FlowAdded: f}}); err != nil {
			return err
		}
	}

	if !req.GetFollow() {
		return nil
	}
	ls := v.hub.get(req.GetSessionId())
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

func (v *Viewer) GetBody(req *trafficv1.GetBodyRequest, srv grpc.ServerStreamingServer[trafficv1.BodyChunk]) error {
	body, _, err := v.st.GetBodyBytes(srv.Context(), req.GetSessionId(), req.GetFlowId(), req.GetResponse())
	if errors.Is(err, store.ErrNotFound) {
		return status.Error(codes.NotFound, "body not found")
	}
	if err != nil {
		return status.Errorf(codes.Internal, "get body: %v", err)
	}
	return streamBytes(srv, body)
}

func (v *Viewer) ListMessages(ctx context.Context, req *trafficv1.ListMessagesRequest) (*trafficv1.MessageList, error) {
	msgs, err := v.st.ListMessages(ctx, req.GetSessionId(), req.GetFlowId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list messages: %v", err)
	}
	return &trafficv1.MessageList{Messages: msgs}, nil
}

func (v *Viewer) GetMessageBody(req *trafficv1.GetMessageBodyRequest, srv grpc.ServerStreamingServer[trafficv1.BodyChunk]) error {
	body, err := v.st.GetWsMessageBody(srv.Context(), req.GetSessionId(), req.GetMessageId())
	if errors.Is(err, store.ErrNotFound) {
		return status.Error(codes.NotFound, "message body not found")
	}
	if err != nil {
		return status.Errorf(codes.Internal, "get message body: %v", err)
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
func Register(s *grpc.Server, st *store.Store, obj objstore.Store, tshark string) {
	hub := newLiveHub(tshark)
	dataRoot, _ := obj.LocalPath("") // FSStore root; session bundles live here
	trafficv1.RegisterViewerServiceServer(s, NewViewer(st, hub))
	trafficv1.RegisterIngestServiceServer(s, NewIngest(st, obj, tshark, hub))
	trafficv1.RegisterControlServiceServer(s, NewControl(st, dataRoot))
}
