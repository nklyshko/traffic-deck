// Package server wires the gRPC services onto the gateway's dependencies.
//
// Phase 1: the read-side ViewerService serves stored sessions and flows
// (backfill). Live follow, bodies, and the Ingest/Control services come later.
package server

import (
	"context"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "github.com/nikitak/parsing/traffic-gateway/gen/traffic/v1"
	"github.com/nikitak/parsing/traffic-gateway/internal/store"
)

// Viewer implements trafficv1.ViewerServiceServer backed by the store.
type Viewer struct {
	trafficv1.UnimplementedViewerServiceServer
	st *store.Store
}

func NewViewer(st *store.Store) *Viewer { return &Viewer{st: st} }

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

// StreamFlows replays stored flows as flow_added events (backfill). Live follow
// is Phase 2.
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
	return nil
}

func (v *Viewer) GetBody(req *trafficv1.GetBodyRequest, srv grpc.ServerStreamingServer[trafficv1.BodyChunk]) error {
	body, _, err := v.st.GetBodyBytes(srv.Context(), req.GetSessionId(), req.GetFlowId(), req.GetResponse())
	if errors.Is(err, store.ErrNotFound) {
		return status.Error(codes.NotFound, "body not found")
	}
	if err != nil {
		return status.Errorf(codes.Internal, "get body: %v", err)
	}
	const chunk = 64 << 10
	for off := 0; off < len(body); off += chunk {
		end := min(off+chunk, len(body))
		if err := srv.Send(&trafficv1.BodyChunk{Payload: body[off:end]}); err != nil {
			return err
		}
	}
	return nil
}

// Register attaches all implemented services to s.
func Register(s *grpc.Server, st *store.Store) {
	trafficv1.RegisterViewerServiceServer(s, NewViewer(st))
}
