// Package server wires the gRPC services onto the gateway's dependencies.
//
// Phase 0: only the read-side ViewerService is registered, and most methods are
// stubs (codes.Unimplemented) pending Phase 1 (import + serve stored flows).
package server

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "github.com/nikitak/parsing/traffic-gateway/gen/traffic/v1"
	"github.com/nikitak/parsing/traffic-gateway/internal/objstore"
)

// Viewer implements trafficv1.ViewerServiceServer.
type Viewer struct {
	trafficv1.UnimplementedViewerServiceServer
	store objstore.Store
}

func NewViewer(store objstore.Store) *Viewer {
	return &Viewer{store: store}
}

// ListSessions returns an empty list for now (no persistence wired yet).
func (v *Viewer) ListSessions(_ context.Context, _ *trafficv1.ListSessionsRequest) (*trafficv1.SessionList, error) {
	return &trafficv1.SessionList{}, nil
}

func (v *Viewer) GetFlow(_ context.Context, _ *trafficv1.GetFlowRequest) (*trafficv1.Flow, error) {
	return nil, status.Error(codes.Unimplemented, "GetFlow: pending Phase 1")
}

func (v *Viewer) StreamFlows(_ *trafficv1.StreamFlowsRequest, _ grpc.ServerStreamingServer[trafficv1.FlowEvent]) error {
	return status.Error(codes.Unimplemented, "StreamFlows: pending Phase 1")
}

func (v *Viewer) GetBody(_ *trafficv1.GetBodyRequest, _ grpc.ServerStreamingServer[trafficv1.BodyChunk]) error {
	return status.Error(codes.Unimplemented, "GetBody: pending Phase 1")
}

// Register attaches all implemented services to s.
func Register(s *grpc.Server, store objstore.Store) {
	trafficv1.RegisterViewerServiceServer(s, NewViewer(store))
}
