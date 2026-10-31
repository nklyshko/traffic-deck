package server

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAHandlerPanicBecomesAnInternalErrorForThatCall(t *testing.T) {
	_, err := RecoveryUnaryInterceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/t/Unary"},
		func(context.Context, any) (any, error) { panic("boom") })
	if status.Code(err) != codes.Internal {
		t.Fatalf("unary: got %v, want Internal", err)
	}

	err = RecoveryStreamInterceptor(nil, nil, &grpc.StreamServerInfo{FullMethod: "/t/Stream"},
		func(any, grpc.ServerStream) error { panic("boom") })
	if status.Code(err) != codes.Internal {
		t.Fatalf("stream: got %v, want Internal", err)
	}
}
