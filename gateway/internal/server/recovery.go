package server

// Panic recovery for the gRPC surface. The decode paths are hand-rolled wire parsers fed
// hostile-by-nature input (imported pcaps, pushed flows, bundles), and a panic in a
// handler goroutine is otherwise fatal to the whole process — grpc-go does not recover
// handler panics on its own, and this gateway hosts the store, every live capture and the
// MCP server in that same process. These interceptors turn a handler panic into an
// Internal error for the one call, logged with a stack, so one bad request cannot take the
// gateway down. Live decode runs in its own goroutine (not a handler) and is recovered at
// its own site in live.go.

import (
	"context"
	"log"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RecoveryUnaryInterceptor recovers a panic in a unary handler and returns it as Internal.
func RecoveryUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (resp any, err error) {
	defer recoverAsInternal(info.FullMethod, &err)
	return handler(ctx, req)
}

// RecoveryStreamInterceptor is RecoveryUnaryInterceptor for streaming handlers.
func RecoveryStreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo,
	handler grpc.StreamHandler) (err error) {
	defer recoverAsInternal(info.FullMethod, &err)
	return handler(srv, ss)
}

// recoverAsInternal must be deferred directly: recover only stops a panic when called by
// the deferred function itself.
func recoverAsInternal(method string, err *error) {
	if r := recover(); r != nil {
		log.Printf("panic in %s: %v\n%s", method, r, debug.Stack())
		*err = status.Errorf(codes.Internal, "internal error handling %s", method)
	}
}
