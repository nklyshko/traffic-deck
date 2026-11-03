// Command trafficdeck-web is the browser viewer's bridge: a stateless HTTP server that
// translates to the gateway's gRPC API and serves the embedded SPA. It is a client of the
// gateway like the TUI, and holds no data of its own (ADR-0018).
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
)

const (
	defaultGatewayAddr = "127.0.0.1:7331"
	defaultWebAddr     = "127.0.0.1:18890"
	// A flow can inline its bodies; matches the gateway's own receive limit.
	maxGRPCMessage = 256 << 20
	shutdownGrace  = 2 * time.Second
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	gatewayAddr := env("GATEWAY_ADDR", defaultGatewayAddr)
	webAddr := env("TRAFFICDECK_WEB_ADDR", defaultWebAddr)

	conn, err := grpc.NewClient(gatewayAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxGRPCMessage), grpc.MaxCallSendMsgSize(maxGRPCMessage)))
	if err != nil {
		log.Fatalf("gateway %s: %v", gatewayAddr, err)
	}
	defer conn.Close()

	// Bound before anything is announced, so a taken port is a fatal error rather than a
	// banner promising a URL that belongs to something else.
	lis, err := net.Listen("tcp", webAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", webAddr, err)
	}
	url := "http://" + lis.Addr().String()
	announce(os.Stdout, url, gatewayAddr)

	// A follow stream never ends on its own, so Shutdown alone would always run out its
	// deadline: cancelling the base context is what releases the SSE handlers.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge := newServer(backend{
		viewer:  trafficv1.NewViewerServiceClient(conn),
		control: trafficv1.NewControlServiceClient(conn),
		ingest:  trafficv1.NewIngestServiceClient(conn),
	}, lis.Addr().String())
	bridge.wireshark = newWiresharkLauncher(lis.Addr().String(), gatewayAddr)
	srv := &http.Server{
		Handler:           bridge.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sig
		signal.Reset(syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		cancel()
		sctx, done := context.WithTimeout(context.Background(), shutdownGrace)
		defer done()
		if err := srv.Shutdown(sctx); err != nil {
			_ = srv.Close()
		}
	}()

	if os.Getenv("TRAFFICDECK_WEB_OPEN") == "1" {
		go openWhenUp(url)
	}
	if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
}

// openWhenUp hands the URL to the OS once it answers; a browser opened sooner can race the
// server and show a connection error.
func openWhenUp(url string) {
	client := http.Client{Timeout: 100 * time.Millisecond}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if err := opener(url).Start(); err != nil {
			log.Printf("open browser: %v", err)
		}
		return
	}
	log.Printf("open browser: %s did not answer", url)
}

func opener(url string) *exec.Cmd {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url)
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	}
	return exec.Command("xdg-open", url)
}
