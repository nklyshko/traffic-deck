// Command gateway is the traffic-gateway entry point.
//
//	gateway serve                              run the gRPC server
//	gateway import --pcap f --keylog f --label s   import a capture (Phase 1, stub)
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	"github.com/nikitak/parsing/traffic-gateway/internal/config"
	"github.com/nikitak/parsing/traffic-gateway/internal/objstore"
	"github.com/nikitak/parsing/traffic-gateway/internal/server"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		serve()
	case "import":
		importCapture(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gateway <serve|import> [flags]")
	os.Exit(2)
}

func serve() {
	cfg := config.Load()
	store, err := objstore.NewFSStore(cfg.ObjStoreRoot)
	if err != nil {
		log.Fatalf("objstore: %v", err)
	}
	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.GRPCAddr, err)
	}
	s := grpc.NewServer()
	server.Register(s, store)
	log.Printf("traffic-gateway listening on %s (objstore=%s)", cfg.GRPCAddr, store.Root)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// importCapture is a Phase 1 stub: batch-decode an existing pcap + key.log.
func importCapture(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	pcap := fs.String("pcap", "", "path to capture .pcap")
	keylog := fs.String("keylog", "", "path to NSS key.log")
	label := fs.String("label", "", "session label")
	_ = fs.Parse(args)
	if *pcap == "" {
		log.Fatal("import: --pcap is required")
	}
	log.Printf("import: pcap=%s keylog=%s label=%q — not yet implemented (Phase 1)", *pcap, *keylog, *label)
	os.Exit(1)
}
