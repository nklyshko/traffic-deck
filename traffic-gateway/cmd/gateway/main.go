// Command gateway is the traffic-gateway entry point.
//
//	gateway serve                                      run the gRPC server
//	gateway import --pcap f [--keylog f] [--label s]   import a capture (Phase 1)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	"github.com/nikitak/parsing/traffic-gateway/internal/config"
	"github.com/nikitak/parsing/traffic-gateway/internal/importer"
	"github.com/nikitak/parsing/traffic-gateway/internal/objstore"
	"github.com/nikitak/parsing/traffic-gateway/internal/server"
	"github.com/nikitak/parsing/traffic-gateway/internal/store"
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

// openDeps opens the object store (session bundles) and the SQLite store.
func openDeps(ctx context.Context, cfg config.Config) (objstore.Store, *store.Store) {
	obj, err := objstore.NewFSStore(cfg.DataRoot)
	if err != nil {
		log.Fatalf("objstore: %v", err)
	}
	st, err := store.Open(ctx, cfg.DataRoot)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	return obj, st
}

func serve() {
	ctx := context.Background()
	cfg := config.Load()
	obj, st := openDeps(ctx, cfg)
	defer st.Close()

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.GRPCAddr, err)
	}
	s := grpc.NewServer()
	server.Register(s, st, obj, cfg.TsharkPath)
	log.Printf("traffic-gateway listening on %s", cfg.GRPCAddr)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func importCapture(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	pcap := fs.String("pcap", "", "path to capture .pcap")
	keylog := fs.String("keylog", "", "path to NSS key.log (optional)")
	label := fs.String("label", "", "session label")
	_ = fs.Parse(args)
	if *pcap == "" {
		log.Fatal("import: --pcap is required")
	}

	ctx := context.Background()
	cfg := config.Load()
	obj, st := openDeps(ctx, cfg)
	defer st.Close()

	res, err := importer.Import(ctx, st, obj, importer.Options{
		PcapPath:   *pcap,
		KeylogPath: *keylog,
		Label:      *label,
		TsharkPath: cfg.TsharkPath,
	})
	if err != nil {
		log.Fatalf("import: %v", err)
	}
	log.Printf("imported session %s: %d flows", res.SessionID, res.FlowCount)
}
