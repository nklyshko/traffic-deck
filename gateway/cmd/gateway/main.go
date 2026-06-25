// Command gateway is the TrafficDeck gateway entry point.
//
//	gateway serve                                      run the gRPC server
//	gateway import --pcap f [--keylog f] [--label s]   import a capture
//	gateway export <session-id> [-o file.tar.gz]       export a session bundle
//	gateway import-session <file> [--new-id] [--label s] import a session bundle
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path"

	"google.golang.org/grpc"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/bundle"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/config"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/importer"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/objstore"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/server"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"

	// Custom protocol decoders self-register via init(). Add a blank import
	// here to compile a decoder into the gateway.
	_ "gitlab.com/nklyshko/traffic-deck/gateway/decoders/max"
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
	case "redecode":
		redecode(os.Args[2:])
	case "export":
		exportSession(os.Args[2:])
	case "import-session":
		importSession(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gateway <serve|import|redecode|export|import-session> [flags]")
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
	server.Register(s, st, obj, cfg.TsharkPath, cfg.LiveDecode)
	log.Printf("gateway listening on %s (live decode: %v)", cfg.GRPCAddr, cfg.LiveDecode)
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

// redecode re-runs the custom (non-HTTP) decoders over an already-captured session's
// stored pcap + key.log and inserts the decoded protocol flows (e.g. MAX).
func redecode(args []string) {
	fs := flag.NewFlagSet("redecode", flag.ExitOnError)
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		log.Fatal("usage: gateway redecode <session-id>")
	}
	sid := fs.Arg(0)

	ctx := context.Background()
	cfg := config.Load()
	obj, st := openDeps(ctx, cfg)
	defer st.Close()

	pcapLocal, ok := obj.LocalPath(path.Join("sessions", sid, "capture.pcap"))
	if !ok {
		log.Fatalf("redecode: no capture.pcap for session %s", sid)
	}
	keylogLocal := ""
	if p, ok := obj.LocalPath(path.Join("sessions", sid, "key.log")); ok {
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			keylogLocal = p
		}
	}

	n, err := importer.RedecodeCustom(ctx, st, cfg.TsharkPath, sid, pcapLocal, keylogLocal)
	if err != nil {
		log.Fatalf("redecode: %v", err)
	}
	log.Printf("redecoded session %s: %d custom-protocol flows", sid, n)
}

// parsePositionalFlags parses a subcommand that takes one leading positional arg
// plus flags, tolerating either order (`export <id> -o f` or `export -o f <id>`).
// Go's flag package stops at the first non-flag arg, so we parse, take the positional,
// then parse the remaining flags. Returns the positional and ok=false if absent.
func parsePositionalFlags(fs *flag.FlagSet, args []string) (string, bool) {
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		return "", false
	}
	pos := rest[0]
	_ = fs.Parse(rest[1:])
	return pos, true
}

// exportSession writes a session bundle (catalog row + flows.sqlite + pcap/key.log +
// blobs) to a self-contained .tar.gz.
func exportSession(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	out := fs.String("o", "", "output file (default: <session-id>.tar.gz)")
	sid, ok := parsePositionalFlags(fs, args)
	if !ok {
		log.Fatal("usage: gateway export <session-id> [-o file.tar.gz]")
	}
	dest := *out
	if dest == "" {
		dest = sid + ".tar.gz"
	}

	ctx := context.Background()
	cfg := config.Load()
	_, st := openDeps(ctx, cfg)
	defer st.Close()

	f, err := os.Create(dest)
	if err != nil {
		log.Fatalf("export: %v", err)
	}
	defer f.Close()
	if err := bundle.Export(ctx, st, cfg.DataRoot, sid, f); err != nil {
		os.Remove(dest)
		log.Fatalf("export: %v", err)
	}
	log.Printf("exported session %s -> %s", sid, dest)
}

// importSession registers a session bundle (.tar.gz) into this gateway's data root +
// catalog. --new-id imports a copy under a fresh id when the original
// collides; --label overrides the bundle's label.
func importSession(args []string) {
	fs := flag.NewFlagSet("import-session", flag.ExitOnError)
	newID := fs.Bool("new-id", false, "assign a fresh session id (import a copy)")
	label := fs.String("label", "", "override the session label")
	src, ok := parsePositionalFlags(fs, args)
	if !ok {
		log.Fatal("usage: gateway import-session <file.tar.gz> [--new-id] [--label s]")
	}

	ctx := context.Background()
	cfg := config.Load()
	_, st := openDeps(ctx, cfg)
	defer st.Close()

	f, err := os.Open(src)
	if err != nil {
		log.Fatalf("import-session: %v", err)
	}
	defer f.Close()
	id, err := bundle.Import(ctx, st, cfg.DataRoot, f, bundle.ImportOptions{NewID: *newID, Label: *label})
	if err != nil {
		log.Fatalf("import-session: %v", err)
	}
	log.Printf("imported session %s from %s", id, src)
}
