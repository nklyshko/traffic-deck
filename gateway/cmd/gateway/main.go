// Command gateway is the TrafficDeck gateway entry point.
//
//	gateway serve                                      run the gRPC server
//	gateway import --pcap f [--keylog f] [--label s] [--decoder tshark|native]  import a capture
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
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"

	"google.golang.org/grpc"

	"gitlab.com/nklyshko/traffic-deck/gateway/internal/bundle"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/config"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/importer"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/logging"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/objstore"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/server"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/sourcemgr"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsfp"

	// Custom protocol decoders self-register via init(). Add a blank import
	// here to compile a decoder into the gateway.
	_ "gitlab.com/nklyshko/traffic-deck/gateway/decoders/max"
)

func main() {
	if len(os.Args) < 2 {
		runFused() // no args: gateway in-process + the TUI in the foreground (ADR-0010)
		return
	}
	switch os.Args[1] {
	case "run":
		runFused()
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
	fmt.Fprintln(os.Stderr, "usage: trafficdeck [run|serve|import|redecode|export|import-session] [flags]")
	fmt.Fprintln(os.Stderr, "  (no command)  run the gateway and the TUI together")
	os.Exit(2)
}

// openDeps opens the object store (session bundles) and the SQLite store.
// configureFingerprints points the TLS-fingerprint classifier at the user's directory
// (default ~/.traffic-deck/fingerprints) on top of the compiled-in builtin set, and
// routes load errors (malformed rows/files) to the gateway log instead of failing.
func configureFingerprints(cfg config.Config) {
	tlsfp.LogErrors = func(errs []error) {
		for _, err := range errs {
			log.Printf("tlsfp: %v", err)
		}
	}
	tlsfp.Configure(cfg.FingerprintsDir)
	if cfg.FingerprintsDir != "" {
		log.Printf("TLS fingerprints: builtin + %s", cfg.FingerprintsDir)
	}
}

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
	logging.Setup(cfg) // tee logs to stderr + a rolling file (default on)
	configureFingerprints(cfg)
	obj, st := openDeps(ctx, cfg)
	defer st.Close()

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.GRPCAddr, err)
	}
	// Pushed flows (mitmproxy) inline full bodies; a large download can far exceed gRPC's
	// 4 MiB default, so raise the receive limit to avoid dropping those flows.
	s := grpc.NewServer(grpc.MaxRecvMsgSize(256 << 20))
	mgr, svcs := server.Register(s, st, obj, cfg.TsharkPath, cfg.GRPCAddr, cfg.LiveDecode, cfg.RecordLive, cfg.TsharkVerify)
	if cfg.StartMCP {
		if _, err := svcs.Start("mcp"); err != nil {
			log.Printf("auto-start mcp: %v", err)
		}
	}
	// Reap spawned capture-source and service processes (and their groups) on shutdown, so a
	// browser, emulator, or MCP server they started doesn't linger after the gateway stops.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("shutting down: reaping capture sources and services")
		mgr.Close()
		svcs.Close()
		s.GracefulStop()
	}()
	log.Printf("gateway listening on %s (live decode: %v, record live: %v, tshark verify: %v)",
		cfg.GRPCAddr, cfg.LiveDecode, cfg.RecordLive, cfg.TsharkVerify)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// runFused is the one-command mode: start the gateway in-process and run the TUI in the
// foreground, so `trafficdeck` alone brings the whole thing up. When the viewer exits the
// gateway is shut down cleanly (capture sources reaped). If the gateway address is already
// in use we assume one is running and just attach the viewer to it. See ADR-0010.
func runFused() {
	ctx := context.Background()
	cfg := config.Load()
	logging.Setup(cfg)
	configureFingerprints(cfg)

	tuiDir := findTUIDir()
	if tuiDir == "" {
		log.Fatal("cannot locate the tui/ directory; run `trafficdeck serve` and the TUI separately")
	}
	if _, err := exec.LookPath("uv"); err != nil {
		log.Fatal("`uv` is required to run the TUI; install it or run the TUI yourself against `trafficdeck serve`")
	}

	// Past the preflight the terminal is the viewer's: send our logs and every child's
	// output to the log file alone, or they overwrite the top of the TUI.
	logging.SetupFused(cfg)

	var s *grpc.Server
	var mgr *sourcemgr.Manager
	var svcs *sourcemgr.Services
	var stClose func()
	if lis, err := net.Listen("tcp", cfg.GRPCAddr); err != nil {
		log.Printf("gateway address %s already in use — attaching the viewer to the running gateway", cfg.GRPCAddr)
	} else {
		obj, st := openDeps(ctx, cfg)
		stClose = st.Close
		s = grpc.NewServer(grpc.MaxRecvMsgSize(256 << 20))
		mgr, svcs = server.Register(s, st, obj, cfg.TsharkPath, cfg.GRPCAddr, cfg.LiveDecode, cfg.RecordLive, cfg.TsharkVerify)
		if cfg.StartMCP {
			if _, err := svcs.Start("mcp"); err != nil {
				log.Printf("auto-start mcp: %v", err)
			}
		}
		go func() { _ = s.Serve(lis) }()
		log.Printf("gateway listening on %s (live decode: %v, record live: %v)",
			cfg.GRPCAddr, cfg.LiveDecode, cfg.RecordLive)
	}

	// The viewer runs in the foreground, inheriting the terminal.
	cmd := exec.Command("uv", "run", "--directory", tuiDir, "python", "-m", "traffic_viewer.app")
	cmd.Env = append(os.Environ(), "GATEWAY_ADDR="+cfg.GRPCAddr)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	runErr := cmd.Run()
	logging.Setup(cfg) // viewer's gone, the terminal is ours again — teardown errors must show

	// Viewer exited → tear the gateway down (reap capture sources + services, close store).
	if mgr != nil {
		mgr.Close()
	}
	if svcs != nil {
		svcs.Close()
	}
	if s != nil {
		s.GracefulStop()
	}
	if stClose != nil {
		stClose()
	}
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		log.Fatalf("run viewer: %v", runErr)
	}
}

// findTUIDir locates the repo's tui/ directory (holding traffic_viewer/app.py) by walking
// up from the working directory, then the executable's directory. Returns "" if not found.
func findTUIDir() string {
	var starts []string
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	if exe, err := os.Executable(); err == nil {
		starts = append(starts, filepath.Dir(exe))
	}
	for _, start := range starts {
		for dir := start; ; {
			cand := filepath.Join(dir, "tui", "traffic_viewer", "app.py")
			if _, err := os.Stat(cand); err == nil {
				return filepath.Join(dir, "tui")
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return ""
}

func importCapture(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	pcap := fs.String("pcap", "", "path to capture .pcap")
	keylog := fs.String("keylog", "", "path to NSS key.log (optional)")
	label := fs.String("label", "", "session label")
	decoder := fs.String("decoder", decode.EngineTshark, "batch decoder: tshark | native (in-process Go, no tshark)")
	_ = fs.Parse(args)
	if *pcap == "" {
		log.Fatal("import: --pcap is required")
	}
	if *decoder != decode.EngineTshark && *decoder != decode.EngineNative {
		log.Fatalf("import: --decoder must be %q or %q", decode.EngineTshark, decode.EngineNative)
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
		Engine:     *decoder,
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
