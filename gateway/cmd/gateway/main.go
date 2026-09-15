// Command gateway is the TrafficDeck gateway entry point.
//
//	gateway serve                                      run the gRPC server
//	gateway import --pcap f [--keylog f] [--label s] [--decoder tshark|native]  import a capture
//	gateway export <session-id> [-o file.tar.gz]       export a session bundle
//	gateway import-session <file> [--new-id] [--label s] import a session bundle
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

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

// shutdownTimeout bounds the whole teardown. Quitting the viewer must not be able to hang
// on something that will not finish; past this, what is left is forced.
const shutdownTimeout = 3 * time.Minute

// shutdownStep runs one teardown step, narrating it: what is starting, a tick while it is
// still going, and how long it took. Reports whether it finished before the deadline.
//
// The narration is the point as much as the bound. Teardown can legitimately take a while
// — a capture source closing its session, a batch decode on close — and in silence that is
// indistinguishable from a hang, which is what it looked like.
func shutdownStep(name string, deadline time.Time, fn func()) bool {
	if time.Now().After(deadline) {
		log.Printf("shutdown: skipping %s — out of time", name)
		return false
	}
	log.Printf("shutdown: %s…", name)
	start := time.Now()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	timeout := time.NewTimer(time.Until(deadline))
	defer timeout.Stop()
	for {
		select {
		case <-done:
			log.Printf("shutdown: %s done in %s", name, time.Since(start).Round(time.Millisecond))
			return true
		case <-tick.C:
			log.Printf("shutdown: still %s — %s elapsed, %s left before giving up",
				name, time.Since(start).Round(time.Second), time.Until(deadline).Round(time.Second))
		case <-timeout.C:
			log.Printf("shutdown: %s did not finish in time; moving on", name)
			return false
		}
	}
}

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
	fmt.Fprintln(os.Stderr, "                (GATEWAY_VIEWER=tui|<module>|<command>|none picks the foreground viewer)")
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

// startMCP brings the MCP server up at launch (GATEWAY_MCP, on by default) so an agent
// client can attach without anyone toggling it in the TUI first. Not having it installed is
// not a failure — DefaultServices omits a service it can't locate — so that case says what's
// missing and how to turn the attempt off, rather than logging an error every launch.
func startMCP(cfg config.Config, svcs *sourcemgr.Services) {
	if !cfg.StartMCP {
		return
	}
	_, err := svcs.Start("mcp")
	switch {
	case errors.Is(err, sourcemgr.ErrServiceNotFound):
		log.Print("MCP server not started: no launcher found (needs `uv` with the repo's mcp/ dir, " +
			"a trafficdeck-mcp on PATH, or TRAFFICDECK_SERVICE_MCP); set GATEWAY_MCP=off to skip this")
	case err != nil:
		log.Printf("auto-start mcp: %v", err)
	}
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
	startMCP(cfg, svcs)
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

// runFused is the one-command mode: start the gateway in-process and run the viewer in the
// foreground, so `trafficdeck` alone brings the whole thing up. When the viewer exits the
// gateway is shut down cleanly (capture sources reaped). If the gateway address is already
// in use we assume one is running and just attach the viewer to it. See ADR-0010.
//
// Which viewer is GATEWAY_VIEWER (see resolveViewer). With no foreground viewer the gateway
// stays up on its own and Ctrl-C ends it — everything else about the run is identical.
func runFused() {
	ctx := context.Background()
	cfg := config.Load()
	logging.Setup(cfg)
	configureFingerprints(cfg)

	v, err := resolveViewer(cfg.Viewer)
	if err != nil {
		log.Fatal(err)
	}
	if v != nil && v.screen {
		// A full-screen viewer owns the terminal: send our logs and every child's output to
		// the log file alone, or they overwrite the top of it. A viewer that only prints
		// lines — and no viewer at all — shares the terminal with us.
		logging.SetupFused(cfg)
	}

	var s *grpc.Server
	var mgr *sourcemgr.Manager
	var svcs *sourcemgr.Services
	var stClose func()
	if lis, err := net.Listen("tcp", cfg.GRPCAddr); err != nil {
		if v == nil {
			// Nothing to attach and nothing to tear down: the running gateway already
			// launched whatever serves the UI. Blocking on a signal here would do nothing.
			log.Printf("gateway address %s already in use — the running gateway already has the viewer", cfg.GRPCAddr)
			return
		}
		log.Printf("gateway address %s already in use — attaching the viewer to the running gateway", cfg.GRPCAddr)
	} else {
		obj, st := openDeps(ctx, cfg)
		stClose = st.Close
		s = grpc.NewServer(grpc.MaxRecvMsgSize(256 << 20))
		mgr, svcs = server.Register(s, st, obj, cfg.TsharkPath, cfg.GRPCAddr, cfg.LiveDecode, cfg.RecordLive, cfg.TsharkVerify)
		startMCP(cfg, svcs)
		go func() { _ = s.Serve(lis) }()
		log.Printf("gateway listening on %s (live decode: %v, record live: %v)",
			cfg.GRPCAddr, cfg.LiveDecode, cfg.RecordLive)
		if v == nil {
			warnNoViewer(svcs.List())
		}
	}

	var runErr error
	if v == nil {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		log.Printf("no foreground viewer (GATEWAY_VIEWER=%s) — Ctrl-C to stop", cfg.Viewer)
		<-sig
	} else {
		// The viewer runs in the foreground, inheriting the terminal. A module viewer also
		// gets the cwd and env its manifest declares, same as when it runs as a service.
		if v.url != "" {
			log.Printf("viewer %s — open %s", v.label, v.url)
		}
		cmd := exec.Command(v.argv[0], v.argv[1:]...)
		cmd.Dir = v.cwd
		cmd.Env = append(os.Environ(), "GATEWAY_ADDR="+cfg.GRPCAddr)
		for k, val := range v.env {
			cmd.Env = append(cmd.Env, k+"="+val)
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		runErr = cmd.Run()
		if v.screen {
			logging.Setup(cfg) // viewer's gone, the terminal is ours again — teardown errors must show
		}
	}

	// Viewer exited → tear the gateway down (reap capture sources + services, close store).
	// Narrated and bounded: the terminal is ours again but nothing here used to print, so a
	// slow teardown looked identical to a hang.
	deadline := time.Now().Add(shutdownTimeout)
	log.Printf("shutting down (up to %s)…", shutdownTimeout)
	if mgr != nil {
		shutdownStep("stopping capture sources", deadline, mgr.Close)
	}
	if svcs != nil {
		shutdownStep("stopping services", deadline, svcs.Close)
	}
	if s != nil {
		// GracefulStop waits for every in-flight RPC, and a follow stream never returns on
		// its own — so without a bound, one reader that will not let go hangs the exit.
		if !shutdownStep("closing client connections", deadline, s.GracefulStop) {
			log.Printf("shutdown: forcing connections closed")
			s.Stop()
		}
	}
	if stClose != nil {
		shutdownStep("closing the store", deadline, stClose)
	}
	log.Printf("shutdown complete")
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		log.Fatalf("run viewer: %v", runErr)
	}
}

// viewer is the foreground viewer one-command mode runs: the built-in TUI, a module process
// marked `viewer = true`, or a bare command. Screen means it paints the terminal, so the
// gateway must stop writing there while it runs.
type viewer struct {
	label  string
	argv   []string
	cwd    string
	env    map[string]string
	url    string
	screen bool
}

// resolveViewer turns GATEWAY_VIEWER into the viewer to run, or nil for "no foreground
// viewer — keep the gateway up until Ctrl-C".
//
//	tui                 the built-in TUI (default)
//	<module>[:<process>] a module's `viewer = true` process (docs/modules.md); the manifest
//	                    carries its command, cwd, env, url and whether it owns the screen
//	<command>           run this, e.g. `myviewer --flag`; assumed to own the screen
//	none                nothing: the gateway stays up and a module (or you) serves the UI
func resolveViewer(name string) (*viewer, error) {
	switch {
	case strings.EqualFold(name, "none"):
		return nil, nil
	case strings.EqualFold(name, "tui"):
		tuiDir := findTUIDir()
		if tuiDir == "" {
			return nil, errors.New("cannot locate the tui/ directory; run `trafficdeck serve` and the TUI separately")
		}
		if _, err := exec.LookPath("uv"); err != nil {
			return nil, errors.New("`uv` is required to run the TUI; install it or run the TUI yourself against `trafficdeck serve`")
		}
		return &viewer{
			label:  "tui",
			argv:   []string{"uv", "run", "--directory", tuiDir, "python", "-m", "traffic_viewer.app"},
			screen: true,
		}, nil
	}

	viewers := sourcemgr.Viewers(sourcemgr.PluginsDir())
	spec, found, err := sourcemgr.SelectViewer(viewers, name)
	if err != nil {
		return nil, err
	}
	if found {
		return &viewer{
			label: spec.Key(), argv: spec.Argv, cwd: spec.Cwd, env: spec.Env,
			url: spec.URL, screen: spec.Screen,
		}, nil
	}

	// Not a module viewer: a command line. ponytail: split on spaces like
	// TRAFFICDECK_SERVICE_MCP, no shell quoting — a path with a space needs a wrapper
	// script until someone actually hits that.
	argv := strings.Fields(name)
	if len(argv) == 0 {
		return nil, fmt.Errorf("GATEWAY_VIEWER=%q is empty: %s", name, viewerChoices(viewers))
	}
	if _, err := exec.LookPath(argv[0]); err != nil {
		return nil, fmt.Errorf("GATEWAY_VIEWER=%q: %w — %s", name, err, viewerChoices(viewers))
	}
	// A bare command gets the screen: assuming it doesn't would scribble the gateway's log
	// over a full-screen viewer, while the reverse only sends our own logs to the file.
	return &viewer{label: argv[0], argv: argv, screen: true}, nil
}

// viewerChoices names what GATEWAY_VIEWER accepts here, installed modules included — the
// answer to a typo is the list, not just "not found".
func viewerChoices(viewers []sourcemgr.ViewerSpec) string {
	choices := []string{`"tui"`, `"none"`, "a command to run"}
	for _, v := range viewers {
		choices = append(choices, strconv.Quote(v.Key()))
	}
	return "use " + strings.Join(choices, ", ")
}

// warnNoViewer says so when nothing at all is serving a UI: with no foreground viewer the
// gateway would otherwise sit there looking like it worked. Auto-start is the only thing
// that knows what a module brought up, and a module's service name isn't ours to hardcode,
// so the check is "did anything besides our own MCP server come up". Not fatal — a gateway
// with no viewer is still worth having (`trafficdeck serve` is exactly that).
func warnNoViewer(services []sourcemgr.ServiceInfo) {
	for _, svc := range services {
		if svc.Running && svc.Name != "mcp" {
			return
		}
	}
	log.Print("no foreground viewer and no module process is running — nothing is serving a UI. " +
		"A module enrolls by dropping its manifest in ~/.traffic-deck/plugins/ (see docs/modules.md); " +
		"otherwise attach a viewer to this gateway yourself.")
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
	engine := fs.String("engine", decode.EngineNative,
		"decode engine: native (in-process Go, as the live capture path) | tshark")
	sid, ok := parsePositionalFlags(fs, args)
	if !ok {
		log.Fatal("usage: gateway redecode <session-id> [-engine native|tshark]")
	}
	if *engine != decode.EngineTshark && *engine != decode.EngineNative {
		log.Fatalf("redecode: -engine must be %q or %q", decode.EngineNative, decode.EngineTshark)
	}

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

	n, err := importer.RedecodeCustom(ctx, st, *engine, cfg.TsharkPath, sid, pcapLocal, keylogLocal)
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

// logOutput/setLogOutput exist so the shutdown narration can be asserted in tests; the
// standard logger has no getter.
var currentLogOutput io.Writer = os.Stderr

func logOutput() io.Writer { return currentLogOutput }

func setLogOutput(w io.Writer) {
	currentLogOutput = w
	log.SetOutput(w)
}
