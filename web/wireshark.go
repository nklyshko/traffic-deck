package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
)

// Opening a flow in Wireshark is the one thing the bridge does that starts a program, so the
// endpoint takes nothing that shapes the command: the browser names a session and a flow,
// and the program, the files, the display filter and the frame all come from the bridge's
// own configuration and the gateway's records, validated and re-printed. The most a caller
// can achieve, whoever they are, is Wireshark opening on a flow already captured.
//
// The display filter matches the TUI's (tui/traffic_viewer/wireshark.py): the connection's
// address/port 4-tuple, not its connection id, which only matches tcp.stream on the tshark
// path; on HTTP/2 narrowed to the flow's stream plus the packets that carry no HTTP/2.

const (
	wiresharkCooldown   = 2 * time.Second
	wiresharkMaxRunning = 4
	// A header no form or simple request can set, so a cross-site post can't get here even
	// if the content-type gate were ever loosened.
	actionHeader = "X-TrafficDeck-Action"
)

// The gateway names sessions by UUID; flows by UUID or a decoder's own id. Neither reaches
// the command line, but the session id is checked against the artifact paths.
var recordIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type wiresharkLauncher struct {
	binary    string // absolute path; "" when Wireshark isn't installed
	local     bool   // the bridge listens on loopback and the gateway is reached on loopback
	hostname  string // this machine, to tell the gateway's paths are ours
	start     func(argv []string) (wait func(), err error)
	now       func() time.Time
	mu        sync.Mutex
	running   int
	lastStart map[string]time.Time
}

func newWiresharkLauncher(listenAddr, gatewayAddr string) *wiresharkLauncher {
	host, _ := os.Hostname()
	return &wiresharkLauncher{
		binary:    findWireshark(),
		local:     loopbackAddr(listenAddr) && loopbackAddr(gatewayAddr),
		hostname:  host,
		start:     startDetached,
		now:       time.Now,
		lastStart: map[string]time.Time{},
	}
}

func loopbackAddr(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && ip.IsLoopback()
}

// findWireshark resolves the program once, at startup: $TRAFFICDECK_WIRESHARK (a name on
// PATH or an absolute path), else `wireshark` on PATH, else the macOS app bundle.
func findWireshark() string {
	candidates := []string{"wireshark"}
	if runtime.GOOS == "darwin" {
		candidates = append(candidates, "/Applications/Wireshark.app/Contents/MacOS/Wireshark")
	}
	if v := strings.TrimSpace(os.Getenv("TRAFFICDECK_WIRESHARK")); v != "" {
		candidates = []string{v}
	}
	for _, c := range candidates {
		if strings.ContainsRune(c, filepath.Separator) && !filepath.IsAbs(c) {
			continue
		}
		p, err := exec.LookPath(c)
		if err != nil {
			continue
		}
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
	}
	return ""
}

type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return e.msg }

func failf(code int, format string, a ...any) error {
	return &httpError{code, fmt.Sprintf(format, a...)}
}

func (s *server) openInWireshark(w http.ResponseWriter, r *http.Request) {
	if err := s.launchWireshark(r); err != nil {
		var he *httpError
		if errors.As(err, &he) {
			http.Error(w, he.msg, he.code)
			return
		}
		rpcError(w, "open in Wireshark", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) launchWireshark(r *http.Request) error {
	if !contentTypeIs(r, "application/json") {
		return failf(http.StatusUnsupportedMediaType, "Content-Type must be application/json")
	}
	if r.Header.Get(actionHeader) != "wireshark" {
		return failf(http.StatusForbidden, "missing %s header", actionHeader)
	}
	// Host is already one of ours (guardHost); the page must come from that same origin.
	if r.Header.Get("Origin") != "http://"+r.Host {
		return failf(http.StatusForbidden, "request from another origin")
	}
	var req struct {
		SessionID string `json:"sessionId"`
		FlowID    string `json:"flowId"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return failf(http.StatusBadRequest, "unreadable request: %v", err)
	}
	// Decode stops after the first value; anything behind it is no more trusted than an unknown field.
	if _, err := dec.Token(); err != io.EOF {
		return failf(http.StatusBadRequest, "unreadable request: data after the JSON object")
	}
	if !recordIDRe.MatchString(req.SessionID) || !recordIDRe.MatchString(req.FlowID) {
		return failf(http.StatusBadRequest, "invalid session or flow id")
	}

	l := s.wireshark
	if l == nil || !l.local {
		return failf(http.StatusForbidden, "Wireshark opens only when the web viewer and the gateway both run on this machine, on loopback")
	}
	if l.binary == "" {
		return failf(http.StatusServiceUnavailable, "Wireshark not found: install it, or set TRAFFICDECK_WIRESHARK to its path, then restart the web viewer")
	}

	arts, err := s.control.GetSessionArtifacts(r.Context(), &trafficv1.GetSessionArtifactsRequest{SessionId: req.SessionID})
	if err != nil {
		return err
	}
	if arts.GetHostname() != l.hostname {
		return failf(http.StatusForbidden, "the session's files are on %s, not this machine", arts.GetHostname())
	}
	if arts.GetPcapPath() == "" {
		return failf(http.StatusConflict, "this session has no pcap: a proxy capture records flows, not packets")
	}
	pcap, err := sessionFile(arts.GetPcapPath(), req.SessionID, "capture.pcap")
	if err != nil {
		return err
	}
	keylog := ""
	if arts.GetKeylogPath() != "" {
		if keylog, err = sessionFile(arts.GetKeylogPath(), req.SessionID, "key.log"); err != nil {
			return err
		}
	}
	flow, err := s.viewer.GetFlow(r.Context(), &trafficv1.GetFlowRequest{SessionId: req.SessionID, FlowId: req.FlowID})
	if err != nil {
		return err
	}
	filter, err := displayFilter(flow)
	if err != nil {
		return err
	}
	return l.launch(req.SessionID+"/"+req.FlowID, wiresharkArgs(l.binary, pcap, keylog, filter, flow.GetFrameNumber()))
}

// sessionFile accepts only the layout the gateway's file store writes,
// <root>/sessions/<session id>/<name>, as an existing regular file (a symlink is refused),
// so a path the gateway reports can name nothing but that session's own capture.
func sessionFile(p, sessionID, name string) (string, error) {
	bad := func(why string) error {
		log.Printf("open in Wireshark: refusing %q: %s", p, why)
		return failf(http.StatusUnprocessableEntity, "the gateway reported an unexpected %s path", name)
	}
	if strings.IndexFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "", bad("control character")
	}
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return "", bad("not an absolute, clean path")
	}
	dir := filepath.Dir(p)
	if filepath.Base(p) != name || filepath.Base(dir) != sessionID || filepath.Base(filepath.Dir(dir)) != "sessions" {
		return "", bad("not sessions/<session>/" + name)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return "", bad(err.Error())
	}
	if !fi.Mode().IsRegular() {
		return "", bad("not a regular file")
	}
	return p, nil
}

// displayFilter isolates one flow, built only from values parsed and printed back here,
// never from the record's strings. "" when the flow records no addresses: Wireshark then
// opens the whole capture at the flow's frame.
func displayFilter(f *trafficv1.Flow) (string, error) {
	transport := "tcp"
	if strings.HasPrefix(f.GetProtocol(), "HTTP/3") || strings.HasPrefix(f.GetConnectionId(), "quic:") {
		transport = "udp"
	}
	var terms []string
	for _, a := range []string{f.GetSrcAddr(), f.GetDstAddr()} {
		host, port := splitAddr(a)
		if host != "" {
			ip, err := netip.ParseAddr(host)
			if err != nil || ip.Zone() != "" {
				return "", failf(http.StatusUnprocessableEntity, "flow address %q is not an IP address", a)
			}
			ip = ip.Unmap()
			field := "ipv6.addr"
			if ip.Is4() {
				field = "ip.addr"
			}
			terms = append(terms, field+" eq "+ip.String())
		}
		if port != "" {
			n, err := strconv.ParseUint(port, 10, 16)
			if err != nil || n == 0 {
				return "", failf(http.StatusUnprocessableEntity, "flow port %q is not a port", port)
			}
			terms = append(terms, transport+".port eq "+strconv.FormatUint(n, 10))
		}
	}
	conn := strings.Join(terms, " and ")
	if conn == "" {
		return "", nil
	}
	// An empty stream id is a flow that doesn't know its stream (mitmproxy pushes none), and
	// its connection is still the right view. A non-number means the source wrote nonsense,
	// which a quietly wider filter would hide.
	if sid := f.GetStreamId(); strings.HasPrefix(f.GetProtocol(), "HTTP/2") && sid != "" {
		n, err := strconv.ParseUint(sid, 10, 31)
		if err != nil {
			return "", failf(http.StatusUnprocessableEntity, "flow stream id %q is not an HTTP/2 stream id", sid)
		}
		return conn + " and (http2.streamid eq " + strconv.FormatUint(n, 10) + " or not http2)", nil
	}
	return conn, nil
}

// splitAddr reads the three shapes the decoders write: "1.2.3.4:443", "[2606::1]:443", and
// the PDML path's bare "2606::1:443", whose last numeric group is the port unless taking
// it would leave a dangling "::".
func splitAddr(a string) (host, port string) {
	a = strings.TrimSpace(a)
	if a == "" {
		return "", ""
	}
	if strings.HasPrefix(a, "[") {
		h, rest, ok := strings.Cut(a[1:], "]")
		if !ok {
			return a, ""
		}
		return h, strings.TrimPrefix(rest, ":")
	}
	i := strings.LastIndexByte(a, ':')
	if i <= 0 || !isDigits(a[i+1:]) || strings.HasSuffix(a[:i], ":") {
		return a, ""
	}
	return a[:i], a[i+1:]
}

func isDigits(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

func wiresharkArgs(binary, pcap, keylog, filter string, frame uint64) []string {
	argv := []string{binary, "-r", pcap}
	if keylog != "" {
		argv = append(argv, "-o", "tls.keylog_file:"+keylog)
	}
	if filter != "" {
		argv = append(argv, "-Y", filter)
	}
	if frame > 0 {
		argv = append(argv, "-g", strconv.FormatUint(frame, 10))
	}
	return argv
}

// launch starts Wireshark without a shell, refusing a repeat of the same flow within the
// cooldown and more than a few windows at once.
func (l *wiresharkLauncher) launch(key string, argv []string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if t, ok := l.lastStart[key]; ok && now.Sub(t) < wiresharkCooldown {
		return failf(http.StatusTooManyRequests, "Wireshark is already opening this flow")
	}
	if l.running >= wiresharkMaxRunning {
		return failf(http.StatusTooManyRequests, "%d Wireshark windows are already open from here; close one first", l.running)
	}
	wait, err := l.start(argv)
	if err != nil {
		return failf(http.StatusInternalServerError, "start Wireshark: %v", err)
	}
	l.lastStart[key] = now
	for k, t := range l.lastStart {
		if now.Sub(t) >= wiresharkCooldown {
			delete(l.lastStart, k)
		}
	}
	l.running++
	go func() {
		wait()
		l.mu.Lock()
		l.running--
		l.mu.Unlock()
	}()
	log.Printf("open in Wireshark: %s", key)
	return nil
}

func startDetached(argv []string) (func(), error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	detach(cmd) // its own session: Ctrl-C on the web viewer leaves Wireshark open
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() { _ = cmd.Wait() }, nil
}
