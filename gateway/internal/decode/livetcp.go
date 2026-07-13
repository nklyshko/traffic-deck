package decode

// Live decoding, fully in-process in Go and authoritative by default. Instead of
// re-running `tshark -z follow,tls,raw` over the growing capture, we tap the same live
// pcap byte stream, reassemble TCP with gopacket, decrypt TLS from the key-log
// (internal/tlsdecrypt: SSL 3.0 – TLS 1.3), and feed each connection's decrypted
// application bytes to its HTTP/WebSocket parser or to a decoder's stateful Session —
// emitting flows and frames through the onFlow/onMsg callbacks.
//
// A connection this decoder can't handle (an unsupported version/suite or link type, or
// one whose key-log secret never arrived) is only recoverable by the batch tshark pass,
// which runs on close just when the live decode isn't authoritative — see skippedFate.

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	gplayers "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/reassembly"
	"github.com/google/uuid"

	"gitlab.com/nklyshko/traffic-deck/gateway/decoders"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/quicdecrypt"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

// linkTypeNFLOG is LINKTYPE_NFLOG (239), used by the Android per-app capture
// (`tcpdump -i nflog:<group>`). gopacket has no decoder for it, so we extract the
// inner IP packet ourselves (nflogIPPayload).
const linkTypeNFLOG = gplayers.LinkType(239)

// LiveTCPDecode reads a live pcap byte stream from r, reassembles TCP, decrypts TLS
// using the (growing) key-log at keylogPath, and emits decoded flows and frames via
// onFlow/onMsg. Returns when r reaches EOF (the capture's pipe is closed).
//
// recordLive tells the decoder whether it is the authoritative decode (the caller's
// GATEWAY_RECORD_LIVE): it changes no decoding, only what the diagnostics say becomes of
// a connection this decoder skips — nothing else will decode it when authoritative.
func LiveTCPDecode(r io.Reader, keylogPath string, onFlow func(*Flow, bool), onMsg func(*WsMessage),
	recordLive bool) error {
	reader, err := pcapgo.NewReader(r)
	if err != nil {
		return err // includes EOF if the session sent no pcap
	}
	if onMsg == nil {
		onMsg = func(*WsMessage) {} // the WebSocket/custom paths call it unconditionally
	}
	lt := &liveTCP{
		keylog:     tlsdecrypt.NewKeylog(keylogPath),
		onFlow:     onFlow,
		onMsg:      onMsg,
		quic:       map[string]*quicConnState{},
		recordLive: recordLive,
	}
	asm := reassembly.NewAssembler(reassembly.NewStreamPool(lt))
	linkType := reader.LinkType()
	for {
		data, _, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // truncated trailing packet while the file grows — skip, keep going
		}
		var pkt gopacket.Packet
		if linkType == linkTypeNFLOG {
			ipType, ip, ok := nflogIPPayload(data)
			if !ok {
				continue
			}
			pkt = gopacket.NewPacket(ip, ipType, gopacket.Lazy)
		} else {
			pkt = gopacket.NewPacket(data, linkType, gopacket.Lazy)
		}
		netLayer := pkt.NetworkLayer()
		if netLayer == nil {
			continue
		}
		if tcpLayer := pkt.Layer(gplayers.LayerTypeTCP); tcpLayer != nil {
			asm.Assemble(netLayer.NetworkFlow(), tcpLayer.(*gplayers.TCP))
		} else if udpLayer := pkt.Layer(gplayers.LayerTypeUDP); udpLayer != nil {
			lt.handleUDP(netLayer.NetworkFlow(), udpLayer.(*gplayers.UDP))
		}
	}
	asm.FlushAll() // TCP only: closes each tcpStream via ReassemblyComplete
	for _, st := range lt.quic {
		st.sess.close() // QUIC has no assembler to flush it, so end each connection here
	}
	return nil
}

// liveTCP is the gopacket StreamFactory: shared key-log + sinks for all connections.
type liveTCP struct {
	keylog *tlsdecrypt.Keylog
	onFlow func(*Flow, bool)
	onMsg  func(*WsMessage)
	quic   map[string]*quicConnState // QUIC connections keyed by canonical UDP 4-tuple

	// recordLive: this decode is authoritative and no batch pass will run on close, so a
	// connection skipped here is simply absent from the session. Diagnostics only.
	recordLive bool

	// Connection counter handed out by connID, in first-seen order. Needs no lock: New
	// and handleUDP both run on the single packet loop in LiveTCPDecode (as the unlocked
	// quic map above already assumes).
	nextConn int
}

// skippedFate describes what actually becomes of a connection the live decoder can't
// handle, so the diagnostic doesn't promise a recovery that won't happen. Only a
// non-record-live close runs the authoritative batch tshark pass; the extra decode
// GATEWAY_VERIFY_LIVE does under record-live is diagnostic and never persisted.
func (f *liveTCP) skippedFate() string {
	if f.recordLive {
		return "dropped from the session (live decode is authoritative; " +
			"set GATEWAY_RECORD_LIVE=off to batch-decode on close instead)"
	}
	return "left to the authoritative batch tshark pass on close"
}

// partialFate is skippedFate for a loss *inside* a connection that is otherwise decoding
// — an HTTP/3 QPACK failure costs individual requests, not the whole connection, so
// skippedFate's wording would overstate it.
func (f *liveTCP) partialFate() string {
	if f.recordLive {
		return "the affected requests are missing from the session (live decode is " +
			"authoritative; set GATEWAY_RECORD_LIVE=off to batch-decode on close instead)"
	}
	return "the affected requests come from the authoritative batch tshark pass on close"
}

// connID assigns the next connection identifier, numbering connections in first-seen
// order the way tshark's tcp.stream index does — the same identity the PDML decode path
// puts on Flow.TCPStream. Requests sharing one id shared one connection, which is what
// makes HTTP/2 multiplexing legible in the viewer.
func (f *liveTCP) connID() string {
	id := strconv.Itoa(f.nextConn)
	f.nextConn++
	return id
}

// quicConnState is one tracked QUIC connection: its HTTP/3 decoder + the address that
// initiated it (the client), so each datagram's direction can be determined.
type quicConnState struct {
	sess   *quicSession
	client string
}

// handleUDP routes a UDP datagram to its QUIC connection's HTTP/3 decoder, starting one
// when a datagram first looks like a QUIC client Initial. Non-QUIC UDP is ignored.
func (f *liveTCP) handleUDP(netFlow gopacket.Flow, udp *gplayers.UDP) {
	payload := udp.Payload
	if len(payload) < 5 {
		return
	}
	src := net.JoinHostPort(netFlow.Src().String(), strconv.Itoa(int(udp.SrcPort)))
	dst := net.JoinHostPort(netFlow.Dst().String(), strconv.Itoa(int(udp.DstPort)))
	key := src + "|" + dst
	if src > dst {
		key = dst + "|" + src
	}
	st := f.quic[key]
	if st == nil {
		if !quicdecrypt.IsClientInitial(payload) {
			return // not (the start of) an HTTP/3 connection
		}
		st = &quicConnState{
			// "quic:" prefix as the PDML decode path uses, so a QUIC connection id can't be
			// mistaken for (or collide with) a TCP one.
			sess: newQUICSession(f, "quic:"+f.connID(),
				netFlow.Dst().String(), strconv.Itoa(int(udp.DstPort)), src),
			client: src,
		}
		f.quic[key] = st
	}
	st.sess.feed(src == st.client, payload)
}

func (f *liveTCP) New(netFlow, tcpFlow gopacket.Flow, _ *gplayers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	// reassembly treats the first-seen packet's source as the client; with capture
	// starting at connection setup that's the real TLS client, so its peer is the server.
	s := &tcpStream{
		lt:         f,
		connID:     f.connID(),
		serverHost: netFlow.Dst().String(),
		serverPort: tcpFlow.Dst().String(),
		clientAddr: net.JoinHostPort(netFlow.Src().String(), tcpFlow.Src().String()),
	}
	s.conn = tlsdecrypt.NewConn(f.keylog, s.onApp)
	return s
}

// tcpStream is one reassembled TCP connection: its TLS decryptor, and — once classified
// from its first decrypted bytes — either a custom-decoder session or an HTTP/1.1 parser.
type tcpStream struct {
	lt                                 *liveTCP
	connID                             string // this connection's id; goes on every flow it carries
	serverHost, serverPort, clientAddr string
	conn                               *tlsdecrypt.Conn

	reset       atomic.Bool // a TCP RST was seen (set on the packet loop, read by the HTTP parser)
	sniffed     bool        // checked the first client bytes look like TLS
	plaintext   bool        // first client bytes weren't TLS → parse the stream as cleartext HTTP
	decided     bool        // classified the connection from its first decrypted client bytes
	matched     bool        // a custom decoder claimed it
	isHTTP      bool        // decoding as HTTP/1.1
	isH2        bool        // decoding as HTTP/2
	dropped     bool
	flowEmitted bool
	sess        decoders.Session
	flow        *Flow
	httpSess    *httpStream
	h2Sess      *h2Stream
	preBuf      []appChunk // decrypted bytes buffered until classification (needs client bytes)
}

// appChunk is one decrypted application record buffered before classification.
type appChunk struct {
	fromClient bool
	data       []byte
}

func (s *tcpStream) Accept(tcp *gplayers.TCP, _ gopacket.CaptureInfo, _ reassembly.TCPFlowDirection,
	_ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	*start = true // accept even if the SYN wasn't captured
	if tcp.RST {
		s.reset.Store(true) // a reset explains a request left without a response
	}
	return true
}

func (s *tcpStream) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
	if s.dropped {
		return
	}
	dir, _, _, _ := sg.Info()
	n, _ := sg.Lengths()
	if n == 0 {
		return
	}
	data := sg.Fetch(n)
	fromClient := dir == reassembly.TCPDirClientToServer
	// Classify the transport from the first client→server bytes: a TLS handshake record
	// (type 22, version 0x03xx) is decrypted by the TLS layer; anything else is treated as
	// cleartext HTTP and parsed directly (so plaintext HTTP/1.1, HTTP/2 and WebSocket decode
	// in-process too — no tshark). Clients always speak first on HTTP, so this is decided
	// before any server bytes arrive.
	if fromClient && !s.sniffed {
		s.sniffed = true
		s.plaintext = len(data) < 2 || data[0] != 0x16 || data[1] != 0x03
	}
	if s.plaintext {
		s.onApp(fromClient, data) // the raw bytes are the application bytes
		return
	}
	s.conn.Feed(fromClient, data)
	if s.conn.Unsupported() {
		// A TLS connection we recognized but can't decrypt live (e.g. 3DES/RC4). Surface it
		// with what becomes of it, which depends on whether a batch pass will run.
		log.Printf("live decode: not decoding %s (%s) live: %s — %s",
			hostLabel(s.conn.SNI(), s.serverHost), s.serverHost, s.conn.UnsupportedReason(),
			s.lt.skippedFate())
		s.dropped = true
	}
}

func (s *tcpStream) ReassemblyComplete(_ reassembly.AssemblerContext) bool {
	if s.httpSess != nil {
		s.httpSess.close() // EOF the HTTP parser goroutines so they drain + exit
	}
	if s.h2Sess != nil {
		s.h2Sess.close()
	}
	// A reset on a custom-protocol connection (its flow lives on the stream) is a hard
	// drop — record it. HTTP/1.1 is annotated in its own parser; h2 uses RST_STREAM/GOAWAY.
	if s.reset.Load() && s.flowEmitted && s.flow != nil && s.flow.Error == "" {
		s.flow.Error = "connection reset (TCP RST)"
		s.lt.onFlow(s.flow, false)
	}
	// A TLS connection we never managed to decrypt (no key-log secret arrived, or the
	// handshake never completed in the capture) yields no live flow — flag it so the gap
	// isn't silent, and say what becomes of it.
	if s.sniffed && !s.dropped && !s.decided && !s.conn.Unsupported() {
		log.Printf("live decode: %s (%s) not decoded live: no TLS key-log secret (or incomplete handshake) — %s",
			hostLabel(s.conn.SNI(), s.serverHost), s.serverHost, s.lt.skippedFate())
	}
	return true
}

// hostLabel prefers the SNI for identifying a connection, falling back to the server host.
func hostLabel(sni, host string) string {
	if sni != "" {
		return sni
	}
	return host
}

// onApp receives application bytes — decrypted from the TLS layer, or raw for a cleartext
// connection. It buffers until the first client bytes arrive, classifies the connection
// (custom decoder / HTTP/2 / HTTP/1.1), then dispatches each chunk to the chosen decoder.
func (s *tcpStream) onApp(fromClient bool, plain []byte) {
	if s.dropped {
		return
	}
	if !s.decided {
		// Buffer (copy: the decryptor reuses its plaintext buffer). Classification needs
		// the first client bytes — to match a custom decoder and to spot an HTTP/2 preface.
		s.preBuf = append(s.preBuf, appChunk{fromClient, append([]byte(nil), plain...)})
		if !fromClient {
			return
		}
		s.classify(plain)
		buffered := s.preBuf
		s.preBuf = nil
		for _, c := range buffered {
			s.dispatch(c.fromClient, c.data)
		}
		return
	}
	s.dispatch(fromClient, plain)
}

// classify decides how to decode the connection from its first decrypted client bytes.
//
// Detection is by content, not just the connection's host. A host that speaks a custom
// binary protocol (e.g. MAX) commonly also serves plain HTTP/2 and HTTP/1.1 on *other*
// connections — static assets, images, a WebSocket upgrade. Matching the custom decoder by
// host alone (as this used to) commits those HTTP connections to a decoder that frames none
// of their bytes, so no flow is ever emitted and live silently drops them — while the batch
// pass on close decodes them fine, which is exactly the live-vs-batch divergence. So sniff
// HTTP first and fall back to a host-matched custom decoder only for a genuinely non-HTTP
// byte stream (a raw MAX transport opens straight with binary frames, never an HTTP
// request-line or the h2 preface, so this split is unambiguous). A WebSocket-transported
// custom protocol still decodes: the HTTP/1.1 path hands the upgraded connection to a WS
// decoder (e.g. MAX-over-WebSocket) after the 101.
func (s *tcpStream) classify(firstClient []byte) {
	s.decided = true
	// HTTP/2 (ALPN h2) opens with the client connection preface.
	if bytes.HasPrefix(firstClient, []byte("PRI * HTTP/2.0\r\n")) {
		s.h2Sess = newH2Stream(s)
		s.isH2 = true
		return
	}
	if looksLikeHTTP1Request(firstClient) {
		s.httpSess = newHTTPStream(s)
		s.isHTTP = true
		return
	}
	if m := decoders.Match(decoders.StreamMeta{
		ServerHost: s.serverHost, ServerPort: s.serverPort, SNI: s.conn.SNI(),
	}); len(m) > 0 {
		s.sess = m[0].NewSession()
		s.flow = customFlowMeta(s.conn.SNI(), s.serverHost, s.serverPort, s.clientAddr, m[0].Name())
		// Live has no per-packet time here (the decrypted bytes come from the TLS layer,
		// not a timestamped frame), so use wall-clock at connection start — same as the
		// live HTTP path (newHTTPFlow). Without it the persisted flow has time 0 and sorts
		// to the top of the list with a blank time column.
		s.flow.TSUnixMicros = time.Now().UnixMicro()
		s.flow.TLSDecrypted = !s.plaintext
		s.applyTLSFingerprint(s.flow)
		s.matched = true
		log.Printf("live decode: matched %s decoder for %s (%s)", m[0].Name(), s.conn.SNI(), s.serverHost)
		return
	}
	s.httpSess = newHTTPStream(s)
	s.isHTTP = true
}

// http1Methods are the HTTP/1.x request methods a decrypted client stream may open with —
// used to tell a plaintext HTTP/1.1 connection (including a WebSocket upgrade) apart from a
// binary custom protocol on the same host.
var http1Methods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "), []byte("DELETE "),
	[]byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "), []byte("TRACE "),
}

// looksLikeHTTP1Request reports whether b begins with an HTTP/1.x request line
// (METHOD SP request-target SP "HTTP/1."). The version token is checked too so a binary
// custom-protocol frame that merely starts with these bytes isn't mistaken for HTTP.
func looksLikeHTTP1Request(b []byte) bool {
	hasMethod := false
	for _, m := range http1Methods {
		if bytes.HasPrefix(b, m) {
			hasMethod = true
			break
		}
	}
	if !hasMethod {
		return false
	}
	line := b
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		line = b[:i]
	}
	return bytes.Contains(line, []byte(" HTTP/1."))
}

func (s *tcpStream) dispatch(fromClient bool, plain []byte) {
	switch {
	case s.matched:
		s.feedCustom(fromClient, plain)
	case s.isHTTP:
		s.httpSess.feed(fromClient, plain)
	case s.isH2:
		s.h2Sess.feed(fromClient, plain)
	}
}

// feedCustom frames decrypted bytes into messages via a custom decoder and publishes
// them like the WebSocket live path. The raw (undecoded) directional streams are kept on
// the flow's request/response body so the original bytes remain queryable.
func (s *tcpStream) feedCustom(fromClient bool, plain []byte) {
	if fromClient {
		s.flow.RequestBody = appendCapped(s.flow.RequestBody, plain)
		s.flow.RequestBytes = uint64(len(s.flow.RequestBody))
	} else {
		s.flow.ResponseBody = appendCapped(s.flow.ResponseBody, plain)
		// A raw/custom connection has no request→response boundary and lives for a long
		// time, so stop the viewer's stopwatch at the first server byte (time-to-first-byte)
		// instead of ticking for the connection's whole lifetime. Re-emit so it propagates.
		if s.flow.DurationMicros == 0 {
			s.flow.DurationMicros = uint64(max(time.Now().UnixMicro()-s.flow.TSUnixMicros, 0))
			if s.flowEmitted {
				s.lt.onFlow(s.flow, false)
			}
		}
	}
	for _, msg := range s.sess.Feed(fromClient, plain) {
		if !s.flowEmitted {
			s.lt.onFlow(s.flow, true)
			s.flowEmitted = true
			log.Printf("live decode: %s first frame on %s: %s (%d bytes)", s.flow.Protocol, s.conn.SNI(), msg.Opcode, len(msg.Payload))
		}
		s.flow.WsMessageCount++
		s.lt.onMsg(&WsMessage{
			ID:           uuid.NewString(),
			FlowID:       s.flow.ID,
			TSUnixMicros: time.Now().UnixMicro(),
			FromClient:   msg.FromClient,
			Opcode:       msg.Opcode,
			Payload:      msg.Payload,
		})
		s.lt.onFlow(s.flow, false) // refresh the row's ⇅ count
	}
}

// nflogIPPayload extracts the inner IP packet from one LINKTYPE_NFLOG record. The
// record is a 4-byte header (family, version, resource_id) followed by little-endian
// TLVs (length incl. header, type), 4-byte aligned; NFULA_PAYLOAD (type 9) carries the
// captured IP packet. family selects IPv4 (AF_INET=2) or IPv6 (AF_INET6=10).
func nflogIPPayload(data []byte) (gopacket.LayerType, []byte, bool) {
	if len(data) < 4 {
		return 0, nil, false
	}
	family := data[0]
	for off := 4; off+4 <= len(data); {
		l := int(binary.LittleEndian.Uint16(data[off : off+2]))
		typ := binary.LittleEndian.Uint16(data[off+2 : off+4])
		if l < 4 || off+l > len(data) {
			break
		}
		if typ == 9 { // NFULA_PAYLOAD
			payload := data[off+4 : off+l]
			switch family {
			case 2: // AF_INET
				return gplayers.LayerTypeIPv4, payload, true
			case 10: // AF_INET6
				return gplayers.LayerTypeIPv6, payload, true
			default:
				return 0, nil, false
			}
		}
		off += (l + 3) &^ 3 // advance to the next 4-byte-aligned TLV
	}
	return 0, nil, false
}
