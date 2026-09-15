package decode

// Custom raw-TCP decoding. After the PDML pass identifies TLS streams (SNI
// + tls.stream index), any stream a registered decoder claims is decrypted via tshark
// `follow,tls,raw` and handed to the decoder. We use follow because tshark only
// exposes the decrypted bytes of an *undissected* protocol through the follow output
// (they don't surface as a PDML field).

import (
	"context"
	"os/exec"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/nklyshko/traffic-deck/gateway/decoders"
)

// HasCustomDecoders reports whether any custom protocol decoders are registered, so
// callers can skip the live custom-decode pipeline entirely when there are none.
func HasCustomDecoders() bool { return len(decoders.All()) > 0 }

// decodeCustomStreams runs registered decoders over the matched TLS streams collected
// by the stitcher, appending each decoded connection (a synthetic Flow + its messages)
// to the dataset. Best-effort: a decoder or tshark error skips that stream.
func decodeCustomStreams(ctx context.Context, tsharkPath, pcapPath, keylogPath string, st *stitcher) {
	httpStreams := httpStreamSet(st.ds)
	for tcp, info := range st.streamMeta {
		if httpStreams[tcp] {
			// tshark already dissected this connection as HTTP/HTTP2/WebSocket. A raw-TCP
			// decoder claims connections by host (the mobile app's raw-TLS transport has no
			// HTTP to sniff), so on a shared host it would also grab these HTTP connections
			// and frame their bytes into a bogus flow — e.g. reading an HTTP/2 SETTINGS
			// frame as a MAX frame. Skip them; the live path skips them the same way
			// (HTTP-first classification), so the two decode paths agree. A WebSocket-carried
			// custom protocol is still decoded — on the HTTP/1.1 upgrade flow, via the WS path.
			continue
		}
		meta := decoders.StreamMeta{
			TCPStream:  tcp,
			ServerHost: info.serverHost,
			ServerPort: info.serverPort,
			SNI:        info.sni,
		}
		matched := decoders.Match(meta)
		if len(matched) == 0 || info.tlsStreamIdx == "" {
			continue
		}
		turns, err := followTLSRaw(ctx, tsharkPath, pcapPath, keylogPath, info.tlsStreamIdx)
		if err != nil || len(turns) == 0 {
			continue
		}
		msgs := decoders.DecodeTurns(matched[0], turns)
		if len(msgs) == 0 {
			continue
		}
		f := customFlow(info, tcp, matched[0].Name())
		// Keep the raw (undecoded) directional streams on the flow body so the original
		// bytes remain queryable alongside the decoded messages.
		for _, tn := range turns {
			if tn.FromClient {
				f.RequestBody = append(f.RequestBody, tn.Data...)
			} else {
				f.ResponseBody = append(f.ResponseBody, tn.Data...)
			}
		}
		f.RequestBytes = uint64(len(f.RequestBody))
		st.ds.Flows = append(st.ds.Flows, f)
		for _, m := range msgs {
			st.ds.Messages = append(st.ds.Messages, &WsMessage{
				ID:           uuid.NewString(),
				FlowID:       f.ID,
				TSUnixMicros: m.TSUnixMicros,
				FromClient:   m.FromClient,
				Opcode:       matched[0].Name(),
				Payload:      m.Payload,
				Metadata:     m.Fields,
			})
		}
	}
}

// httpStreamSet returns the tcp.stream ids tshark dissected as HTTP-family (HTTP/1.1 or
// HTTP/2, a WebSocket upgrade being an HTTP/1.1 flow). decodeCustomStreams uses it to
// leave those connections to their HTTP decode instead of double-claiming them with a
// host-matched raw-TCP decoder. HTTP/3 flows key on a "quic:" stream, never a bare tcp
// id, so they don't appear here and don't matter (custom decoding is TCP-only).
func httpStreamSet(ds *Dataset) map[string]bool {
	out := map[string]bool{}
	for _, f := range ds.Flows {
		if f.TCPStream == "" {
			continue
		}
		if f.Protocol == "HTTP/1.1" || f.Protocol == "HTTP/2" {
			out[f.TCPStream] = true
		}
	}
	return out
}

// customFlowMeta builds the synthetic Flow representing a decoded custom-protocol
// connection (shared by the batch and live Go paths). Websocket=true so it reuses the
// message-timeline UI; on the stored path attachWsCounts recomputes that on read.
func customFlowMeta(sni, serverHost, serverPort, clientAddr, name string) *Flow {
	host := sni
	if host == "" {
		host = serverHost
	}
	return &Flow{
		ID:           uuid.NewString(),
		Protocol:     strings.ToUpper(name),
		Authority:    host,
		SrcAddr:      clientAddr,
		DstAddr:      addr(serverHost, "", serverPort),
		TLSDecrypted: true,
		Websocket:    true,
	}
}

// customFlow is the batch variant: it also records the tcp.stream index and stamps the
// flow with the connection's ClientHello time (follow,tls,raw yields no per-frame times,
// so without this the flow would sort to the top of the list with a blank time column).
func customFlow(info *tlsStream, tcp, name string) *Flow {
	f := customFlowMeta(info.sni, info.serverHost, info.serverPort, info.clientAddr, name)
	f.TCPStream = tcp
	f.TSUnixMicros = info.tsMicros
	f.FrameNumber = info.frameNumber
	return f
}

// followTLSRaw extracts a TLS stream's decrypted, directional byte turns via
// `tshark -z follow,tls,raw,<tls.stream>`.
func followTLSRaw(ctx context.Context, tsharkPath, pcapPath, keylogPath, tlsStream string) ([]decoders.Turn, error) {
	args := []string{"-r", pcapPath}
	if keylogPath != "" {
		args = append(args, "-o", "tls.keylog_file:"+keylogPath)
	}
	args = append(args, "-q", "-z", "follow,tls,raw,"+tlsStream)
	out, err := exec.CommandContext(ctx, tsharkPath, args...).Output()
	if err != nil {
		return nil, err
	}
	return parseFollowRaw(string(out)), nil
}

var hexLineRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// parseFollowRaw turns `follow,tls,raw` output into ordered turns. Non-indented hex
// lines are node0→node1 (client→server); tab-indented lines are node1→node0
// (server→client). Header lines (Follow:/Filter:/Node/===) aren't hex and are skipped.
func parseFollowRaw(out string) []decoders.Turn {
	var turns []decoders.Turn
	for _, line := range strings.Split(out, "\n") {
		fromClient := !strings.HasPrefix(line, "\t")
		h := strings.TrimSpace(line)
		if h == "" || !hexLineRe.MatchString(h) {
			continue
		}
		b := hexBytes(h)
		if len(b) == 0 {
			continue
		}
		turns = append(turns, decoders.Turn{FromClient: fromClient, Data: b})
	}
	return turns
}
