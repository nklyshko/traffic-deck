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

	"github.com/nikitak/parsing/traffic-gateway/decoders"
)

// HasCustomDecoders reports whether any custom protocol decoders are registered, so
// callers can skip the live custom-decode pipeline entirely when there are none.
func HasCustomDecoders() bool { return len(decoders.All()) > 0 }

// decodeCustomStreams runs registered decoders over the matched TLS streams collected
// by the stitcher, appending each decoded connection (a synthetic Flow + its messages)
// to the dataset. Best-effort: a decoder or tshark error skips that stream.
func decodeCustomStreams(ctx context.Context, tsharkPath, pcapPath, keylogPath string, st *stitcher) {
	for tcp, info := range st.streamMeta {
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
		st.ds.Flows = append(st.ds.Flows, f)
		for _, m := range msgs {
			st.ds.Messages = append(st.ds.Messages, &WsMessage{
				ID:           uuid.NewString(),
				FlowID:       f.ID,
				TSUnixMicros: m.TSUnixMicros,
				FromClient:   m.FromClient,
				Opcode:       m.Opcode,
				Payload:      m.Payload,
			})
		}
	}
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

// customFlow is the batch variant: it also records the tcp.stream index.
func customFlow(info *tlsStream, tcp, name string) *Flow {
	f := customFlowMeta(info.sni, info.serverHost, info.serverPort, info.clientAddr, name)
	f.TCPStream = tcp
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
