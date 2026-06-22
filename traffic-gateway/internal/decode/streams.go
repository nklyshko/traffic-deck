package decode

// Custom raw-TCP decoding (plan §8). After the PDML pass identifies TLS streams (SNI
// + tls.stream index), any stream a registered decoder claims is decrypted via tshark
// `follow,tls,raw` and handed to the decoder. We use follow because tshark only
// exposes the decrypted bytes of an *undissected* protocol through the follow output
// (they don't surface as a PDML field).

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nikitak/parsing/traffic-gateway/decoders"
)

// liveCustomPollInterval is how often the live path re-runs follow over the growing
// capture to feed matched decoders. follow re-decrypts the whole stream each time, so
// this is a deliberate cadence (not per-packet); the framing itself is incremental.
const liveCustomPollInterval = 2 * time.Second

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

// customFlow builds the synthetic Flow representing a decoded custom-protocol
// connection (shared by the batch and live paths). Websocket=true so it reuses the
// message-timeline UI; on the stored path attachWsCounts recomputes that on read.
func customFlow(info *tlsStream, tcp, name string) *Flow {
	host := info.sni
	if host == "" {
		host = info.serverHost
	}
	return &Flow{
		ID:           uuid.NewString(),
		Protocol:     strings.ToUpper(name),
		Authority:    host,
		SrcAddr:      info.clientAddr,
		DstAddr:      addr(info.serverHost, "", info.serverPort),
		TCPStream:    tcp,
		TLSDecrypted: true,
		Websocket:    true,
	}
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

// liveStream holds the per-connection state the live poller carries across ticks:
// the decoder's stateful framer, the synthetic flow, how many decrypted bytes have
// already been fed per direction, and whether the flow has been announced yet.
type liveStream struct {
	sess        decoders.Session
	flow        *Flow
	consumed    map[bool]int // direction -> bytes already fed to the session
	flowEmitted bool
}

// pollCustomStreams drives live custom-protocol decoding (plan §8.2): on a fixed
// cadence it re-runs follow over the growing capture for each matched stream, feeds
// only the newly-arrived decrypted bytes to the decoder's stateful session, and emits
// any completed frames via the same onFlow/onMsg callbacks the WebSocket live path
// uses — so they flow through the live hub to the viewer's message timeline. Runs
// until ctx is cancelled (the live decode finishing).
func (s *stitcher) pollCustomStreams(ctx context.Context, tsharkPath, pcapPath, keylogPath string,
	onFlow func(*Flow, bool), onMsg func(*WsMessage)) {
	states := map[string]*liveStream{} // tcp.stream -> state
	t := time.NewTicker(liveCustomPollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.customPollPass(ctx, tsharkPath, pcapPath, keylogPath, states, onFlow, onMsg)
		}
	}
}

func (s *stitcher) customPollPass(ctx context.Context, tsharkPath, pcapPath, keylogPath string,
	states map[string]*liveStream, onFlow func(*Flow, bool), onMsg func(*WsMessage)) {
	for tcp, info := range s.snapshotMeta() {
		if info.tlsStreamIdx == "" {
			continue
		}
		st := states[tcp]
		if st == nil {
			matched := decoders.Match(decoders.StreamMeta{
				TCPStream: tcp, ServerHost: info.serverHost, ServerPort: info.serverPort, SNI: info.sni,
			})
			if len(matched) == 0 {
				states[tcp] = &liveStream{} // remember the miss so we don't re-Match each tick
				continue
			}
			st = &liveStream{
				sess:     matched[0].NewSession(),
				flow:     customFlow(info, tcp, matched[0].Name()),
				consumed: map[bool]int{},
			}
			states[tcp] = st
		}
		if st.sess == nil {
			continue // a known non-matching stream
		}
		turns, err := followTLSRaw(ctx, tsharkPath, pcapPath, keylogPath, info.tlsStreamIdx)
		if err != nil {
			continue // partial/locked capture this tick; try again next time
		}
		// follow returns the full per-direction byte stream (append-only as the capture
		// grows); feed only the bytes past what we've already consumed.
		cum := map[bool][]byte{}
		for _, tn := range turns {
			cum[tn.FromClient] = append(cum[tn.FromClient], tn.Data...)
		}
		for _, dir := range []bool{true, false} {
			full := cum[dir]
			if len(full) <= st.consumed[dir] {
				continue
			}
			fresh := full[st.consumed[dir]:]
			st.consumed[dir] = len(full)
			for _, m := range st.sess.Feed(dir, fresh) {
				if !st.flowEmitted {
					onFlow(st.flow, true)
					st.flowEmitted = true
				}
				st.flow.WsMessageCount++
				onMsg(&WsMessage{
					ID:         uuid.NewString(),
					FlowID:     st.flow.ID,
					FromClient: m.FromClient,
					Opcode:     m.Opcode,
					Payload:    m.Payload,
				})
				onFlow(st.flow, false) // refresh the row's ⇅ count
			}
		}
	}
}
