// Package decode turns a captured pcap + TLS key.log into HTTP flows by
// orchestrating tshark (plan §8). tshark does the heavy lifting (TCP reassembly,
// TLS decryption, HPACK); we parse its PDML and stitch per-frame records into flows.
//
// PDML (per-protocol XML tree) rather than `-T ek` flat fields: a single packet can
// carry many multiplexed HTTP/2 frames, and the flat format can't keep each frame's
// stream id associated with its own fields (plan §8.6).
package decode

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Header is one HTTP header (order preserved, duplicates allowed).
type Header struct {
	Name  string
	Value string
}

// Flow is one decoded HTTP exchange (request + optional response).
type Flow struct {
	ID              string // stable per-flow id (assigned by the stitcher)
	FrameNumber     uint64
	TSUnixMicros    int64
	Method          string
	Scheme          string
	Authority       string
	Path            string
	Query           string
	Protocol        string
	Status          uint32
	SrcAddr         string
	DstAddr         string
	UserAgent       string
	ContentType     string
	RequestBytes    uint64
	TLSDecrypted    bool
	TCPStream       string
	H2StreamID      string
	RequestHeaders  []Header
	ResponseHeaders []Header

	RequestBody  []byte
	ResponseBody []byte

	// Websocket is set when this flow is an HTTP Upgrade that carries WebSocket
	// frames; the frames themselves are WsMessages keyed by this flow's ID (§8.6).
	Websocket bool

	// internal: set once a reassembled (complete) body has been captured, so raw
	// per-frame chunks no longer append.
	reqBodyFinal  bool
	respBodyFinal bool
}

// WsMessage is one decoded WebSocket frame, a message-shaped record distinct from
// the request/response Flow model (plan §8.6). It belongs to the Upgrade flow on its
// TCP stream (FlowID).
type WsMessage struct {
	ID           string
	FlowID       string // parent Upgrade flow
	FrameNumber  uint64
	TSUnixMicros int64
	FromClient   bool   // direction: true = client→server
	Opcode       string // text|binary|close|ping|pong|continuation
	Payload      []byte
}

// Dataset is the result of decoding one capture.
type Dataset struct {
	Engine        string
	TLSKeyLogUsed bool
	Flows         []*Flow
	Messages      []*WsMessage
	Warnings      []string
}

// metaProtos contribute packet-level fields (merged into every PDU of the packet).
var metaProtos = map[string]bool{"frame": true, "ip": true, "ipv6": true, "tcp": true, "udp": true}

// pduProtos each become one stitcher record: one per HTTP/2 frame, the HTTP/1.1
// message, or one WebSocket frame. This per-<proto> separation is what fixes HTTP/2
// multiplexing (§8.6) and likewise keeps each WebSocket frame distinct.
var pduProtos = map[string]bool{"http2": true, "http": true, "websocket": true}

// bodyFields are byte fields whose raw hex lives in the `value` attribute (the
// `show` attribute is truncated for bytes). websocket.payload is the unmasked frame
// payload.
var bodyFields = map[string]bool{
	"http2.data.data": true, "http2.body.reassembled.data": true,
	"http.file_data": true, "http.body.reassembled.data": true,
	"websocket.payload": true,
}

// tsharkArgs builds the common tshark PDML invocation. input selects the source
// (["-r", path] for a file, ["-r", "-"] for a streamed stdin capture).
//
// PDML (not `-T ek` + `-e` fields) so multiplexed HTTP/2 frames in one packet each
// keep their own <proto name="http2"> with its own stream id + fields (plan §8.6).
func tsharkArgs(input []string, keylogPath string, live bool) []string {
	args := append([]string{}, input...)
	if keylogPath != "" {
		args = append(args, "-o", "tls.keylog_file:"+keylogPath)
	}
	// Decompress bodies and tolerate out-of-order TCP for better reassembly.
	args = append(args, "-o", "http.decompress_body:TRUE", "-o", "tcp.reassemble_out_of_order:TRUE")
	if live {
		args = append(args, "-l") // flush output per packet
	}
	// -O bounds PDML detail to the protocols we parse (tls excluded — frame.protocols
	// still reports it); -Y keeps HTTP-bearing and WebSocket packets (the latter carry
	// no http layer after the Upgrade).
	args = append(args, "-Y", "http or http2 or websocket", "-T", "pdml",
		"-O", "frame,ip,ipv6,tcp,udp,http,http2,websocket")
	return args
}

// runTshark spawns tshark (PDML output) and feeds one stitcher record per HTTP PDU.
// Packet-level (frame/ip/tcp/…) fields are merged into each PDU so the stitcher sees
// a complete, per-frame-correct field map.
func runTshark(ctx context.Context, tsharkPath string, args []string, stdin io.Reader, st *stitcher) error {
	cmd := exec.CommandContext(ctx, tsharkPath, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tshark: %w", err)
	}

	dec := xml.NewDecoder(bufio.NewReaderSize(stdout, 1<<20))
	var meta layers    // packet-level fields, reset per <packet>
	var cur layers     // current proto's target map (nil = ignore this proto)
	var pduName string // non-empty while inside a PDU proto

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("parse tshark pdml: %w", err)
		}
		switch se := tok.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "packet":
				meta = layers{}
			case "proto":
				name := attrVal(se, "name")
				switch {
				case metaProtos[name]:
					cur, pduName = meta, ""
				case pduProtos[name]:
					cur, pduName = layers{}, name
				default:
					cur, pduName = nil, ""
				}
			case "field":
				if cur == nil {
					break
				}
				name := attrVal(se, "name")
				if name == "" {
					break
				}
				val := attrVal(se, "show")
				if bodyFields[name] {
					if v := attrVal(se, "value"); v != "" {
						val = v
					}
				}
				cur[name] = append(cur[name], val)
			}
		case xml.EndElement:
			if se.Name.Local == "proto" {
				if pduName != "" { // emit one record per HTTP PDU
					rec := make(layers, len(meta)+len(cur))
					for k, v := range meta {
						rec[k] = v
					}
					for k, v := range cur {
						rec[k] = v
					}
					st.add(rec)
				}
				cur, pduName = nil, ""
			}
		}
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("tshark: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func attrVal(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// Decode runs tshark over pcapPath (decrypting with keylogPath if non-empty) and
// returns the decoded flows in first-seen order.
func Decode(ctx context.Context, tsharkPath, pcapPath, keylogPath string) (*Dataset, error) {
	ds := &Dataset{Engine: "tshark", TLSKeyLogUsed: keylogPath != ""}
	st := newStitcher(ds, nil)
	if err := runTshark(ctx, tsharkPath, tsharkArgs([]string{"-r", pcapPath}, keylogPath, false), nil, st); err != nil {
		return nil, err
	}
	return ds, nil
}

// layers is a per-PDU field map (field name -> values), built from PDML.
type layers map[string][]string

// all returns every value of a field ([] if absent).
func (l layers) all(field string) []string { return l[field] }

// first returns the first value of a field, or "".
func (l layers) first(field string) string {
	if v := l[field]; len(v) > 0 {
		return v[0]
	}
	return ""
}
