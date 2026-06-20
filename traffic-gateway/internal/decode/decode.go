// Package decode turns a captured pcap + TLS key.log into HTTP flows by
// orchestrating tshark (plan §8). This is the native-Go batch decode path
// (§8.2): one `tshark -T ek` pass, parsed and stitched into flows.
//
// Logic is ported from the reference sniff-pcap crate; tshark does the heavy
// lifting (TCP reassembly, TLS decryption, HPACK), we orchestrate + stitch.
package decode

import (
	"bufio"
	"context"
	"encoding/json"
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

	// internal: set once a reassembled (complete) body has been captured, so raw
	// per-frame chunks no longer append.
	reqBodyFinal  bool
	respBodyFinal bool
}

// Dataset is the result of decoding one capture.
type Dataset struct {
	Engine        string
	TLSKeyLogUsed bool
	Flows         []*Flow
	Warnings      []string
}

// tshark -e fields, in request order. EK keys are these with dots -> underscores.
var ekFields = []string{
	"frame.number", "frame.time_epoch",
	"ip.src", "ipv6.src", "tcp.srcport",
	"ip.dst", "ipv6.dst", "tcp.dstport",
	"tcp.stream", "http2.streamid",
	"http2.headers.method", "http2.headers.scheme", "http2.headers.authority",
	"http2.headers.path", "http2.headers.status",
	"http2.header.name", "http2.header.value",
	"http.request.method", "http.host", "http.request.uri", "http.response.code",
	"http.user_agent", "http.content_type",
	"http.request.line", "http.response.line",
	// body data (prefer reassembled). Direction is derived from src vs the flow's client.
	"http.file_data", "http.body.reassembled.data",
	"http2.data.data", "http2.body.reassembled.data",
}

// tsharkArgs builds the common tshark EK invocation. input selects the source
// (["-r", path] for a file, ["-i", "-"] for a live stdin stream).
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
	args = append(args, "-Y", "http or http2", "-T", "ek")
	for _, f := range ekFields {
		args = append(args, "-e", f)
	}
	return args
}

// runTshark spawns tshark, feeds each EK record to the stitcher, and waits.
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

	// EK emits two JSON objects per packet (an index line and the source line);
	// json.Decoder reads the concatenated stream regardless of newlines.
	dec := json.NewDecoder(bufio.NewReaderSize(stdout, 1<<20))
	for dec.More() {
		var rec ekRecord
		if err := dec.Decode(&rec); err != nil {
			return fmt.Errorf("parse tshark ek: %w", err)
		}
		if rec.Layers != nil {
			st.add(rec.Layers)
		}
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("tshark: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
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

// ekRecord is one Elasticsearch-format line from tshark.
type ekRecord struct {
	Timestamp string                     `json:"timestamp"`
	Layers    map[string]json.RawMessage `json:"layers"`
}

// layers wraps an EK layers map with typed accessors.
type layers map[string]json.RawMessage

func ekKey(field string) string { return strings.ReplaceAll(field, ".", "_") }

// all returns every value of a field ([] if absent).
func (l layers) all(field string) []string {
	raw, ok := l[ekKey(field)]
	if !ok {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	return nil
}

// first returns the first value of a field, or "".
func (l layers) first(field string) string {
	v := l.all(field)
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
