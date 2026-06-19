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
}

// Decode runs tshark over pcapPath (decrypting with keylogPath if non-empty) and
// returns the decoded flows in first-seen order.
func Decode(ctx context.Context, tsharkPath, pcapPath, keylogPath string) (*Dataset, error) {
	args := []string{"-r", pcapPath}
	if keylogPath != "" {
		args = append(args, "-o", "tls.keylog_file:"+keylogPath)
	}
	args = append(args, "-Y", "http or http2", "-T", "ek")
	for _, f := range ekFields {
		args = append(args, "-e", f)
	}

	cmd := exec.CommandContext(ctx, tsharkPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tshark: %w", err)
	}

	ds := &Dataset{Engine: "tshark", TLSKeyLogUsed: keylogPath != ""}
	st := newStitcher(ds)

	// EK emits two JSON objects per packet (an index line and the source line);
	// json.Decoder reads the concatenated stream regardless of newlines.
	dec := json.NewDecoder(bufio.NewReaderSize(stdout, 1<<20))
	for dec.More() {
		var rec ekRecord
		if err := dec.Decode(&rec); err != nil {
			return nil, fmt.Errorf("parse tshark ek: %w", err)
		}
		if rec.Layers == nil {
			continue // index action line
		}
		st.add(rec.Layers)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("tshark: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
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
