// Package max decodes the MAX messenger (ru.oneme) raw-TCP protocol (plan §8).
// Ported from the reference mitmproxy addon _EXTERNAL/max-sniff/maxproto_dump.py.
//
// Frame: 10-byte big-endian header [ver(1) cmd(2) seq(1) opcode(2) packed_len(4)],
// where the top byte of packed_len is an LZ4-compression flag and the low 24 bits are
// the payload length; payload = next payload_length bytes → if compressed, LZ4
// block-decompress → MessagePack. We frame the (decrypted) per-direction byte stream
// and decode each frame's payload to JSON.
package max

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pierrec/lz4/v4"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/nikitak/parsing/traffic-gateway/decoders"
)

const (
	headerLen   = 10
	maxDecompSz = 1 << 20 // matches the addon's uncompressed_size hint
)

func init() { decoders.Register(&decoder{}) }

type decoder struct{}

func (decoder) Name() string { return "max" }

func (decoder) Matches(m decoders.StreamMeta) bool {
	host := m.SNI
	if host == "" {
		host = m.ServerHost
	}
	return strings.Contains(host, "oneme.ru") || strings.HasPrefix(m.ServerHost, "155.212")
}

// NewSession returns a stateful framer: each direction's byte stream is framed
// independently (a frame stays within one direction), buffering a partial frame until
// the rest arrives — so it works whether fed all at once (batch) or incrementally (live).
func (decoder) NewSession() decoders.Session { return &session{bufs: map[bool][]byte{}} }

type session struct {
	bufs map[bool][]byte // from_client -> pending (un-framed) bytes
}

// Feed appends newly-arrived bytes for one direction and returns any frames that
// completed. follow,tls,raw carries no timestamps, so messages have ts=0.
func (s *session) Feed(fromClient bool, data []byte) []decoders.Message {
	buf := append(s.bufs[fromClient], data...)
	var out []decoders.Message
	for {
		frame, rest, ok := nextFrame(buf)
		if !ok {
			break
		}
		buf = rest
		if m, ok := decodeFrame(frame, fromClient, 0); ok {
			out = append(out, m)
		}
	}
	s.bufs[fromClient] = buf
	return out
}

// nextFrame splits one complete frame off the front of buf, or reports !ok if buf
// doesn't yet hold a full frame.
func nextFrame(buf []byte) (frame, rest []byte, ok bool) {
	if len(buf) < headerLen {
		return nil, buf, false
	}
	plen := int(binary.BigEndian.Uint32(buf[6:10]) & 0xFFFFFF)
	total := headerLen + plen
	if len(buf) < total {
		return nil, buf, false
	}
	return buf[:total], buf[total:], true
}

func decodeFrame(frame []byte, fromClient bool, ts int64) (decoders.Message, bool) {
	ver := frame[0]
	cmd := binary.BigEndian.Uint16(frame[1:3])
	seq := frame[3]
	opcode := binary.BigEndian.Uint16(frame[4:6])
	packed := binary.BigEndian.Uint32(frame[6:10])
	comp := packed >> 24
	plen := int(packed & 0xFFFFFF)

	msg := decoders.Message{
		FromClient:   fromClient,
		Opcode:       fmt.Sprintf("cmd%d/op0x%x", cmd, opcode),
		Summary:      fmt.Sprintf("ver=%d seq=%d", ver, seq),
		ContentType:  "application/json",
		TSUnixMicros: ts,
	}
	if plen == 0 {
		msg.Payload = []byte(`"[empty / ack]"`)
		return msg, true
	}

	payload := frame[headerLen : headerLen+plen]
	if comp != 0 {
		dst := make([]byte, maxDecompSz)
		n, err := lz4.UncompressBlock(payload, dst)
		if err != nil {
			return decoders.Message{}, false // skip undecodable frame
		}
		payload = dst[:n]
	}

	var v interface{}
	if err := msgpack.Unmarshal(payload, &v); err != nil {
		return decoders.Message{}, false
	}
	js, err := json.Marshal(jsonSafe(v))
	if err != nil {
		return decoders.Message{}, false
	}
	msg.Payload = js
	return msg, true
}

// jsonSafe makes a msgpack-decoded value JSON-encodable: stringify non-string map
// keys and hex-encode raw bytes.
func jsonSafe(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		m := make(map[string]interface{}, len(x))
		for k, val := range x {
			m[k] = jsonSafe(val)
		}
		return m
	case map[interface{}]interface{}:
		m := make(map[string]interface{}, len(x))
		for k, val := range x {
			m[fmt.Sprint(k)] = jsonSafe(val)
		}
		return m
	case []interface{}:
		a := make([]interface{}, len(x))
		for i, val := range x {
			a[i] = jsonSafe(val)
		}
		return a
	case []byte:
		return hex.EncodeToString(x)
	default:
		return v
	}
}
