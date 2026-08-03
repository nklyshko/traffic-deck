// Package max decodes the MAX messenger (ru.oneme / web.max.ru) protocol, over either
// a raw TLS/TCP stream (mobile app) or WebSocket binary messages (web client).
//
// Frame: 10-byte big-endian header [ver(1) cmd(1) seq(2) opcode(2) len(4)]. The top
// byte of the length field (header[6]) is a compression flag — 0 = none, 0xFF = zstd,
// any other value = LZ4 block — and the low 24 bits are the payload length. The body is
// decompressed accordingly, then MessagePack-decoded to JSON. Two MAX-isms (see the
// reference client _EXTERNAL/max-desktop/maxclient/protocol/codec.py): it sometimes
// prefixes 1-4 service bytes before the msgpack (we try a few offsets), and it boxes
// 64-bit ids in ext type 1 — used both as values and as map keys (presence/chats), so
// we register an ext decoder and decode maps untyped. A body that still won't parse
// (e.g. truncated) is kept raw rather than dropped.
package max

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/vmihailenco/msgpack/v5"

	"gitlab.com/nklyshko/traffic-deck/gateway/decoders"
)

const (
	headerLen = 10
	compZstd  = 0xFF // header[6] flag: body is zstd-compressed
)

// zstdDec is a shared stateless decoder (DecodeAll is safe for concurrent use).
var zstdDec, _ = zstd.NewReader(nil)

var errLZ4 = errors.New("max: lz4 block decompress produced no output")

func init() {
	decoders.Register(&decoder{})   // raw TLS/TCP transport (e.g. the mobile app)
	decoders.RegisterWS(&decoder{}) // WebSocket binary transport (e.g. web.max.ru)

	// MAX boxes 64-bit IDs (chat/contact/message ids) in MessagePack ext type 1, whose
	// body is itself a msgpack integer. Without a decoder, the stdlib aborts on the
	// unknown ext and large LOGIN/contacts/history frames fall back to raw bytes; unbox
	// it to the plain integer so those frames decode to JSON.
	msgpack.RegisterExtDecoder(maxIDExt, int64(0),
		func(dec *msgpack.Decoder, v reflect.Value, _ int) error {
			n, err := dec.DecodeInt64()
			if err != nil {
				return err
			}
			v.SetInt(n)
			return nil
		})
}

const maxIDExt = 1 // MessagePack ext type carrying a boxed 64-bit MAX id

type decoder struct{}

func (decoder) Name() string { return "max" }

func (decoder) Matches(m decoders.StreamMeta) bool {
	host := m.SNI
	if host == "" {
		host = m.ServerHost
	}
	return isMaxHost(host) || strings.HasPrefix(m.ServerHost, "155.212")
}

// MatchesWS claims MAX's WebSocket transport: web.max.ru / api.oneme.ru carry the same
// 10-byte-framed MessagePack frames inside binary WebSocket messages.
func (decoder) MatchesWS(m decoders.WSMeta) bool {
	host := m.SNI
	if host == "" {
		host = m.Host
	}
	return isMaxHost(host)
}

func isMaxHost(host string) bool {
	return strings.Contains(host, "oneme.ru") || strings.Contains(host, "max.ru")
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
	cmd := frame[1]
	seq := binary.BigEndian.Uint16(frame[2:4])
	opcode := binary.BigEndian.Uint16(frame[4:6])
	comp := frame[6] // compression flag (top byte of len)
	plen := int(binary.BigEndian.Uint32(frame[6:10]) & 0xFFFFFF)

	msg := decoders.Message{
		FromClient:   fromClient,
		Opcode:       opcodeLabel(opcode),
		ContentType:  "application/json",
		TSUnixMicros: ts,
		Fields: map[string]string{
			"max.cmd":    cmdLabel(cmd),
			"max.seq":    strconv.FormatUint(uint64(seq), 10),
			"max.opcode": opcodeField(opcode),
			"max.ver":    strconv.FormatUint(uint64(ver), 10),
		},
	}
	if plen == 0 {
		msg.Payload = []byte(`"[empty / ack]"`)
		return msg, true
	}

	body, err := decompressBody(frame[headerLen:headerLen+plen], comp)
	if err != nil {
		return rawMessage(msg, frame[headerLen:headerLen+plen]), true // keep the raw frame
	}

	v, ok := unpackMsgpack(body)
	if !ok {
		// LOGIN/HISTORY use a compact/ref encoding plain msgpack can't parse; keep the
		// decompressed bytes raw (like the reference client's decoded=None path) rather
		// than dropping the frame.
		return rawMessage(msg, body), true
	}
	js, err := json.Marshal(jsonSafe(v))
	if err != nil {
		return rawMessage(msg, body), true
	}
	msg.Payload = js
	return msg, true
}

// cmdNames are the four frame kinds MAX sends. The command is one byte: a request from
// the client, the response that echoes its sequence number, an unsolicited push, or an
// error. (This used to be read as a 16-bit field spanning the sequence number's high
// byte, which made every response read as "cmd256".)
var cmdNames = map[byte]string{
	0: "Request",
	1: "Response",
	2: "Push",
	3: "Error",
}

// opcodeNames are the frame opcodes with a confirmed meaning. Deliberately partial: an
// opcode that is not in here renders as its number, which is honest, rather than as a
// guess that would read like knowledge.
var opcodeNames = map[uint16]string{
	3:   "Reset",
	6:   "Init",
	19:  "Auth",
	49:  "GetMessages",
	83:  "VideoContent",
	89:  "LinkResolution",
	288: "QrCode",
}

// cmdLabel renders the command as "Response(1)", or "cmd7" when it is not one of the four.
func cmdLabel(cmd byte) string {
	if n := cmdNames[cmd]; n != "" {
		return fmt.Sprintf("%s(%d)", n, cmd)
	}
	return fmt.Sprintf("cmd%d", cmd)
}

// opcodeLabel is the frame's short label — the name alone ("Auth"), since the number is
// carried in its own field beside it. An unnamed opcode keeps the hex form the decoder
// has always used.
func opcodeLabel(op uint16) string {
	if n := opcodeNames[op]; n != "" {
		return n
	}
	return fmt.Sprintf("op0x%x", op)
}

// opcodeField renders the opcode column as "Auth(19)": the name for reading, the number
// for looking up against a protocol reference.
func opcodeField(op uint16) string {
	if n := opcodeNames[op]; n != "" {
		return fmt.Sprintf("%s(%d)", n, op)
	}
	return fmt.Sprintf("op0x%x", op)
}

// decompressBody decompresses a frame body per the header[6] flag: 0 = none,
// 0xFF = zstd, any other value = LZ4 block (net.jpountz raw block, no framing).
func decompressBody(body []byte, comp byte) ([]byte, error) {
	if len(body) == 0 || comp == 0 {
		return body, nil
	}
	if comp == compZstd {
		return zstdDec.DecodeAll(body, nil)
	}
	out := lz4BlockDecompress(body)
	if len(out) == 0 {
		return nil, errLZ4
	}
	return out, nil
}

// lz4BlockDecompress decodes a raw LZ4 block (net.jpountz style: no frame header and no
// stored uncompressed size, so the output grows dynamically). Ported from the reference
// client's codec.lz4_block_decompress, including byte-by-byte copies for overlapping
// matches (offset < length). Best-effort: it returns what it decoded if the block ends
// or is truncated, leaving msgpack parsing to judge the result.
func lz4BlockDecompress(src []byte) []byte {
	var out []byte
	i, n := 0, len(src)
	for i < n {
		token := src[i]
		i++
		litLen := int(token >> 4)
		if litLen == 15 {
			for i < n {
				b := src[i]
				i++
				litLen += int(b)
				if b != 0xFF {
					break
				}
			}
		}
		if i+litLen > n { // truncated literal run — copy the remainder and stop
			out = append(out, src[i:n]...)
			break
		}
		out = append(out, src[i:i+litLen]...)
		i += litLen
		if i >= n {
			break // final literal run (no trailing match)
		}
		if i+2 > n {
			break
		}
		offset := int(src[i]) | int(src[i+1])<<8 // little-endian
		i += 2
		if offset == 0 || offset > len(out) {
			break
		}
		matchLen := int(token&0x0F) + 4
		if token&0x0F == 15 {
			for i < n {
				b := src[i]
				i++
				matchLen += int(b)
				if b != 0xFF {
					break
				}
			}
		}
		start := len(out) - offset
		for j := 0; j < matchLen; j++ { // byte-by-byte handles overlapping matches
			out = append(out, out[start+j])
		}
	}
	return out
}

// unpackMsgpack decodes the body as MessagePack, tolerating 1-4 leading service bytes
// MAX sometimes prefixes (it tries offsets 0..4). A candidate is accepted only if it
// decodes AND consumes the whole remainder — mirroring python msgpack's ExtraData
// check, so a stray leading byte isn't mistaken for a tiny scalar value.
//
// Maps are decoded untyped (map[interface{}]interface{}): MAX keys presence/chat maps
// by a boxed-id ext (a non-string key), which the default string-keyed map decoder
// rejects ("invalid code=c7 decoding string length"). jsonSafe stringifies the keys.
func unpackMsgpack(body []byte) (interface{}, bool) {
	for off := 0; off <= 4 && off < len(body); off++ {
		r := bytes.NewReader(body[off:])
		dec := msgpack.NewDecoder(r)
		dec.SetMapDecoder(func(d *msgpack.Decoder) (interface{}, error) { return d.DecodeUntypedMap() })
		var v interface{}
		if err := dec.Decode(&v); err == nil && r.Len() == 0 {
			return v, true
		}
	}
	return nil, false
}

// rawMessage keeps an undecodable (e.g. compact-encoded) frame's bytes verbatim so no
// data is lost; the viewer renders them as hex.
func rawMessage(msg decoders.Message, raw []byte) decoders.Message {
	msg.ContentType = "application/octet-stream"
	msg.Payload = raw
	return msg
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
