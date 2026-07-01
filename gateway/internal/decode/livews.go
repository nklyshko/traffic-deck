package decode

// Live WebSocket decode. A WebSocket connection begins as an HTTP/1.1 Upgrade request
// answered with 101 Switching Protocols (handled in livehttp.go); after that both
// directions carry RFC 6455 frames over the same TLS-decrypted byte streams. We parse
// those frames here and emit a WsMessage per frame, like the custom-decoder live path.

import (
	"bufio"
	"encoding/binary"
	"io"
)

// wsFrameOpName maps an RFC 6455 opcode byte to the short label the viewer uses (the
// same labels as the tshark-path wsOpcodeName, which takes tshark's decimal string).
func wsFrameOpName(op byte) string {
	switch op {
	case 0x0:
		return "continuation"
	case 0x1:
		return "text"
	case 0x2:
		return "binary"
	case 0x8:
		return "close"
	case 0x9:
		return "ping"
	case 0xA:
		return "pong"
	default:
		return "reserved"
	}
}

// readWSFrames parses RFC 6455 frames from one direction of an upgraded connection and
// calls emit per frame until r hits EOF (the connection's byte stream is closed). It
// unmasks frames that carry the mask bit (client→server frames are masked), and caps the
// kept payload at maxLiveBody while still consuming the whole frame to stay aligned.
func readWSFrames(r *bufio.Reader, fromClient bool, emit func(opcode string, fromClient bool, payload []byte)) {
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return
		}
		opcode := hdr[0] & 0x0f
		masked := hdr[1]&0x80 != 0
		ln := uint64(hdr[1] & 0x7f)
		switch ln {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(r, ext[:]); err != nil {
				return
			}
			ln = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(r, ext[:]); err != nil {
				return
			}
			ln = binary.BigEndian.Uint64(ext[:])
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(r, mask[:]); err != nil {
				return
			}
		}
		keep := ln
		if keep > uint64(maxLiveBody) {
			keep = uint64(maxLiveBody)
		}
		payload := make([]byte, keep)
		if _, err := io.ReadFull(r, payload); err != nil {
			return
		}
		if rest := ln - keep; rest > 0 {
			if _, err := io.CopyN(io.Discard, r, int64(rest)); err != nil {
				return
			}
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i&3]
			}
		}
		emit(wsFrameOpName(opcode), fromClient, payload)
	}
}
