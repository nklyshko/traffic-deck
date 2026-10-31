package decode

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"testing"
)

// FuzzPruneBlocks runs arbitrary bytes through the pcapng-by-pid rewriter. It must never
// panic, and its reads are bounded by maxBlockBytes whatever a block claims.
func FuzzPruneBlocks(f *testing.F) {
	shb := []byte{0x0A, 0x0D, 0x0D, 0x0A, 28, 0, 0, 0, 0x4D, 0x3C, 0x2B, 0x1A, 1, 0, 0, 0,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 28, 0, 0, 0}
	f.Add(shb)
	f.Add(append(append([]byte{}, shb...), 6, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x7F))
	f.Fuzz(func(_ *testing.T, data []byte) {
		var res PruneResult
		_, _ = pruneBlocks(bufio.NewReader(bytes.NewReader(data)), bufio.NewWriter(io.Discard),
			map[int32]bool{1: true}, &res)
	})
}

// FuzzSocksHandshake drives the SOCKS4/5 handshake parser with arbitrary client and proxy
// bytes until it stops making progress. It must never panic.
func FuzzSocksHandshake(f *testing.F) {
	f.Add(true, []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x01, 'a', 0x01, 0xbb},
		[]byte{0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	f.Add(false, []byte{0x04, 0x01, 0x01, 0xbb, 1, 2, 3, 4, 0}, []byte{0x00, 0x5a, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(_ *testing.T, v5 bool, req, resp []byte) {
		version := socksV4
		if v5 {
			version = socksV5
		}
		h := newSocksHandshake(version)
		h.req, h.resp = append([]byte{}, req...), append([]byte{}, resp...)
		for i := 0; i < 16; i++ {
			if h.step() != socksAdvanced {
				break
			}
		}
	})
}

// FuzzLiveDecode runs the whole live pipeline — pcap/pcapng reading, TCP and QUIC
// reassembly, TLS, HTTP/1.1, HTTP/2, WebSocket, SOCKS/CONNECT and decoder dispatch — over
// mutated captures, seeded with the head of the sample capture so mutations reach past the
// file header. It must never panic.
func FuzzLiveDecode(f *testing.F) {
	if b, err := os.ReadFile("testdata/sample.pcap"); err == nil {
		for _, n := range []int{24 + 16 + 64, 4096, 32 << 10} {
			if n <= len(b) {
				f.Add(b[:n])
			}
		}
	}
	f.Add([]byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0})
	f.Fuzz(func(_ *testing.T, pcap []byte) {
		_ = LiveDecode(bytes.NewReader(pcap), "", Sinks{
			OnFlow: func(*Flow, bool) {}, OnMsg: func(*WsMessage) {}, OnUndecoded: func(*UndecodedConn) {}})
	})
}
