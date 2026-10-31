package decode

// Guards between a capture file and gopacket's readers. Both pcapgo readers trust the
// file's own length fields when they allocate: the classic reader makes a buffer of a
// record's captured length (checked only against the snap length — which is also in the
// file), and the pcapng reader makes one of a packet block's captured length without
// comparing it to the block that holds it. Either way a few bytes can demand 4 GiB per
// packet. Imported captures are untrusted, and the fuzzer found this as a stall, so these
// guards check the lengths first and end the decode cleanly (as if the file stopped there)
// rather than let gopacket allocate.

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// maxConsecutiveReadErrors ends a decode whose reader keeps failing without returning a
// packet. Every caller loops on ReadPacketData and skips errors (a truncated record in a
// growing file is expected), which spins forever if a reader fails without consuming
// input. A corrupt region costs at least a header per error, so this many in a row is
// over a hundred kilobytes of unparseable bytes (classic pcap has no way to resync past
// that anyway) — or no progress at all.
const maxConsecutiveReadErrors = 10_000

// progressGuard turns a reader that has stopped making progress into a clean end.
type progressGuard struct {
	packetReader
	errs int
}

func (g *progressGuard) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := g.packetReader.ReadPacketData()
	switch {
	case err == nil:
		g.errs = 0
	case err != io.EOF:
		if g.errs++; g.errs > maxConsecutiveReadErrors {
			log.Printf("decode: capture reader failed %d times in a row without a packet (last: %v); stopping",
				g.errs, err)
			return nil, ci, io.EOF
		}
	}
	return data, ci, err
}

// recoveringReader contains panics from pcapgo's parsers, which are reachable from file
// contents: an Interface Description Block whose timestamp resolution is 10^64 or 2^64
// overflows the scale to zero and divides by it (in readInterfaceDescriptor, and again per
// packet in convertTime). Such a file is malformed, not a reason to crash the importer, so
// a panic ends the capture there. The reader's state after a panic is unknown, so it is
// not called again.
type recoveringReader struct {
	packetReader
	broken bool
}

func (r *recoveringReader) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if r.broken {
		return nil, ci, io.EOF
	}
	defer func() {
		if p := recover(); p != nil {
			r.broken = true
			log.Printf("decode: capture reader failed on malformed input (%v); stopping", p)
			data, ci, err = nil, gopacket.CaptureInfo{}, io.EOF
		}
	}()
	return r.packetReader.ReadPacketData()
}

// newNgReader is pcapgo.NewNgReader with the same containment: it parses the first section
// and interface on construction, where the same panic can happen.
func newNgReader(r io.Reader, opts pcapgo.NgReaderOptions) (rd *pcapgo.NgReader, err error) {
	defer func() {
		if p := recover(); p != nil {
			rd, err = nil, fmt.Errorf("malformed pcapng: %v", p)
		}
	}()
	return pcapgo.NewNgReader(r, opts)
}

// classicGuard checks each classic-pcap record header before pcapgo allocates for it.
// pcapgo.Reader reads records straight from br, so the next header is what Peek sees.
type classicGuard struct {
	*pcapgo.Reader
	br *bufio.Reader
	bo binary.ByteOrder
}

func (g *classicGuard) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if hdr, err := g.br.Peek(16); err == nil {
		if incl := g.bo.Uint32(hdr[8:12]); incl > maxBlockBytes {
			log.Printf("decode: classic pcap record claims %d captured bytes (max %d); stopping here",
				incl, maxBlockBytes)
			return nil, gopacket.CaptureInfo{}, io.EOF
		}
	}
	return g.Reader.ReadPacketData()
}

// ngGuard sits under pcapgo's pcapng reader and hands it one whole, checked block at a
// time. A block longer than maxBlockBytes, or a packet block whose captured length does not
// fit inside it, ends the stream at that block boundary. Bytes pass through unchanged.
type ngGuard struct {
	r    *bufio.Reader
	bo   binary.ByteOrder
	buf  []byte // the current block, not yet handed out
	err  error  // returned once buf is drained
	done bool
}

func newNgGuard(r *bufio.Reader) *ngGuard { return &ngGuard{r: r, bo: binary.LittleEndian} }

func (g *ngGuard) Read(p []byte) (int, error) {
	for len(g.buf) == 0 {
		if g.err != nil {
			// Report a truncation once, then end: pcapgo retries after an error, and an
			// "unexpected EOF" returned forever kept it retrying — and allocating — forever.
			err := g.err
			g.err = io.EOF
			return 0, err
		}
		g.buf, g.err = g.nextBlock()
	}
	n := copy(p, g.buf)
	g.buf = g.buf[n:]
	return n, nil
}

// Block types whose body starts with interface id, timestamp, captured length and packet
// length — the obsolete Packet Block and the Enhanced Packet Block. pcapgo allocates the
// captured length for these.
const (
	ngObsoletePacket = 2
	ngEnhancedPacket = 6
)

func (g *ngGuard) nextBlock() ([]byte, error) {
	hdr, err := g.r.Peek(8)
	if err != nil {
		if len(hdr) > 0 && err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		rest := append([]byte(nil), hdr...)
		_, _ = g.r.Discard(len(rest))
		return rest, err
	}
	typ := g.bo.Uint32(hdr[0:4])
	if typ == blockSectionHeader {
		// The byte order is settled by the section's magic, which follows the length.
		if b, err := g.r.Peek(12); err == nil {
			switch {
			case binary.BigEndian.Uint32(b[8:12]) == sectionByteOrderMagic:
				g.bo = binary.BigEndian
			case binary.LittleEndian.Uint32(b[8:12]) == sectionByteOrderMagic:
				g.bo = binary.LittleEndian
			}
		}
	}
	total := g.bo.Uint32(hdr[4:8])
	if total < 12 || total > maxBlockBytes {
		return g.stop("block type %#x has length %d", typ, total)
	}
	block := make([]byte, total)
	n, err := io.ReadFull(g.r, block)
	// Check the captured length even for a block cut short: pcapgo reads it from the
	// partial header and allocates it before noticing the bytes ran out.
	if typ == ngObsoletePacket || typ == ngEnhancedPacket {
		var room uint32
		if total >= 32 { // header 8 + fields 20 + trailing length 4
			room = total - 32
		}
		if total < 28 || (n >= 24 && g.bo.Uint32(block[20:24]) > room) {
			return g.stop("packet block of %d bytes claims a larger captured length", total)
		}
	}
	if err != nil {
		return block[:n], err // a block cut short: let pcapgo see the truncation
	}
	return block, nil
}

func (g *ngGuard) stop(format string, args ...any) ([]byte, error) {
	if !g.done {
		g.done = true
		log.Printf("decode: pcapng "+format+"; stopping at this block", args...)
	}
	return nil, io.EOF
}
