package decode

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Cutting a macOS per-process capture down to the browser that was launched.
//
// The pktap capture filters in the kernel by process *name*, which is as narrow as a
// filter fixed at capture start can be: the name is shared by every Chrome-family
// instance on the machine, and the pids that exist when tcpdump starts can be excluded
// but the ones that appear later cannot. So a browser the user opens mid-capture still
// lands in the pcap.
//
// The pid is the thing that identifies one instance, and the source learns it — by
// watching its own browser's children — only after the capture is already running. That
// is why the narrowing finishes here rather than in the filter: by the time the session
// closes, the source knows every pid its network process used, including one it was
// replaced by, and every packet on disk carries the pid that owned it.

// pcap-ng block types we care about. Everything else is copied through untouched, which
// is what keeps this forward-compatible: a block this doesn't understand is not a packet,
// so it cannot be another process's traffic.
const (
	blockSectionHeader    = 0x0A0D0D0A
	blockEnhancedPacket   = 0x00000006
	blockSimplePacket     = 0x00000003
	sectionByteOrderMagic = 0x1A2B3C4D
)

// Offsets within an Enhanced Packet Block's *body* — that is, after the 8 bytes of block
// type and total length this code reads separately: interface id (4), timestamp high and
// low (8), captured length (4), original length (4), then the captured bytes.
const (
	epbCapturedLenOffset = 12
	epbPacketDataOffset  = 20
)

// maxBlockBytes bounds what a corrupt length field can make this allocate. A block holds
// one packet, and tcpdump's default snaplen is 256 KiB, so this is generous by three
// orders of magnitude while still refusing a length that is obviously garbage.
const maxBlockBytes = 64 << 20

// PruneResult reports what a prune did, so the caller can log it and a caller's test can
// assert the capture actually shrank.
type PruneResult struct {
	Before, After          int64
	PacketsIn, PacketsKept int
	// PacketsUnknown is packets kept because their pktap header could not be read. A
	// non-zero count here with nothing dropped is the signature of a parsing problem
	// rather than a capture that genuinely belonged to one process.
	PacketsUnknown int
}

// ErrNotPktap is returned when the file is not a pcap-ng recorded off a pktap interface,
// so there is no per-packet process to prune by. The file is left untouched.
var ErrNotPktap = errors.New("not a PKTAP pcap-ng capture")

// PrunePcapngByPID rewrites the pcap-ng at path keeping only packets owned by a pid in
// keep, and returns what it cut.
//
// The rewrite goes to a temp file in the same directory and is renamed over the original,
// so a failure part-way leaves the capture as it was rather than truncated — the file is
// the only copy of the session's packets.
//
// An empty keep set is refused. It would mean "drop every packet", which is never what a
// caller means: it means the source failed to identify its browser, and silently emptying
// the capture would hide that.
func PrunePcapngByPID(path string, keep map[int32]bool) (PruneResult, error) {
	var res PruneResult
	if len(keep) == 0 {
		return res, errors.New("prune by pid: empty keep set")
	}

	// Refuse anything that isn't PKTAP before touching the file: a plain Ethernet pcap-ng
	// has no pid in its packet data, and reading one out of the frame would be nonsense
	// that happens to match.
	f, err := os.Open(path)
	if err != nil {
		return res, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil {
		res.Before = fi.Size()
	}
	if lt := pcapngLinkType(bufio.NewReader(f)); lt != linkTypePKTAP {
		return res, fmt.Errorf("%w (link type %d)", ErrNotPktap, lt)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return res, err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".prune-pid-*")
	if err != nil {
		return res, err
	}
	defer os.Remove(tmp.Name()) // no-op once the rename below succeeds

	w := bufio.NewWriter(tmp)
	if err := pruneBlocks(bufio.NewReader(f), w, keep, &res); err != nil {
		tmp.Close()
		return res, err
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return res, err
	}
	if fi, err := tmp.Stat(); err == nil {
		res.After = fi.Size()
	}
	if err := tmp.Close(); err != nil {
		return res, err
	}
	return res, os.Rename(tmp.Name(), path)
}

// pruneBlocks copies pcap-ng blocks from r to w, dropping the packet blocks whose owning
// pid is not in keep.
//
// Byte order is per section and comes from the Section Header Block, so it is re-read at
// every SHB rather than assumed once: concatenated captures are legal pcap-ng and a
// second section may disagree with the first.
func pruneBlocks(r *bufio.Reader, w *bufio.Writer, keep map[int32]bool, res *PruneResult) error {
	bo := binary.ByteOrder(binary.LittleEndian)
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				return nil // a clean end between blocks
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				// A capture cut off mid-block — tcpdump killed as the session ended. The
				// partial block is unparseable and cannot be a packet we want, so ending
				// here leaves a valid file rather than erroring on the whole prune.
				return nil
			}
			return err
		}
		blockType := bo.Uint32(hdr[0:4])
		if blockType == blockSectionHeader {
			// A Section Header Block's own type is byte-order independent by design
			// (0x0A0D0D0A reads the same either way), which is what lets it be recognised
			// before the section's order is known. Its length is not, so the order has to
			// be settled from the byte-order magic — the first field of the body — before
			// the length two fields earlier can be read.
			magic, err := r.Peek(4)
			if err != nil {
				return err
			}
			switch {
			case binary.BigEndian.Uint32(magic) == sectionByteOrderMagic:
				bo = binary.BigEndian
			case binary.LittleEndian.Uint32(magic) == sectionByteOrderMagic:
				bo = binary.LittleEndian
			default:
				return errors.New("prune by pid: section header with no byte-order magic")
			}
		}
		total := bo.Uint32(hdr[4:8])
		if total < 12 || total%4 != 0 || total > maxBlockBytes {
			return fmt.Errorf("prune by pid: block type %#x has invalid length %d", blockType, total)
		}
		body := make([]byte, int(total)-8)
		if _, err := io.ReadFull(r, body); err != nil {
			return fmt.Errorf("prune by pid: short block type %#x: %w", blockType, err)
		}

		if blockType == blockEnhancedPacket || blockType == blockSimplePacket {
			res.PacketsIn++
			if !keepPacketBlock(blockType, body, bo, keep, res) {
				continue // dropped: neither header nor body is written
			}
			res.PacketsKept++
		}
		if _, err := w.Write(hdr); err != nil {
			return err
		}
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
}

// keepPacketBlock decides one packet block. Anything it cannot read the pid out of is
// kept and counted — a capture that shrinks to nothing because of a layout change would
// be far worse than one that doesn't shrink at all.
func keepPacketBlock(blockType uint32, body []byte, bo binary.ByteOrder,
	keep map[int32]bool, res *PruneResult) bool {
	if blockType != blockEnhancedPacket {
		// A Simple Packet Block carries no captured length of its own beyond the original
		// length and no options, and tcpdump does not write them. Keep rather than guess.
		res.PacketsUnknown++
		return true
	}
	if len(body) < epbCapturedLenOffset+4 {
		res.PacketsUnknown++
		return true
	}
	capLen := bo.Uint32(body[epbCapturedLenOffset : epbCapturedLenOffset+4])
	if uint64(epbPacketDataOffset)+uint64(capLen) > uint64(len(body)) {
		res.PacketsUnknown++
		return true
	}
	pid, _, ok := pktapPID(body[epbPacketDataOffset : epbPacketDataOffset+int(capLen)])
	if !ok {
		res.PacketsUnknown++
		return true
	}
	return keep[pid]
}
