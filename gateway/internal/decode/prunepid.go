package decode

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	gonet "net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/google/gopacket"
	gplayers "github.com/google/gopacket/layers"
)

// Cutting a macOS per-process capture down to the browser that was launched.
//
// The pktap capture filters in the kernel by process *name*, which is as narrow as a
// filter fixed at capture start can be: the name is shared by every Chrome-family
// instance on the machine, and the pids that exist when tcpdump starts can be excluded
// but the ones that appear later cannot. So a browser the user opens mid-capture still
// lands in the pcap — observed in the wild as 91% of one capture, because a second
// capture launched stable Chrome a minute in and Canary's helper shares its name.
//
// The pid is the thing that identifies one instance, and the source learns it — by
// watching its own browser's children — only after the capture is already running. That
// is why the narrowing finishes here rather than in the filter: by the time the session
// closes, the source knows every pid its network process used, including one it was
// replaced by, and every packet on disk carries the pid that owned it.
//
// Where it carries it is the part worth writing down. A *live* pktap interface hands out
// DLT_PKTAP frames with a per-packet header, but tcpdump writing a file does not store
// that. It decapsulates, records the interface's real link type (Ethernet), and puts the
// process into pcap-ng structure instead: a Process Information Block per process, and an
// option on every packet naming which one. Assuming the per-packet header meant this
// pruner refused every real capture with "not a PKTAP pcap-ng capture (link type 1)".

// pcap-ng block types. Everything not named here is copied through untouched, which keeps
// this forward-compatible: a block this does not understand is not a packet, so it cannot
// be another process's traffic.
const (
	blockSectionHeader  = 0x0A0D0D0A
	blockInterfaceDesc  = 0x00000001
	blockEnhancedPacket = 0x00000006
	blockSimplePacket   = 0x00000003
	// blockProcessInfo is Apple's addition: pid at body offset 0, process name in an
	// option. Packets reference it by its position among the PIBs in the file.
	blockProcessInfo      = 0x80000001
	sectionByteOrderMagic = 0x1A2B3C4D
)

// optProcessIndex is the per-packet option holding the index of the owning process's
// Process Information Block. Apple's option space starts at 0x8000; this is the only one
// of theirs read here (the others carry service class, flow id and direction).
const optProcessIndex = 0x8001

// Offsets within an Enhanced Packet Block's *body* — after the 8 bytes of block type and
// total length read separately: interface id (4), timestamp high and low (8), captured
// length (4), original length (4), then the captured bytes, then options.
const (
	epbInterfaceOffset   = 0
	epbCapturedLenOffset = 12
	epbPacketDataOffset  = 20
)

// idbLinkTypeOffset is where an Interface Description Block's body starts: the link type,
// as a uint16.
const idbLinkTypeOffset = 0

// maxBlockBytes bounds what a corrupt length field can make this allocate. A block holds
// one packet, and tcpdump's default snaplen is 256 KiB, so this is generous by three
// orders of magnitude while still refusing a length that is obviously garbage.
const maxBlockBytes = 64 << 20

// ConnKey identifies a connection by its two endpoints ("ip:port"), without a direction —
// a flow and a packet name the same connection whichever way the bytes were going.
type ConnKey struct{ A, B string }

// NewConnKey orders the endpoints so both directions produce the same key.
func NewConnKey(x, y string) ConnKey {
	if x > y {
		x, y = y, x
	}
	return ConnKey{A: x, B: y}
}

// PruneResult reports what a prune did, so the caller can log it and a caller's test can
// assert the capture actually shrank.
type PruneResult struct {
	Before, After          int64
	PacketsIn, PacketsKept int
	// PacketsUnknown is packets kept because their owning process could not be read. A
	// non-zero count here with nothing dropped is the signature of a parsing problem
	// rather than a capture that genuinely belonged to one process.
	PacketsUnknown int
	// PIDsSeen is every process the capture holds packets for, whether kept or not. The
	// difference between this and what the source reported is the whole point of the
	// exercise, so it is worth logging.
	PIDsSeen map[int32]bool
	// Kept and Dropped are the connections observed carrying packets on each side of the
	// decision. They exist so flows can be narrowed the same way the packets were: a flow
	// on a connection that only ever carried dropped packets belonged to another process.
	//
	// Both are needed, and "not in Kept" is not good enough. A connection whose frame
	// could not be parsed lands in neither, and a caller that deleted everything outside
	// Kept would delete those too — turning a parsing gap into lost flows.
	Kept, Dropped map[ConnKey]bool
}

// ForeignConns are the connections that carried only packets belonging to other processes.
// Deleting the flows on these is safe in the way the packet prune is safe: it requires
// having positively seen the connection owned by a process we did not launch, and never
// seen it owned by one we did.
func (r PruneResult) ForeignConns() map[ConnKey]bool {
	foreign := map[ConnKey]bool{}
	for c := range r.Dropped {
		if !r.Kept[c] {
			foreign[c] = true
		}
	}
	return foreign
}

// ErrNoProcessInfo is returned when the file carries no Process Information Blocks, so
// there is nothing to say which process owned which packet. The file is left untouched.
var ErrNoProcessInfo = errors.New("capture has no per-packet process information")

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
	res := PruneResult{
		PIDsSeen: map[int32]bool{},
		Kept:     map[ConnKey]bool{},
		Dropped:  map[ConnKey]bool{},
	}
	if len(keep) == 0 {
		return res, errors.New("prune by pid: empty keep set")
	}

	f, err := os.Open(path)
	if err != nil {
		return res, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil {
		res.Before = fi.Size()
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".prune-pid-*")
	if err != nil {
		return res, err
	}
	defer os.Remove(tmp.Name()) // no-op once the rename below succeeds

	w := bufio.NewWriter(tmp)
	sawProcessInfo, err := pruneBlocks(bufio.NewReader(f), w, keep, &res)
	if err != nil {
		tmp.Close()
		return res, err
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return res, err
	}
	if err := tmp.Close(); err != nil {
		return res, err
	}
	// Checked after the pass rather than by sniffing first: the blocks that say which
	// process owns what are scattered through the file, not in a header. With none of
	// them every packet is unattributable and was kept, so the rewrite is a copy — and
	// renaming a copy over the original would be pointless risk.
	if !sawProcessInfo {
		return res, ErrNoProcessInfo
	}
	if fi, err := os.Stat(tmp.Name()); err == nil {
		res.After = fi.Size()
	}
	return res, os.Rename(tmp.Name(), path)
}

// pruneBlocks copies pcap-ng blocks from r to w, dropping the packet blocks whose owning
// pid is not in keep. It reports whether the file said anything about processes at all.
//
// Byte order is per section and comes from the Section Header Block, so it is re-read at
// every SHB rather than assumed once: concatenated captures are legal pcap-ng and a
// second section may disagree with the first.
func pruneBlocks(r *bufio.Reader, w *bufio.Writer, keep map[int32]bool, res *PruneResult) (bool, error) {
	bo := binary.ByteOrder(binary.LittleEndian)
	// pids indexed by the order their Process Information Blocks appear, which is how
	// packets refer to them. Several blocks can name the same pid — tcpdump writes one
	// with the process UUID and one without — so this is a list, not a set.
	var pids []int32
	// linkTypes indexed by interface id, for decoding a kept packet's frame far enough to
	// read its connection endpoints.
	var linkTypes []gplayers.LinkType
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				return len(pids) > 0, nil // a clean end between blocks
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				// A capture cut off mid-block — tcpdump killed as the session ended. The
				// partial block is unparseable and cannot be a packet we want, so ending
				// here leaves a valid file rather than erroring on the whole prune.
				return len(pids) > 0, nil
			}
			return len(pids) > 0, err
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
				return len(pids) > 0, err
			}
			switch {
			case binary.BigEndian.Uint32(magic) == sectionByteOrderMagic:
				bo = binary.BigEndian
			case binary.LittleEndian.Uint32(magic) == sectionByteOrderMagic:
				bo = binary.LittleEndian
			default:
				return len(pids) > 0, errors.New("prune by pid: section header with no byte-order magic")
			}
			// A new section restarts both numbering spaces.
			pids, linkTypes = nil, nil
		}
		total := bo.Uint32(hdr[4:8])
		if total < 12 || total%4 != 0 || total > maxBlockBytes {
			return len(pids) > 0, fmt.Errorf("prune by pid: block type %#x has invalid length %d", blockType, total)
		}
		body := make([]byte, int(total)-8)
		if _, err := io.ReadFull(r, body); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				// The same truncation as above, caught one field later: a capture ends
				// mid-block whenever tcpdump is killed as the session stops, which is
				// every session. Stop here and keep what was written — the partial block
				// cannot be parsed, so it cannot be a packet worth keeping.
				return len(pids) > 0, nil
			}
			return len(pids) > 0, fmt.Errorf("prune by pid: short block type %#x: %w", blockType, err)
		}

		switch blockType {
		case blockProcessInfo:
			if len(body) >= 8 { // pid, plus the trailing total length
				pids = append(pids, int32(bo.Uint32(body[0:4])))
			}
		case blockInterfaceDesc:
			lt := gplayers.LinkType(0)
			if len(body) >= idbLinkTypeOffset+2 {
				lt = gplayers.LinkType(bo.Uint16(body[idbLinkTypeOffset : idbLinkTypeOffset+2]))
			}
			linkTypes = append(linkTypes, lt)
		case blockEnhancedPacket, blockSimplePacket:
			res.PacketsIn++
			if !keepPacketBlock(blockType, body, bo, pids, linkTypes, keep, res) {
				continue // dropped: neither header nor body is written
			}
			res.PacketsKept++
		}
		// Everything that survives is written back byte for byte, including every Process
		// Information Block — dropping one would renumber the rest and reassign packets to
		// the wrong process.
		if _, err := w.Write(hdr); err != nil {
			return len(pids) > 0, err
		}
		if _, err := w.Write(body); err != nil {
			return len(pids) > 0, err
		}
	}
}

// keepPacketBlock decides one packet block. Anything it cannot read the owner of is kept
// and counted — a capture that shrinks to nothing because of a layout change would be far
// worse than one that does not shrink at all.
func keepPacketBlock(blockType uint32, body []byte, bo binary.ByteOrder,
	pids []int32, linkTypes []gplayers.LinkType, keep map[int32]bool, res *PruneResult) bool {
	if blockType != blockEnhancedPacket {
		// A Simple Packet Block carries no options, so it cannot name its process at all;
		// tcpdump does not write them. Keep rather than guess.
		res.PacketsUnknown++
		return true
	}
	if len(body) < epbPacketDataOffset {
		res.PacketsUnknown++
		return true
	}
	capLen := bo.Uint32(body[epbCapturedLenOffset : epbCapturedLenOffset+4])
	if uint64(epbPacketDataOffset)+uint64(capLen) > uint64(len(body)) {
		res.PacketsUnknown++
		return true
	}
	idx, ok := epbOptionUint32(body, bo, capLen, optProcessIndex)
	if !ok || uint64(idx) >= uint64(len(pids)) {
		res.PacketsUnknown++
		return true
	}
	pid := pids[idx]
	res.PIDsSeen[pid] = true
	kept := keep[pid]

	// Note which connection this packet put on which side, so the caller can narrow the
	// flow list by the same evidence. A frame we cannot read the endpoints out of is
	// simply not recorded: it still counts for the packet decision above, but it must not
	// contribute to a claim about who owns a connection.
	lt := gplayers.LinkType(0)
	if iface := bo.Uint32(body[epbInterfaceOffset : epbInterfaceOffset+4]); uint64(iface) < uint64(len(linkTypes)) {
		lt = linkTypes[iface]
	}
	if conn, ok := recordConn(body[epbPacketDataOffset:epbPacketDataOffset+int(capLen)], lt); ok {
		if kept {
			res.Kept[conn] = true
		} else {
			res.Dropped[conn] = true
		}
	}
	return kept
}

// epbOptionUint32 finds a 4-byte option by code in an Enhanced Packet Block's option list,
// which follows the captured bytes padded up to a 4-byte boundary.
//
// Each option is a 2-byte code, a 2-byte length and a value padded the same way; code 0
// ends the list. The block's own trailing total length is the last 4 bytes and is not an
// option, so the walk stops short of it.
func epbOptionUint32(body []byte, bo binary.ByteOrder, capLen uint32, want uint16) (uint32, bool) {
	off := epbPacketDataOffset + int((capLen+3)&^3)
	for off+4 <= len(body)-4 {
		code := bo.Uint16(body[off : off+2])
		length := int(bo.Uint16(body[off+2 : off+4]))
		if code == 0 { // opt_endofopt
			return 0, false
		}
		if code == want && length == 4 && off+8 <= len(body) {
			return bo.Uint32(body[off+4 : off+8]), true
		}
		off += 4 + ((length + 3) &^ 3)
	}
	return 0, false
}

// recordConn reads the connection endpoints out of one captured frame.
//
// Lazy decoding stops as soon as the transport layer is reached, so nothing parses a
// payload.
func recordConn(frame []byte, linkType gplayers.LinkType) (ConnKey, bool) {
	if len(frame) == 0 {
		return ConnKey{}, false
	}
	pkt := gopacket.NewPacket(frame, linkType, gopacket.Lazy)
	net := pkt.NetworkLayer()
	if net == nil {
		return ConnKey{}, false
	}
	var srcPort, dstPort uint16
	switch t := pkt.TransportLayer().(type) {
	case *gplayers.TCP:
		srcPort, dstPort = uint16(t.SrcPort), uint16(t.DstPort)
	case *gplayers.UDP:
		srcPort, dstPort = uint16(t.SrcPort), uint16(t.DstPort)
	default:
		// No ports (ICMP, ARP): there is no connection here to attribute a flow to.
		return ConnKey{}, false
	}
	flow := net.NetworkFlow()
	// Built exactly as the decoders build a flow's src_addr/dst_addr (livetcp.go) — same
	// helper, same order — so the two strings are equal by construction rather than by
	// coincidence. Anything else would silently fail to match on IPv6, which needs
	// brackets, and a mismatch here means flows are never attributed at all.
	return NewConnKey(
		gonet.JoinHostPort(flow.Src().String(), strconv.Itoa(int(srcPort))),
		gonet.JoinHostPort(flow.Dst().String(), strconv.Itoa(int(dstPort))),
	), true
}
