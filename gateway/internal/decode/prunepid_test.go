package decode

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// A pcap-ng in the shape Apple's tcpdump actually writes a per-process capture: the
// interface's own link type (Ethernet, not DLT_PKTAP), a Process Information Block per
// process, and an option on every packet naming which one.
//
// The layout below was read off a real capture rather than from documentation — assuming
// the live interface's per-packet header instead is what made this pruner refuse every
// real file it was given.

func shb() []byte {
	b := make([]byte, 28)
	binary.LittleEndian.PutUint32(b[0:], blockSectionHeader)
	binary.LittleEndian.PutUint32(b[4:], 28)
	binary.LittleEndian.PutUint32(b[8:], sectionByteOrderMagic)
	binary.LittleEndian.PutUint16(b[12:], 1) // major version
	binary.LittleEndian.PutUint16(b[14:], 0)
	binary.LittleEndian.PutUint64(b[16:], ^uint64(0)) // section length: unknown
	binary.LittleEndian.PutUint32(b[24:], 28)
	return b
}

func idb(linkType uint16) []byte {
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b[0:], blockInterfaceDesc)
	binary.LittleEndian.PutUint32(b[4:], 20)
	binary.LittleEndian.PutUint16(b[8:], linkType)
	binary.LittleEndian.PutUint32(b[12:], 262144) // snaplen
	binary.LittleEndian.PutUint32(b[16:], 20)
	return b
}

// pib is a Process Information Block: the pid, then the process name as option 2.
func pib(pid int32, name string) []byte {
	nameLen := (len(name) + 3) &^ 3
	total := 12 + 4 + 4 + nameLen + 4 // header+trailer, pid, option hdr+value, endofopt
	b := make([]byte, total)
	binary.LittleEndian.PutUint32(b[0:], blockProcessInfo)
	binary.LittleEndian.PutUint32(b[4:], uint32(total))
	binary.LittleEndian.PutUint32(b[8:], uint32(pid))
	binary.LittleEndian.PutUint16(b[12:], 2) // option code 2: process name
	binary.LittleEndian.PutUint16(b[14:], uint16(len(name)))
	copy(b[16:], name)
	binary.LittleEndian.PutUint32(b[16+nameLen:], 0) // opt_endofopt
	binary.LittleEndian.PutUint32(b[total-4:], uint32(total))
	return b
}

// epb is an Enhanced Packet Block carrying `frame`, tagged with the process at `pibIndex`.
func epb(frame []byte, pibIndex uint32) []byte {
	padded := (len(frame) + 3) &^ 3
	total := 32 + padded + 8 + 4 // header+trailer+fixed, frame, one option, endofopt
	b := make([]byte, total)
	binary.LittleEndian.PutUint32(b[0:], blockEnhancedPacket)
	binary.LittleEndian.PutUint32(b[4:], uint32(total))
	binary.LittleEndian.PutUint32(b[8:], 0)                   // interface id
	binary.LittleEndian.PutUint32(b[20:], uint32(len(frame))) // captured length
	binary.LittleEndian.PutUint32(b[24:], uint32(len(frame))) // original length
	copy(b[28:], frame)
	opt := 28 + padded
	binary.LittleEndian.PutUint16(b[opt:], optProcessIndex)
	binary.LittleEndian.PutUint16(b[opt+2:], 4)
	binary.LittleEndian.PutUint32(b[opt+4:], pibIndex)
	binary.LittleEndian.PutUint32(b[opt+8:], 0) // opt_endofopt
	binary.LittleEndian.PutUint32(b[total-4:], uint32(total))
	return b
}

// tcpFrame is an Ethernet/IPv4/TCP frame with the given endpoints — enough for the pruner
// to read a connection out of, and nothing more.
func tcpFrame(srcIP, dstIP [4]byte, srcPort, dstPort uint16) []byte {
	f := make([]byte, 54)
	copy(f[12:14], []byte{0x08, 0x00}) // ethertype IPv4
	f[14] = 0x45                       // version 4, IHL 5
	binary.BigEndian.PutUint16(f[16:], 40)
	f[22] = 64 // TTL
	f[23] = 6  // protocol TCP
	copy(f[26:30], srcIP[:])
	copy(f[30:34], dstIP[:])
	// TCP header starts at 34 (14 Ethernet + 20 IPv4): source port, then destination.
	binary.BigEndian.PutUint16(f[34:], srcPort)
	binary.BigEndian.PutUint16(f[36:], dstPort)
	f[46] = 0x50 // data offset 5
	return f
}

func padFrame(size int) []byte {
	f := tcpFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1000, 443)
	if size <= len(f) {
		return f
	}
	return append(f, make([]byte, size-len(f))...)
}

func writeBlocks(t *testing.T, blocks ...[]byte) string {
	t.Helper()
	var buf bytes.Buffer
	for _, b := range blocks {
		buf.Write(b)
	}
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPrunePcapngByPIDKeepsOnlyOurBrowser is the case the whole per-process path exists
// for, and the one seen in the wild: a second Chrome ran during the capture and its
// packets — same process name, a pid we never launched — took 91% of the file.
func TestPrunePcapngByPIDKeepsOnlyOurBrowser(t *testing.T) {
	path := writeBlocks(t,
		shb(), idb(1),
		pib(1166, "Google Chrome He"), // index 0: ours
		pib(9999, "Google Chrome He"), // index 1: the other browser
		epb(padFrame(100), 0),
		epb(padFrame(4000), 1), // theirs: big, and most of the file
		epb(padFrame(100), 0),
		epb(padFrame(4000), 1),
	)
	before, _ := os.ReadFile(path)

	res, err := PrunePcapngByPID(path, map[int32]bool{1166: true})
	if err != nil {
		t.Fatalf("PrunePcapngByPID: %v", err)
	}
	if res.PacketsIn != 4 || res.PacketsKept != 2 {
		t.Errorf("kept %d of %d packets, want 2 of 4", res.PacketsKept, res.PacketsIn)
	}
	if res.PacketsUnknown != 0 {
		t.Errorf("PacketsUnknown = %d, want 0 — every packet here names its process", res.PacketsUnknown)
	}
	if !res.PIDsSeen[1166] || !res.PIDsSeen[9999] {
		t.Errorf("PIDsSeen = %v, want both processes reported", res.PIDsSeen)
	}
	if res.After >= res.Before {
		t.Errorf("capture did not shrink: %d -> %d", res.Before, res.After)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(after, epb(padFrame(100), 0)); n != 2 {
		t.Errorf("found %d of our packets in the pruned file, want 2", n)
	}
	if bytes.Contains(after, epb(padFrame(4000), 1)) {
		t.Error("the other browser's packets survived the prune")
	}
	// Both Process Information Blocks must survive even though one names a process whose
	// packets all went: dropping it would renumber the rest and reassign every remaining
	// packet to the wrong process.
	if !bytes.Contains(after, pib(9999, "Google Chrome He")) {
		t.Error("a Process Information Block was dropped, which renumbers the others")
	}
	if !bytes.HasPrefix(after, before[:48]) {
		t.Error("section and interface blocks were not copied through unchanged")
	}
}

// TestPrunePcapngByPIDReportsConnectionOwnership pins the evidence the flow prune runs
// on. Packets say which process owned which connection; a connection seen only under a
// dropped pid is another process's, and one seen under ours never is — whichever
// direction the packet was going.
func TestPrunePcapngByPIDReportsConnectionOwnership(t *testing.T) {
	ours := [4]byte{192, 168, 1, 240}
	site := [4]byte{93, 184, 216, 34}
	other := [4]byte{1, 1, 1, 1}

	path := writeBlocks(t,
		shb(), idb(1),
		pib(1166, "Google Chrome He"),
		pib(9999, "Google Chrome He"),
		// Ours, outbound then the reply — the same connection seen both ways.
		epb(tcpFrame(ours, site, 49152, 443), 0),
		epb(tcpFrame(site, ours, 443, 49152), 0),
		// Another browser's connection entirely.
		epb(tcpFrame(ours, other, 50000, 443), 1),
	)

	res, err := PrunePcapngByPID(path, map[int32]bool{1166: true})
	if err != nil {
		t.Fatalf("PrunePcapngByPID: %v", err)
	}

	mine := NewConnKey("192.168.1.240:49152", "93.184.216.34:443")
	theirs := NewConnKey("192.168.1.240:50000", "1.1.1.1:443")
	if !res.Kept[mine] {
		t.Errorf("our connection missing from Kept: %v", res.Kept)
	}
	if !res.Dropped[theirs] {
		t.Errorf("the other browser's connection missing from Dropped: %v", res.Dropped)
	}
	foreign := res.ForeignConns()
	if !foreign[theirs] {
		t.Error("the other browser's connection was not reported as foreign")
	}
	if foreign[mine] {
		t.Error("our own connection was reported as foreign")
	}
	// Both directions of our connection collapse to one key, or a flow would match only
	// when the decoder happened to name the endpoints the same way round.
	if len(res.Kept) != 1 {
		t.Errorf("Kept has %d connections, want 1 — both directions are one connection", len(res.Kept))
	}
}

// TestForeignConnsRequiresPositiveEvidence covers the safety direction for flows. A
// connection carrying packets from both a kept and a dropped pid is not foreign: ports get
// reused, and deleting on ambiguous evidence loses a real flow.
func TestForeignConnsRequiresPositiveEvidence(t *testing.T) {
	shared := NewConnKey("10.0.0.1:1234", "10.0.0.2:443")
	res := PruneResult{
		Kept:    map[ConnKey]bool{shared: true},
		Dropped: map[ConnKey]bool{shared: true, NewConnKey("10.0.0.1:2", "10.0.0.3:443"): true},
	}
	foreign := res.ForeignConns()
	if foreign[shared] {
		t.Error("a connection seen under a kept pid was reported as foreign")
	}
	if len(foreign) != 1 {
		t.Errorf("foreign = %v, want only the connection seen under a dropped pid alone", foreign)
	}
}

// TestPrunePcapngByPIDRefusesToEmptyACapture covers the two ways this could silently
// destroy a session: an empty keep set, and a capture with no process information at all,
// where every packet is unattributable and keeping them is the only safe answer.
func TestPrunePcapngByPIDRefusesToEmptyACapture(t *testing.T) {
	path := writeBlocks(t, shb(), idb(1), pib(1166, "Google Chrome He"), epb(padFrame(100), 0))
	original, _ := os.ReadFile(path)

	if _, err := PrunePcapngByPID(path, nil); err == nil {
		t.Error("an empty keep set was accepted; it would delete every packet")
	}

	// An ordinary capture: same blocks, no Process Information Block anywhere.
	plain := writeBlocks(t, shb(), idb(1), epb(padFrame(100), 0))
	plainBefore, _ := os.ReadFile(plain)
	if _, err := PrunePcapngByPID(plain, map[int32]bool{1166: true}); !errorIs(err, ErrNoProcessInfo) {
		t.Errorf("a capture with no process info gave %v, want ErrNoProcessInfo", err)
	}
	if now, _ := os.ReadFile(plain); !bytes.Equal(now, plainBefore) {
		t.Error("a capture with no process info was modified")
	}
	if now, _ := os.ReadFile(path); !bytes.Equal(now, original) {
		t.Error("a refused prune modified the capture")
	}
}

// TestPrunePcapngByPIDKeepsUnattributablePackets pins the safety direction: a packet whose
// process option is missing or points past the blocks we have is kept and counted, never
// dropped. A layout change must show up as a capture that did not shrink, not one that
// lost packets.
func TestPrunePcapngByPIDKeepsUnattributablePackets(t *testing.T) {
	// A packet naming process index 7, of which there is one.
	path := writeBlocks(t,
		shb(), idb(1),
		pib(1166, "Google Chrome He"),
		epb(padFrame(100), 0),
		epb(padFrame(100), 7),
	)
	res, err := PrunePcapngByPID(path, map[int32]bool{1166: true})
	if err != nil {
		t.Fatalf("PrunePcapngByPID: %v", err)
	}
	if res.PacketsKept != 2 || res.PacketsUnknown != 1 {
		t.Errorf("kept %d (unknown %d), want 2 kept with 1 unknown",
			res.PacketsKept, res.PacketsUnknown)
	}
}

func errorIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
