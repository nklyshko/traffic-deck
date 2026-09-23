package decode

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// A PKTAP pcap-ng built by hand. There is no recorded fixture to use: producing one needs
// root and a Mac, so the format is written here from the spec the pruner reads it by.

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
	binary.LittleEndian.PutUint32(b[0:], 0x00000001)
	binary.LittleEndian.PutUint32(b[4:], 20)
	binary.LittleEndian.PutUint16(b[8:], linkType)
	binary.LittleEndian.PutUint32(b[12:], 262144) // snaplen
	binary.LittleEndian.PutUint32(b[16:], 20)
	return b
}

// pktapRecord is one packet's captured bytes: a pktap header naming the owning process,
// then a stand-in frame. Only the fields the pruner reads are filled, plus pth_type_next,
// without which Apple's own tcpdump calls the record UNSUPPORTED rather than a packet.
func pktapRecord(pid int32, comm string, frame []byte) []byte {
	const hdrLen = 108
	b := make([]byte, hdrLen+len(frame))
	binary.LittleEndian.PutUint32(b[0:], hdrLen)       // pth_length
	binary.LittleEndian.PutUint32(b[4:], 1)            // pth_type_next = PTH_TYPE_PACKET
	binary.LittleEndian.PutUint32(b[8:], 1)            // pth_dlt = EN10MB
	binary.LittleEndian.PutUint32(b[52:], uint32(pid)) // pth_pid
	copy(b[56:73], comm)                               // pth_comm, NUL-padded
	copy(b[hdrLen:], frame)
	return b
}

func epb(record []byte) []byte {
	padded := (len(record) + 3) &^ 3
	total := 32 + padded
	b := make([]byte, total)
	binary.LittleEndian.PutUint32(b[0:], blockEnhancedPacket)
	binary.LittleEndian.PutUint32(b[4:], uint32(total))
	binary.LittleEndian.PutUint32(b[8:], 0)                    // interface id
	binary.LittleEndian.PutUint32(b[20:], uint32(len(record))) // captured length
	binary.LittleEndian.PutUint32(b[24:], uint32(len(record))) // original length
	copy(b[28:], record)
	binary.LittleEndian.PutUint32(b[uint32(total)-4:], uint32(total))
	return b
}

// writeCapture assembles a capture from (pid, payload size) pairs and returns its path.
func writeCapture(t *testing.T, linkType uint16, packets ...struct {
	pid  int32
	size int
}) string {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(shb())
	buf.Write(idb(linkType))
	for _, p := range packets {
		buf.Write(epb(pktapRecord(p.pid, "Google Chrome He", make([]byte, p.size))))
	}
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type pkt = struct {
	pid  int32
	size int
}

// TestPrunePcapngByPIDKeepsOnlyOurBrowser is the case the whole per-process path exists
// for: a second Chrome ran during the capture, and its packets — same process name, a pid
// we never launched — have to go, while ours stay byte-for-byte.
func TestPrunePcapngByPIDKeepsOnlyOurBrowser(t *testing.T) {
	path := writeCapture(t, linkTypePKTAP,
		pkt{pid: 1166, size: 100},
		pkt{pid: 9999, size: 4000}, // the other browser: big, and most of the file
		pkt{pid: 1166, size: 100},
		pkt{pid: 9999, size: 4000},
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
		t.Errorf("PacketsUnknown = %d, want 0 — every record here has a readable header", res.PacketsUnknown)
	}
	if res.After >= res.Before {
		t.Errorf("capture did not shrink: %d -> %d", res.Before, res.After)
	}

	// The survivors must be intact, not merely counted: a rewrite that corrupted packet
	// bytes would still produce the right count.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	keptRecord := epb(pktapRecord(1166, "Google Chrome He", make([]byte, 100)))
	if n := bytes.Count(after, keptRecord); n != 2 {
		t.Errorf("found %d of our packets in the pruned file, want 2", n)
	}
	if bytes.Contains(after, epb(pktapRecord(9999, "Google Chrome He", make([]byte, 4000)))) {
		t.Error("the other browser's packets survived the prune")
	}
	if !bytes.HasPrefix(after, before[:48]) {
		t.Error("section and interface blocks were not copied through unchanged")
	}
}

// tcpFrame is an Ethernet/IPv4/TCP frame with the given endpoints — enough for the
// pruner to read a connection out of, and nothing more.
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

// TestPrunePcapngByPIDReportsConnectionOwnership pins the evidence the flow prune runs
// on. Packets say which process owned which connection; a connection seen only under a
// dropped pid is another process's, and one seen under ours never is — whichever
// direction the packet was going.
func TestPrunePcapngByPIDReportsConnectionOwnership(t *testing.T) {
	ours := [4]byte{192, 168, 1, 240}
	site := [4]byte{93, 184, 216, 34}
	other := [4]byte{1, 1, 1, 1}

	var buf bytes.Buffer
	buf.Write(shb())
	buf.Write(idb(linkTypePKTAP))
	// Ours, outbound then the reply — the same connection seen both ways.
	buf.Write(epb(pktapRecord(1166, "Google Chrome He", tcpFrame(ours, site, 49152, 443))))
	buf.Write(epb(pktapRecord(1166, "Google Chrome He", tcpFrame(site, ours, 443, 49152))))
	// Another browser's connection entirely.
	buf.Write(epb(pktapRecord(9999, "Google Chrome He", tcpFrame(ours, other, 50000, 443))))
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

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
// connection carrying packets from both a kept and a dropped pid is not foreign: shared
// ports get reused, and deleting on ambiguous evidence loses a real flow.
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
// destroy a session: an empty keep set, and a capture that isn't PKTAP at all (so the
// bytes at the pid's offset are frame data that might match anything).
func TestPrunePcapngByPIDRefusesToEmptyACapture(t *testing.T) {
	path := writeCapture(t, linkTypePKTAP, pkt{pid: 1166, size: 100})
	original, _ := os.ReadFile(path)

	if _, err := PrunePcapngByPID(path, nil); err == nil {
		t.Error("an empty keep set was accepted; it would delete every packet")
	}
	ethernet := writeCapture(t, 1, pkt{pid: 1166, size: 100})
	if _, err := PrunePcapngByPID(ethernet, map[int32]bool{1166: true}); err == nil {
		t.Error("a non-PKTAP capture was pruned by pid")
	}

	if now, _ := os.ReadFile(path); !bytes.Equal(now, original) {
		t.Error("a refused prune modified the capture")
	}
}

// TestPrunePcapngByPIDKeepsUnreadableRecords pins the safety direction: a record whose
// pktap header is too short to hold a pid is kept and counted, never dropped. A layout
// change must show up as a capture that didn't shrink, not one that lost packets.
func TestPrunePcapngByPIDKeepsUnreadableRecords(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(shb())
	buf.Write(idb(linkTypePKTAP))
	buf.Write(epb(pktapRecord(1166, "Google Chrome He", make([]byte, 100))))
	buf.Write(epb([]byte{1, 2, 3, 4, 5, 6, 7, 8})) // too short for a pktap header
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := PrunePcapngByPID(path, map[int32]bool{1166: true})
	if err != nil {
		t.Fatalf("PrunePcapngByPID: %v", err)
	}
	if res.PacketsKept != 2 || res.PacketsUnknown != 1 {
		t.Errorf("kept %d (unknown %d), want 2 kept with 1 unknown",
			res.PacketsKept, res.PacketsUnknown)
	}
}

// TestPktapPIDReadsProcessIdentity covers the header accessor directly, including the
// truncated process name the kernel records and the short-record rejection the pruner
// depends on for its keep-on-unknown behaviour.
func TestPktapPIDReadsProcessIdentity(t *testing.T) {
	pid, comm, ok := pktapPID(pktapRecord(1166, "Google Chrome He", []byte{0xAA}))
	if !ok || pid != 1166 || comm != "Google Chrome He" {
		t.Errorf("pktapPID = (%d, %q, %v), want (1166, \"Google Chrome He\", true)", pid, comm, ok)
	}
	if _, _, ok := pktapPID(make([]byte, 40)); ok {
		t.Error("a record too short to hold a pid reported one")
	}
}
