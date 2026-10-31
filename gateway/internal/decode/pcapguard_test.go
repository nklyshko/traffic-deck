package decode

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

// allocatedBy reports how many bytes fn allocated.
func allocatedBy(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func decodeAll(t *testing.T, capture []byte) {
	t.Helper()
	_ = LiveDecode(bytes.NewReader(capture), "", Sinks{
		OnFlow: func(*Flow, bool) {}, OnMsg: func(*WsMessage) {}, OnUndecoded: func(*UndecodedConn) {}})
}

// A classic pcap whose snap length and record length both say 4 GiB made pcapgo allocate a
// 4 GiB buffer for a record backed by a handful of bytes.
func TestClassicPcapHugeRecordIsNotAllocated(t *testing.T) {
	le := binary.LittleEndian
	var b bytes.Buffer
	hdr := make([]byte, 24)
	le.PutUint32(hdr[0:], 0xa1b2c3d4)
	le.PutUint16(hdr[4:], 2)
	le.PutUint16(hdr[6:], 4)
	le.PutUint32(hdr[16:], 0xffffffff) // snaplen
	le.PutUint32(hdr[20:], 1)          // Ethernet
	b.Write(hdr)
	rec := make([]byte, 16)
	le.PutUint32(rec[8:], 0xfffffff0)  // captured length
	le.PutUint32(rec[12:], 0xfffffff0) // original length
	b.Write(rec)
	b.Write([]byte{1, 2, 3, 4})

	if n := allocatedBy(func() { decodeAll(t, b.Bytes()) }); n > 64<<20 {
		t.Fatalf("decoding a 44-byte capture allocated %d bytes", n)
	}
}

// A pcapng Enhanced Packet Block whose captured length (4 GiB) is far larger than the block
// holding it made pcapgo allocate 4 GiB, since it never compares the two.
func TestPcapngPacketLargerThanItsBlockIsNotAllocated(t *testing.T) {
	le := binary.LittleEndian
	var b bytes.Buffer
	shb := make([]byte, 28)
	le.PutUint32(shb[0:], blockSectionHeader)
	le.PutUint32(shb[4:], 28)
	le.PutUint32(shb[8:], sectionByteOrderMagic)
	le.PutUint16(shb[12:], 1)
	le.PutUint64(shb[16:], 0xffffffffffffffff)
	le.PutUint32(shb[24:], 28)
	b.Write(shb)
	idb := make([]byte, 20)
	le.PutUint32(idb[0:], 1) // Interface Description Block
	le.PutUint32(idb[4:], 20)
	le.PutUint16(idb[8:], 1) // Ethernet
	le.PutUint32(idb[16:], 20)
	b.Write(idb)
	epb := make([]byte, 36)
	le.PutUint32(epb[0:], 6) // Enhanced Packet Block
	le.PutUint32(epb[4:], 36)
	le.PutUint32(epb[20:], 0xfffffff0) // captured length: far past this 36-byte block
	le.PutUint32(epb[24:], 0xfffffff0)
	le.PutUint32(epb[32:], 36)
	b.Write(epb)

	if n := allocatedBy(func() { decodeAll(t, b.Bytes()) }); n > 64<<20 {
		t.Fatalf("decoding an 84-byte capture allocated %d bytes", n)
	}
}
