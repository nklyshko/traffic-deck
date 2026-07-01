// Package qpackdec is a passive QPACK decoder (RFC 9204) with dynamic-table support, for
// decoding HTTP/3 HEADERS live. Unlike github.com/quic-go/qpack (static table only), it
// processes the QPACK encoder stream to maintain the dynamic table, so field sections that
// reference dynamic entries decode without waiting for the batch tshark pass.
//
// One Decoder handles one direction of a connection: feed that direction's encoder-stream
// bytes to ReadEncoderStream, then decode each HEADERS field section with DecodeFieldSection.
package qpackdec

import (
	"errors"

	"golang.org/x/net/http2/hpack"
)

// HeaderField is a decoded name/value pair. The field name matches the static table's.
type HeaderField struct {
	Name  string
	Value string
}

func (f HeaderField) size() uint64 { return uint64(len(f.Name) + len(f.Value) + 32) }

// Decoder holds one direction's QPACK dynamic table and encoder-stream reassembly state.
type Decoder struct {
	entries     []HeaderField // dynamic table, oldest first
	insertCount uint64        // total insertions ever (absolute index of the next insert)
	capacity    uint64
	size        uint64
	encBuf      []byte // buffered partial encoder-stream bytes
}

// New returns an empty Decoder (capacity 0 until the encoder sets it).
func New() *Decoder { return &Decoder{} }

// InsertCount returns the number of dynamic-table insertions seen so far.
func (d *Decoder) InsertCount() uint64 { return d.insertCount }

var errQPACK = errors.New("qpack: malformed")

// --- primitives (RFC 7541 §5.1 / §5.2, reused by RFC 9204) ---

// readInt decodes a prefixBits-prefix integer. ok is false if truncated.
func readInt(prefixBits int, p []byte) (val uint64, n int, ok bool) {
	if len(p) == 0 {
		return 0, 0, false
	}
	max := uint64(1)<<uint(prefixBits) - 1
	val = uint64(p[0]) & max
	n = 1
	if val < max {
		return val, n, true
	}
	var m uint
	for {
		if n >= len(p) {
			return 0, 0, false
		}
		b := p[n]
		n++
		val += uint64(b&0x7f) << m
		m += 7
		if b&0x80 == 0 {
			return val, n, true
		}
		if m > 63 {
			return 0, 0, false
		}
	}
}

// readString decodes a length-prefixed string whose length uses a prefixBits prefix and
// whose Huffman flag is the bit just above that prefix. ok is false if truncated/invalid.
func readString(prefixBits int, p []byte) (s string, n int, ok bool) {
	if len(p) == 0 {
		return "", 0, false
	}
	huff := p[0]&(1<<uint(prefixBits)) != 0
	l, ni, ok := readInt(prefixBits, p)
	if !ok || uint64(ni)+l > uint64(len(p)) {
		return "", 0, false
	}
	data := p[ni : ni+int(l)]
	if huff {
		out, err := hpack.HuffmanDecodeToString(data)
		if err != nil {
			return "", 0, false
		}
		return out, ni + int(l), true
	}
	return string(data), ni + int(l), true
}

// --- dynamic table ---

// dynByRel returns the entry at a relative index (0 = most recently inserted).
func (d *Decoder) dynByRel(rel uint64) (HeaderField, bool) {
	if rel >= uint64(len(d.entries)) {
		return HeaderField{}, false
	}
	return d.entries[uint64(len(d.entries))-1-rel], true
}

// dynByAbs returns the entry at an absolute index.
func (d *Decoder) dynByAbs(abs uint64) (HeaderField, bool) {
	oldest := d.insertCount - uint64(len(d.entries))
	if abs < oldest || abs >= d.insertCount {
		return HeaderField{}, false
	}
	return d.entries[abs-oldest], true
}

func (d *Decoder) setCapacity(c uint64) {
	d.capacity = c
	d.evict(0)
}

// evict drops oldest entries until an incoming entry of `incoming` bytes would fit.
func (d *Decoder) evict(incoming uint64) {
	for len(d.entries) > 0 && d.size+incoming > d.capacity {
		d.size -= d.entries[0].size()
		d.entries = d.entries[1:]
	}
}

func (d *Decoder) insert(f HeaderField) bool {
	sz := f.size()
	d.evict(sz)
	if d.size+sz > d.capacity {
		return false // doesn't fit even after eviction — malformed
	}
	d.entries = append(d.entries, f)
	d.size += sz
	d.insertCount++
	return true
}

// --- encoder stream (RFC 9204 §4.3) ---

// ReadEncoderStream feeds newly-arrived encoder-stream bytes, applying every complete
// instruction to the dynamic table. Partial trailing instructions are buffered for the
// next call. Returns an error only on malformed input.
func (d *Decoder) ReadEncoderStream(p []byte) error {
	d.encBuf = append(d.encBuf, p...)
	buf := d.encBuf
	for len(buf) > 0 {
		b0 := buf[0]
		var consumed int
		var err error
		switch {
		case b0&0x80 != 0: // Insert with Name Reference: 1 T index(6)
			consumed, err = d.encInsertNameRef(buf)
		case b0&0x40 != 0: // Insert with Literal Name: 01 H name(5)
			consumed, err = d.encInsertLiteral(buf)
		case b0&0x20 != 0: // Set Dynamic Table Capacity: 001 cap(5)
			consumed, err = d.encSetCapacity(buf)
		default: // Duplicate: 000 index(5)
			consumed, err = d.encDuplicate(buf)
		}
		if err != nil {
			return err
		}
		if consumed == 0 {
			break // instruction not fully arrived yet — keep the remainder buffered
		}
		buf = buf[consumed:]
	}
	d.encBuf = append([]byte(nil), buf...)
	return nil
}

func (d *Decoder) encInsertNameRef(buf []byte) (int, error) {
	static := buf[0]&0x40 != 0
	idx, n1, ok := readInt(6, buf)
	if !ok {
		return 0, nil
	}
	val, n2, ok := readString(7, buf[n1:])
	if !ok {
		return 0, nil
	}
	var name string
	if static {
		if int(idx) >= len(staticTable) {
			return 0, errQPACK
		}
		name = staticTable[idx].Name
	} else {
		e, ok := d.dynByRel(idx)
		if !ok {
			return 0, errQPACK
		}
		name = e.Name
	}
	if !d.insert(HeaderField{name, val}) {
		return 0, errQPACK
	}
	return n1 + n2, nil
}

func (d *Decoder) encInsertLiteral(buf []byte) (int, error) {
	name, n1, ok := readString(5, buf) // 01 H name(5)
	if !ok {
		return 0, nil
	}
	val, n2, ok := readString(7, buf[n1:])
	if !ok {
		return 0, nil
	}
	if !d.insert(HeaderField{name, val}) {
		return 0, errQPACK
	}
	return n1 + n2, nil
}

func (d *Decoder) encSetCapacity(buf []byte) (int, error) {
	c, n, ok := readInt(5, buf)
	if !ok {
		return 0, nil
	}
	d.setCapacity(c)
	return n, nil
}

func (d *Decoder) encDuplicate(buf []byte) (int, error) {
	idx, n, ok := readInt(5, buf)
	if !ok {
		return 0, nil
	}
	e, ok := d.dynByRel(idx)
	if !ok {
		return 0, errQPACK
	}
	if !d.insert(e) {
		return 0, errQPACK
	}
	return n, nil
}

// --- field section (RFC 9204 §4.5) ---

// DecodeFieldSection decodes one HEADERS field section. blocked is true when the section's
// Required Insert Count exceeds the entries received so far on the encoder stream — the
// caller should buffer the section and retry after more encoder-stream bytes arrive.
func (d *Decoder) DecodeFieldSection(p []byte) (fields []HeaderField, blocked bool, err error) {
	_, base, n, blocked, ok := d.readPrefix(p)
	if blocked {
		return nil, true, nil
	}
	if !ok {
		return nil, false, errQPACK
	}
	p = p[n:]
	for len(p) > 0 {
		var f HeaderField
		var consumed int
		b0 := p[0]
		switch {
		case b0&0x80 != 0: // Indexed Field Line: 1 T index(6)
			f, consumed, ok = d.fieldIndexed(base, p)
		case b0&0x40 != 0: // Literal with Name Reference: 01 N T index(4)
			f, consumed, ok = d.fieldLiteralNameRef(base, p)
		case b0&0x20 != 0: // Literal with Literal Name: 001 N H name(3)
			f, consumed, ok = d.fieldLiteralName(p)
		case b0&0x10 != 0: // Indexed with Post-Base Index: 0001 index(4)
			f, consumed, ok = d.fieldPostBaseIndexed(base, p)
		default: // Literal with Post-Base Name Reference: 0000 N index(3)
			f, consumed, ok = d.fieldPostBaseNameRef(base, p)
		}
		if !ok || consumed == 0 {
			return nil, false, errQPACK
		}
		fields = append(fields, f)
		p = p[consumed:]
	}
	return fields, false, nil
}

// readPrefix decodes the Encoded Field Section Prefix (RFC 9204 §4.5.1): the Required
// Insert Count and the Base. blocked is true when the section references entries not yet
// received on the encoder stream (or the table capacity hasn't been learned yet).
func (d *Decoder) readPrefix(p []byte) (ric, base uint64, n int, blocked, ok bool) {
	enc, n1, ok := readInt(8, p)
	if !ok {
		return 0, 0, 0, false, false
	}
	if enc != 0 {
		maxEntries := d.capacity / 32
		if maxEntries == 0 {
			return 0, 0, 0, true, false // encoder-stream Set-Capacity not seen yet
		}
		ric, ok = d.decodeRIC(enc, maxEntries)
		if !ok {
			return 0, 0, 0, false, false
		}
		if ric > d.insertCount {
			return 0, 0, 0, true, false // waiting on not-yet-received dynamic entries
		}
	}
	if n1 >= len(p) {
		return 0, 0, 0, false, false
	}
	sign := p[n1]&0x80 != 0
	delta, n2, ok := readInt(7, p[n1:])
	if !ok {
		return 0, 0, 0, false, false
	}
	if sign {
		if delta+1 > ric {
			return 0, 0, 0, false, false
		}
		base = ric - delta - 1
	} else {
		base = ric + delta
	}
	return ric, base, n1 + n2, false, true
}

// decodeRIC reconstructs a non-zero Required Insert Count from its wire encoding (RFC 9204
// §4.5.1.1) using the total insertions seen so far. maxEntries derives from the table
// capacity (an approximation of the peer's advertised SETTINGS_QPACK_MAX_TABLE_CAPACITY,
// which the encoder in practice matches).
func (d *Decoder) decodeRIC(enc, maxEntries uint64) (uint64, bool) {
	fullRange := 2 * maxEntries
	if enc > fullRange {
		return 0, false
	}
	maxValue := d.insertCount + maxEntries
	maxWrapped := (maxValue / fullRange) * fullRange
	ric := maxWrapped + enc - 1
	if ric > maxValue {
		if ric <= fullRange {
			return 0, false
		}
		ric -= fullRange
	}
	if ric == 0 {
		return 0, false
	}
	return ric, true
}

func (d *Decoder) fieldIndexed(base uint64, p []byte) (HeaderField, int, bool) {
	static := p[0]&0x40 != 0
	idx, n, ok := readInt(6, p)
	if !ok {
		return HeaderField{}, 0, false
	}
	if static {
		if int(idx) >= len(staticTable) {
			return HeaderField{}, 0, false
		}
		return staticTable[idx], n, true
	}
	e, ok := d.dynByAbs(base - 1 - idx)
	return e, n, ok
}

func (d *Decoder) fieldPostBaseIndexed(base uint64, p []byte) (HeaderField, int, bool) {
	idx, n, ok := readInt(4, p)
	if !ok {
		return HeaderField{}, 0, false
	}
	e, ok := d.dynByAbs(base + idx)
	return e, n, ok
}

func (d *Decoder) fieldLiteralNameRef(base uint64, p []byte) (HeaderField, int, bool) {
	static := p[0]&0x10 != 0
	idx, n1, ok := readInt(4, p)
	if !ok {
		return HeaderField{}, 0, false
	}
	val, n2, ok := readString(7, p[n1:])
	if !ok {
		return HeaderField{}, 0, false
	}
	var name string
	if static {
		if int(idx) >= len(staticTable) {
			return HeaderField{}, 0, false
		}
		name = staticTable[idx].Name
	} else {
		e, ok := d.dynByAbs(base - 1 - idx)
		if !ok {
			return HeaderField{}, 0, false
		}
		name = e.Name
	}
	return HeaderField{name, val}, n1 + n2, true
}

func (d *Decoder) fieldPostBaseNameRef(base uint64, p []byte) (HeaderField, int, bool) {
	idx, n1, ok := readInt(3, p)
	if !ok {
		return HeaderField{}, 0, false
	}
	val, n2, ok := readString(7, p[n1:])
	if !ok {
		return HeaderField{}, 0, false
	}
	e, ok := d.dynByAbs(base + idx)
	if !ok {
		return HeaderField{}, 0, false
	}
	return HeaderField{e.Name, val}, n1 + n2, true
}

func (d *Decoder) fieldLiteralName(p []byte) (HeaderField, int, bool) {
	name, n1, ok := readString(3, p) // 001 N H name(3)
	if !ok {
		return HeaderField{}, 0, false
	}
	val, n2, ok := readString(7, p[n1:])
	if !ok {
		return HeaderField{}, 0, false
	}
	return HeaderField{name, val}, n1 + n2, true
}
