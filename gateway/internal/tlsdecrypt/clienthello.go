package tlsdecrypt

// ClientHello fingerprinting: parse the cleartext ClientHello and compute the JA3 (MD5 of
// version,ciphers,extensions,curves,point-formats) and JA4 (FoxIO ja4.io) fingerprints,
// plus keep the readable JA3 string and the offered ALPN so the viewer can export the
// ClientHello. GREASE values (RFC 8701) are excluded from every list, as both specs require.

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// ClientHelloInfo is the fingerprint-relevant view of a ClientHello.
type ClientHelloInfo struct {
	LegacyVersion uint16   // the record's legacy_version (used by JA3)
	Version       uint16   // effective version: supported_versions max, else legacy (JA4)
	SNI           string   // present ⇒ JA4 "d", absent ⇒ "i"
	Ciphers       []uint16 // in wire order (GREASE included; excluded when hashing)
	Extensions    []uint16 // in wire order
	Curves        []uint16 // supported_groups
	PointFormats  []uint16 // ec_point_formats
	ALPN          []string // offered ALPN protocols
	SigAlgs       []uint16 // signature_algorithms (JA4c, in order)
	JA3           string   // md5 hex
	JA3Text       string   // the pre-hash JA3 string (exportable ClientHello)
	JA4           string
	transport     byte // JA4 transport marker: 't' (TLS/TCP) or 'q' (QUIC)
}

// isGREASE reports whether v is a GREASE value (RFC 8701): both bytes equal and of form 0x?A.
func isGREASE(v uint16) bool {
	return v&0xff == v>>8 && v&0x0f == 0x0a
}

// parseClientHelloInfo parses a TLS-over-TCP ClientHello body (starting at legacy_version)
// and computes JA3/JA4. Returns nil on a malformed structure.
func parseClientHelloInfo(b []byte) *ClientHelloInfo { return parseCH(b, 't') }

// ParseClientHelloInfoQUIC is parseClientHelloInfo for a ClientHello carried in a QUIC
// Initial — same parsing, but JA4 marks the transport as QUIC ('q').
func ParseClientHelloInfoQUIC(b []byte) *ClientHelloInfo { return parseCH(b, 'q') }

func parseCH(b []byte, transport byte) *ClientHelloInfo {
	// legacy_version(2) random(32) session_id<1> cipher_suites<2> compression<1> extensions<2>
	if len(b) < 2+32+1 {
		return nil
	}
	ci := &ClientHelloInfo{LegacyVersion: be16(b, 0), transport: transport}
	ci.Version = ci.LegacyVersion
	p := 2 + 32
	sidLen := int(b[p])
	p += 1 + sidLen
	if p+2 > len(b) {
		return nil
	}
	csLen := int(be16(b, p))
	p += 2
	if p+csLen > len(b) || csLen%2 != 0 {
		return nil
	}
	for i := 0; i < csLen; i += 2 {
		ci.Ciphers = append(ci.Ciphers, be16(b, p+i))
	}
	p += csLen
	if p >= len(b) {
		return nil
	}
	p += 1 + int(b[p]) // compression_methods
	if p+2 <= len(b) {
		ci.parseExtensions(b, p)
	}
	ci.finalize()
	return ci
}

func (ci *ClientHelloInfo) parseExtensions(b []byte, p int) {
	end := p + 2 + int(be16(b, p))
	p += 2
	if end > len(b) {
		end = len(b)
	}
	for p+4 <= end {
		etype := be16(b, p)
		elen := int(be16(b, p+2))
		p += 4
		if p+elen > end {
			return
		}
		ci.Extensions = append(ci.Extensions, etype)
		ext := b[p : p+elen]
		switch etype {
		case 0: // server_name
			ci.SNI = sniFromExt(ext)
		case 10: // supported_groups
			ci.Curves = u16ListVec16(ext)
		case 11: // ec_point_formats
			ci.PointFormats = u8ListVec8(ext)
		case 13: // signature_algorithms
			ci.SigAlgs = u16ListVec16(ext)
		case 16: // ALPN
			ci.ALPN = alpnList(ext)
		case 43: // supported_versions
			if v := maxCHVersion(ext); v != 0 {
				ci.Version = v
			}
		}
		p += elen
	}
}

// finalize computes JA3 + JA4 from the parsed fields.
func (ci *ClientHelloInfo) finalize() {
	// JA3: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats (GREASE excluded).
	ci.JA3Text = strings.Join([]string{
		strconv.Itoa(int(ci.LegacyVersion)),
		dashDecimal(dropGREASE(ci.Ciphers)),
		dashDecimal(dropGREASE(ci.Extensions)),
		dashDecimal(dropGREASE(ci.Curves)),
		dashDecimalU8(ci.PointFormats),
	}, ",")
	sum := md5.Sum([]byte(ci.JA3Text))
	ci.JA3 = hex.EncodeToString(sum[:])
	ci.JA4 = ci.ja4()
}

// ja4 builds the FoxIO JA4 fingerprint: ja4_a _ ja4_b _ ja4_c.
func (ci *ClientHelloInfo) ja4() string {
	ciphers := dropGREASE(ci.Ciphers)
	// Count uses all extensions (incl. SNI + ALPN), GREASE excluded.
	exts := dropGREASE(ci.Extensions)

	sniChar := "i"
	if ci.SNI != "" {
		sniChar = "d"
	}
	alpn := "00"
	if len(ci.ALPN) > 0 && ci.ALPN[0] != "" {
		a := ci.ALPN[0]
		alpn = string(a[0]) + string(a[len(a)-1])
	}
	transport := ci.transport
	if transport == 0 {
		transport = 't'
	}
	ja4a := string(transport) + ja4Version(ci.Version) + sniChar +
		twoDigit(len(ciphers)) + twoDigit(len(exts)) + alpn

	ja4b := sha12(hexCSVSorted(ciphers))

	// ja4_c: sorted extensions excluding SNI(0x0000) and ALPN(0x0010), then "_" and the
	// signature_algorithms in their original order.
	var extForHash []uint16
	for _, e := range exts {
		if e != 0x0000 && e != 0x0010 {
			extForHash = append(extForHash, e)
		}
	}
	sort.Slice(extForHash, func(i, j int) bool { return extForHash[i] < extForHash[j] })
	ja4c := sha12(hexCSV(extForHash) + "_" + hexCSV(ci.SigAlgs))

	return ja4a + "_" + ja4b + "_" + ja4c
}

// --- helpers ---------------------------------------------------------------

func be16(b []byte, p int) uint16 { return uint16(b[p])<<8 | uint16(b[p+1]) }

func dropGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func dashDecimal(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func dashDecimalU8(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

// twoDigit formats n as a 2-digit string, capped at 99 (JA4 convention).
func twoDigit(n int) string {
	if n > 99 {
		n = 99
	}
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	default:
		return "00"
	}
}

// hexCSV formats each value as 4-hex lowercase, comma-joined, in order.
func hexCSV(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = hex4(v)
	}
	return strings.Join(parts, ",")
}

// hexCSVSorted is hexCSV over an ascending-sorted copy.
func hexCSVSorted(vs []uint16) string {
	cp := append([]uint16(nil), vs...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return hexCSV(cp)
}

func hex4(v uint16) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[v>>12&0xf], digits[v>>8&0xf], digits[v>>4&0xf], digits[v&0xf]})
}

// sha12 returns the first 12 hex chars of SHA256(s), or 12 zeros for an empty input (the
// JA4 spec uses "000000000000" when the list is empty).
func sha12(s string) string {
	if s == "" || s == "_" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// sniFromExt extracts the host_name from a server_name extension body.
func sniFromExt(d []byte) string {
	// server_name_list<2>, entry: name_type(1) host_name<2>
	if len(d) >= 5 && d[2] == 0 {
		n := int(be16(d, 3))
		if 5+n <= len(d) {
			return string(d[5 : 5+n])
		}
	}
	return ""
}

// u16ListVec16 parses a 2-byte-length vector of uint16s (supported_groups, sig_algs).
func u16ListVec16(d []byte) []uint16 {
	if len(d) < 2 {
		return nil
	}
	n := int(be16(d, 0))
	if 2+n > len(d) || n%2 != 0 {
		return nil
	}
	out := make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		out = append(out, be16(d, 2+i))
	}
	return out
}

// u8ListVec8 parses a 1-byte-length vector of uint8s (ec_point_formats).
func u8ListVec8(d []byte) []uint16 {
	if len(d) < 1 {
		return nil
	}
	n := int(d[0])
	if 1+n > len(d) {
		return nil
	}
	out := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, uint16(d[1+i]))
	}
	return out
}

// alpnList parses the ALPN extension body into its protocol strings.
func alpnList(d []byte) []string {
	if len(d) < 2 {
		return nil
	}
	end := 2 + int(be16(d, 0))
	if end > len(d) {
		end = len(d)
	}
	var out []string
	for p := 2; p < end; {
		n := int(d[p])
		p++
		if p+n > end {
			break
		}
		out = append(out, string(d[p:p+n]))
		p += n
	}
	return out
}

// maxCHVersion returns the highest (non-GREASE) version in a ClientHello supported_versions
// extension body (versions<1>: 1-byte length, then 2-byte versions).
func maxCHVersion(d []byte) uint16 {
	if len(d) < 1 {
		return 0
	}
	n := int(d[0])
	if 1+n > len(d) || n%2 != 0 {
		return 0
	}
	var best uint16
	for i := 0; i < n; i += 2 {
		v := be16(d, 1+i)
		if !isGREASE(v) && v > best {
			best = v
		}
	}
	return best
}
