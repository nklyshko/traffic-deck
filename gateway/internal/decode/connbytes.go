package decode

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	gplayers "github.com/google/gopacket/layers"

	"github.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

// ConnBytes is one connection's payload read back from a capture, per direction.
type ConnBytes struct {
	Up, Down []byte // client→server, server→client; TCP reassembled by sequence, UDP datagrams back to back
	// Gaps counts the holes reassembly found (segments the capture lost), so bytes after
	// one are known not to follow on directly.
	Gaps int
	// Truncated says a direction reached maxBytes and stopped.
	Truncated bool
	// Scanned says the read could not start at the indexed offset and scanned the whole
	// capture instead (pcapng, or a capture rewritten since it was indexed).
	Scanned bool
}

// ReadConnection reads one indexed connection's bytes back out of a capture, starting at
// its record's offset when that still holds its first packet and from the top otherwise,
// and stopping a little past its last packet. Each direction is capped at maxBytes.
func ReadConnection(pcapPath string, u *UndecodedConn, maxBytes int) (*ConnBytes, error) {
	f, err := os.Open(pcapPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := &ConnBytes{}
	if u.PcapOffset >= 24 {
		var hdr [24]byte
		if _, err := io.ReadFull(f, hdr[:]); err == nil {
			if _, err := f.Seek(u.PcapOffset, io.SeekStart); err == nil {
				if ok, err := readConn(io.MultiReader(bytes.NewReader(hdr[:]), f), u, maxBytes, out, true); err != nil || ok {
					return out, err
				}
			}
		}
		*out = ConnBytes{}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	out.Scanned = true
	_, err = readConn(f, u, maxBytes, out, false)
	return out, err
}

// readConn collects u's packets from r into out. With mustStartHere, the first record
// must be u's first packet — else ok=false and the caller rescans from the top.
func readConn(r io.Reader, u *UndecodedConn, maxBytes int, out *ConnBytes, mustStartHere bool) (ok bool, err error) {
	reader, rawLinkType, _, err := newPacketReader(r)
	if err != nil {
		return false, err
	}
	linkType := reader.LinkType()
	cliHost, cliPort, _ := net.SplitHostPort(u.Client)
	srvHost, srvPort, _ := net.SplitHostPort(u.Server)
	const slack = 2_000_000 // µs past the last packet: retransmits, a late FIN
	segs := [2]map[uint32][]byte{{}, {}}
	first := true
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		ts := ci.Timestamp.UnixMicro()
		if first && mustStartHere && ts != u.FirstTS {
			return false, nil // the offset no longer holds this connection's first packet
		}
		if ts > u.LastTS+slack {
			break
		}
		if ts < u.FirstTS-slack {
			first = false
			continue
		}
		pkt := packetOf(data, linkType, rawLinkType)
		if pkt == nil || pkt.NetworkLayer() == nil {
			continue
		}
		nf := pkt.NetworkLayer().NetworkFlow()
		src, dst := nf.Src().String(), nf.Dst().String()
		var sport, dport string
		var payload []byte
		var seq uint32
		if u.Transport == "udp" {
			l, isUDP := pkt.Layer(gplayers.LayerTypeUDP).(*gplayers.UDP)
			if !isUDP {
				continue
			}
			sport, dport, payload = strconv.Itoa(int(l.SrcPort)), strconv.Itoa(int(l.DstPort)), l.Payload
		} else {
			l, isTCP := pkt.Layer(gplayers.LayerTypeTCP).(*gplayers.TCP)
			if !isTCP {
				continue
			}
			sport, dport, payload, seq = strconv.Itoa(int(l.SrcPort)), strconv.Itoa(int(l.DstPort)), l.Payload, l.Seq
		}
		var dir int
		switch {
		case src == cliHost && sport == cliPort && dst == srvHost && dport == srvPort:
			dir = 0
		case src == srvHost && sport == srvPort && dst == cliHost && dport == cliPort:
			dir = 1
		default:
			if first && mustStartHere {
				return false, nil
			}
			first = false
			continue
		}
		first = false
		if len(payload) == 0 {
			continue
		}
		if u.Transport == "udp" {
			buf := &out.Up
			if dir == 1 {
				buf = &out.Down
			}
			if len(*buf)+len(payload) > maxBytes {
				out.Truncated = true
				continue
			}
			*buf = append(*buf, payload...)
			continue
		}
		if prev, dup := segs[dir][seq]; !dup || len(payload) > len(prev) {
			segs[dir][seq] = append([]byte(nil), payload...)
		}
	}
	if u.Transport != "udp" {
		var g0, g1 int
		var t0, t1 bool
		out.Up, g0, t0 = stitch(segs[0], maxBytes)
		out.Down, g1, t1 = stitch(segs[1], maxBytes)
		out.Gaps, out.Truncated = g0+g1, t0 || t1
	}
	return true, nil
}

// stitch orders one direction's segments by sequence number (relative to the lowest, so
// a wrap of the 32-bit space within the connection is harmless) and lays them end to end,
// trimming retransmitted overlap and counting the holes a lost segment left.
func stitch(segs map[uint32][]byte, maxBytes int) (out []byte, gaps int, truncated bool) {
	if len(segs) == 0 {
		return nil, 0, false
	}
	seqs := make([]uint32, 0, len(segs))
	for s := range segs {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	// The stream starts after the largest jump between consecutive sequence numbers when
	// that jump is most of the space — i.e. the sequence wrapped.
	start := 0
	for i := 1; i < len(seqs); i++ {
		if seqs[i]-seqs[i-1] > 1<<31 {
			start = i
		}
	}
	base := seqs[start]
	rel := make([]uint32, len(seqs))
	for i, s := range seqs {
		rel[i] = s - base
	}
	order := make([]int, len(seqs))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool { return rel[order[a]] < rel[order[b]] })
	var cursor uint32
	for _, i := range order {
		data, at := segs[seqs[i]], rel[i]
		end := at + uint32(len(data))
		if end <= cursor {
			continue // wholly retransmitted
		}
		if at > cursor {
			gaps++
		} else {
			data = data[cursor-at:]
		}
		if len(out)+len(data) > maxBytes {
			out = append(out, data[:maxBytes-len(out)]...)
			return out, gaps, true
		}
		out = append(out, data...)
		cursor = end
	}
	return out, gaps, false
}

// DescribeTLS reads what a TLS connection says in the clear — the ClientHello, the
// ServerHello and, under TLS 1.2, the server's certificate chain — so a connection with no
// key-log secret is still more than ciphertext. Lines, most telling first; nil when the
// bytes are not TLS.
func DescribeTLS(up, down []byte) []string {
	var out []string
	if ch := firstHandshake(up, 1); ch != nil {
		if info := tlsdecrypt.ParseClientHelloInfo(ch); info != nil {
			line := fmt.Sprintf("ClientHello: sni=%q version=%s", info.SNI, tlsVersionName(info.Version))
			if len(info.ALPN) > 0 {
				line += " alpn=" + strings.Join(info.ALPN, ",")
			}
			out = append(out, line, "ClientHello JA4: "+info.JA4)
		}
	}
	sh := firstHandshake(down, 2)
	if sh == nil {
		if out != nil {
			out = append(out, "no ServerHello in the capture: the handshake did not complete")
		}
		return out
	}
	version, cipher := parseServerHello(sh)
	out = append(out, fmt.Sprintf("ServerHello: version=%s cipher=%#04x", tlsVersionName(version), cipher))
	if version == 0x0304 {
		return append(out, "TLS 1.3: the server's certificate is encrypted; only a key-log secret reveals it")
	}
	if cert := firstHandshake(down, 11); len(cert) > 6 {
		out = append(out, describeCertificates(cert)...)
	}
	return out
}

// firstHandshake returns the body of the first handshake message of type typ in a
// stream's leading cleartext records (reassembling one that spans records), or nil.
func firstHandshake(stream []byte, typ byte) []byte {
	var hs []byte
	for len(stream) >= 5 && stream[1] == 0x03 {
		ctype, n := stream[0], int(binary.BigEndian.Uint16(stream[3:5]))
		if len(stream) < 5+n {
			break
		}
		if ctype == 22 {
			hs = append(hs, stream[5:5+n]...)
		} else if ctype != 20 && ctype != 21 { // past ChangeCipherSpec / alerts: encrypted
			break
		}
		stream = stream[5+n:]
	}
	for len(hs) >= 4 {
		n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if len(hs) < 4+n {
			return nil
		}
		if hs[0] == typ {
			return hs[4 : 4+n]
		}
		hs = hs[4+n:]
	}
	return nil
}

// parseServerHello returns a ServerHello's effective version (supported_versions when
// present) and cipher suite.
func parseServerHello(b []byte) (version, cipher uint16) {
	if len(b) < 2+32+1 {
		return 0, 0
	}
	version = binary.BigEndian.Uint16(b[0:2])
	p := 2 + 32
	p += 1 + int(b[p]) // session_id
	if len(b) < p+3 {
		return version, 0
	}
	cipher = binary.BigEndian.Uint16(b[p : p+2])
	p += 3
	if len(b) < p+2 {
		return version, cipher
	}
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
	for p += 2; p+4 <= end && p+4 <= len(b); {
		et, el := binary.BigEndian.Uint16(b[p:p+2]), int(binary.BigEndian.Uint16(b[p+2:p+4]))
		if et == 43 && el == 2 && p+6 <= len(b) { // supported_versions
			version = binary.BigEndian.Uint16(b[p+4 : p+6])
		}
		p += 4 + el
	}
	return version, cipher
}

// describeCertificates names a TLS 1.2 Certificate message's chain: subject and the
// leaf's DNS names, which say whose server this is even when nothing else does.
func describeCertificates(b []byte) []string {
	var out []string
	total := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	b = b[3:]
	if total < len(b) {
		b = b[:total]
	}
	for i := 0; len(b) >= 3 && i < 3; i++ {
		n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		if len(b) < 3+n {
			break
		}
		cert, err := x509.ParseCertificate(b[3 : 3+n])
		b = b[3+n:]
		if err != nil {
			continue
		}
		line := fmt.Sprintf("certificate[%d]: subject=%q issuer=%q", i, cert.Subject.String(), cert.Issuer.String())
		if i == 0 && len(cert.DNSNames) > 0 {
			names := cert.DNSNames
			if len(names) > 10 {
				names = append(names[:10:10], "…")
			}
			line += " dns=" + strings.Join(names, ",")
		}
		out = append(out, line)
	}
	return out
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS1.3"
	case 0x0303:
		return "TLS1.2"
	case 0x0302:
		return "TLS1.1"
	case 0x0301:
		return "TLS1.0"
	case 0x0300:
		return "SSL3.0"
	}
	return fmt.Sprintf("%#04x", v)
}
