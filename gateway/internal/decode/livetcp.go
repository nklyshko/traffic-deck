package decode

// Live custom-protocol decoding, fully in-process in Go. Instead of
// re-running `tshark -z follow,tls,raw` over the growing capture, we tap the same live
// pcap byte stream, reassemble TCP with gopacket, decrypt TLS 1.3 from the key-log
// (internal/tlsdecrypt), and feed each matched connection's decrypted application bytes
// to the decoder's stateful Session — emitting frames through the same onFlow/onMsg
// callbacks the WebSocket live path uses. Streams that aren't TLS 1.3 (or use an
// unsupported link type) are left to the batch tshark pass on close.

import (
	"encoding/binary"
	"io"
	"log"
	"net"

	"github.com/google/gopacket"
	gplayers "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/reassembly"
	"github.com/google/uuid"

	"gitlab.com/nklyshko/traffic-deck/gateway/decoders"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"
)

// linkTypeNFLOG is LINKTYPE_NFLOG (239), used by the Android per-app capture
// (`tcpdump -i nflog:<group>`). gopacket has no decoder for it, so we extract the
// inner IP packet ourselves (nflogIPPayload).
const linkTypeNFLOG = gplayers.LinkType(239)

// LiveTCPDecode reads a live pcap byte stream from r, reassembles TCP, decrypts TLS 1.3
// using the (growing) key-log at keylogPath, and emits decoded custom-protocol frames
// via onFlow/onMsg. Returns when r reaches EOF (the capture's pipe is closed).
func LiveTCPDecode(r io.Reader, keylogPath string, onFlow func(*Flow, bool), onMsg func(*WsMessage)) error {
	reader, err := pcapgo.NewReader(r)
	if err != nil {
		return err // includes EOF if the session sent no pcap
	}
	lt := &liveTCP{
		keylog: tlsdecrypt.NewKeylog(keylogPath),
		onFlow: onFlow,
		onMsg:  onMsg,
	}
	asm := reassembly.NewAssembler(reassembly.NewStreamPool(lt))
	linkType := reader.LinkType()
	for {
		data, _, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // truncated trailing packet while the file grows — skip, keep going
		}
		var pkt gopacket.Packet
		if linkType == linkTypeNFLOG {
			ipType, ip, ok := nflogIPPayload(data)
			if !ok {
				continue
			}
			pkt = gopacket.NewPacket(ip, ipType, gopacket.Lazy)
		} else {
			pkt = gopacket.NewPacket(data, linkType, gopacket.Lazy)
		}
		netLayer := pkt.NetworkLayer()
		tcpLayer := pkt.Layer(gplayers.LayerTypeTCP)
		if netLayer == nil || tcpLayer == nil {
			continue // non-TCP, or a link type gopacket can't decode
		}
		asm.Assemble(netLayer.NetworkFlow(), tcpLayer.(*gplayers.TCP))
	}
	asm.FlushAll()
	return nil
}

// liveTCP is the gopacket StreamFactory: shared key-log + sinks for all connections.
type liveTCP struct {
	keylog *tlsdecrypt.Keylog
	onFlow func(*Flow, bool)
	onMsg  func(*WsMessage)
}

func (f *liveTCP) New(netFlow, tcpFlow gopacket.Flow, _ *gplayers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	// reassembly treats the first-seen packet's source as the client; with capture
	// starting at connection setup that's the real TLS client, so its peer is the server.
	s := &tcpStream{
		lt:         f,
		serverHost: netFlow.Dst().String(),
		serverPort: tcpFlow.Dst().String(),
		clientAddr: net.JoinHostPort(netFlow.Src().String(), tcpFlow.Src().String()),
	}
	s.conn = tlsdecrypt.NewConn(f.keylog, s.onApp)
	return s
}

// tcpStream is one reassembled TCP connection: its TLS decryptor, and (once a decoder
// claims it) the decoder session + synthetic flow.
type tcpStream struct {
	lt                                 *liveTCP
	serverHost, serverPort, clientAddr string
	conn                               *tlsdecrypt.Conn

	sniffed     bool // checked the first client bytes look like TLS
	decided     bool // ran decoder matching once the SNI was known
	matched     bool
	dropped     bool
	flowEmitted bool
	sess        decoders.Session
	flow        *Flow
}

func (s *tcpStream) Accept(_ *gplayers.TCP, _ gopacket.CaptureInfo, _ reassembly.TCPFlowDirection,
	_ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	*start = true // accept even if the SYN wasn't captured
	return true
}

func (s *tcpStream) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
	if s.dropped {
		return
	}
	dir, _, _, _ := sg.Info()
	n, _ := sg.Lengths()
	if n == 0 {
		return
	}
	data := sg.Fetch(n)
	fromClient := dir == reassembly.TCPDirClientToServer
	// Cheap non-TLS filter: the first client→server bytes must begin a TLS handshake
	// record (type 22, version 0x03xx); otherwise drop the connection.
	if fromClient && !s.sniffed {
		s.sniffed = true
		if len(data) < 2 || data[0] != 0x16 || data[1] != 0x03 {
			s.dropped = true
			return
		}
	}
	s.conn.Feed(fromClient, data)
	if s.conn.Unsupported() {
		s.dropped = true
	}
}

func (s *tcpStream) ReassemblyComplete(_ reassembly.AssemblerContext) bool { return true }

// onApp receives decrypted application bytes from the TLS layer. On the first call it
// matches the connection (by SNI/host) to a decoder; thereafter it frames the bytes
// into messages and publishes them like the WebSocket live path.
func (s *tcpStream) onApp(fromClient bool, plain []byte) {
	if !s.decided {
		s.decided = true
		m := decoders.Match(decoders.StreamMeta{
			ServerHost: s.serverHost, ServerPort: s.serverPort, SNI: s.conn.SNI(),
		})
		if len(m) == 0 {
			s.dropped = true
			return
		}
		s.sess = m[0].NewSession()
		s.flow = customFlowMeta(s.conn.SNI(), s.serverHost, s.serverPort, s.clientAddr, m[0].Name())
		s.matched = true
		log.Printf("live decode: matched %s decoder for %s (%s)", m[0].Name(), s.conn.SNI(), s.serverHost)
	}
	if !s.matched {
		return
	}
	for _, msg := range s.sess.Feed(fromClient, plain) {
		if !s.flowEmitted {
			s.lt.onFlow(s.flow, true)
			s.flowEmitted = true
			log.Printf("live decode: %s first frame on %s: %s (%d bytes)", s.flow.Protocol, s.conn.SNI(), msg.Opcode, len(msg.Payload))
		}
		s.flow.WsMessageCount++
		s.lt.onMsg(&WsMessage{
			ID:         uuid.NewString(),
			FlowID:     s.flow.ID,
			FromClient: msg.FromClient,
			Opcode:     msg.Opcode,
			Payload:    msg.Payload,
		})
		s.lt.onFlow(s.flow, false) // refresh the row's ⇅ count
	}
}

// nflogIPPayload extracts the inner IP packet from one LINKTYPE_NFLOG record. The
// record is a 4-byte header (family, version, resource_id) followed by little-endian
// TLVs (length incl. header, type), 4-byte aligned; NFULA_PAYLOAD (type 9) carries the
// captured IP packet. family selects IPv4 (AF_INET=2) or IPv6 (AF_INET6=10).
func nflogIPPayload(data []byte) (gopacket.LayerType, []byte, bool) {
	if len(data) < 4 {
		return 0, nil, false
	}
	family := data[0]
	for off := 4; off+4 <= len(data); {
		l := int(binary.LittleEndian.Uint16(data[off : off+2]))
		typ := binary.LittleEndian.Uint16(data[off+2 : off+4])
		if l < 4 || off+l > len(data) {
			break
		}
		if typ == 9 { // NFULA_PAYLOAD
			payload := data[off+4 : off+l]
			switch family {
			case 2: // AF_INET
				return gplayers.LayerTypeIPv4, payload, true
			case 10: // AF_INET6
				return gplayers.LayerTypeIPv6, payload, true
			default:
				return 0, nil, false
			}
		}
		off += (l + 3) &^ 3 // advance to the next 4-byte-aligned TLV
	}
	return 0, nil, false
}
