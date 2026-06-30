package quicdecrypt

import "gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsdecrypt"

// Conn passively decrypts one QUIC connection from its two directional datagram streams,
// fed incrementally. It decrypts Initial packets with the version-derived keys to recover
// the ClientHello (client_random + SNI) and ServerHello (cipher suite), then derives
// 1-RTT keys from the key-log (by client_random) to decrypt application packets and
// reassemble each QUIC stream, delivering ordered stream bytes via onStream. Direction is
// taken from the capture (first datagram's sender is the client), like the TCP path.
type Conn struct {
	keylog   *tlsdecrypt.Keylog
	onStream func(streamID uint64, fromClient bool, data []byte)

	origDCID    []byte // client's first DCID — seeds the Initial secrets for both sides
	clientSCID  []byte // from the client long header (DCID of server→client short packets)
	serverSCID  []byte // from the server long header (DCID of client→server short packets)
	initialKeys [2]*keys

	clientRandom []byte
	suite        *suite
	app          [2]*keys // 1-RTT keys: [0]=client, [1]=server

	crypto    [2]cryptoReasm
	streams   map[uint64]*streamReasm
	largestPN [2]uint64 // 1-RTT, per direction
	unsupp    bool

	// SNI is the ClientHello server name, available after the client Initial.
	SNI string
}

// NewConn returns a decryptor that calls onStream with newly-available, in-order bytes
// for a stream (direction + stream id).
func NewConn(keylog *tlsdecrypt.Keylog, onStream func(streamID uint64, fromClient bool, data []byte)) *Conn {
	return &Conn{keylog: keylog, onStream: onStream, streams: map[uint64]*streamReasm{}}
}

func dirIdx(fromClient bool) int {
	if fromClient {
		return 0
	}
	return 1
}

// Feed processes one UDP datagram (which may hold coalesced QUIC packets).
func (c *Conn) Feed(fromClient bool, datagram []byte) {
	if c.unsupp {
		return
	}
	off := 0
	for off < len(datagram) {
		if datagram[off]&0x80 == 0 { // short header (1-RTT) — always the last packet
			c.handleShort(fromClient, datagram[off:])
			return
		}
		h, ok := parseLongHeader(datagram[off:])
		if !ok {
			return
		}
		abs := datagram[off : off+h.end]
		if h.kind == pktInitial && h.version == Version1 {
			c.handleInitial(fromClient, h, abs)
		}
		// 0-RTT/Handshake are not needed for HTTP/3 (which rides 1-RTT); skip them.
		off += h.end
	}
}

func (c *Conn) handleInitial(fromClient bool, h longHeader, pkt []byte) {
	if fromClient {
		if c.origDCID == nil {
			c.origDCID = append([]byte(nil), h.dcid...)
			cl, sv := initialSecrets(c.origDCID)
			c.initialKeys[0], _ = deriveKeys(cl, aes128gcm)
			c.initialKeys[1], _ = deriveKeys(sv, aes128gcm)
		}
		c.clientSCID = append([]byte(nil), h.scid...)
	} else {
		if c.origDCID == nil {
			return // haven't seen the client Initial yet; can't derive Initial keys
		}
		c.serverSCID = append([]byte(nil), h.scid...)
	}
	k := c.initialKeys[dirIdx(fromClient)]
	if k == nil {
		return
	}
	_, payload, _, ok := k.open(pkt, h.pnOffset, h.end, true, 0)
	if !ok {
		return
	}
	crypto, _, _ := parseFrames(payload)
	for _, fr := range crypto {
		if msg := c.crypto[dirIdx(fromClient)].add(fr.offset, fr.data); msg != nil {
			c.onHandshake(fromClient, msg)
		}
	}
}

func (c *Conn) onHandshake(fromClient bool, msg []byte) {
	if fromClient {
		if ch, ok := parseClientHello(msg); ok {
			c.clientRandom = ch.random
			c.SNI = ch.sni
		}
	} else {
		if id, ok := parseServerHello(msg); ok {
			if s, found := suiteByID(id); found {
				c.suite = s
			} else {
				c.unsupp = true
			}
		}
	}
	c.derive1RTT()
}

// derive1RTT pulls the 1-RTT traffic secrets from the key-log (by client_random) once
// the suite is known, and derives the application keys for both directions.
func (c *Conn) derive1RTT() {
	if c.app[0] != nil || c.clientRandom == nil || c.suite == nil {
		return
	}
	cs, ok1 := c.keylog.Get("CLIENT_TRAFFIC_SECRET_0", c.clientRandom)
	ss, ok2 := c.keylog.Get("SERVER_TRAFFIC_SECRET_0", c.clientRandom)
	if !ok1 || !ok2 {
		return // secrets not in the key-log yet; retry on a later packet
	}
	c.app[0], _ = deriveKeys(cs, c.suite)
	c.app[1], _ = deriveKeys(ss, c.suite)
}

func (c *Conn) handleShort(fromClient bool, pkt []byte) {
	c.derive1RTT()
	k := c.app[dirIdx(fromClient)]
	if k == nil {
		return // 1-RTT keys not available yet
	}
	// Short-header DCID is the peer's chosen connection id; its length isn't on the wire,
	// so use the length learned from the long headers.
	dcidLen := len(c.serverSCID)
	if !fromClient {
		dcidLen = len(c.clientSCID)
	}
	pnOffset := 1 + dcidLen
	if pnOffset+4 > len(pkt) {
		return
	}
	_, payload, pn, ok := k.open(pkt, pnOffset, len(pkt), false, c.largestPN[dirIdx(fromClient)])
	if !ok {
		return
	}
	if pn > c.largestPN[dirIdx(fromClient)] {
		c.largestPN[dirIdx(fromClient)] = pn
	}
	_, streams, _ := parseFrames(payload)
	for _, fr := range streams {
		c.deliverStream(fromClient, fr)
	}
}

func (c *Conn) deliverStream(fromClient bool, fr streamFrame) {
	r := c.streams[fr.id]
	if r == nil {
		r = &streamReasm{}
		c.streams[fr.id] = r
	}
	if data := r.add(fr.offset, fr.data); len(data) > 0 {
		c.onStream(fr.id, fromClient, data)
	}
}

// cryptoReasm reassembles CRYPTO stream bytes (offset-ordered) and yields the handshake
// message once its declared length is contiguous from offset 0.
type cryptoReasm struct {
	buf     []byte
	have    int // contiguous bytes from 0
	pending map[uint64][]byte
	done    bool
}

func (r *cryptoReasm) add(offset uint64, data []byte) []byte {
	if r.done {
		return nil
	}
	if r.pending == nil {
		r.pending = map[uint64][]byte{}
	}
	r.pending[offset] = data
	for {
		next, ok := r.pending[uint64(r.have)]
		if !ok {
			break
		}
		delete(r.pending, uint64(r.have))
		if int(r.have) == len(r.buf) {
			r.buf = append(r.buf, next...)
		} else if int(r.have)+len(next) > len(r.buf) {
			r.buf = append(r.buf[:r.have], next...)
		}
		r.have = len(r.buf)
	}
	if r.have >= 4 { // handshake header present: type(1) + length(3)
		msgLen := 4 + (int(r.buf[1])<<16 | int(r.buf[2])<<8 | int(r.buf[3]))
		if r.have >= msgLen {
			r.done = true
			return r.buf[:msgLen]
		}
	}
	return nil
}

// streamReasm reassembles one QUIC stream's bytes, returning newly contiguous bytes.
type streamReasm struct {
	have    uint64
	pending map[uint64][]byte
}

func (r *streamReasm) add(offset uint64, data []byte) []byte {
	if r.pending == nil {
		r.pending = map[uint64][]byte{}
	}
	if offset+uint64(len(data)) <= r.have {
		return nil // fully old
	}
	if offset < r.have { // partial overlap: trim already-delivered prefix
		data = data[r.have-offset:]
		offset = r.have
	}
	r.pending[offset] = data
	var out []byte
	for {
		next, ok := r.pending[r.have]
		if !ok {
			break
		}
		delete(r.pending, r.have)
		out = append(out, next...)
		r.have += uint64(len(next))
	}
	return out
}
