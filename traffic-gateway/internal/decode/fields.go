package decode

// PDML field and body-field names the decoder reads from tshark, in one place so the
// schema the gateway depends on is discoverable and typo-safe.

// Packet / transport / TLS metadata fields.
const (
	fFrameNum   = "frame.number"
	fFrameTime  = "frame.time_epoch"
	fFrameProto = "frame.protocols"
	fIPSrc      = "ip.src"
	fIPDst      = "ip.dst"
	fIP6Src     = "ipv6.src"
	fIP6Dst     = "ipv6.dst"
	fTCPStream  = "tcp.stream"
	fTCPSrcPort = "tcp.srcport"
	fTCPDstPort = "tcp.dstport"
	fUDPSrcPort = "udp.srcport"
	fUDPDstPort = "udp.dstport"
	fTLSStream  = "tls.stream"
	fTLSSNI     = "tls.handshake.extensions_server_name"
	fQUICConn   = "quic.connection.number"
)

// HTTP/1.1 fields.
const (
	fH1Method      = "http.request.method"
	fH1URI         = "http.request.uri"
	fH1Status      = "http.response.code"
	fH1Host        = "http.host"
	fH1UserAgent   = "http.user_agent"
	fH1ContentType = "http.content_type"
)

// HTTP/2 fields.
const (
	fH2StreamID  = "http2.streamid"
	fH2Method    = "http2.headers.method"
	fH2Scheme    = "http2.headers.scheme"
	fH2Authority = "http2.headers.authority"
	fH2Path      = "http2.headers.path"
	fH2Status    = "http2.headers.status"
	fH2HdrName   = "http2.header.name"
	fH2HdrValue  = "http2.header.value"
)

// HTTP/3 fields.
const (
	fH3StreamID  = "http3.frame_streamid"
	fH3Method    = "http3.headers.method"
	fH3Scheme    = "http3.headers.scheme"
	fH3Authority = "http3.headers.authority"
	fH3Path      = "http3.headers.path"
	fH3Status    = "http3.headers.status"
	fH3HdrName   = "http3.header.header.name"
	fH3HdrValue  = "http3.headers.header.value"
)

// WebSocket fields.
const (
	fWSOpcode      = "websocket.opcode"
	fWSPayload     = "websocket.payload"
	fWSPayloadText = "websocket.payload.text"
)

// Body byte-fields: raw hex lives in the `value` attribute. The "reassembled" variants
// carry the complete body; the others carry a single frame's bytes.
const (
	fH2Data            = "http2.data.data"
	fH2BodyReassembled = "http2.body.reassembled.data"
	fH1FileData        = "http.file_data"
	fH1BodyReassembled = "http.body.reassembled.data"
	fH3Data            = "http3.data"
)
