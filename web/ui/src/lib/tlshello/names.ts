// Names for the values a ClientHello carries. The large registries are generated from IANA
// (iana.ts); this file adds the small ones IANA keeps as prose and the code points clients
// send before or without registering them.
import * as iana from './iana'

export const CIPHER_SUITES: Record<number, string> = {
  ...iana.CIPHER_SUITES,
  // Pre-RFC 7905 ChaCha20 code points, still sent by old Chrome and Android builds.
  0xcc13: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD',
  0xcc14: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD',
  0xcc15: 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD',
}

export const EXTENSIONS: Record<number, string> = {
  ...iana.EXTENSIONS,
  0x3374: 'next_protocol_negotiation', // draft-agl-tls-nextprotoneg, before ALPN
  0x4469: 'application_settings_old', // ALPS, draft-vvv-tls-alps; Chrome's first code point
  0x44cd: 'application_settings', // ALPS, Chrome's current code point
  0x7550: 'channel_id', // draft-balfanz-tls-channelid
  0xca34: 'trust_anchors', // draft-ietf-tls-trust-anchor-ids; Chrome's experimental code point
}

export const { GROUPS, EC_POINT_FORMATS, CERTIFICATE_TYPES, QUIC_PARAMETERS } = iana

// TLS 1.2 sent signature algorithms as (hash, signature) pairs (RFC 5246 §7.4.1.4.1). TLS 1.3
// kept the code points of the ones it adopted and IANA now lists the rest only as reserved,
// but TLS 1.2 clients still offer them.
const LEGACY_SIGNATURES: Record<number, string> = {}
for (const [h, hash] of ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'].entries()) {
  for (const [s, sig] of ['rsa', 'dsa', 'ecdsa'].entries()) LEGACY_SIGNATURES[((h + 1) << 8) | (s + 1)] = `${sig}_${hash}`
}
export const SIGNATURE_SCHEMES: Record<number, string> = { ...LEGACY_SIGNATURES, ...iana.SIGNATURE_SCHEMES }

export const VERSIONS: Record<number, string> = {
  0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3',
  0xfeff: 'DTLS 1.0', 0xfefd: 'DTLS 1.2', 0xfefc: 'DTLS 1.3',
}

export const COMPRESSION_METHODS: Record<number, string> = { 0: 'null', 1: 'DEFLATE', 64: 'LZS' } // RFC 3749, RFC 3943
export const PSK_MODES: Record<number, string> = { 0: 'psk_ke', 1: 'psk_dhe_ke' } // RFC 8446 §4.2.9
export const CERT_COMPRESSION: Record<number, string> = { 1: 'zlib', 2: 'brotli', 3: 'zstd' } // RFC 8879 §7.3
export const STATUS_TYPES: Record<number, string> = { 1: 'ocsp', 2: 'ocsp_multi' } // RFC 6066, RFC 6961
export const SERVER_NAME_TYPES: Record<number, string> = { 0: 'host_name' } // RFC 6066 §3
export const MAX_FRAGMENT_LENGTHS: Record<number, string> = { 1: '2^9', 2: '2^10', 3: '2^11', 4: '2^12' } // RFC 6066 §4
export const HEARTBEAT_MODES: Record<number, string> = { 1: 'peer_allowed_to_send', 2: 'peer_not_allowed_to_send' } // RFC 6520
export const HPKE_KDFS: Record<number, string> = { 1: 'HKDF-SHA256', 2: 'HKDF-SHA384', 3: 'HKDF-SHA512' } // RFC 9180 §7.2
export const HPKE_AEADS: Record<number, string> = { 1: 'AES-128-GCM', 2: 'AES-256-GCM', 3: 'ChaCha20Poly1305', 0xffff: 'Export-only' } // RFC 9180 §7.3

// QUIC parameters whose value is a varint (RFC 9000 §18.2 and the extensions that define
// them); the rest are bytes, or text for the two Google ones that carry ASCII.
export const QUIC_INTEGER_PARAMETERS = new Set(['0x1', '0x3', '0x4', '0x5', '0x6', '0x7', '0x8', '0x9', '0xa', '0xb', '0xe', '0x20', '0x3e', '0x3127', '0xff04de1b'])
export const QUIC_TEXT_PARAMETERS = new Set(['0x3128', '0x3129'])
export const QUIC_VERSIONS: Record<number, string> = { 0x00000001: 'QUIC v1', 0x6b3343cf: 'QUIC v2' } // RFC 9000, RFC 9369
