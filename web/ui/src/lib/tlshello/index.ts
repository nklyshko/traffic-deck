// TLS ClientHello parser. Self-contained: no dependencies and nothing outside this folder,
// only Uint8Array, so it runs in a browser, Node, Deno or a worker alike.
//
// Covers the ClientHello of RFC 8446 §4.1.2 (and the TLS 1.0–1.2 form, RFC 5246 §7.4.1.2),
// every extension a ClientHello may carry by RFC 8446 §4.2 and the TLS ExtensionType
// registry, and GREASE (RFC 8701). Input is either a handshake message (01 + length, as TLS
// stores it and as QUIC carries it in CRYPTO frames) or TLS records (16 03 0x + length)
// holding one, split over several records or not.
import {
  CERT_COMPRESSION, CERTIFICATE_TYPES, CIPHER_SUITES, COMPRESSION_METHODS, EC_POINT_FORMATS, EXTENSIONS, GROUPS,
  HEARTBEAT_MODES, HPKE_AEADS, HPKE_KDFS, MAX_FRAGMENT_LENGTHS, PSK_MODES, QUIC_INTEGER_PARAMETERS, QUIC_PARAMETERS,
  QUIC_TEXT_PARAMETERS, QUIC_VERSIONS, SERVER_NAME_TYPES, SIGNATURE_SCHEMES, STATUS_TYPES, VERSIONS,
} from './names'

export * as names from './names'

/** A registry value: the number on the wire and its name, "GREASE" or "unknown". */
export interface Code { value: number; name: string; bits: 8 | 16 }

export type Field = string | number | boolean | Code | Uint8Array | Field[] | { [key: string]: Field }

export interface Extension {
  type: Code
  /** Offset of the extension's type field from the start of the handshake message. */
  offset: number
  data: Uint8Array
  /** The extension's contents, when the type is one this parser reads and the bytes parse. */
  body?: { [key: string]: Field }
  error?: string
}

export interface ClientHello {
  /** The handshake message alone (type, length, body), record framing removed. */
  message: Uint8Array
  /** Present when the input was TLS records rather than a bare handshake message. */
  record?: { version: Code; count: number }
  version: Code
  random: Uint8Array
  sessionId: Uint8Array
  cipherSuites: Code[]
  compressionMethods: Code[]
  /** Absent only for a pre-TLS 1.0 style ClientHello that ends after compression methods. */
  extensions?: Extension[]
  /** Bytes after the ClientHello: a following message, or junk pasted along with it. */
  trailing: number
  /** Where the message departs from the specs without being unreadable. */
  warnings: string[]
}

export class TlsParseError extends Error {
  constructor(message: string, readonly offset: number) {
    super(message)
    this.name = 'TlsParseError'
  }
}

// --- GREASE (RFC 8701) -----------------------------------------------------------------

/** Cipher suites, extensions, groups, signature schemes and versions: 0x0A0A … 0xFAFA. */
export const isGrease = (v: number) => (v & 0x0f0f) === 0x0a0a && v >> 8 === (v & 0xff)
/** PskKeyExchangeModes: 0x0B, 0x2A, … 0xE4. */
export const isGreasePskMode = (v: number) => v >= 0x0b && v <= 0xe4 && (v - 0x0b) % 0x1f === 0
/** QUIC transport parameter ids (RFC 9000 §18.1): 31 · N + 27. */
export const isGreaseQuicParameter = (id: bigint) => id >= 27n && (id - 27n) % 31n === 0n
/** ALPN: a two-byte protocol id whose bytes form a GREASE value. */
export const isGreaseAlpn = (p: Uint8Array) => p.length === 2 && isGrease((p[0] << 8) | p[1])

// --- reading ------------------------------------------------------------------------------

class Reader {
  constructor(readonly buf: Uint8Array, public pos: number, readonly end: number) {}
  get left() { return this.end - this.pos }
  private need(n: number, what: string) {
    if (n > this.left) throw new TlsParseError(`${what}: needs ${n} bytes at offset ${this.pos}, ${this.left} left`, this.pos)
  }
  u8(what: string) { this.need(1, what); return this.buf[this.pos++] }
  u16(what: string) { this.need(2, what); const v = (this.buf[this.pos] << 8) | this.buf[this.pos + 1]; this.pos += 2; return v }
  u24(what: string) { this.need(3, what); const v = (this.buf[this.pos] << 16) | (this.buf[this.pos + 1] << 8) | this.buf[this.pos + 2]; this.pos += 3; return v }
  u32(what: string) { return this.u16(what) * 0x10000 + this.u16(what) }
  bytes(n: number, what: string) { this.need(n, what); const b = this.buf.subarray(this.pos, this.pos + n); this.pos += n; return b }
  /** A length-prefixed vector, as a reader over just its contents. */
  vec(lenBytes: 1 | 2 | 3, what: string) {
    const n = lenBytes === 1 ? this.u8(what) : lenBytes === 2 ? this.u16(what) : this.u24(what)
    this.need(n, what)
    const r = new Reader(this.buf, this.pos, this.pos + n)
    this.pos += n
    return r
  }
  /** QUIC variable-length integer (RFC 9000 §16): up to 62 bits, so a bigint. */
  varint(what: string) {
    const first = this.u8(what)
    const len = 1 << (first >> 6)
    let v = BigInt(first & 0x3f)
    for (let i = 1; i < len; i++) v = (v << 8n) | BigInt(this.u8(what))
    return v
  }
  list<T>(lenBytes: 1 | 2, what: string, item: (r: Reader) => T): T[] {
    const r = this.vec(lenBytes, what)
    const out: T[] = []
    while (r.left > 0) out.push(item(r))
    return out
  }
}

const hex = (v: number, digits: number) => v.toString(16).padStart(digits, '0')

function code(table: Record<number, string>, value: number, bits: 8 | 16 = 16, grease = isGrease): Code {
  return { value, bits, name: grease(value) ? 'GREASE' : (table[value] ?? unknownName(table, value)) }
}

function unknownName(table: Record<number, string>, value: number) {
  // Pre-RFC TLS 1.3 drafts, which some middleboxes and old clients still offer.
  if (table === VERSIONS && value >> 8 === 0x7f) return `TLS 1.3 draft ${value & 0xff}`
  return 'unknown'
}

const neverGrease = () => false
const u16Codes = (table: Record<number, string>, lenBytes: 1 | 2, what: string) => (r: Reader) => r.list(lenBytes, what, (x) => code(table, x.u16(what)))
const u8Codes = (table: Record<number, string>, what: string, grease: (v: number) => boolean = neverGrease) => (r: Reader) => r.list(1, what, (x) => code(table, x.u8(what), 8, grease))

const ascii = (b: Uint8Array) => String.fromCharCode(...b)
const printable = (b: Uint8Array) => b.length > 0 && b.every((c) => c >= 0x20 && c < 0x7f)
const protocolId = (b: Uint8Array): Field => (isGreaseAlpn(b) ? code({}, (b[0] << 8) | b[1]) : printable(b) ? ascii(b) : b)

// --- extensions ---------------------------------------------------------------------------

type Body = { [key: string]: Field }
const EMPTY = (r: Reader): Body => (r.left ? { unexpected: r.bytes(r.left, 'data') } : {})

// Each reads the extension's whole extension_data; bytes it leaves unread are an error.
const BODIES: Record<number, (r: Reader) => Body> = {
  0: (r) => ({
    server_names: r.list(2, 'server_name_list', (x) => {
      const type = x.u8('name_type')
      const name = x.vec(2, 'host_name')
      return { type: code(SERVER_NAME_TYPES, type, 8, neverGrease), name: ascii(name.bytes(name.left, 'host_name')) }
    }),
  }),
  1: (r) => {
    const v = r.u8('max_fragment_length')
    return { max_fragment_length: code(MAX_FRAGMENT_LENGTHS, v, 8, neverGrease) }
  },
  5: (r): Body => {
    const type = code(STATUS_TYPES, r.u8('status_type'), 8, neverGrease)
    if (type.value !== 1) return { status_type: type, request: r.bytes(r.left, 'request') }
    const responders = r.list(2, 'responder_id_list', (x) => { const id = x.vec(2, 'ResponderID'); return id.bytes(id.left, 'ResponderID') })
    const ext = r.vec(2, 'request_extensions')
    return { status_type: type, responder_ids: responders, request_extensions: ext.bytes(ext.left, 'request_extensions') }
  },
  10: (r) => ({ named_groups: u16Codes(GROUPS, 2, 'named_group_list')(r) }),
  11: (r) => ({ ec_point_formats: u8Codes(EC_POINT_FORMATS, 'ec_point_format_list')(r) }),
  13: (r) => ({ signature_schemes: u16Codes(SIGNATURE_SCHEMES, 2, 'supported_signature_algorithms')(r) }),
  14: (r) => {
    const profiles = r.list(2, 'SRTPProtectionProfiles', (x) => hex(x.u16('profile'), 4))
    const mki = r.vec(1, 'srtp_mki')
    return { profiles, mki: mki.bytes(mki.left, 'srtp_mki') }
  },
  15: (r) => ({ mode: code(HEARTBEAT_MODES, r.u8('HeartbeatMode'), 8, neverGrease) }),
  16: (r) => ({ protocols: r.list(2, 'protocol_name_list', (x) => { const p = x.vec(1, 'ProtocolName'); return protocolId(p.bytes(p.left, 'ProtocolName')) }) }),
  18: EMPTY,
  19: (r) => ({ certificate_types: u8Codes(CERTIFICATE_TYPES, 'client_certificate_types')(r) }),
  20: (r) => ({ certificate_types: u8Codes(CERTIFICATE_TYPES, 'server_certificate_types')(r) }),
  21: (r) => {
    const pad = r.bytes(r.left, 'padding')
    return { length: pad.length, zeros: pad.every((b) => b === 0) }
  },
  22: EMPTY,
  23: EMPTY,
  24: (r) => ({ version: hex(r.u16('TB_ProtocolVersion'), 4), key_parameters: r.list(1, 'key_parameters_list', (x) => x.u8('TokenBindingKeyParameters')) }),
  27: (r) => ({ algorithms: r.list(1, 'algorithms', (x) => code(CERT_COMPRESSION, x.u16('CertificateCompressionAlgorithm'))) }),
  28: (r) => ({ record_size_limit: r.u16('RecordSizeLimit') }),
  34: (r) => ({ signature_schemes: u16Codes(SIGNATURE_SCHEMES, 2, 'supported_signature_algorithms')(r) }),
  35: (r) => ({ ticket: r.bytes(r.left, 'ticket') }),
  41: (r) => ({
    identities: r.list(2, 'identities', (x) => {
      const id = x.vec(2, 'identity')
      return { identity: id.bytes(id.left, 'identity'), obfuscated_ticket_age: x.u32('obfuscated_ticket_age') }
    }),
    binders: r.list(2, 'binders', (x) => { const b = x.vec(1, 'PskBinderEntry'); return b.bytes(b.left, 'PskBinderEntry') }),
  }),
  42: EMPTY,
  43: (r) => ({ versions: u16Codes(VERSIONS, 1, 'versions')(r) }),
  44: (r) => { const c = r.vec(2, 'cookie'); return { cookie: c.bytes(c.left, 'cookie') } },
  45: (r) => ({ modes: u8Codes(PSK_MODES, 'ke_modes', isGreasePskMode)(r) }),
  47: (r) => ({ authorities: r.list(2, 'authorities', (x) => { const dn = x.vec(2, 'DistinguishedName'); return dn.bytes(dn.left, 'DistinguishedName') }) }),
  49: EMPTY,
  50: (r) => ({ signature_schemes: u16Codes(SIGNATURE_SCHEMES, 2, 'supported_signature_algorithms_cert')(r) }),
  51: (r) => ({
    shares: r.list(2, 'client_shares', (x) => {
      const group = code(GROUPS, x.u16('group'))
      const key = x.vec(2, 'key_exchange')
      return { group, key_exchange: key.bytes(key.left, 'key_exchange') }
    }),
  }),
  54: (r) => { const c = r.vec(1, 'cid'); return { cid: c.bytes(c.left, 'cid') } },
  58: (r) => ({ new_session_count: r.u8('new_session_count'), resumption_count: r.u8('resumption_count') }),
  0x3374: EMPTY,
  0x4469: (r) => ({ protocols: alpsProtocols(r) }),
  0x44cd: (r) => ({ protocols: alpsProtocols(r) }),
  0x7550: EMPTY,
  0xca34: (r) => ({ trust_anchors: r.list(2, 'trust_anchor_ids', (x) => { const id = x.vec(1, 'TrustAnchorId'); return relativeOid(id.bytes(id.left, 'TrustAnchorId')) }) }),
  0xfd00: (r) => ({ outer_extensions: r.list(1, 'OuterExtensions', (x) => code(EXTENSIONS, x.u16('ExtensionType'))) }),
  65037: (r): Body => {
    const type = r.u8('ECHClientHelloType')
    // Not "type": that key is the extension's own in describe().
    if (type === 1) return { hello_type: 'inner' }
    if (type !== 0) return { hello_type: `unknown (${type})`, data: r.bytes(r.left, 'data') }
    const kdf = code(HPKE_KDFS, r.u16('kdf_id'), 16, neverGrease)
    const aead = code(HPKE_AEADS, r.u16('aead_id'), 16, neverGrease)
    const configId = r.u8('config_id')
    const enc = r.vec(2, 'enc')
    const payload = r.vec(2, 'payload')
    return { hello_type: 'outer', kdf, aead, config_id: configId, enc: enc.bytes(enc.left, 'enc'), payload: payload.bytes(payload.left, 'payload') }
  },
  65281: (r) => { const c = r.vec(1, 'renegotiated_connection'); return { renegotiated_connection: c.bytes(c.left, 'renegotiated_connection') } },
}

// QUIC transport parameters (RFC 9000 §18) use varint lengths, not TLS's u16 vectors.
BODIES[57] = (r) => {
  const parameters: Body[] = []
  while (r.left > 0) {
    const id = r.varint('transport parameter id')
    const len = Number(r.varint('transport parameter length'))
    const start = r.pos
    r.bytes(len, 'transport parameter value')
    const value = new Reader(r.buf, start, start + len)
    const key = `0x${id.toString(16)}`
    const name = isGreaseQuicParameter(id) ? 'GREASE' : (QUIC_PARAMETERS[key] ?? 'unknown')
    const entry: Body = { id: `${name} (${key})` }
    if (len > 0 && key === '0x11') {
      // RFC 9368 §3: the chosen version, then every version the client supports.
      const versions: string[] = []
      while (value.left >= 4) {
        const v = value.u32('version')
        versions.push(`${(v & 0x0f0f0f0f) === 0x0a0a0a0a ? 'GREASE' : (QUIC_VERSIONS[v] ?? 'unknown')} (0x${hex(v, 8)})`)
      }
      entry.chosen_version = versions[0]
      entry.available_versions = versions.slice(1)
      if (value.left) entry.unexpected = value.bytes(value.left, name)
    } else if (len > 0 && QUIC_INTEGER_PARAMETERS.has(key)) {
      const n = value.varint(name)
      entry.value = n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n.toString()
      if (value.left) entry.unexpected = value.bytes(value.left, name)
    } else if (len > 0) {
      const b = value.bytes(len, name)
      entry.value = QUIC_TEXT_PARAMETERS.has(key) && printable(b) ? ascii(b) : b
    }
    parameters.push(entry)
  }
  return { parameters }
}

// A trust anchor id is an OID relative to nothing: base-128 arcs, high bit = more to come.
function relativeOid(b: Uint8Array): string {
  const arcs: string[] = []
  let v = 0n
  for (const byte of b) {
    v = (v << 7n) | BigInt(byte & 0x7f)
    if (!(byte & 0x80)) { arcs.push(v.toString()); v = 0n }
  }
  return arcs.join('.') || toHex(b)
}

function alpsProtocols(r: Reader): Field[] {
  return r.list(2, 'supported_protocols', (x) => { const p = x.vec(1, 'ProtocolName'); return protocolId(p.bytes(p.left, 'ProtocolName')) })
}

// --- the message ----------------------------------------------------------------------------

const HANDSHAKE_TYPES: Record<number, string> = {
  0: 'hello_request', 1: 'client_hello', 2: 'server_hello', 4: 'new_session_ticket', 8: 'encrypted_extensions',
  11: 'certificate', 12: 'server_key_exchange', 13: 'certificate_request', 14: 'server_hello_done',
  15: 'certificate_verify', 16: 'client_key_exchange', 20: 'finished',
}

/** Strips TLS record framing: the handshake bytes of consecutive handshake records. */
function unrecord(input: Uint8Array): { bytes: Uint8Array; version: number; count: number } {
  const parts: Uint8Array[] = []
  let pos = 0, version = 0, count = 0
  while (pos + 5 <= input.length && input[pos] === 0x16) {
    const len = (input[pos + 3] << 8) | input[pos + 4]
    if (count === 0) version = (input[pos + 1] << 8) | input[pos + 2]
    if (pos + 5 + len > input.length) throw new TlsParseError(`TLS record ${count + 1} declares ${len} bytes, ${input.length - pos - 5} present`, pos)
    parts.push(input.subarray(pos + 5, pos + 5 + len))
    pos += 5 + len
    count++
  }
  const bytes = new Uint8Array(parts.reduce((n, p) => n + p.length, 0) + input.length - pos)
  let off = 0
  for (const p of parts) { bytes.set(p, off); off += p.length }
  bytes.set(input.subarray(pos), off) // what follows the records counts as trailing
  return { bytes, version, count }
}

/** Whether the bytes start like TLS records or a handshake message; cheap, for sniffing. */
export function looksLikeClientHello(input: Uint8Array): boolean {
  if (input.length >= 9 && input[0] === 0x16 && input[1] === 0x03 && input[5] === 0x01) return true
  return input.length >= 6 && input[0] === 0x01 && input[4] === 0x03
}

/** Parses a ClientHello; throws TlsParseError when the bytes are not one or are cut short. */
export function parseClientHello(input: Uint8Array): ClientHello {
  let bytes = input
  let record: ClientHello['record']
  if (input[0] === 0x16 && input[1] === 0x03) {
    const u = unrecord(input)
    bytes = u.bytes
    record = { version: code(VERSIONS, u.version), count: u.count }
  }
  const r = new Reader(bytes, 0, bytes.length)
  const type = r.u8('handshake type')
  if (type !== 1) throw new TlsParseError(`not a ClientHello: handshake type ${type} (${HANDSHAKE_TYPES[type] ?? 'unknown'})`, 0)
  const length = r.u24('handshake length')
  if (length > r.left) throw new TlsParseError(`ClientHello declares ${length} bytes, ${r.left} present`, 1)
  const body = new Reader(bytes, r.pos, r.pos + length)
  const warnings: string[] = []

  const version = code(VERSIONS, body.u16('legacy_version'))
  const random = body.bytes(32, 'random')
  const sid = body.vec(1, 'legacy_session_id')
  if (sid.left > 32) warnings.push(`legacy_session_id is ${sid.left} bytes; at most 32 are allowed`)
  const sessionId = sid.bytes(sid.left, 'legacy_session_id')
  const suites = body.vec(2, 'cipher_suites')
  if (suites.left % 2) throw new TlsParseError(`cipher_suites length ${suites.left} is odd`, suites.pos)
  const cipherSuites: Code[] = []
  while (suites.left) cipherSuites.push(code(CIPHER_SUITES, suites.u16('cipher_suite')))
  const compressionMethods = u8Codes(COMPRESSION_METHODS, 'legacy_compression_methods')(body)

  let extensions: Extension[] | undefined
  if (body.left > 0) {
    extensions = []
    const exts = body.vec(2, 'extensions')
    while (exts.left > 0) {
      const offset = exts.pos
      const extType = code(EXTENSIONS, exts.u16('extension_type'))
      const data = exts.vec(2, `${extType.name} extension_data`)
      const ext: Extension = { type: extType, offset, data: bytes.subarray(data.pos, data.end) }
      const read = BODIES[extType.value]
      if (read && extType.name !== 'GREASE') {
        try {
          ext.body = read(data)
          if (data.left) ext.error = `${data.left} bytes left over after the ${extType.name} contents`
        } catch (e) {
          if (!(e instanceof TlsParseError)) throw e
          ext.error = e.message
          delete ext.body
        }
      }
      extensions.push(ext)
    }
    if (body.left) warnings.push(`${body.left} bytes after the extensions, inside the ClientHello`)
  }

  checkSpec(extensions, compressionMethods, warnings)
  return {
    message: bytes.subarray(0, 4 + length),
    record, version, random, sessionId, cipherSuites, compressionMethods, extensions,
    trailing: bytes.length - 4 - length,
    warnings,
  }
}

function checkSpec(extensions: Extension[] | undefined, compression: Code[], warnings: string[]) {
  const seen = new Map<number, number>()
  for (const e of extensions ?? []) seen.set(e.type.value, (seen.get(e.type.value) ?? 0) + 1)
  for (const [type, n] of seen) {
    if (n > 1) warnings.push(`${code(EXTENSIONS, type).name} (0x${hex(type, 4)}) appears ${n} times; RFC 8446 §4.2 allows one of each`)
  }
  const last = extensions?.[extensions.length - 1]
  if (extensions?.some((e) => e.type.value === 41) && last?.type.value !== 41) warnings.push('pre_shared_key is not the last extension (RFC 8446 §4.2.11)')
  const versions = extensions?.find((e) => e.type.value === 43)?.body?.versions
  const offersTls13 = Array.isArray(versions) && versions.some((v) => (v as Code).value === 0x0304)
  if (offersTls13 && (compression.length !== 1 || compression[0].value !== 0)) warnings.push('TLS 1.3 requires legacy_compression_methods to be exactly [null] (RFC 8446 §4.1.2)')
  const padding = extensions?.find((e) => e.type.value === 21)
  if (padding?.body && padding.body.zeros === false) warnings.push('padding extension contains non-zero bytes (RFC 7685 §3)')
}

// --- convenience ------------------------------------------------------------------------------

export function serverName(h: ClientHello): string | undefined {
  const names = h.extensions?.find((e) => e.type.value === 0)?.body?.server_names
  return Array.isArray(names) ? ((names[0] as Body | undefined)?.name as string | undefined) : undefined
}

export function alpn(h: ClientHello): string[] {
  const p = h.extensions?.find((e) => e.type.value === 16)?.body?.protocols
  return Array.isArray(p) ? p.filter((x): x is string => typeof x === 'string') : []
}

/** Wraps a handshake message in TLS records (max 2^14 bytes of fragment each). TLS 1.3
 *  clients put 0x0301 on the first ClientHello's record and 0x0303 on any later one. */
export function toRecords(message: Uint8Array, version = 0x0301): Uint8Array {
  const out: number[] = []
  for (let off = 0; off < message.length || off === 0; off += 0x4000) {
    const frag = message.subarray(off, Math.min(off + 0x4000, message.length))
    out.push(0x16, version >> 8, version & 0xff, frag.length >> 8, frag.length & 0xff, ...frag)
    if (message.length === 0) break
  }
  return Uint8Array.from(out)
}

export const toHex = (b: Uint8Array) => Array.from(b, (x) => hex(x, 2)).join('')

export function toBase64(b: Uint8Array): string {
  let s = ''
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000))
  return btoa(s)
}

const OFFSET = /^\s*[0-9a-fA-F]{4,8}(?:\s*[-:]\s*|\s+)/

/** Bytes from pasted text: hex (spaces, colons, 0x and newlines allowed), a hex dump with an
 *  offset column (Wireshark, `openssl s_client -debug`, `xxd`, `hexdump -C`), or base64.
 *  null when it is none of those. */
export function bytesFromText(text: string): Uint8Array | null {
  const t = text.trim()
  if (!t) return null
  const lines = t.split(/\r?\n/)
  if (lines.length > 1 && lines.every((l) => !l.trim() || OFFSET.test(l))) {
    const out: number[] = []
    for (const l of lines) {
      const tokens = l.replace(OFFSET, '').trim().split(/\s+/)
      for (const tok of tokens.slice(0, 16)) {
        // xxd groups bytes in fours ("1603 0100"); a dump's ASCII column ends the bytes.
        if (!/^(?:[0-9a-fA-F]{2})+$/.test(tok) || tok.length > 4) break
        for (let i = 0; i < tok.length; i += 2) out.push(parseInt(tok.slice(i, i + 2), 16))
      }
    }
    return out.length ? Uint8Array.from(out) : null
  }
  const compact = t.replace(/0x/gi, '').replace(/[\s:,]/g, '')
  if (compact.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(compact)) return Uint8Array.from(compact.match(/../g)!, (b) => parseInt(b, 16))
  const b64 = t.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/')
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(b64) && b64.replace(/=+$/, '').length % 4 !== 1) {
    try {
      return Uint8Array.from(atob(b64.replace(/=+$/, '')), (c) => c.charCodeAt(0))
    } catch {
      return null
    }
  }
  return null
}

// --- display ----------------------------------------------------------------------------------

export const codeLabel = (c: Code) => `${c.name} (0x${hex(c.value, c.bits / 4)})`

function plain(v: Field): unknown {
  if (v instanceof Uint8Array) return toHex(v)
  if (Array.isArray(v)) return v.map(plain)
  if (typeof v === 'object' && v !== null) {
    if ('bits' in v && 'value' in v && 'name' in v) return codeLabel(v as Code)
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, plain(x)]))
  }
  return v
}

// Keyed by the extension's name, in wire order, so a collapsed tree still says what each one
// is. A type that repeats (two GREASE, or a duplicate the spec forbids) gets " #2", " #3".
function describeExtensions(extensions: Extension[]): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const e of extensions) {
    const label = codeLabel(e.type)
    let key = label
    for (let n = 2; key in out; n++) key = `${label} #${n}`
    out[key] = {
      length: e.data.length,
      ...(e.body ? plain(e.body) as object : e.data.length && !e.error ? { data: toHex(e.data) } : {}),
      ...(e.error ? { error: e.error, data: toHex(e.data) } : {}),
    }
  }
  return out
}

/** A JSON-ready view: registry values as "name (0x1301)", bytes as hex, extensions keyed by name. */
export function describe(h: ClientHello): Record<string, unknown> {
  return {
    ...(h.warnings.length ? { warnings: h.warnings } : {}),
    ...(h.record ? { record: `${codeLabel(h.record.version)}, ${h.record.count} record${h.record.count > 1 ? 's' : ''}` } : {}),
    length: h.message.length,
    version: codeLabel(h.version),
    random: toHex(h.random),
    session_id: toHex(h.sessionId),
    cipher_suites: h.cipherSuites.map(codeLabel),
    compression_methods: h.compressionMethods.map(codeLabel),
    ...(h.extensions ? { extensions: describeExtensions(h.extensions) } : {}),
    ...(h.trailing ? { trailing_bytes: h.trailing } : {}),
  }
}
