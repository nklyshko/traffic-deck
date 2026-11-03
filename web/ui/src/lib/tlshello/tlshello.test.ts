import { describe, expect, it } from 'vitest'
import {
  alpn, bytesFromText, codeLabel, describe as show, isGrease, isGreasePskMode, isGreaseQuicParameter, parseClientHello,
  serverName, toBase64, toHex, toRecords, TlsParseError, type ClientHello, type Code, type Extension,
} from './index'

// RFC 8448 traces, as the complete TLS records the client sends; RFC 9001 A.2 as the
// ClientHello in the client's first CRYPTO frame; browsers as the gateway stores them.
const fixtures = import.meta.glob('./testdata/*.hex', { query: '?raw', import: 'default', eager: true }) as Record<string, string>
const bytes = (name: string) => bytesFromText(fixtures[`./testdata/${name}.hex`])!
const hello = (name: string) => parseClientHello(bytes(name))
const values = (codes: Code[]) => codes.map((c) => c.value)
const ext = (h: ClientHello, type: number) => h.extensions!.find((e) => e.type.value === type)!
const fromHex = (s: string) => bytesFromText(s)!

describe('RFC 8448 §3 simple 1-RTT', () => {
  const h = hello('rfc8448-1rtt')
  it('strips the record and reads the fixed fields', () => {
    expect(h.record).toEqual({ version: { value: 0x0301, name: 'TLS 1.0', bits: 16 }, count: 1 })
    expect(h.message.length).toBe(196)
    expect(toHex(h.message.subarray(0, 4))).toBe('010000c0')
    expect(codeLabel(h.version)).toBe('TLS 1.2 (0x0303)')
    expect(toHex(h.random)).toBe('cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7')
    expect(h.sessionId.length).toBe(0)
    expect(values(h.cipherSuites)).toEqual([0x1301, 0x1303, 0x1302])
    expect(h.compressionMethods.map(codeLabel)).toEqual(['null (0x00)'])
    expect(h.trailing).toBe(0)
    expect(h.warnings).toEqual([])
  })
  it('reads every extension in wire order', () => {
    expect(h.extensions!.map((e) => e.type.name)).toEqual([
      'server_name', 'renegotiation_info', 'supported_groups', 'session_ticket', 'key_share', 'supported_versions',
      'signature_algorithms', 'psk_key_exchange_modes', 'record_size_limit',
    ])
    expect(h.extensions!.every((e) => e.body && !e.error)).toBe(true)
    expect(serverName(h)).toBe('server')
    expect(values(ext(h, 10).body!.named_groups as Code[])).toEqual([0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104])
    expect((ext(h, 43).body!.versions as Code[]).map(codeLabel)).toEqual(['TLS 1.3 (0x0304)'])
    expect((ext(h, 45).body!.modes as Code[]).map((c) => c.name)).toEqual(['psk_dhe_ke'])
    expect(ext(h, 28).body!.record_size_limit).toBe(0x4001)
  })
  it('keeps the key share bytes, which the RFC prints as the client public key', () => {
    const [share] = ext(h, 51).body!.shares as { group: Code; key_exchange: Uint8Array }[]
    expect(share.group.name).toBe('x25519')
    expect(toHex(share.key_exchange)).toBe('99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c')
  })
  it('names the TLS 1.2 signature pairs IANA lists only as reserved', () => {
    expect((ext(h, 13).body!.signature_schemes as Code[]).map((c) => c.name)).toEqual([
      'ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'ecdsa_sha1', 'rsa_pss_rsae_sha256',
      'rsa_pss_rsae_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha256', 'rsa_pkcs1_sha384', 'rsa_pkcs1_sha512', 'rsa_pkcs1_sha1',
      'dsa_sha256', 'dsa_sha384', 'dsa_sha512', 'dsa_sha1',
    ])
  })
  it('parses the bare handshake message the same way', () => {
    const bare = parseClientHello(h.message)
    expect(bare.record).toBeUndefined()
    expect(show(bare)).toEqual(Object.fromEntries(Object.entries(show(h)).filter(([k]) => k !== 'record')))
  })
})

describe('RFC 8448 §4 resumed 0-RTT', () => {
  const h = hello('rfc8448-0rtt')
  it('reads the PSK, last as the spec requires', () => {
    expect(h.message.length).toBe(512)
    expect(h.extensions!.at(-1)!.type.name).toBe('pre_shared_key')
    const psk = ext(h, 41).body!
    const [identity] = psk.identities as { identity: Uint8Array; obfuscated_ticket_age: number }[]
    expect(identity.identity.length).toBe(178)
    expect(identity.obfuscated_ticket_age).toBe(4208372427)
    expect((psk.binders as Uint8Array[]).map((b) => b.length)).toEqual([32])
    expect(ext(h, 42).body).toEqual({})
    expect(h.warnings).toEqual([])
  })
  it('reads the padding', () => {
    expect(ext(h, 21).body).toEqual({ length: 87, zeros: true })
  })
})

describe('RFC 8448 §5 HelloRetryRequest', () => {
  it('reads both ClientHellos, the second on a TLS 1.2 record with the cookie and a new share', () => {
    const first = hello('rfc8448-hrr-first'), second = hello('rfc8448-hrr-second')
    expect(first.extensions!.some((e) => e.type.name === 'cookie')).toBe(false)
    expect(second.record!.version.value).toBe(0x0303)
    expect((ext(second, 44).body!.cookie as Uint8Array).length).toBe(114)
    const [share] = ext(second, 51).body!.shares as { group: Code; key_exchange: Uint8Array }[]
    expect(share.group.name).toBe('secp256r1')
    expect(share.key_exchange.length).toBe(65)
    expect(share.key_exchange[0]).toBe(0x04) // uncompressed point
    expect(toHex(second.random)).toBe(toHex(first.random))
  })
})

describe('RFC 8448 §6 client auth and §7 compatibility mode', () => {
  it('reads a 32-byte legacy session id in compatibility mode', () => {
    expect(hello('rfc8448-client-auth').sessionId.length).toBe(0)
    expect(hello('rfc8448-compat').sessionId.length).toBe(32)
  })
})

describe('RFC 9001 A.2 QUIC client Initial', () => {
  const h = hello('rfc9001-initial')
  it('reads the ClientHello from the CRYPTO frame', () => {
    expect(h.message.length).toBe(241)
    expect(serverName(h)).toBe('example.com')
    expect(alpn(h)).toEqual(['alpn'])
    expect(ext(h, 5).body!.status_type).toMatchObject({ name: 'ocsp' })
  })
  it('reads the transport parameters, varints included', () => {
    expect(ext(h, 57).body!.parameters).toEqual([
      // An 8-byte varint of all ones: 2^62 - 1, past what a JS number holds exactly.
      { id: 'initial_max_data (0x4)', value: '4611686018427387903' },
      { id: 'initial_max_stream_data_bidi_local (0x5)', value: 65535 },
      { id: 'initial_max_stream_data_uni (0x7)', value: 65535 },
      { id: 'initial_max_streams_bidi (0x8)', value: 16 },
      { id: 'max_idle_timeout (0x1)', value: 30000 },
      { id: 'initial_max_streams_uni (0x9)', value: 16 },
      { id: 'initial_source_connection_id (0xf)', value: fromHex('8394c8f03e515708') },
      { id: 'initial_max_stream_data_bidi_remote (0x6)', value: 65535 },
    ])
  })
})

describe('browsers', () => {
  it('Chrome over TCP: GREASE, ECH, ALPS, ML-KEM and trust anchors', () => {
    const h = hello('chrome-tcp')
    expect(h.cipherSuites[0]).toMatchObject({ name: 'GREASE', value: 0x2a2a })
    expect(h.extensions![0].type.name).toBe('GREASE')
    expect(h.extensions!.at(-1)!.type.name).toBe('GREASE')
    expect(h.extensions!.filter((e) => e.error)).toEqual([])
    expect(h.extensions!.filter((e) => e.type.name === 'unknown')).toEqual([])
    const shares = ext(h, 51).body!.shares as { group: Code; key_exchange: Uint8Array }[]
    expect(shares.map((s) => [s.group.name, s.key_exchange.length])).toEqual([['GREASE', 1], ['X25519MLKEM768', 1216], ['x25519', 32]])
    expect(ext(h, 0x44cd).body!.protocols).toEqual(['h2'])
    expect(ext(h, 0xfe0d).body).toMatchObject({ hello_type: 'outer', kdf: { name: 'HKDF-SHA256' }, aead: { name: 'AES-128-GCM' } })
    expect((ext(h, 0xca34).body!.trust_anchors as string[])[0]).toBe('44947.2.1')
    expect(alpn(h)).toEqual(['h2', 'http/1.1'])
    expect(serverName(h)).toBe('clientservices.googleapis.com')
    expect(h.warnings).toEqual([])
  })
  it('Chrome over QUIC: GREASE transport parameter and version information', () => {
    const h = hello('chrome-quic')
    const params = ext(h, 57).body!.parameters as Record<string, unknown>[]
    expect(params.find((p) => (p.id as string).startsWith('GREASE'))).toBeTruthy()
    expect(params.find((p) => p.id === 'google_connection_options (0x3128)')!.value).toBe('ORIG')
    expect(params.find((p) => p.id === 'version_information (0x11)')).toMatchObject({ chosen_version: 'QUIC v1 (0x00000001)' })
  })
  it('Firefox over TCP: delegated credentials, ECH and a PSK', () => {
    const h = hello('firefox-tcp')
    expect(isGrease(h.cipherSuites[0].value)).toBe(false)
    expect(h.extensions!.map((e) => e.type.name)).toEqual(expect.arrayContaining(['delegated_credential', 'encrypted_client_hello', 'record_size_limit']))
    expect(h.extensions!.at(-1)!.type.name).toBe('pre_shared_key')
    expect(h.extensions!.filter((e) => e.error || e.type.name === 'unknown')).toEqual([])
    expect(h.warnings).toEqual([])
  })
  it('Firefox offering TLS 1.2 only', () => {
    const h = hello('firefox-tls12')
    expect(h.extensions!.some((e) => e.type.name === 'supported_versions')).toBe(false)
    expect(h.extensions!.filter((e) => e.error || e.type.name === 'unknown')).toEqual([])
  })
})

// A minimal TLS 1.3 ClientHello built from parts, for the malformed cases.
function build(extensions: [number, string][], { suites = '1301', compression = '00' } = {}): Uint8Array {
  const u16 = (n: number) => n.toString(16).padStart(4, '0')
  const exts = extensions.map(([t, d]) => u16(t) + u16(d.length / 2) + d).join('')
  const body = '0303' + '00'.repeat(32) + '00' + u16(suites.length / 2) + suites + (compression.length / 2).toString(16).padStart(2, '0') + compression + u16(exts.length / 2) + exts
  return fromHex('01' + (body.length / 2).toString(16).padStart(6, '0') + body)
}

describe('malformed and unusual input', () => {
  it('rejects what is not a ClientHello, naming what it is', () => {
    expect(() => parseClientHello(fromHex('020000260303'))).toThrow(/handshake type 2 \(server_hello\)/)
    expect(() => parseClientHello(fromHex('170303001000'))).toThrow(TlsParseError)
  })
  it('reports a cut-short message and record with offsets', () => {
    const msg = hello('rfc8448-1rtt').message
    expect(() => parseClientHello(msg.subarray(0, 100))).toThrow('ClientHello declares 192 bytes, 96 present')
    expect(() => parseClientHello(bytes('rfc8448-1rtt').subarray(0, 50))).toThrow('TLS record 1 declares 196 bytes, 45 present')
  })
  it('joins a ClientHello split over several records', () => {
    const msg = hello('rfc8448-1rtt').message
    const split = new Uint8Array([...toRecords(msg.subarray(0, 50)), ...toRecords(msg.subarray(50), 0x0301)])
    const h = parseClientHello(split)
    expect(h.record!.count).toBe(2)
    expect(toHex(h.message)).toBe(toHex(msg))
  })
  it('counts what follows the message as trailing', () => {
    const msg = hello('rfc8448-1rtt').message
    expect(parseClientHello(new Uint8Array([...msg, 0x14, 0, 0])).trailing).toBe(3)
  })
  it('keeps going past a broken extension, with the error on that one', () => {
    const h = parseClientHello(build([[0x0000, '0003000003'], [0x002b, '020304']]))
    expect(ext(h, 0).error).toMatch(/host_name: needs 3 bytes/)
    expect(toHex(ext(h, 0).data)).toBe('0003000003')
    expect((ext(h, 43).body!.versions as Code[]).map((c) => c.name)).toEqual(['TLS 1.3'])
    expect((show(h).extensions as Record<string, unknown>)['server_name (0x0000)']).toEqual({ length: 5, error: expect.any(String), data: '0003000003' })
  })
  it('flags bytes left over inside an extension', () => {
    expect(ext(parseClientHello(build([[0x001c, '4001ff']])), 28).error).toBe('1 bytes left over after the record_size_limit contents')
  })
  it('warns where the message breaks the specs but still reads', () => {
    expect(parseClientHello(build([[0x0029, '00000000'], [0x002b, '020304']])).warnings).toContain('pre_shared_key is not the last extension (RFC 8446 §4.2.11)')
    expect(parseClientHello(build([[0x0017, ''], [0x0017, '']])).warnings[0]).toMatch(/extended_main_secret \(0x0017\) appears 2 times/)
    expect(parseClientHello(build([[0x0015, '0001']])).warnings).toContain('padding extension contains non-zero bytes (RFC 7685 §3)')
    expect(parseClientHello(build([[0x002b, '020304']], { compression: '0100' })).warnings[0]).toMatch(/legacy_compression_methods/)
  })
  it('reads a ClientHello without extensions (SSL 3.0 style)', () => {
    const body = '0300' + '00'.repeat(32) + '00' + '0002002f' + '0100'
    const h = parseClientHello(fromHex('01' + (body.length / 2).toString(16).padStart(6, '0') + body))
    expect(h.extensions).toBeUndefined()
    expect(h.version.name).toBe('SSL 3.0')
  })
  it('keeps repeated extension types apart in the description', () => {
    const d = show(parseClientHello(build([[0x0017, ''], [0x0017, '']])))
    expect(Object.keys(d.extensions as object)).toEqual(['extended_main_secret (0x0017)', 'extended_main_secret (0x0017) #2'])
  })
  it('names unregistered values as unknown, and drafts of TLS 1.3', () => {
    const h = parseClientHello(build([[0x002b, '047f1c0304'], [0x7777, 'ab']], { suites: '1301eeee' }))
    expect(h.cipherSuites[1].name).toBe('unknown')
    expect(h.extensions![1]).toMatchObject({ type: { name: 'unknown' } })
    expect((show(h).extensions as Record<string, unknown>)['unknown (0x7777)']).toEqual({ length: 1, data: 'ab' })
    expect((ext(h, 43).body!.versions as Code[]).map((c) => c.name)).toEqual(['TLS 1.3 draft 28', 'TLS 1.3'])
  })
})

describe('GREASE (RFC 8701)', () => {
  it('recognises all sixteen values and nothing else', () => {
    const all = Array.from({ length: 0x10000 }, (_, v) => v).filter(isGrease)
    expect(all).toEqual(Array.from({ length: 16 }, (_, i) => (i << 12) | 0x0a00 | (i << 4) | 0x0a))
  })
  it('recognises PSK mode, QUIC parameter and ALPN GREASE', () => {
    expect([0x0b, 0x2a, 0x49, 0x68, 0x87, 0xa6, 0xc5, 0xe4].every(isGreasePskMode)).toBe(true)
    expect(isGreasePskMode(0x01)).toBe(false)
    expect(isGreaseQuicParameter(27n) && isGreaseQuicParameter(31n * 1000n + 27n)).toBe(true)
    expect(isGreaseQuicParameter(0x3128n)).toBe(false)
    const h = parseClientHello(build([[0x0010, '0006020a0a026833']]))
    expect((show(h).extensions as Record<string, unknown>)['application_layer_protocol_negotiation (0x0010)']).toEqual({ length: 8, protocols: ['GREASE (0x0a0a)', 'h3'] })
  })
})

describe('input text', () => {
  const msg = () => hello('rfc8448-1rtt').message
  it('reads plain, spaced, colon and 0x hex', () => {
    expect(toHex(fromHex('16 03 01'))).toBe('160301')
    expect(toHex(fromHex('16:03:01'))).toBe('160301')
    expect(toHex(fromHex('0x16, 0x03, 0x01'))).toBe('160301')
  })
  it('reads hex dumps with an offset column and an ASCII column', () => {
    const wireshark = '0000   16 03 01 00 c4 01 00 00 c0 03 03 cb 34 ec b1 e7   ............4...\n0010   81 63                                             .c'
    expect(toHex(fromHex(wireshark))).toBe('16030100c4010000c00303cb34ecb1e78163')
    const openssl = '0000 - 16 03 01 00 c4 01 00 00-c0 03 03 cb 34 ec b1 e7   ............4...\n0010 - 81 63                                             .c'
    expect(toHex(fromHex(openssl.replace('00-c0', '00 c0')))).toBe('16030100c4010000c00303cb34ecb1e78163')
    const xxd = '00000000: 1603 0100 c401 0000 c003 03cb 34ec b1e7  ............4...\n00000010: 8163                                     .c'
    expect(toHex(fromHex(xxd))).toBe('16030100c4010000c00303cb34ecb1e78163')
  })
  it('reads base64, standard or URL-safe', () => {
    expect(toHex(bytesFromText(toBase64(msg()))!)).toBe(toHex(msg()))
    expect(toHex(bytesFromText(toBase64(msg()).replace(/\+/g, '-').replace(/\//g, '_'))!)).toBe(toHex(msg()))
  })
  it('returns null for anything else', () => {
    expect(bytesFromText('')).toBeNull()
    expect(bytesFromText('not hex at all!')).toBeNull()
    expect(bytesFromText('16 03 0')).toBeNull()
  })
})

describe('output', () => {
  it('wraps a message in records the parser reads back', () => {
    const msg = hello('rfc8448-1rtt').message
    expect(toHex(toRecords(msg))).toBe(toHex(bytes('rfc8448-1rtt')))
    expect(toHex(toRecords(msg, 0x0303)).slice(0, 10)).toBe('16030300c4')
    const big = new Uint8Array(0x4000 + 10)
    const recs = toRecords(big)
    expect(recs.length).toBe(big.length + 10)
    expect(toHex(recs.subarray(0x4005, 0x400a))).toBe('160301000a')
  })
  it('describes registry values as name (0x…) and bytes as hex', () => {
    const d = show(hello('chrome-tcp'))
    expect(d.cipher_suites).toContain('GREASE (0x2a2a)')
    const extensions = d.extensions as Record<string, unknown>
    expect(Object.keys(extensions)[0]).toBe('GREASE (0x3a3a)')
    expect(extensions['GREASE (0x3a3a)']).toEqual({ length: 0 })
    expect(Object.keys(extensions)).toHaveLength(hello('chrome-tcp').extensions!.length)
    expect(JSON.parse(JSON.stringify(d))).toEqual(d)
  })
  it('keeps every extension byte-exact', () => {
    for (const name of Object.keys(fixtures).map((k) => k.slice(11, -4))) {
      const h = hello(name)
      const rebuilt = h.extensions!.map((e: Extension) => toHex(h.message.subarray(e.offset, e.offset + 4 + e.data.length))).join('')
      expect(toHex(h.message).endsWith(rebuilt), name).toBe(true)
    }
  })
})
