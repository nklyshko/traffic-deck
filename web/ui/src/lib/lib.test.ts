import { describe, expect, it } from 'vitest'
import { bodyDiffText, compareBodies, compareFlows, compareForms, compareMessages, describeLayout, diffLines, diffParts, diffText, fitLines, formDecode, goSlice, messagePosition, MISSING, pairValues, plainAuthority, positionSection, requestLine, wordDiff, differingParts, positionLines, prettyJson, prettyPayload, prettyXml, renderBudget, splitRows, unifiedDiff } from './compare'
import { canDecode, decodeAs, guessKind, readable, stripWrappers } from './decoder'
import { sentAs, sniffImage, svgInfo, tooLarge } from './image'
import { idnDecoded, punycodeDecode, unicodeHost } from './idn'
import rfc8448 from './tlshello/testdata/rfc8448-1rtt.hex?raw'
import { dropTerm, formatFilter, halfTyped, opAtCaret, parseFilter, readsAnnotations, readStatus, readTerm, termLabel, wordAtCaret, writeStatus, writeTerm } from './filter'
import { packFlags } from './flags'
import { durationTone, fitWidth, formatBytes, formatCount, formatDateTime, formatDuration, formatMatched, hiddenReason, reasonPhrase, statusTone } from './format'
import { bodyExt, cookiePairs, curlCommand, HEX_CAP, hexDump, looksTextual, nameCut, queryPairs, rawExchange, rejoinCookies } from './http'
import { classifyLogLine } from './logs'
import { matchesTerms, matchRuns, plural, searchTerms } from './search'
import { select, NOTHING } from './selection'
import { rem, TEXT_SIZES } from './scale'
import { accepts } from './settings'
import { unknownIds } from './catalog'
import { declaredColumns, groupScope, inScope, resolveScope, SCOPE_ALL, SCOPE_UNGROUPED, sessionMatcher, sessionScopes } from './sessions'
import { checkedAgo, lastEightAm, refreshDue, updateNotice } from './updates'
import { cursorOf, extendWindow, patchFlow } from './window'
import type { Flow, Session, WsMessage } from './types'

declare const process: { env: Record<string, string | undefined> }

const b64 = (s: string) => btoa(s)
const b64url = (s: string) => btoa(s).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')

describe('filter tokeniser', () => {
  it('parses ops, flags, negation and bare regexes', () => {
    expect(parseFilter('~d example !~t json ~s foo')).toEqual([
      { negated: false, op: '~d', arg: 'example' }, { negated: true, op: '~t', arg: 'json' },
      { negated: false, op: '~s', arg: '' }, { negated: false, op: '', arg: 'foo' },
    ])
  })
  it('drops a lone ! and round-trips a half-typed op', () => {
    expect(parseFilter('! ~d')).toEqual([{ negated: false, op: '~d', arg: '' }])
    expect(formatFilter(parseFilter('~d'))).toBe('~d')
  })
  it('treats an unknown ~x as a bare regex', () => {
    expect(parseFilter('~x y')).toEqual([{ negated: false, op: '', arg: '~x' }, { negated: false, op: '', arg: 'y' }])
  })
  it('reads and writes only non-negated terms', () => {
    expect(readTerm('!~t json ~t html', '~t')).toBe('html')
    expect(readTerm('~fav', '~fav')).toBe('')
    expect(readTerm('~d a', '~t')).toBeNull()
    expect(writeTerm('!~t json ~t html', '~t', null)).toBe('!~t json')
    expect(writeTerm('~d a ~t html ~c 2', '~t', 'css')).toBe('~d a ~t css ~c 2')
    expect(writeTerm('!~t json', '~t', 'css')).toBe('!~t json ~t css')
  })
  it('drops by index and labels terms', () => {
    expect(dropTerm('~d a ~c 2', 0)).toBe('~c 2')
    expect(termLabel({ negated: true, op: '~t', arg: 'json' })).toBe('not type: json')
    expect(termLabel({ negated: false, op: '~q', arg: '' })).toBe('no response')
  })
  it('keeps the status control over three ops exclusive', () => {
    expect(writeStatus('~c 2.. ~d a', 'No response')).toBe('~d a ~q')
    expect(readStatus('~c [45]..')).toBe('Errors')
    expect(readStatus('~c 201')).toBe('')
  })
  it('knows an op waiting for its argument', () => {
    expect([halfTyped('~d a ~h'), halfTyped('~d a'), halfTyped('~fav'), halfTyped('')]).toEqual([true, false, false, false])
  })
  it('finds the op being typed', () => {
    expect(opAtCaret('~d a !~h', 8)).toEqual({ start: 6, end: 8, prefix: '~h' })
    expect(opAtCaret('~d a', 4)).toBeNull()
  })
  it('knows the whole op under the caret, and that an argument is not one', () => {
    expect(opAtCaret('~mark x', 3)).toEqual({ start: 0, end: 5, prefix: '~ma' })
    expect(opAtCaret('~m ~', 4)).toBeNull()
    expect(opAtCaret('~s ~', 4)).toEqual({ start: 3, end: 4, prefix: '~' })
  })
  it('finds no word on empty space', () => {
    expect(wordAtCaret('~m GET ', 7).word).toBe('')
    expect(wordAtCaret('', 0).word).toBe('')
  })
})

describe('extendWindow', () => {
  const rows = (...ids: number[]) => ids.map((i) => ({ id: String(i) }))
  it('dedupes in both directions', () => {
    expect(extendWindow(rows(2, 3), rows(1, 2), 'older', 10)).toMatchObject({ rows: rows(1, 2, 3), frontDelta: 1, trimmedFar: false })
    expect(extendWindow(rows(2, 3), rows(3, 4), 'newer', 10)).toMatchObject({ rows: rows(2, 3, 4), frontDelta: 0, trimmedFar: false })
  })
  it('trims the far end', () => {
    expect(extendWindow(rows(3, 4), rows(1, 2), 'older', 3)).toEqual({ rows: rows(1, 2, 3), frontDelta: 2, trimmedFar: true })
    expect(extendWindow(rows(1, 2), rows(3, 4), 'newer', 3)).toEqual({ rows: rows(2, 3, 4), frontDelta: -1, trimmedFar: true })
  })
  it('keeps identity on a no-op', () => {
    const cur = rows(1)
    expect(extendWindow(cur, rows(1), 'newer', 3).rows).toBe(cur)
  })
  it('derives a cursor with zero defaults', () => {
    expect(cursorOf({ id: 'x', tsUnixMicros: '5' })).toBe('5:0')
  })
  it('drops cleared annotations on merge', () => {
    const merged = patchFlow<Flow>({ id: 'a', markColor: 'red', favorite: true, path: '/' }, { id: 'a', status: 200 })
    expect(merged).toEqual({ id: 'a', path: '/', status: 200 })
  })
})

describe('cookies and exports', () => {
  const headers = [{ name: ':method', value: 'GET' }, { name: 'cookie', value: 'a=1' }, { name: 'x', value: 'y' }, { name: 'cookie', value: 'b=2' }]
  const flow: Flow = { id: 'f1', method: 'POST', scheme: 'https', authority: 'api.example.test', path: '/p', query: 'q=1', protocol: 'HTTP/2', status: 200, requestHeaders: headers, responseHeaders: [{ name: 'server', value: 's' }] }
  it('rejoins crumbs at the first position', () => {
    expect(rejoinCookies(headers).map((h) => h.value)).toEqual(['GET', 'a=1; b=2', 'y'])
    expect(cookiePairs(rejoinCookies(headers))).toEqual([{ name: 'a', value: '1' }, { name: 'b', value: '2' }])
  })
  it('splits a query', () => {
    expect(queryPairs('a=b+c&d=%41&e=%zz')).toEqual([{ name: 'a', value: 'b c' }, { name: 'd', value: 'A' }, { name: 'e', value: '%zz' }])
  })
  it('builds curl', () => {
    expect(curlCommand(flow, { text: "it's" })).toBe(
      `curl -X POST 'https://api.example.test/p?q=1' \\\n  --http2 \\\n  -H 'cookie: a=1; b=2' \\\n  -H 'x: y' \\\n  --data-binary 'it'\\''s'`)
    expect(curlCommand({ ...flow, requestHeaders: [] }, { binary: true })).toContain('--data-binary @f1-request.body')
    expect(curlCommand({ id: 'x', path: '/only' })).toBe(`curl -X GET '/only'`)
  })
  it('keeps crumbs in the raw export', () => {
    const raw = rawExchange(flow, 'req', 'rsp')
    expect(raw.startsWith('POST /p?q=1 HTTP/2\n:method: GET\ncookie: a=1\nx: y\ncookie: b=2\n\nreq\n====')).toBe(true)
    expect(raw.endsWith('HTTP/2 200\nserver: s\n\nrsp')).toBe(true)
  })
  it('picks a body extension', () => {
    const cases: [string | undefined, string][] = [['text/plain; charset=utf-8', 'txt'], ['application/javascript', 'js'], ['image/jpeg', 'jpg'], ['image/svg+xml', 'svg'], ['application/vnd.api+json', 'json'], ['application/x-tar', 'tar'], ['application/octet-stream', 'bin'], ['weird', 'bin'], [undefined, 'bin'], ['application/x-very-long-subtype-name', 'bin']]
    for (const [ct, ext] of cases) expect(bodyExt(ct)).toBe(ext)
  })
  it('detects text', () => {
    const enc = new TextEncoder()
    expect(looksTextual(enc.encode('hello'))).toBe(true)
    expect(looksTextual(new Uint8Array([104, 0, 105]))).toBe(false)
    expect(looksTextual(new Uint8Array([0xff, 0xfe]))).toBe(false)
    const cut = new Uint8Array(1026).fill(97)
    cut.set(enc.encode('€'), 1023)
    expect(looksTextual(cut)).toBe(true)
  })
  it('dumps hex with a cap', () => {
    expect(hexDump(new TextEncoder().encode('AB'))).toBe(`00000000  41 42${' '.repeat(42)}  AB`)
    expect(hexDump(new Uint8Array(100), 16).split('\n')).toHaveLength(1)
  })
})

describe('idn', () => {
  it('decodes RFC 3492 sample labels', () => {
    expect(punycodeDecode('80aairftm')).toBe('магазин')
    expect(punycodeDecode('bcher-kva')).toBe('bücher')
    expect(punycodeDecode('ihqwcrb4cv8a8dqg056pqjye')).toBe('他们为什么不说中文')
    expect(punycodeDecode('bcher-k!a')).toBeNull()
  })
  it('converts only hosts with a valid xn-- label', () => {
    expect(unicodeHost('xn--80aairftm.example.test')).toBe('магазин.example.test')
    expect(unicodeHost('XN--80AAIRFTM.example.test')).toBe('магазин.example.test')
    expect(unicodeHost('api.example.test')).toBeNull()
    expect(unicodeHost('xn--a.example.test')).toBeNull()
    expect(unicodeHost('xn--zz-1.example')).toBeNull()
  })
  it('keeps the port, and in a URL converts only the host', () => {
    expect(idnDecoded('xn--80aairftm.example.test:8443')).toBe('магазин.example.test:8443')
    expect(idnDecoded('https://xn--80aairftm.example.test/xn--80aairftm?q=1')).toBe('https://магазин.example.test/xn--80aairftm?q=1')
    expect(idnDecoded('see xn--80aairftm')).toBeNull()
  })
})

describe('decoder', () => {
  it('guesses idn before url, and chains a URL with both through idn → url', () => {
    const url = 'https://xn--80aairftm.example.test/%D0%BA%D0%BD%D0%B8%D0%B3%D0%B8'
    expect(guessKind('xn--80aairftm.example.test')).toBe('idn')
    expect(guessKind(url)).toBe('idn')
    const d = decodeAs(url, 'idn')!
    expect(d.steps).toEqual(['idn', 'url'])
    expect(d.output.text).toBe('https://магазин.example.test/книги')
    expect(decodeAs(url, 'url', 0, false)!.output.text).toBe('https://xn--80aairftm.example.test/книги')
  })
  it('leaves escaped delimiters encoded on a full URL, not on a plain value', () => {
    expect(decodeAs('https://x.test/a%20b?q=a%26b%3Dc', 'url')!.output.text).toBe('https://x.test/a b?q=a%26b%3Dc')
    expect(decodeAs('q=a%26b%20c', 'url')!.output.text).toBe('q=a&b c')
    expect(canDecode('https://x.test/a%2Fb', 'url')).toBe(false)
  })
  it('reads a host or path with both encodings undone', () => {
    expect(readable('xn--80aairftm.example.test')).toBe('магазин.example.test')
    expect(readable('/%d0%ba')).toBe('/к')
    expect(readable('/plain')).toBe('/plain')
  })

  const jwt = `${b64url('{"alg":"HS256"}')}.${b64url('{"sub":"demo","exp":1000000000}')}.sig`
  it('strips wrappers', () => {
    expect(stripWrappers('  Bearer abc ')).toBe('abc')
    expect(stripWrappers('"abc"')).toBe('abc')
  })
  it('guesses strictly and in order', () => {
    expect(guessKind(`Bearer ${jwt}`)).toBe('jwt')
    expect(guessKind('1793197528', 'created_at')).toBe('ts')
    expect(guessKind('1793197528', 'count')).toBeNull()
    expect(guessKind('1999999999', 'exp')).toBeNull()
    expect(guessKind('a%20b')).toBe('url')
    expect(guessKind(b64('hello world example'))).toBe('b64')
    expect(guessKind('68656c6c6f20776f726c64')).toBe('hex')
    expect(guessKind('abcdefghijkl')).toBeNull()
    expect(guessKind('short')).toBeNull()
  })
  it('accepts more when asked by hand', () => {
    expect(canDecode('1234567890', 'ts')).toBe(true)
    expect(canDecode('abcd', 'b64')).toBe(true)
    expect(canDecode('abcde', 'b64')).toBe(false)
    expect(canDecode('abc', 'hex')).toBe(false)
  })
  it('decodes a JWT and flags expiry', () => {
    const d = decodeAs(jwt, 'jwt', 2_000_000_000_000)!
    expect(d.output.jwt?.header).toEqual({ alg: 'HS256' })
    expect(d.output.jwt?.claims[0]).toMatchObject({ name: 'exp', expired: true })
  })
  it('chains url → base64 → JSON', () => {
    const value = encodeURIComponent(b64('{"a":1,"bc":2}'))
    const d = decodeAs(value, 'url')!
    expect(d.steps).toEqual(['url', 'b64'])
    expect(d.output).toMatchObject({ isJson: true, text: '{"a":1,"bc":2}' })
  })
  it('stops the chain on binary', () => {
    const d = decodeAs(btoa('\xff\xfe\x00\x01'), 'b64')!
    expect(d.steps).toEqual(['b64'])
    expect(d.output.binaryLabel).toBe('b64 · 4 bytes, not text')
    expect(d.output.hex).toContain('ff fe 00 01')
  })
  it('recognises a TLS ClientHello as hex, a hex dump or base64', () => {
    const record = rfc8448.trim()
    const message = record.slice(10)
    expect(guessKind(record)).toBe('tls')
    expect(guessKind(message)).toBe('tls')
    expect(guessKind(btoa(String.fromCharCode(...message.match(/../g)!.map((b) => parseInt(b, 16)))))).toBe('tls')
    expect(guessKind(message.match(/.{1,32}/g)!.map((l, i) => `${(i * 16).toString(16).padStart(4, '0')}  ${l.match(/../g)!.join(' ')}`).join('\n'))).toBe('tls')
    expect(guessKind('68656c6c6f20776f726c64')).toBe('hex')
    expect(canDecode(message.slice(0, 100), 'tls')).toBe(false)
    const d = decodeAs(record, 'tls')!
    expect(d.steps).toEqual(['tls'])
    expect(d.output.tls?.view).toMatchObject({ record: 'TLS 1.0 (0x0301), 1 record', length: 196, cipher_suites: ['TLS_AES_128_GCM_SHA256 (0x1301)', 'TLS_CHACHA20_POLY1305_SHA256 (0x1303)', 'TLS_AES_256_GCM_SHA384 (0x1302)'] })
  })
  it('caps a chain at three steps', () => {
    let v = 'hello world example text'
    for (let i = 0; i < 5; i++) v = b64(v)
    expect(decodeAs(v, 'b64')!.steps).toHaveLength(3)
  })
})

describe('compare', () => {
  it('aligns a diff with equal columns', () => {
    const rows = diffLines([':method', ':authority', ':path'], [':method', ':path', ':authority'])
    expect(rows.every((r) => r.a !== undefined && r.b !== undefined)).toBe(true)
    expect(rows[0]).toEqual({ a: ':method', b: ':method', same: true })
    expect(rows.filter((r) => !r.same)).toHaveLength(2)
  })
  it('pairs a run of changes', () => {
    expect(diffLines(['a', 'x'], ['b', 'x'])).toEqual([{ a: 'a', b: 'b', same: false }, { a: 'x', b: 'x', same: true }])
  })
  it('pairs repeated names by occurrence', () => {
    const v = (name: string, value: string) => ({ name, value })
    expect(pairValues([v('a', '1'), v('a', '2')], [v('a', '2'), v('b', '3')])).toEqual([
      { name: 'a', a: '1', b: '2', same: false }, { name: 'a', a: '2', b: MISSING, same: false }, { name: 'b', a: MISSING, b: '3', same: false },
    ])
  })
  it('compares two flows section by section', () => {
    const f: Flow = { id: 'a', protocol: 'HTTP/2', requestHeaders: [{ name: ':method', value: 'GET' }, { name: 'accept', value: '*/*' }] }
    const sections = compareFlows(f, { ...f, id: 'b', protocol: 'HTTP/1.1' })
    expect(sections).toHaveLength(9)
    expect(sections[0]).toMatchObject({ title: 'Request line', match: true })
    expect(sections[1].match).toBe(false)
    expect(sections[3].match).toBe(true)
  })
  it('compares the request line part by part', () => {
    const f: Flow = { id: 'a', method: 'GET', scheme: 'https', authority: 'api.example.test', path: '/v1/cart', query: 'a=1&b=2' }
    const line = requestLine(f, { ...f, id: 'b', method: 'POST', query: 'b=2&a=1' })
    expect(line.match).toBe(false)
    expect(line.rows.map((r) => [r.name, r.a, r.b, r.same])).toEqual([
      ['method', 'GET', 'POST', false], ['scheme', 'https', 'https', true], ['authority', 'api.example.test', 'api.example.test', true],
      ['path', '/v1/cart', '/v1/cart', true], ['query', 'a=1&b=2', 'b=2&a=1', false],
    ])
    expect(line.rows.filter((r) => r.full).map((r) => r.name)).toEqual(['path', 'query'])
    expect(requestLine(f, f).fold).toBe('GET https://api.example.test/v1/cart?a=1&b=2')
    expect(requestLine({ id: 'c' }, { id: 'd', path: '/x' }).rows.map((r) => [r.a, r.b])).toEqual([
      ['∅', '∅'], ['∅', '∅'], ['∅', '∅'], ['∅', '/x'], ['∅', '∅'],
    ])
  })
  it('compares a host and path as sent, ≈ when they decode the same', () => {
    const f: Flow = { id: 'a', method: 'GET', scheme: 'https', authority: 'xn--80aairftm.example.test', path: '/%D0%BA%D0%BD' }
    const line = requestLine(f, { ...f, id: 'b', authority: 'магазин.example.test', path: '/%d0%ba%d0%bd' })
    expect(line.match).toBe(false)
    expect(line.rows.filter((r) => r.decode).map((r) => [r.name, r.same, r.sameDecoded])).toEqual([['authority', false, true], ['path', false, true]])
    expect(requestLine(f, { ...f, id: 'b', path: '/other' }).rows[3].sameDecoded).toBe(false)
    expect(wordDiff('xn--80aairftm.example.test', 'магазин.example.test')).toEqual([
      { kind: '-', text: 'xn--80aairftm' }, { kind: '+', text: 'магазин' }, { kind: ' ', text: '.example.test' },
    ])
  })
  it('narrows a word diff to the characters that differ', () => {
    expect(wordDiff('/g/chains/2026-11-23-21-33-13.chain', '/g/chains/2026-11-23-21-35-13.chain')).toEqual([
      { kind: ' ', text: '/g/chains/2026-11-23-21-3' }, { kind: '-', text: '3' }, { kind: '+', text: '5' }, { kind: ' ', text: '-13.chain' },
    ])
    expect(wordDiff('/v1/cart/items', '/v2/cart')).toEqual([
      { kind: ' ', text: '/v' }, { kind: '-', text: '1' }, { kind: '+', text: '2' }, { kind: ' ', text: '/cart' }, { kind: '-', text: '/items' },
    ])
    expect(wordDiff('/same', '/same')).toEqual([{ kind: ' ', text: '/same' }])
    expect(differingParts('GET', 'POST')).toBeNull()
    expect(differingParts('firefox-settings.cdn.mozilla.net', 'mozilla-ohttp.fastly-edge.com')).toBeNull()
    expect(differingParts('c-91d2', 'c-04ab')?.filter((p) => p.kind !== ' ')).toEqual([{ kind: '-', text: '91d2' }, { kind: '+', text: '04ab' }])
    expect(differingParts('s-7f3a90c2e1d4', 's-7f3a90c2e1d5')?.filter((p) => p.kind !== ' ')).toEqual([{ kind: '-', text: '4' }, { kind: '+', text: '5' }])
  })
  it('drops only a default port for its scheme', () => {
    expect(plainAuthority('api.example.test:443', 'https')).toBe('api.example.test')
    expect(plainAuthority('api.example.test:80', 'HTTP')).toBe('api.example.test')
    expect(plainAuthority('api.example.test:80', 'https')).toBe('api.example.test:80')
    expect(plainAuthority('api.example.test:8443', 'https')).toBe('api.example.test:8443')
    expect(plainAuthority('api.example.test:443', undefined)).toBe('api.example.test:443')
    expect(plainAuthority('[::1]:443', 'https')).toBe('[::1]')
  })
  it('formats a Go slice', () => {
    expect(goSlice(['a"b', 'c\\'])).toBe('[]string{\n\t"a\\"b",\n\t"c\\\\",\n}')
    expect(goSlice([])).toBe('[]string{}')
  })
})

describe('format', () => {
  it('colours only success, warning and error', () => {
    expect([101, 200, 304, 404, 502].map(statusTone)).toEqual(['grey', 'green', 'grey', 'amber', 'red'])
    expect([0, 84_000, 640_000, 2_400_000].map(durationTone)).toEqual([null, 'grey', 'amber', 'red'])
  })
  it('formats dates in 24 h whatever the locale', () => {
    expect(formatDateTime(0)).toBe('—')
    expect(formatDateTime(new Date(2026, 9, 28, 14, 20, 3).getTime())).toBe('28 Oct 2026, 14:20:03')
    expect(formatDateTime(new Date(2026, 0, 5, 0, 7, 9).getTime())).toBe('5 Jan 2026, 00:07:09')
  })
  it('formats bytes and durations', () => {
    expect([formatBytes(0), formatBytes(10), formatBytes(2048), formatBytes(1572864)]).toEqual(['', '10B', '2K', '1.5M'])
    expect([formatDuration(0), formatDuration(1999), formatDuration(2_400_000), formatDuration(252_000_000)]).toEqual(['', '1ms', '2.4s', '4m12s'])
  })
  it('formats counts and reasons', () => {
    expect(formatMatched(1284, true)).toBe('1,284+')
    expect(formatCount(0)).toBe('0')
    expect(formatCount(999)).toBe('999')
    expect(formatCount(1906)).toBe('1.9K')
    expect(formatCount(9_949)).toBe('9.9K')
    expect(formatCount(9_950)).toBe('10K')
    expect(formatCount(12_345)).toBe('12K')
    expect(formatCount(999_499)).toBe('999K')
    expect(formatCount(999_500)).toBe('1.0M')
    expect(formatCount(2_500_000)).toBe('2.5M')
    expect(formatCount(12_345_678)).toBe('12M')
    expect([reasonPhrase(404), reasonPhrase(599), reasonPhrase(299)]).toEqual(['Not Found', 'Server Error', 'Success'])
  })
})

describe('nameCut', () => {
  const tail = (n: string) => n.slice(nameCut(n))
  it('keeps what tells a family of names apart', () => {
    expect(tail('access-control-allow-credentials')).toBe('-allow-credentials')
    expect(tail('access-control-allow-headers')).toBe('-allow-headers')
  })
  it('falls back to a fixed tail without a separator', () => {
    expect(tail('averyveryveryverylongcookiename')).toBe('gcookiename'.padStart(12, 'n'))
  })
  it('leaves a short name whole', () => {
    expect(nameCut('vary')).toBe(0)
  })
})

describe('fitWidth', () => {
  it('sizes to the longest of the label and the values', () => {
    expect(fitWidth('max.ver', ['10'])).toBeLessThan(fitWidth('max.opcode', ['VideoContent(83)']))
  })
  it('is bounded either way', () => {
    expect(fitWidth('n', ['1'])).toBe(44)
    expect(fitWidth('n', ['x'.repeat(500)])).toBe(180)
  })
})

describe('session scopes', () => {
  const live = (s: Session) => s.status === 'SESSION_STATUS_OPEN'
  const sessions: Session[] = [
    { id: 'new', status: 'SESSION_STATUS_OPEN' }, { id: 'a', group: 'zeta', status: 'SESSION_STATUS_OPEN' },
    { id: 'b', group: 'Alpha' }, { id: 'c', group: 'zeta' }, { id: 'old' },
  ]
  it('offers only All until a group exists', () => {
    expect(sessionScopes([{ id: 'x' }, { id: 'y' }], live)).toEqual([{ key: SCOPE_ALL, label: 'All sessions', count: 2, live: 0 }])
  })
  it('lists All and Ungrouped, then groups alphabetically with counts and live captures', () => {
    expect(sessionScopes(sessions, live)).toEqual([
      { key: SCOPE_ALL, label: 'All sessions', count: 5, live: 2 },
      { key: SCOPE_UNGROUPED, label: 'Ungrouped', count: 2, live: 1 },
      { key: groupScope('Alpha'), label: 'Alpha', count: 1, live: 0 },
      { key: groupScope('zeta'), label: 'zeta', count: 2, live: 1 },
    ])
  })
  it('drops Ungrouped once every session has a group', () => {
    expect(sessionScopes([{ id: 'x', group: 'g' }], live).map((s) => s.key)).toEqual([SCOPE_ALL, groupScope('g')])
  })
  it('keeps a group called "all" apart from the All scope', () => {
    const scopes = sessionScopes([{ id: 'x', group: 'all' }, { id: 'y' }], live)
    expect(scopes.map((s) => s.count)).toEqual([2, 1, 1])
    expect(inScope({ id: 'y' }, groupScope('all'))).toBe(false)
  })
  it('selects by scope, keeping list order', () => {
    const ids = (scope: string) => sessions.filter((s) => inScope(s, scope)).map((s) => s.id)
    expect(ids(SCOPE_ALL)).toEqual(['new', 'a', 'b', 'c', 'old'])
    expect(ids(SCOPE_UNGROUPED)).toEqual(['new', 'old'])
    expect(ids(groupScope('zeta'))).toEqual(['a', 'c'])
  })
  it('falls back to All when the remembered group is gone', () => {
    const scopes = sessionScopes(sessions, live)
    expect(resolveScope(scopes, groupScope('zeta'))).toBe(groupScope('zeta'))
    expect(resolveScope(scopes, groupScope('deleted'))).toBe(SCOPE_ALL)
  })
})

describe('session search', () => {
  const live = (s: Session) => s.status === 'SESSION_STATUS_OPEN'
  const sessions: Session[] = [
    { id: '7f3a90c2', label: 'Chromium baseline', source: 'mitmproxy', status: 'SESSION_STATUS_OPEN' },
    { id: '91d2aa01', label: 'Imitation v2', source: 'native', group: 'regression' },
    { id: 'c04b11ee', label: 'Login replay', source: 'mitmproxy', group: 'fixtures', metadata: { device: 'Pixel 8' } },
  ]
  const ids = (q: string) => sessions.filter(sessionMatcher(q)).map((s) => s.id)
  it('matches every term in any field, ignoring case', () => {
    expect(ids('CHROMIUM')).toEqual(['7f3a90c2'])
    expect(ids('mitm')).toEqual(['7f3a90c2', 'c04b11ee'])
    expect(ids('mitm login')).toEqual(['c04b11ee'])
    expect(ids('91d2')).toEqual(['91d2aa01'])
    expect(ids('regress')).toEqual(['91d2aa01'])
    expect(ids('pixel')).toEqual(['c04b11ee'])
    expect(ids('mitm native')).toEqual([])
  })
  it('matches everything on a blank query, and takes no syntax', () => {
    expect(ids('   ')).toHaveLength(3)
    expect(ids('.*')).toEqual([])
    expect(ids('~s')).toEqual([])
  })
  it('counts matches per scope and keeps every scope listed', () => {
    const scopes = sessionScopes(sessions, live, sessionMatcher('mitm'))
    expect(scopes.map((s) => [s.key, s.count, s.live])).toEqual([
      [SCOPE_ALL, 2, 1], [SCOPE_UNGROUPED, 1, 1], [groupScope('fixtures'), 1, 0], [groupScope('regression'), 0, 0],
    ])
  })
})

describe('settings', () => {
  it('reads a corrupt value as the default', () => {
    expect(accepts('columnOverrides', null, {})).toBe(false)
    expect(accepts('columnOverrides', [], {})).toBe(false)
    expect(accepts('columnOverrides', { path: false }, {})).toBe(true)
    expect(accepts('detailsWidth', 999, 40)).toBe(false)
    expect(accepts('detailsWidth', 55, 40)).toBe(true)
    expect(accepts('compact', 'yes', false)).toBe(false)
    expect(accepts('diffView', 'split', 'inline')).toBe(true)
    expect(accepts('textSize', 'large', 'default')).toBe(true)
    expect(accepts('textSize', 'huge', 'default')).toBe(false)
    expect(accepts('diffView', 'sideways', 'inline')).toBe(false)
  })
})

describe('compare request bodies', () => {
  const enc = (t: string) => new TextEncoder().encode(t)
  const JSON_A = '{"cart":"demo-cart-7","items":[{"sku":"demo-42","qty":1}],"currency":"USD","nonce":"4f1c9a77e2"}'
  const JSON_B = '{\n  "items": [\n    {\n      "sku": "demo-42",\n      "qty": 1\n    }\n  ],\n  "cart": "demo-cart-7",\n  "currency": "USD",\n  "nonce": "b83d0e1150"\n}\n'
  const FORM_A = 'email=user%40example.test&password=demo%21pass&remember=on&csrf=a1b2c3&ctx=eyJyZXQiOiIvY2FydCJ9'
  const FORM_B = 'email=user@example.test&remember=on&password=demo!pass&csrf=d4e5f6&ctx=eyJyZXQiOiIvY2FydCJ9'
  const json = 'application/json', form = 'application/x-www-form-urlencoded; charset=UTF-8'

  it('describes how JSON and XML were laid out', () => {
    expect(describeLayout(JSON_A, 'json')).toBe('1 line · compact, no spaces')
    expect(describeLayout(JSON_B, 'json')).toBe('11 lines · 2-space indent · LF · final newline')
    expect(describeLayout('{"a": "x y"}', 'json')).toBe('1 line')
    expect(describeLayout('{"a":"x y"}', 'json')).toBe('1 line · compact, no spaces')
    expect(describeLayout('{\r\n\t"a": 1\r\n}', 'json')).toBe('3 lines · tab indent · CRLF')
    expect(describeLayout('<a>\n    <b/>\n</a>', 'xml')).toBe('3 lines · 4-space indent · LF')
    expect(describeLayout('<a><b>x y</b></a>', 'xml')).toBe('1 line · compact, no spaces')
  })
  it('diffs JSON pretty-printed with key order kept', () => {
    const c = compareBodies(enc(JSON_A), enc(JSON_B), json, json)
    expect(c).toMatchObject({ kind: 'json', identical: false, verdict: 'differ', sizes: [JSON_A.length, JSON_B.length] })
    expect(c.layout![0]).not.toBe(c.layout![1])
    expect([c.diff!.removed, c.diff!.added]).toEqual([2, 2])
  })
  it('calls a layout-only difference so', () => {
    const c = compareBodies(enc('{"a":1,"b":[2]}'), enc('{\n  "a": 1,\n  "b": [\n    2\n  ]\n}\n'), json, json)
    expect(c.verdict).toBe('layout')
    expect(compareBodies(enc('{"a":1}'), enc('{"a":1}'), json, json).verdict).toBe('match')
  })
  it('falls back to text when a kind is not confirmed or not shared', () => {
    expect(compareBodies(enc('{"a":'), enc('{"a":1}'), json, json).kind).toBe('text')
    expect(compareBodies(enc('{"a":1}'), enc('<a/>'), json, 'text/xml').kind).toBe('text')
    expect(compareBodies(enc('{"a":1}'), enc('{"a":1}'), undefined, undefined).kind).toBe('text')
    expect(compareBodies(new Uint8Array([0, 1, 2, 255]), enc('x'), undefined, undefined).kind).toBe('binary')
  })
  it('form-decodes with + as a space and UTF-8', () => {
    expect(formDecode('a+b%20c')).toBe('a b c')
    expect(formDecode('%D0%BF%D1%80')).toBe('пр')
    expect(formDecode('%E0%A4%A')).toBeNull()
  })
  it('pairs form fields by name and occurrence, values as sent', () => {
    const { order, rows } = compareForms('a=1&a=2&x=%20', 'a=2&b=3&x=+')
    expect(order).toEqual([['a', 'a', 'x'], ['a', 'b', 'x']])
    expect(rows).toEqual([
      { name: 'a', a: '1', b: '2', same: false, sameDecoded: false },
      { name: 'a', a: '2', b: null, same: false, sameDecoded: false },
      { name: 'x', a: '%20', b: '+', same: false, sameDecoded: true },
      { name: 'b', a: null, b: '3', same: false, sameDecoded: false },
    ])
  })
  it('marks values that differ only in encoding', () => {
    const c = compareBodies(enc(FORM_A), enc(FORM_B), form, form)
    expect(c.kind).toBe('form')
    expect(c.verdict).toBe('differ') // field order and csrf differ
    const by = Object.fromEntries(c.form!.rows.map((r) => [r.name, r]))
    expect(by.email).toMatchObject({ same: false, sameDecoded: true })
    expect(by.remember.same).toBe(true)
    expect(by.csrf).toMatchObject({ same: false, sameDecoded: false })
    expect(compareBodies(enc('q=a+b&n=%31'), enc('q=a%20b&n=1'), form, form).verdict).toBe('encoding')
    expect(compareBodies(enc('n=1&q=a+b'), enc('q=a%20b&n=1'), form, form).verdict).toBe('differ')
  })
  it('handles missing bodies', () => {
    expect(compareBodies(null, new Uint8Array(), json, json)).toEqual({ sizes: [null, null], identical: true, verdict: 'match' })
    const one = compareBodies(null, enc('{"a":1}'), undefined, json)
    expect(one).toMatchObject({ identical: false, verdict: 'differ', alone: { side: 'b', lines: ['{', '  "a": 1', '}'] } })
  })
  it('compares big bodies byte for byte only', () => {
    const big = enc('x'.repeat((1 << 20) + 1))
    expect(compareBodies(big, big.slice())).toMatchObject({ identical: true, verdict: 'match', bytesOnly: true })
  })
  it('copies the diff, or a form as name=value lines', () => {
    expect(bodyDiffText(compareBodies(enc('a'), enc('b')))).toBe('--- A\n+++ B\n@@ -1,1 +1,1 @@\n-a\n+b')
    expect(bodyDiffText(compareBodies(enc('a=1&b=2'), enc('a=1&b=3'), form, form))).toBe('--- A\n+++ B\n a=1\n-b=2\n+b=3')
  })
  it('pairs diff lines side by side', () => {
    const lines = unifiedDiff(['a', 'b', 'c'], ['a', 'x', 'y', 'c']).hunks[0].lines
    expect(splitRows(lines).map(([l, r]) => [l?.text ?? null, r?.text ?? null])).toEqual([['a', 'a'], ['b', 'x'], [null, 'y'], ['c', 'c']])
  })
})

describe('update notices', () => {
  const at = { checkedUnixMs: '1000' }
  const notice = (components: object[]) => updateNotice({ ...at, components })
  it('never reads unknown as up to date', () => {
    expect(updateNotice(null)).toMatchObject({ tone: 'amber', headline: 'no update answer yet — checks may be off', key: '' })
    expect(notice([])).toMatchObject({ tone: 'blue', headline: 'nothing is enrolled for update checks' })
    expect(notice([{ name: 'a' }])).toMatchObject({ tone: 'blue', headline: 'everything is up to date', key: '' })
  })
  it('lifts one shared hint into the action', () => {
    const n = notice([
      { name: 'a', updateAvailable: true, localRev: '1', remoteRev: '2', updateHint: 'make update' },
      { name: 'b', updateAvailable: true, updateHint: 'make update' }, { name: 'c' },
    ])
    expect(n).toMatchObject({ headline: 'update available', action: 'make update', key: 'a@2 b@', details: ['a 1 → 2', 'b ? → ?'] })
  })
  it('appends hints that differ', () => {
    const n = notice([{ name: 'a', updateAvailable: true, localRev: '1', remoteRev: '2', updateHint: 'x' }, { name: 'b', updateAvailable: true, localRev: '3', remoteRev: '4', updateHint: 'y' }])
    expect(n.action).toBeUndefined()
    expect(n.details).toEqual(['a 1 → 2 — x', 'b 3 → 4 — y'])
  })
  it('never claims up to date on a partial answer, and folds a shared error', () => {
    const n = notice([{ name: 'a' }, { name: 'b', error: 'offline' }, { name: 'c', error: 'offline' }])
    expect(n).toMatchObject({ tone: 'amber', headline: 'nothing new where it could be checked', details: ['could not check b, c (offline)'] })
    expect(notice([{ name: 'a', error: 'x' }, { name: 'b', error: 'y' }, { name: 'c' }]).details).toEqual(['could not check a (x)', 'could not check b (y)'])
    expect(notice([{ name: 'a', error: 'x' }]).headline).toBe('could not check for updates')
  })
  it('keeps the 08:00 cutoff across DST', () => {
    const before = process.env.TZ
    process.env.TZ = 'Europe/Amsterdam'
    const local = (y: number, m: number, d: number, h: number) => new Date(y, m, d, h).getTime()
    // Sunday 30 March 2025 lost an hour at 02:00, so the day before is 23 hours long.
    expect(new Date(local(2025, 2, 30, 7)).getTimezoneOffset()).not.toBe(new Date(local(2025, 2, 29, 7)).getTimezoneOffset())
    expect(lastEightAm(local(2025, 2, 30, 7))).toBe(local(2025, 2, 29, 8))
    expect(new Date(lastEightAm(local(2025, 2, 30, 7))).getHours()).toBe(8)
    expect(lastEightAm(local(2025, 2, 30, 9))).toBe(local(2025, 2, 30, 8))
    expect(lastEightAm(local(2025, 2, 1, 7))).toBe(local(2025, 1, 28, 8))
    process.env.TZ = before
  })
  it('is due only when the stamp predates the cutoff', () => {
    const now = new Date(2026, 5, 10, 9).getTime()
    expect(refreshDue(new Date(2026, 5, 10, 7).getTime(), now)).toBe(true)
    expect(refreshDue(new Date(2026, 5, 10, 8).getTime(), now)).toBe(false)
    expect(refreshDue(0, now)).toBe(true)
  })
  it('words the age of an answer', () => {
    expect(checkedAgo(2000, 1000)).toBe('just now')
    expect(checkedAgo(0, 59_000)).toBe('just now')
    expect(checkedAgo(0, 12 * 60000)).toBe('12 min ago')
    expect(checkedAgo(0, 3 * 3600000)).toBe('3h ago')
    expect(checkedAgo(0, 50 * 3600000)).toBe('2d ago')
  })
})

describe('log lines', () => {
  it('dims the timestamp and tints by the first severity word', () => {
    expect(classifyLogLine('2026/10/28 14:32:10.5 error: upstream warn')).toEqual({ time: '2026/10/28 14:32:10.5', message: 'error: upstream warn', tone: 'red', run: false })
    expect(classifyLogLine('2026-10-28T14:32:10Z WARNING slow')).toMatchObject({ time: '2026-10-28T14:32:10Z', tone: 'amber' })
    expect(classifyLogLine('level=info msg=up').tone).toBe('blue')
    expect(classifyLogLine('Traceback (most recent call last):').tone).toBe('red')
    expect(classifyLogLine('trace: step').tone).toBe('grey')
    expect(classifyLogLine('no level here').tone).toBeNull()
  })
  it('spots run markers', () => {
    expect(classifyLogLine('=== gateway start · 2026/10/28 ===').run).toBe(true)
    expect(classifyLogLine('=== half').run).toBe(false)
  })
})

describe('row selection', () => {
  const ids = ['a', 'b', 'c', 'd']
  const none = { anchor: null, set: NOTHING }
  it('a plain click selects one and clears the set', () => {
    expect(select(ids, { anchor: 'a', set: new Set(['a', 'b']) }, 'c', {})).toEqual({ anchor: 'c', set: NOTHING })
  })
  it('shift selects the range from the anchor, in either direction', () => {
    const s = select(ids, { anchor: 'b', set: NOTHING }, 'd', { shift: true })
    expect([...s.set]).toEqual(['b', 'c', 'd'])
    expect(s.anchor).toBe('b')
    expect([...select(ids, { anchor: 'c', set: NOTHING }, 'a', { shift: true }).set]).toEqual(['a', 'b', 'c'])
    expect(select(ids, none, 'b', { shift: true }).anchor).toBe('b')
  })
  it('toggle keeps the first row and moves the anchor', () => {
    const s = select(ids, { anchor: 'a', set: NOTHING }, 'c', { toggle: true })
    expect([...s.set]).toEqual(['a', 'c'])
    expect(s.anchor).toBe('c')
    const off = select(ids, s, 'c', { toggle: true })
    expect([...off.set]).toEqual(['a'])
    expect(off.anchor).toBe('a')
  })
})

describe('message compare', () => {
  const frame = (o: Partial<WsMessage>): WsMessage => ({ id: 'm', ...o })
  it('pretty-prints JSON without reordering keys or rounding numbers', () => {
    expect(prettyJson('{"b":1,"2":[1,{}],"a":{"x":12345678901234567890}}')).toBe('{\n  "b": 1,\n  "2": [\n    1,\n    {}\n  ],\n  "a": {\n    "x": 12345678901234567890\n  }\n}')
    expect(prettyJson('{"s":"a,:{\\"}"}')).toBe('{\n  "s": "a,:{\\"}"\n}')
    expect(prettyJson('nope')).toBeNull()
  })
  it('pretty-prints XML keeping attribute order', () => {
    expect(prettyXml('<a z="1" b="2"><b>t</b><c/></a>')).toBe('<a z="1" b="2">\n  <b>t</b>\n  <c/>\n</a>')
    expect(prettyXml('<a><b></a>')).toBeNull()
    expect(prettyPayload('<not xml')).toBe('<not xml')
  })
  it('builds hunks with context, line numbers and a summary', () => {
    const a = Array.from({ length: 20 }, (_, i) => `l${i}`)
    const b = [...a]
    b[10] = 'changed'
    b.splice(15, 1)
    const d = unifiedDiff(a, b)
    expect([d.removed, d.added]).toEqual([2, 1])
    expect(d.hunks).toHaveLength(1)
    expect(d.hunks[0].header).toBe('@@ -8,12 +8,11 @@')
    expect(d.hunks[0].lines.find((l) => l.kind === '-')).toMatchObject({ text: 'l10', a: 11 })
    expect(d.hunks[0].lines.find((l) => l.kind === '+')).toMatchObject({ text: 'changed', b: 11 })
    expect(diffText(d).split('\n').slice(0, 3)).toEqual(['--- A', '+++ B', '@@ -8,12 +8,11 @@'])
  })
  it('splits distant changes, and has no hunks for equal text', () => {
    const a = Array.from({ length: 40 }, (_, i) => `l${i}`)
    const b = a.map((l, i) => (i === 2 || i === 30 ? 'x' : l))
    expect(unifiedDiff(a, b).hunks).toHaveLength(2)
    expect(unifiedDiff(a, a)).toMatchObject({ hunks: [], removed: 0, added: 0 })
    expect(unifiedDiff([], ['x']).hunks[0].header).toBe('@@ -0,0 +1,1 @@')
  })
  it('lays out hunks with the unchanged lines between them as gaps', () => {
    const a = Array.from({ length: 40 }, (_, i) => `l${i}`)
    const b = a.map((l, i) => (i === 10 || i === 30 ? 'x' : l))
    const d = unifiedDiff(a, b) // 42 script lines: each change is a − and a + line
    const shape = (revealed: number[]) => diffParts(d, new Set(revealed)).map((p) => (p.kind === 'gap' ? `gap ${p.to - p.from}${p.above ? '↑' : ''}${p.below ? '↓' : ''}` : p.header))
    expect(shape([])).toEqual(['gap 7↓', '@@ -8,7 +8,7 @@', 'gap 13↑↓', '@@ -28,7 +28,7 @@', 'gap 6↑'])
    const [, first, middle] = diffParts(d, new Set())
    // Opening the whole middle gap joins the two hunks into one block with one header.
    const all = Array.from({ length: middle.to - middle.from }, (_, k) => middle.from + k)
    expect(shape(all)).toEqual(['gap 7↓', '@@ -8,27 +8,27 @@', 'gap 6↑'])
    // Opening part of it grows the hunk above and keeps a smaller gap.
    expect(shape([first.to, first.to + 1])).toEqual(['gap 7↓', '@@ -8,9 +8,9 @@', 'gap 11↑↓', '@@ -28,7 +28,7 @@', 'gap 6↑'])
  })
  it('falls back to a block replace past the size guard', () => {
    const a = Array.from({ length: 3000 }, (_, i) => `a${i}`), b = Array.from({ length: 3000 }, (_, i) => `b${i}`)
    const d = unifiedDiff(a, b)
    expect([d.removed, d.added]).toEqual([3000, 3000])
  })
  it('places a frame without counting it as a difference', () => {
    const all = [frame({ id: '1', fromClient: true, tsUnixMicros: '1000000' }), frame({ id: '2', tsUnixMicros: '2000000' }), frame({ id: '3', fromClient: true, tsUnixMicros: '3500000' }), frame({ id: '4', tsUnixMicros: '4000000' })]
    expect(positionLines(messagePosition(all, '3', 500000)!)).toEqual(['#3 of 4 · client #2', 't+3.000 s', '+2.500 s'])
    expect(messagePosition(all, '2', 0)).toMatchObject({ dir: 'server', dirIndex: 1, sincePrevious: null })
    expect(messagePosition(all, 'gone', 0)).toBeNull()
  })
  it('compares direction, exact size and metadata by key', () => {
    const s = compareMessages(frame({ fromClient: true, opcode: 'text', payload: { size: '2100' }, metadata: { k: '1' } }), frame({ opcode: 'text', payload: { size: '2200' }, metadata: { k: '2', o: 'x' } }))
    expect(s.map((x) => [x.title, x.match])).toEqual([['Direction · opcode', false], ['Payload size', false], ['Metadata', false]])
    expect(s[2].rows.map((p) => p.name)).toEqual(['k', 'o'])
    expect(s[2].named && !s[0].named).toBe(true)
  })
  it('folds a matching section to its value once', () => {
    const f: Flow = { id: 'a', protocol: 'HTTP/2', tlsClientName: 'chrome', requestHeaders: [{ name: 'cookie', value: 'sid=1; theme=dark' }] }
    const s = compareFlows(f, { ...f, id: 'b' })
    expect(s.find((x) => x.title === 'Cookie order')?.fold).toBe('sid · theme')
    expect(s.find((x) => x.title === 'TLS fingerprint')?.rows.map((r) => r.name)).toEqual(['client', 'ja3', 'ja4'])
    expect(s.find((x) => x.title === 'HTTP/2 fingerprint')?.fold).toBe('∅')
  })
  it('places both frames as context rows', () => {
    const all = [frame({ id: '1', fromClient: true, tsUnixMicros: '1000000' }), frame({ id: '2', tsUnixMicros: '2000000' })]
    const p = positionSection(messagePosition(all, '1', 0), null)
    expect(p.context).toBe(true)
    expect(p.rows.map((r) => [r.name, r.b])).toEqual([['frame', '∅'], ['since open', '∅'], ['since prev', '∅']])
  })
})

describe('choice search', () => {
  it('needs every term in the label or the value, case ignored', () => {
    const t = searchTerms('  QA  prof ')
    expect(t).toEqual(['qa', 'prof'])
    expect(matchesTerms(t, ['qa-checkout', 'Profile 3'])).toBe(true)
    expect(matchesTerms(t, ['qa-checkout', 'Default'])).toBe(false)
    expect(matchesTerms(searchTerms(''), [undefined])).toBe(true)
    expect(matchesTerms(['x'], [undefined, ''])).toBe(false)
  })
  it('marks every occurrence of every term, overlaps joined', () => {
    expect(matchRuns('Chromium 131 · stable', ['131', 'chrom'])).toEqual([
      { text: 'Chrom', hit: true }, { text: 'ium ', hit: false }, { text: '131', hit: true }, { text: ' · stable', hit: false }])
    expect(matchRuns('aaa', ['aa'])).toEqual([{ text: 'aaa', hit: true }])
    expect(matchRuns('qa-qa', ['qa'])).toEqual([{ text: 'qa', hit: true }, { text: '-', hit: false }, { text: 'qa', hit: true }])
    expect(matchRuns('abc', [])).toEqual([{ text: 'abc', hit: false }])
    expect(matchRuns('', ['a'])).toEqual([])
  })
  it('names the nothing-matches noun', () => {
    expect(plural('Browser binary')).toBe('browser binaries')
    expect(plural('Profile')).toBe('profiles')
    expect(plural('Device')).toBe('devices')
    expect(plural('Proxy')).toBe('proxies')
    expect(plural('Key')).toBe('keys')
    expect(plural('Arch')).toBe('arches')
  })
})

describe('render budget', () => {
  it('stops before the line that would pass it, counting newlines', () => {
    expect(fitLines(['abc', 'de', 'f'], 7)).toEqual({ count: 2, used: 7 })
    expect(fitLines(['abc', 'de', 'f'], 6)).toEqual({ count: 1, used: 4 })
    expect(fitLines(['abc'], 3)).toEqual({ count: 0, used: 0 })
    expect(fitLines([], 10)).toEqual({ count: 0, used: 0 })
  })
  it('holds exactly 4 KiB of hex dump', () => {
    const lines = hexDump(new Uint8Array(HEX_CAP * 2), HEX_CAP * 2).split('\n')
    expect(fitLines(lines, renderBudget(true)).count * 16).toBe(HEX_CAP)
    expect(renderBudget(false)).toBe(50_000)
  })
})

describe('annotations', () => {
  it('knows when a filter reads them', () => {
    expect(readsAnnotations('~fav')).toBe(true)
    expect(readsAnnotations('~b hello !~tag spam')).toBe(true)
    expect(readsAnnotations('~mark red')).toBe(true)
    expect(readsAnnotations('~from client ~b favorite')).toBe(false)
    expect(readsAnnotations('')).toBe(false)
  })
  it('names the ids the catalog no longer knows', () => {
    const catalog = new Map([['t1', {}]])
    expect(unknownIds(['t1', 'gone'], catalog)).toEqual(['gone'])
    expect(unknownIds(undefined, catalog)).toEqual([])
  })
})

describe('declared columns', () => {
  it('reads the comma list a source attaches, trimmed and once each', () => {
    const s = (v?: string): Session => ({ id: 's', metadata: v === undefined ? undefined : { 'viewer.columns': v } })
    expect(declaredColumns(s('conn,stream'))).toEqual(['conn', 'stream'])
    expect(declaredColumns(s(' scrape_group , proxy_provider,,scrape_group'))).toEqual(['scrape_group', 'proxy_provider'])
    expect(declaredColumns(s())).toEqual([])
  })
})

describe('flag slots', () => {
  const pack = (glyphs: string) => {
    const { chip, shown, rest } = packFlags([...glyphs].map((glyph) => ({ glyph })))
    return [chip ? '⇅' : '', shown.map((f) => f.glyph).join(''), rest.map((f) => f.glyph).join('')]
  }
  it('shows up to three flags, and two and ⋯ beyond that', () => {
    expect(pack('★#✎')).toEqual(['', '★#✎', ''])
    expect(pack('★#✎⬡')).toEqual(['', '★#', '✎⬡'])
  })
  it('gives the chip two slots beside one flag, and ⋯ beside more', () => {
    expect(pack('⇅')).toEqual(['⇅', '', ''])
    expect(pack('⇅★')).toEqual(['⇅', '★', ''])
    expect(pack('⇅★#')).toEqual(['⇅', '', '★#'])
  })
})

describe('text size', () => {
  it('writes layout px as rem of the browser default', () => {
    expect(rem(16)).toBe('1rem')
    expect(rem(11)).toBe('0.6875rem')
    expect(rem(57)).toBe('3.5625rem')
  })
  it('offers Default at the browser size, the rest as percentages of it', () => {
    expect(TEXT_SIZES.find((s) => s.id === 'default')?.percent).toBe(100)
    expect(TEXT_SIZES.map((s) => s.percent)).toEqual([...TEXT_SIZES.map((s) => s.percent)].sort((a, b) => a - b))
  })
})

describe('image', () => {
  const bytes = (...parts: (number[] | string)[]) => Uint8Array.from(parts.flatMap((p) => (typeof p === 'string' ? [...p].map((c) => c.charCodeAt(0)) : p)))
  const u32 = (v: number) => [v >>> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255]
  it('reads a transparent 1×1 GIF', () => {
    const gif = Uint8Array.from(atob('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'), (c) => c.charCodeAt(0))
    expect(sniffImage(gif)).toEqual({ format: 'gif', width: 1, height: 1, transparent: true })
  })
  it('reads PNG, JPEG, WebP, BMP and ICO headers', () => {
    const png = bytes([0x89], 'PNG', [13, 10, 26, 10], u32(13), 'IHDR', u32(128), u32(96), [8, 6, 0, 0, 0])
    expect(sniffImage(png)).toEqual({ format: 'png', width: 128, height: 96, transparent: true })
    const opaque = bytes([0x89], 'PNG', [13, 10, 26, 10], u32(13), 'IHDR', u32(4), u32(4), [8, 2, 0, 0, 0], [0, 0, 0, 0], u32(0), 'IDAT')
    expect(sniffImage(opaque)?.transparent).toBe(false)
    const jpeg = bytes([0xff, 0xd8, 0xff, 0xe0, 0, 4, 0, 0, 0xff, 0xc0, 0, 17, 8, 1, 104, 2, 128, 3])
    expect(sniffImage(jpeg)).toEqual({ format: 'jpeg', width: 640, height: 360, transparent: false })
    const webp = bytes('RIFF', [0, 0, 0, 0], 'WEBPVP8X', [10, 0, 0, 0, 0x10, 0, 0, 0], [199, 0, 0, 99, 0, 0])
    expect(sniffImage(webp)).toEqual({ format: 'webp', width: 200, height: 100, transparent: true })
    const bmp = bytes('BM', [30, 0, 0, 0], new Array(12).fill(0), [16, 0, 0, 0, 0xf0, 0xff, 0xff, 0xff], [0, 0, 0, 0])
    expect(sniffImage(bmp)).toMatchObject({ format: 'bmp', width: 16, height: 16 })
    expect(sniffImage(bytes([0, 0, 1, 0, 1, 0, 0, 32], new Array(8).fill(0)))).toMatchObject({ format: 'ico', width: 256, height: 32 })
  })
  it('takes no Content-Type for an image, and text that is no SVG for none', () => {
    expect(sniffImage(bytes('<!doctype html><title>x</title>'), '<!doctype html><title>x</title>')).toBeNull()
    expect(svgInfo('{"svg": 1}')).toBeNull()
  })
  it('notes a Content-Type naming another type', () => {
    const jpeg = { format: 'jpeg' as const }
    expect(sentAs(jpeg, 'image/png')).toBe('image/png')
    expect(sentAs(jpeg, 'image/jpg; q=1')).toBeUndefined()
    expect(sentAs(null, 'image/png')).toBe('image/png')
    expect(sentAs(null, 'text/html')).toBeUndefined()
    expect(sentAs(jpeg, undefined)).toBeUndefined()
  })
  it('refuses to draw past the caps', () => {
    expect(tooLarge({ format: 'png', width: 100, height: 100 }, 6 * 1024 * 1024)).toBe('over 5 MiB')
    expect(tooLarge({ format: 'png', width: 20000, height: 10 }, 100)).toMatch(/^20000 × 10 px/)
    expect(tooLarge({ format: 'png', width: 100, height: 100 }, 100)).toBeNull()
  })
})

describe('hidden flows', () => {
  it('names why the gateway hides a flow, and nothing for one it shows', () => {
    expect(hiddenReason({ protocol: 'DNS', method: 'A' })).toBe('DNS lookup')
    expect(hiddenReason({ protocol: 'HTTP/1.1', method: 'CONNECT' })).toBe('proxy tunnel')
    expect(hiddenReason({ protocol: 'TCP', metadata: { 'conn.outcome': 'no_request' } })).toBe('connection closed before any request')
    // A raw stream nothing claimed has its payload to read, so it is not hidden.
    expect(hiddenReason({ protocol: 'TCP', metadata: { 'conn.outcome': 'tcp_passthrough' } })).toBeNull()
    expect(hiddenReason({ protocol: 'HTTP/2', method: 'GET' })).toBeNull()
  })
})
