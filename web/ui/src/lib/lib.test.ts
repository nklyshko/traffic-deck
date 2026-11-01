import { describe, expect, it } from 'vitest'
import { compareFlows, diffLines, goSlice, MISSING, pairValues } from './compare'
import { canDecode, decodeAs, guessKind, stripWrappers } from './decoder'
import { dropTerm, formatFilter, halfTyped, opAtCaret, parseFilter, readStatus, readTerm, termLabel, wordAtCaret, writeStatus, writeTerm } from './filter'
import { fitWidth, formatBytes, formatCount, formatDuration, formatMatched, reasonPhrase } from './format'
import { bodyExt, cookiePairs, curlCommand, hexDump, looksTextual, nameCut, queryPairs, rawExchange, rejoinCookies } from './http'
import { accepts } from './settings'
import { declaredColumns, groupScope, inScope, resolveScope, SCOPE_ALL, SCOPE_UNGROUPED, sessionScopes } from './sessions'
import { cursorOf, extendWindow, patchFlow } from './window'
import type { Flow, Session } from './types'

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

describe('decoder', () => {
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
    expect(sections[0].match).toBe(false)
    expect(sections[2].match).toBe(true)
  })
  it('formats a Go slice', () => {
    expect(goSlice(['a"b', 'c\\'])).toBe('[]string{\n\t"a\\"b",\n\t"c\\\\",\n}')
    expect(goSlice([])).toBe('[]string{}')
  })
})

describe('format', () => {
  it('formats bytes and durations', () => {
    expect([formatBytes(0), formatBytes(10), formatBytes(2048), formatBytes(1572864)]).toEqual(['', '10B', '2K', '1.5M'])
    expect([formatDuration(0), formatDuration(1999), formatDuration(2_400_000), formatDuration(252_000_000)]).toEqual(['', '1ms', '2.4s', '4m12s'])
  })
  it('formats counts and reasons', () => {
    expect(formatMatched(1284, true)).toBe('1,284+')
    expect(formatCount(0)).toBe('0')
    expect(formatCount(999)).toBe('999')
    expect(formatCount(1906)).toBe('1.9K')
    expect(formatCount(999_949)).toBe('999.9K')
    expect(formatCount(999_950)).toBe('1.0M')
    expect(formatCount(2_500_000)).toBe('2.5M')
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
  it('offers no scopes until a group exists', () => {
    expect(sessionScopes([{ id: 'x' }, { id: 'y' }], live)).toEqual([])
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

describe('settings', () => {
  it('reads a corrupt value as the default', () => {
    expect(accepts('columnOverrides', null, {})).toBe(false)
    expect(accepts('columnOverrides', [], {})).toBe(false)
    expect(accepts('columnOverrides', { path: false }, {})).toBe(true)
    expect(accepts('detailsWidth', 999, 40)).toBe(false)
    expect(accepts('detailsWidth', 55, 40)).toBe(true)
    expect(accepts('compact', 'yes', false)).toBe(false)
  })
})

describe('compare sizes', () => {
  it('tells apart sizes that round to the same text', () => {
    const size = (n: number) => compareFlows({ id: 'a', requestBody: { size: n } } as unknown as Flow, { id: 'b', requestBody: { size: 2100 } } as unknown as Flow).find((s) => s.title === 'Request body size')
    expect(size(2100)?.match).toBe(true)
    expect(size(2200)?.match).toBe(false)
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
