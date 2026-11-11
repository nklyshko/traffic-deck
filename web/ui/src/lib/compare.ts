import { cookiePairs, HEX_CAP, hexDump, looksTextual, rejoinCookies, TEXT_CAP } from './http'
import { readable } from './decoder'
import { num } from './format'
import type { Flow, Header, WsMessage } from './types'

export const MISSING = '∅'

export interface WordPart { kind: ' ' | '-' | '+'; text: string }
export interface DiffRow { a: string | null; b: string | null; same: boolean }
export interface PairRow { name: string; a: string; b: string; same: boolean }
/** A row of a compare table. A null side is a place an ordered list leaves blank; a named
 *  value that one side lacks is `∅`. full: never collapsed, as the request line's parts. */
/** decode: each side gets a decoder chip; sameDecoded: the pair differs only in its encoding (≈). */
export interface CmpRow { name?: string; a: string | null; b: string | null; same: boolean; full?: boolean; decode?: boolean; sameDecoded?: boolean }
export interface Section {
  title: string
  match: boolean
  rows: CmpRow[]
  /** Whether the rows carry names; an ordered list's don't, but keeps the column. */
  named: boolean
  /** The value a matching section folds to, shown once on its one line. */
  fold: string
  /** Each side's own place: rows split without being a difference, and there is no verdict. */
  context?: boolean
}

// LCS alignment: equal lines pair, a run of changes pairs removed against added, and the
// shorter side is padded, so both columns always have equal rows.
export function diffLines(a: string[], b: string[]): DiffRow[] {
  const lcs: number[][] = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0))
  for (let i = a.length - 1; i >= 0; i--)
    for (let j = b.length - 1; j >= 0; j--)
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1])
  const rows: DiffRow[] = []
  let removed: string[] = []
  let added: string[] = []
  const flush = () => {
    for (let k = 0; k < Math.max(removed.length, added.length); k++)
      rows.push({ a: removed[k] ?? null, b: added[k] ?? null, same: false })
    removed = []
    added = []
  }
  let i = 0, j = 0
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) {
      flush()
      rows.push({ a: a[i], b: b[j], same: true })
      i++
      j++
    } else if (j < b.length && (i === a.length || lcs[i][j + 1] >= lcs[i + 1][j])) added.push(b[j++])
    else removed.push(a[i++])
  }
  flush()
  return rows
}

// Repeated names pair by occurrence: a map would hide exactly the repeats this view is for.
export function pairValues(a: { name: string; value: string }[], b: { name: string; value: string }[]): PairRow[] {
  const remaining = [...b]
  const rows: PairRow[] = []
  for (const item of a) {
    const at = remaining.findIndex((x) => x.name === item.name)
    const other = at >= 0 ? remaining.splice(at, 1)[0].value : undefined
    rows.push({ name: item.name, a: item.value, b: other ?? MISSING, same: other === item.value })
  }
  for (const item of remaining) rows.push({ name: item.name, a: MISSING, b: item.value, same: false })
  return rows
}

const regular = (hs: Header[]) => hs.filter((h) => !h.name?.startsWith(':'))
const pseudo = (hs: Header[]) => hs.filter((h) => h.name?.startsWith(':')).map((h) => h.name ?? '')
const named = (hs: Header[]) => hs.map((h) => ({ name: h.name ?? '', value: h.value ?? '' }))

function ordered(title: string, a: string[], b: string[]): Section {
  const rows = diffLines(a.length ? a : [MISSING], b.length ? b : [MISSING])
  return { title, match: rows.every((r) => r.same), rows, named: false, fold: a.join(' · ') || MISSING }
}

export function namedSection(title: string, pairs: PairRow[], fold?: string): Section {
  return {
    title, match: pairs.every((r) => r.same), rows: pairs, named: true,
    fold: fold ?? (pairs.map((r) => `${r.name} ${r.a}`).join(' · ') || MISSING),
  }
}

const DEFAULT_PORT: Record<string, string> = { https: '443', http: '80' }

// A default port spelled out and one left implied reach the same server, so they compare equal.
export function plainAuthority(authority: string, scheme?: string): string {
  const port = DEFAULT_PORT[scheme?.toLowerCase() ?? '']
  return port && authority.endsWith(`:${port}`) ? authority.slice(0, -port.length - 1) : authority
}

const sharedEnds = (a: string, b: string): [number, number] => {
  let start = 0
  while (start < a.length && start < b.length && a[start] === b[start]) start++
  let tail = 0
  while (tail < a.length - start && tail < b.length - start && a[a.length - 1 - tail] === b[b.length - 1 - tail]) tail++
  return [start, tail]
}

/** One-line diff of two strings: tokens are aligned, then a replaced run is narrowed to the
 *  characters that differ, so `…/2026-11-23-21-33-13.chain` shows just the changed digits. */
export function wordDiff(a: string, b: string): WordPart[] {
  const tokens = (s: string) => s.match(/[\p{L}\p{N}]+|[^\p{L}\p{N}]/gu) ?? []
  const ta = tokens(a), tb = tokens(b)
  const rows = ta.length * tb.length > MAX_DIFF_CELLS ? [{ a, b, same: false }] : diffLines(ta, tb)
  const out: WordPart[] = []
  const push = (kind: WordPart['kind'], text: string) => {
    if (!text) return
    const last = out[out.length - 1]
    if (last?.kind === kind) last.text += text
    else out.push({ kind, text })
  }
  let del = '', ins = ''
  const flush = () => {
    const [start, tail] = sharedEnds(del, ins)
    push(' ', del.slice(0, start))
    push('-', del.slice(start, del.length - tail))
    push('+', ins.slice(start, ins.length - tail))
    push(' ', del.slice(del.length - tail))
    del = ''
    ins = ''
  }
  for (const r of rows) {
    if (r.same) {
      flush()
      push(' ', r.a ?? '')
    } else {
      del += r.a ?? ''
      ins += r.b ?? ''
    }
  }
  flush()
  return out
}

/** The marks for two values that differ, or null when they share under a third of the longer:
 *  marking scattered separators of unrelated values is noise, and the tint already says it. */
export function differingParts(a: string, b: string): WordPart[] | null {
  const parts = wordDiff(a, b)
  const shared = parts.reduce((n, p) => n + (p.kind === ' ' ? p.text.length : 0), 0)
  return shared * 3 >= Math.max(a.length, b.length) ? parts : null
}

// [name, value, never collapsed, decodable]: a host and a path are compared as sent, each with
// its own decoder chip (§7.5).
const REQUEST_PARTS: [string, (f: Flow) => string | undefined, boolean, boolean][] = [
  ['method', (f) => f.method, false, false], ['scheme', (f) => f.scheme, false, false],
  ['authority', (f) => f.authority && plainAuthority(f.authority, f.scheme), false, true],
  ['path', (f) => f.path, true, true], ['query', (f) => f.query, true, false],
]

// Row by row, never diffed as lines, so each part always faces its counterpart.
export function requestLine(a: Flow, b: Flow): Section {
  const rows = REQUEST_PARTS.map(([name, get, full, decode]): CmpRow => {
    const va = get(a) || MISSING, vb = get(b) || MISSING
    const same = va === vb
    const sameDecoded = decode && !same && va !== MISSING && vb !== MISSING && readable(va) === readable(vb)
    return { name, a: va, b: vb, same, full, decode, sameDecoded }
  })
  const url = `${a.method || MISSING} ${a.scheme ? `${a.scheme}://` : ''}${rows[2].a === MISSING ? '' : rows[2].a}${a.path ?? ''}${a.query ? `?${a.query}` : ''}`
  return { ...namedSection('Request line', []), match: rows.every((r) => r.same), rows, fold: url }
}

// Fixed names, so a fingerprint absent on one side still faces its counterpart.
const fixed = (names: string[], a: (string | undefined)[], b: (string | undefined)[]): PairRow[] =>
  names.map((name, i) => ({ name, a: a[i] || MISSING, b: b[i] || MISSING, same: (a[i] || MISSING) === (b[i] || MISSING) }))

export function compareFlows(a: Flow, b: Flow): Section[] {
  const ah = rejoinCookies(a.requestHeaders ?? []), bh = rejoinCookies(b.requestHeaders ?? [])
  const ac = cookiePairs(a.requestHeaders ?? []), bc = cookiePairs(b.requestHeaders ?? [])
  const noCookie = (hs: Header[]) => regular(hs).filter((h) => h.name?.toLowerCase() !== 'cookie')
  const tls = (f: Flow) => [f.tlsClientName, f.ja3, f.ja4]
  return [
    requestLine(a, b),
    ordered('HTTP version', [a.protocol ?? ''].filter(Boolean), [b.protocol ?? ''].filter(Boolean)),
    ordered('Pseudo-header order', pseudo(a.requestHeaders ?? []), pseudo(b.requestHeaders ?? [])),
    ordered('Header order', regular(ah).map((h) => h.name ?? ''), regular(bh).map((h) => h.name ?? '')),
    ordered('Cookie order', ac.map((c) => c.name), bc.map((c) => c.name)),
    namedSection('Header values', pairValues(named(noCookie(ah)), named(noCookie(bh)))),
    namedSection('Cookie values', pairValues(ac, bc)),
    namedSection('TLS fingerprint', fixed(['client', 'ja3', 'ja4'], tls(a), tls(b))),
    ordered('HTTP/2 fingerprint', [a.http2Fingerprint ?? ''].filter(Boolean), [b.http2Fingerprint ?? ''].filter(Boolean)),
    // Section 10, the request body, needs the bytes: compareBodies.
  ]
}

export function goSlice(items: string[]): string {
  if (items.length === 0) return '[]string{}'
  const esc = (s: string) => s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
  return `[]string{\n${items.map((s) => `\t"${esc(s)}",\n`).join('')}}`
}

export const headerOrder = (f: Flow) => regular(rejoinCookies(f.requestHeaders ?? [])).map((h) => h.name ?? '')
export const pseudoOrder = (f: Flow) => pseudo(f.requestHeaders ?? [])
export const cookieOrder = (f: Flow) => cookiePairs(f.requestHeaders ?? []).map((c) => c.name)

// --- two messages ---

const DIFF_CONTEXT = 3
const MAX_DIFF_CELLS = 4_000_000

export interface DiffLine { kind: ' ' | '-' | '+'; text: string; a?: number; b?: number }
export interface Hunk { header: string; lines: DiffLine[]; from: number; to: number } // [from, to) in script
export interface UnifiedDiff { hunks: Hunk[]; removed: number; added: number; script: DiffLine[] }

function commonEnds(a: string[], b: string[]): [number, number] {
  let start = 0
  while (start < a.length && start < b.length && a[start] === b[start]) start++
  let tail = 0
  while (tail < a.length - start && tail < b.length - start && a[a.length - 1 - tail] === b[b.length - 1 - tail]) tail++
  return [start, tail]
}

/** Whether the changed middle fits the LCS table; past it a diff is a whole-block replace. */
export function diffFits(a: string[], b: string[]): boolean {
  const [start, tail] = commonEnds(a, b)
  return (a.length - start - tail) * (b.length - start - tail) <= MAX_DIFF_CELLS
}

function editScript(a: string[], b: string[]): DiffLine[] {
  const [start, tail] = commonEnds(a, b)
  const midA = a.slice(start, a.length - tail), midB = b.slice(start, b.length - tail)
  // The LCS table is quadratic: past this a whole-block replace is the honest answer.
  const rows = midA.length * midB.length > MAX_DIFF_CELLS
    ? [...midA.map((l) => ({ a: l, b: null, same: false })), ...midB.map((l) => ({ a: null, b: l, same: false }))]
    : diffLines(midA, midB)
  let i = 0, j = 0
  const out: DiffLine[] = []
  const context = (from: number, to: number) => {
    for (let k = from; k < to; k++) out.push({ kind: ' ', text: a[k], a: ++i, b: ++j })
  }
  context(0, start)
  let run: DiffRow[] = []
  const flush = () => {
    for (const r of run) if (r.a !== null) out.push({ kind: '-', text: r.a, a: ++i })
    for (const r of run) if (r.b !== null) out.push({ kind: '+', text: r.b, b: ++j })
    run = []
  }
  for (const r of rows) {
    if (r.same) {
      flush()
      out.push({ kind: ' ', text: r.a ?? '', a: ++i, b: ++j })
    } else run.push(r)
  }
  flush()
  context(a.length - tail, a.length)
  return out
}

function hunkHeader(script: DiffLine[], from: number, to: number): string {
  const lines = script.slice(from, to), before = script.slice(0, from)
  const count = (side: 'a' | 'b') => lines.filter((l) => l[side] !== undefined).length
  const startOf = (side: 'a' | 'b') => before.filter((l) => l[side] !== undefined).length + (count(side) ? 1 : 0)
  return `@@ -${startOf('a')},${count('a')} +${startOf('b')},${count('b')} @@`
}

export function unifiedDiff(a: string[], b: string[]): UnifiedDiff {
  const script = editScript(a, b)
  const changes = script.flatMap((l, i) => (l.kind === ' ' ? [] : [i]))
  const hunks: Hunk[] = []
  let at = 0
  while (at < changes.length) {
    const from = Math.max(0, changes[at] - DIFF_CONTEXT)
    let last = changes[at]
    while (at + 1 < changes.length && changes[at + 1] - last <= DIFF_CONTEXT * 2) last = changes[++at]
    at++
    const to = Math.min(script.length, last + DIFF_CONTEXT + 1)
    hunks.push({ header: hunkHeader(script, from, to), lines: script.slice(from, to), from, to })
  }
  return { hunks, script, removed: script.filter((l) => l.kind === '-').length, added: script.filter((l) => l.kind === '+').length }
}

export type DiffPart =
  | { kind: 'block'; header: string; from: number; to: number }
  | { kind: 'gap'; from: number; to: number; above: boolean; below: boolean } // above/below: a block borders it

/** The hunks with some unchanged lines revealed: shown runs become blocks with their own
 *  headers, so a gap opened all the way joins its two hunks; the rest stay gaps. */
export function diffParts(d: UnifiedDiff, revealed: ReadonlySet<number>): DiffPart[] {
  const inHunk = new Array<boolean>(d.script.length).fill(false)
  for (const h of d.hunks) inHunk.fill(true, h.from, h.to)
  const shown = (i: number) => inHunk[i] || revealed.has(i)
  const parts: DiffPart[] = []
  let i = 0
  while (i < d.script.length) {
    const on = shown(i)
    let j = i
    while (j < d.script.length && shown(j) === on) j++
    parts.push(on ? { kind: 'block', header: hunkHeader(d.script, i, j), from: i, to: j } : { kind: 'gap', from: i, to: j, above: i > 0, below: j < d.script.length })
    i = j
  }
  return parts
}

/** Side by side: equal lines face each other, a run of changes pairs removed against added,
 *  the shorter side left blank, as diffLines pairs the ordered sections. */
export function splitRows(lines: DiffLine[]): [DiffLine | null, DiffLine | null][] {
  const rows: [DiffLine | null, DiffLine | null][] = []
  let removed: DiffLine[] = [], added: DiffLine[] = []
  const flush = () => {
    for (let k = 0; k < Math.max(removed.length, added.length); k++) rows.push([removed[k] ?? null, added[k] ?? null])
    removed = []
    added = []
  }
  for (const l of lines) {
    if (l.kind === ' ') {
      flush()
      rows.push([l, l])
    } else (l.kind === '-' ? removed : added).push(l)
  }
  flush()
  return rows
}

export const diffText = (d: UnifiedDiff) => ['--- A', '+++ B', ...d.hunks.flatMap((h) => [h.header, ...h.lines.map((l) => `${l.kind}${l.text}`)])].join('\n')

// Reformats the text itself: going through JSON.parse would move integer keys and round
// big numbers, and a fingerprint comparison is about exactly such details.
export function prettyJson(text: string): string | null {
  try {
    JSON.parse(text)
  } catch {
    return null
  }
  let out = '', depth = 0
  const newline = () => { out += `\n${'  '.repeat(depth)}` }
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (c === '"') {
      const start = i
      for (i++; text[i] !== '"'; i++) if (text[i] === '\\') i++
      out += text.slice(start, i + 1)
    } else if (c === '{' || c === '[') {
      const close = c === '{' ? '}' : ']'
      const next = text.slice(i + 1).search(/\S/)
      if (text[i + 1 + next] === close) {
        out += c + close
        i += next + 1
      } else {
        out += c
        depth++
        newline()
      }
    } else if (c === '}' || c === ']') {
      depth--
      newline()
      out += c
    } else if (c === ',') {
      out += c
      newline()
    } else if (c === ':') out += ': '
    else if (!/\s/.test(c)) out += c
  }
  return out
}

const XML_TOKEN = /<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<(?:[^>"']|"[^"]*"|'[^']*')*>|[^<]+/g

export function prettyXml(text: string): string | null {
  const trimmed = text.trim()
  if (!trimmed.startsWith('<') || !trimmed.endsWith('>')) return null
  const tokens = trimmed.match(XML_TOKEN) ?? []
  if (tokens.join('') !== trimmed) return null
  const lines: string[] = []
  const open: string[] = []
  const nameOf = (t: string) => /^<\/?([^\s/>]+)/.exec(t)?.[1] ?? ''
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]
    const pad = '  '.repeat(open.length)
    if (!t.startsWith('<')) {
      if (t.trim()) lines.push(pad + t.trim())
    } else if (t.startsWith('</')) {
      if (open.pop() !== nameOf(t)) return null
      lines.push('  '.repeat(open.length) + t)
    } else if (/^<[!?]/.test(t) || t.endsWith('/>')) lines.push(pad + t)
    else if (tokens[i + 1] !== undefined && !tokens[i + 1].startsWith('<') && tokens[i + 2] === `</${nameOf(t)}>`) {
      lines.push(pad + t + tokens[i + 1].trim() + tokens[i + 2])
      i += 2
    } else {
      lines.push(pad + t)
      open.push(nameOf(t))
    }
  }
  return open.length ? null : lines.join('\n')
}

export const prettyPayload = (text: string): string => prettyJson(text) ?? prettyXml(text) ?? text

export interface Position { index: number; total: number; dir: 'client' | 'server'; dirIndex: number; sinceOpen: number; sincePrevious: number | null }

export function messagePosition(all: WsMessage[], id: string, openMicros: number): Position | null {
  const at = all.findIndex((m) => m.id === id)
  if (at < 0) return null
  const m = all[at]
  const same = all.slice(0, at + 1).filter((x) => !!x.fromClient === !!m.fromClient)
  const ts = num(m.tsUnixMicros)
  return {
    index: at + 1, total: all.length, dir: m.fromClient ? 'client' : 'server', dirIndex: same.length, sinceOpen: ts - openMicros,
    sincePrevious: same.length > 1 ? ts - num(same[same.length - 2].tsUnixMicros) : null,
  }
}

const seconds = (us: number) => `${(us / 1e6).toFixed(3)} s`
const POSITION_NAMES = ['frame', 'since open', 'since prev']

/** Each frame's place: context to orient by, never counted as a difference. */
export function positionSection(a: Position | null, b: Position | null): Section {
  const la = a ? positionLines(a) : [], lb = b ? positionLines(b) : []
  const rows = POSITION_NAMES.map((name, i) => ({ name, a: la[i] ?? MISSING, b: lb[i] ?? MISSING, same: false }))
  return { title: 'Position', match: true, rows, named: true, fold: '', context: true }
}

export const positionLines = (p: Position): string[] => [
  `#${p.index} of ${p.total.toLocaleString('en-US')} · ${p.dir} #${p.dirIndex}`,
  `t+${seconds(p.sinceOpen)}`,
  p.sincePrevious === null ? `first ${p.dir} frame` : `+${seconds(p.sincePrevious)}`,
]

export function compareMessages(a: WsMessage, b: WsMessage): Section[] {
  const line = (m: WsMessage) => `${m.fromClient ? '→ client' : '← server'} · ${m.opcode ?? MISSING}`
  const size = (m: WsMessage) => `${num(m.payload?.size).toLocaleString('en-US')} B`
  const meta = (m: WsMessage) => Object.entries(m.metadata ?? {}).map(([name, value]) => ({ name, value }))
  return [
    ordered('Direction · opcode', [line(a)], [line(b)]),
    ordered('Payload size', [size(a)], [size(b)]),
    namedSection('Metadata', pairValues(meta(a), meta(b))),
  ]
}

// --- two request bodies (§5.9.2) ---

export const BODY_COMPARE_LIMIT = 1 << 20

export type BodyKind = 'json' | 'xml' | 'form' | 'text' | 'binary'

function declaredKind(contentType = ''): BodyKind | null {
  const t = contentType.split(';')[0].trim().toLowerCase()
  if (t === 'application/x-www-form-urlencoded') return 'form'
  if (t === 'application/json' || t.endsWith('+json')) return 'json'
  if (t.endsWith('/xml') || t.endsWith('+xml')) return 'xml'
  return null
}

const utf8 = (bytes: Uint8Array) => new TextDecoder().decode(bytes)

/** The Content-Type names the kind and parsing confirms it: a JSON label on broken JSON is text. */
export function bodyKind(bytes: Uint8Array, contentType?: string): BodyKind {
  if (!looksTextual(bytes)) return 'binary'
  const text = utf8(bytes)
  switch (declaredKind(contentType)) {
    case 'json': return prettyJson(text) !== null ? 'json' : 'text'
    case 'xml': return prettyXml(text) !== null ? 'xml' : 'text'
    case 'form': return /[\r\n\t]/.test(text.trim()) ? 'text' : 'form'
    default: return 'text'
  }
}

// A hexDump line: offset, two spaces, 47 of hex, two spaces, 16 of ASCII, and the newline.
const HEX_LINE = 76
export const renderBudget = (binary: boolean) => (binary ? (HEX_CAP / 16) * HEX_LINE : TEXT_CAP)

/** How many of the lines fit the budget, counting a newline after each, and what they use. */
export function fitLines(lines: string[], budget: number): { count: number; used: number } {
  let used = 0
  for (let i = 0; i < lines.length; i++) {
    const next = used + lines[i].length + 1
    if (next > budget) return { count: i, used }
    used = next
  }
  return { count: lines.length, used }
}

/** The body as Show original shows it: text as sent, anything else as a hex dump. */
export const bodyText = (bytes: Uint8Array) => (looksTextual(bytes) ? utf8(bytes) : hexDump(bytes, bytes.length))

/** How a JSON or XML body was laid out, which pretty-printing for the diff hides. */
export function describeLayout(text: string, kind: 'json' | 'xml'): string {
  const lines = text.split('\n')
  if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop()
  const parts = [`${lines.length} ${lines.length === 1 ? 'line' : 'lines'}`]
  if (lines.length === 1) {
    const line = lines[0].replace(/\r$/, '')
    const compact = kind === 'json' ? !/\s/.test(line.replace(/"(?:[^"\\]|\\.)*"/g, '""')) : !/>\s+</.test(line)
    if (compact) parts.push('compact, no spaces')
  } else {
    const indents = lines.map((l) => /^[ \t]*/.exec(l)![0]).filter(Boolean)
    if (indents.some((i) => i.startsWith('\t'))) parts.push('tab indent')
    else if (indents.length) parts.push(`${Math.min(...indents.map((i) => i.length))}-space indent`)
    else parts.push('no indent')
  }
  const crlf = text.match(/\r\n/g)?.length ?? 0, lf = (text.match(/\n/g)?.length ?? 0) - crlf
  if (crlf && lf) parts.push('mixed LF/CRLF')
  else if (crlf) parts.push('CRLF')
  else if (lf) parts.push('LF')
  if (text.endsWith('\n')) parts.push('final newline')
  return parts.join(' · ')
}

/** Form decoding: `+` is a space, then percent-decoding as UTF-8; null when malformed. */
export function formDecode(s: string): string | null {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '))
  } catch {
    return null
  }
}

/** Fields in order, name and value as sent. */
export function formFields(text: string): { name: string; value: string }[] {
  return text.split('&').filter(Boolean).map((part) => {
    const at = part.indexOf('=')
    return at < 0 ? { name: part, value: '' } : { name: part.slice(0, at), value: part.slice(at + 1) }
  })
}

export interface FormRow { name: string; a: string | null; b: string | null; same: boolean; sameDecoded: boolean }

const fieldName = (raw: string) => formDecode(raw) ?? raw

// Paired by decoded name and by occurrence, as header values are; compared byte for byte.
export function compareForms(a: string, b: string): { order: [string[], string[]]; rows: FormRow[] } {
  const fa = formFields(a), fb = formFields(b)
  const remaining = [...fb]
  const rows: FormRow[] = []
  const decodedEqual = (x: string, y: string) => { const dx = formDecode(x); return dx !== null && dx === formDecode(y) }
  for (const f of fa) {
    const at = remaining.findIndex((x) => fieldName(x.name) === fieldName(f.name))
    const other = at >= 0 ? remaining.splice(at, 1)[0].value : null
    const same = other === f.value
    rows.push({ name: fieldName(f.name), a: f.value, b: other, same, sameDecoded: !same && other !== null && decodedEqual(f.value, other) })
  }
  for (const f of remaining) rows.push({ name: fieldName(f.name), a: null, b: f.value, same: false, sameDecoded: false })
  return { order: [fa.map((f) => fieldName(f.name)), fb.map((f) => fieldName(f.name))], rows }
}

export type BodyVerdict = 'match' | 'layout' | 'encoding' | 'differ'

export interface BodyComparison {
  sizes: [number | null, number | null] // null: no body
  identical: boolean
  kind?: BodyKind // absent when neither side has a body
  layout?: [string, string]
  verdict: BodyVerdict
  diff?: UnifiedDiff
  form?: { order: [string[], string[]]; rows: FormRow[] }
  alone?: { side: 'a' | 'b'; lines: string[] }
  bytesOnly?: boolean // too big to diff: compared byte for byte only
}

function prepared(bytes: Uint8Array, kind: BodyKind): string[] {
  if (kind === 'binary') return hexDump(bytes, bytes.length).split('\n')
  const text = utf8(bytes)
  const pretty = kind === 'json' ? prettyJson(text) : kind === 'xml' ? prettyXml(text) : null
  return (pretty ?? text).split('\n').map((l) => l.replace(/\r$/, ''))
}

const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i])

export function compareBodies(a: Uint8Array | null, b: Uint8Array | null, typeA?: string, typeB?: string): BodyComparison {
  const ba = a?.length ? a : null, bb = b?.length ? b : null
  const sizes: [number | null, number | null] = [ba?.length ?? null, bb?.length ?? null]
  if (!ba || !bb) {
    if (!ba && !bb) return { sizes, identical: true, verdict: 'match' }
    const only = (ba ?? bb)!, kind = bodyKind(only, ba ? typeA : typeB)
    return { sizes, identical: false, kind, verdict: 'differ', alone: { side: ba ? 'a' : 'b', lines: prepared(only, kind) } }
  }
  const identical = sameBytes(ba, bb)
  const ka = bodyKind(ba, typeA), kb = bodyKind(bb, typeB)
  // Both sides must share a kind; otherwise they compare as text, or binary.
  const kind: BodyKind = ka === kb ? ka : ka !== 'binary' && kb !== 'binary' ? 'text' : 'binary'
  const out: BodyComparison = { sizes, identical, kind, verdict: identical ? 'match' : 'differ' }
  if (kind === 'json' || kind === 'xml') out.layout = [describeLayout(utf8(ba), kind), describeLayout(utf8(bb), kind)]
  if (ba.length > BODY_COMPARE_LIMIT || bb.length > BODY_COMPARE_LIMIT) return { ...out, bytesOnly: true }
  if (kind === 'form') {
    const form = compareForms(utf8(ba), utf8(bb))
    const sameOrder = form.order[0].join('&') === form.order[1].join('&')
    const encoding = !identical && sameOrder && form.rows.every((r) => r.same || r.sameDecoded)
    return { ...out, form, verdict: identical ? 'match' : encoding ? 'encoding' : 'differ' }
  }
  const la = prepared(ba, kind), lb = prepared(bb, kind)
  if (!diffFits(la, lb)) return { ...out, bytesOnly: true }
  const diff = unifiedDiff(la, lb)
  const layoutOnly = !identical && (kind === 'json' || kind === 'xml') && diff.removed + diff.added === 0
  return { ...out, diff, verdict: identical ? 'match' : layoutOnly ? 'layout' : 'differ' }
}

/** Copy body diff: the unified diff, or for a form one `name=value` line per field as sent. */
export function bodyDiffText(c: BodyComparison): string {
  if (c.diff) return diffText(c.diff)
  if (c.alone) return [c.alone.side === 'a' ? '--- A' : '+++ B', ...c.alone.lines.map((l) => `${c.alone!.side === 'a' ? '-' : '+'}${l}`)].join('\n')
  if (!c.form) return ''
  return ['--- A', '+++ B', ...c.form.rows.flatMap((r) => (r.same ? [` ${r.name}=${r.a}`]
    : [...(r.a !== null ? [`-${r.name}=${r.a}`] : []), ...(r.b !== null ? [`+${r.name}=${r.b}`] : [])]))].join('\n')
}
