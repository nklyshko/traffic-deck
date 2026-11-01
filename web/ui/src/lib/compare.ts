import { cookiePairs, rejoinCookies } from './http'
import { num } from './format'
import type { Flow, Header, WsMessage } from './types'

export const MISSING = '∅'

export interface DiffRow { a: string | null; b: string | null; same: boolean }
export interface PairRow { name: string; a: string; b: string; same: boolean }
export interface Section {
  title: string
  match: boolean
  rows?: DiffRow[]
  pairs?: PairRow[]
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
  return { title, match: rows.every((r) => r.same), rows }
}

export function compareFlows(a: Flow, b: Flow): Section[] {
  const ah = rejoinCookies(a.requestHeaders ?? []), bh = rejoinCookies(b.requestHeaders ?? [])
  const ac = cookiePairs(a.requestHeaders ?? []), bc = cookiePairs(b.requestHeaders ?? [])
  const noCookie = (hs: Header[]) => regular(hs).filter((h) => h.name?.toLowerCase() !== 'cookie')
  const paired = (title: string, rows: PairRow[]): Section => ({
    title, match: rows.every((r) => r.same), pairs: rows,
  })
  const tls = (f: Flow) => [`client ${f.tlsClientName || MISSING}`, `ja3 ${f.ja3 || MISSING}`, `ja4 ${f.ja4 || MISSING}`]
  // Exact: rounded sizes would call 2100 and 2200 bytes a match.
  const size = (f: Flow) => `${num(f.requestBody?.size).toLocaleString('en-US')} B`
  return [
    ordered('HTTP version', [a.protocol ?? ''].filter(Boolean), [b.protocol ?? ''].filter(Boolean)),
    ordered('Pseudo-header order', pseudo(a.requestHeaders ?? []), pseudo(b.requestHeaders ?? [])),
    ordered('Header order', regular(ah).map((h) => h.name ?? ''), regular(bh).map((h) => h.name ?? '')),
    ordered('Cookie order', ac.map((c) => c.name), bc.map((c) => c.name)),
    paired('Header values', pairValues(named(noCookie(ah)), named(noCookie(bh)))),
    paired('Cookie values', pairValues(ac, bc)),
    ordered('TLS fingerprint', tls(a), tls(b)),
    ordered('HTTP/2 fingerprint', [a.http2Fingerprint ?? ''].filter(Boolean), [b.http2Fingerprint ?? ''].filter(Boolean)),
    ordered('Request body size', [size(a)], [size(b)]),
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
export interface Hunk { header: string; lines: DiffLine[] }
export interface UnifiedDiff { hunks: Hunk[]; removed: number; added: number }

function editScript(a: string[], b: string[]): DiffLine[] {
  let start = 0
  while (start < a.length && start < b.length && a[start] === b[start]) start++
  let tail = 0
  while (tail < a.length - start && tail < b.length - start && a[a.length - 1 - tail] === b[b.length - 1 - tail]) tail++
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

export function unifiedDiff(a: string[], b: string[]): UnifiedDiff {
  const script = editScript(a, b)
  const changes = script.flatMap((l, i) => (l.kind === ' ' ? [] : [i]))
  const hunks: Hunk[] = []
  let at = 0
  while (at < changes.length) {
    const first = Math.max(0, changes[at] - DIFF_CONTEXT)
    let last = changes[at]
    while (at + 1 < changes.length && changes[at + 1] - last <= DIFF_CONTEXT * 2) last = changes[++at]
    at++
    const lines = script.slice(first, Math.min(script.length, last + DIFF_CONTEXT + 1))
    const count = (side: 'a' | 'b') => lines.filter((l) => l[side] !== undefined).length
    const before = script.slice(0, first)
    const startOf = (side: 'a' | 'b') => before.filter((l) => l[side] !== undefined).length + (count(side) ? 1 : 0)
    hunks.push({ header: `@@ -${startOf('a')},${count('a')} +${startOf('b')},${count('b')} @@`, lines })
  }
  return { hunks, removed: script.filter((l) => l.kind === '-').length, added: script.filter((l) => l.kind === '+').length }
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
export const positionLines = (p: Position): string[] => [
  `#${p.index} of ${p.total.toLocaleString('en-US')} · ${p.dir} #${p.dirIndex}`,
  `t+${seconds(p.sinceOpen)}`,
  p.sincePrevious === null ? `first ${p.dir} frame` : `+${seconds(p.sincePrevious)}`,
]

export function compareMessages(a: WsMessage, b: WsMessage): Section[] {
  const line = (m: WsMessage) => `${m.fromClient ? '→ client' : '← server'} · ${m.opcode ?? MISSING}`
  const size = (m: WsMessage) => `${num(m.payload?.size).toLocaleString('en-US')} B`
  const meta = (m: WsMessage) => Object.entries(m.metadata ?? {}).map(([name, value]) => ({ name, value }))
  const pairs = pairValues(meta(a), meta(b))
  return [
    ordered('Direction · opcode', [line(a)], [line(b)]),
    ordered('Payload size', [size(a)], [size(b)]),
    { title: 'Metadata', match: pairs.every((r) => r.same), pairs },
  ]
}
