import { cookiePairs, rejoinCookies } from './http'
import { num } from './format'
import type { Flow, Header } from './types'

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
