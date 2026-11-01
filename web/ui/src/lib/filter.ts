// Tokenising only: the gateway is the sole interpreter of the filter language.
export interface Term { negated: boolean; op: string; arg: string }

const NAMES: Record<string, string> = {
  '~m': 'method', '~d': 'domain', '~u': 'url', '~c': 'status', '~t': 'type', '~proto': 'protocol', '~conn': 'conn',
  '~stream': 'stream', '~h': 'header', '~hq': 'req header', '~hs': 'rsp header', '~b': 'body',
  '~bq': 'req body', '~bs': 'rsp body', '~tag': 'tag', '~group': 'group', '~mark': 'mark',
  '~comment': 'comment', '~meta': 'meta', '~s': 'has response', '~q': 'no response', '~fav': 'favorite',
}
const FLAGS = new Set(['~s', '~q', '~fav'])

export function parseFilter(expr: string): Term[] {
  const terms: Term[] = []
  const tokens = expr.split(/\s+/).filter(Boolean)
  for (let i = 0; i < tokens.length; i++) {
    let tok = tokens[i]
    const negated = tok.startsWith('!')
    if (negated) tok = tok.slice(1)
    if (!tok) continue
    if (FLAGS.has(tok)) terms.push({ negated, op: tok, arg: '' })
    else if (tok in NAMES) terms.push({ negated, op: tok, arg: tokens[++i] ?? '' })
    else terms.push({ negated, op: '', arg: tok })
  }
  return terms
}

export function formatFilter(terms: Term[]): string {
  return terms.map((t) => `${t.negated ? '!' : ''}${t.op}${t.op && t.arg ? ' ' : ''}${t.arg}`).join(' ')
}

export function readTerm(expr: string, op: string): string | null {
  const t = parseFilter(expr).find((x) => x.op === op && !x.negated)
  return t ? t.arg : null
}

// Replaces in place, so a control doesn't reorder a hand-typed expression. Negated terms are
// not this control's: it must never drop a hand-typed `!~t json`.
export function writeTerm(expr: string, op: string, arg: string | null): string {
  const terms = parseFilter(expr)
  const at = terms.findIndex((t) => t.op === op && !t.negated)
  const rest = terms.filter((t, i) => i === at || t.op !== op || t.negated)
  if (arg === null) return formatFilter(rest.filter((t) => t.op !== op || t.negated))
  const term = { negated: false, op, arg }
  if (at < 0) return formatFilter([...terms, term])
  return formatFilter(rest.map((t) => (t.op === op && !t.negated ? term : t)))
}

// An op still waiting for its argument: the gateway would refuse it, and nothing the reader
// meant is lost by holding the last result until it parses.
export function halfTyped(expr: string): boolean {
  const last = parseFilter(expr).at(-1)
  return !!last && !!last.op && !last.arg && !FLAGS.has(last.op)
}

export const dropTerm = (expr: string, i: number): string => formatFilter(parseFilter(expr).filter((_, j) => j !== i))

export function termLabel(t: Term): string {
  const name = t.op ? NAMES[t.op] : 'url'
  return `${t.negated ? 'not ' : ''}${name}${t.arg ? `: ${t.arg}` : ''}`
}

// The one Status control over three ops: picking a value removes the others.
export const STATUS_OPTIONS = [
  { label: '2xx', op: '~c', arg: '2..' }, { label: '3xx', op: '~c', arg: '3..' }, { label: '4xx', op: '~c', arg: '4..' },
  { label: '5xx', op: '~c', arg: '5..' }, { label: 'Errors', op: '~c', arg: '[45]..' },
  { label: 'No response', op: '~q', arg: '' }, { label: 'Answered', op: '~s', arg: '' },
]
export function readStatus(expr: string): string {
  return STATUS_OPTIONS.find((o) => readTerm(expr, o.op) === o.arg)?.label ?? ''
}
export function writeStatus(expr: string, label: string): string {
  let next = expr
  for (const op of ['~c', '~q', '~s']) next = writeTerm(next, op, null)
  const o = STATUS_OPTIONS.find((x) => x.label === label)
  return o ? writeTerm(next, o.op, o.arg) : next
}

export interface HelpTerm { op: string; arg?: string; meaning: string; group: string }

export const FLOW_TERMS: HelpTerm[] = [
  { op: '~m', arg: 're', meaning: 'method', group: 'Request' }, { op: '~d', arg: 're', meaning: 'domain', group: 'Request' },
  { op: '~u', arg: 're', meaning: 'URL', group: 'Request' }, { op: '~hq', arg: 're', meaning: 'request header', group: 'Request' },
  { op: '~bq', arg: 're', meaning: 'request body', group: 'Request' },
  { op: '~c', arg: 're', meaning: 'status code', group: 'Response' }, { op: '~t', arg: 're', meaning: 'content type', group: 'Response' },
  { op: '~hs', arg: 're', meaning: 'response header', group: 'Response' }, { op: '~bs', arg: 're', meaning: 'response body', group: 'Response' },
  { op: '~s', meaning: 'has a response', group: 'Response' }, { op: '~q', meaning: 'no response yet', group: 'Response' },
  { op: '~h', arg: 're', meaning: 'header, any side', group: 'Either side' }, { op: '~b', arg: 're', meaning: 'body, any side', group: 'Either side' },
  { op: '~fav', meaning: 'favorited', group: 'Annotations' }, { op: '~mark', arg: 're', meaning: 'mark colour', group: 'Annotations' },
  { op: '~tag', arg: 're', meaning: 'tag', group: 'Annotations' }, { op: '~group', arg: 're', meaning: 'group', group: 'Annotations' },
  { op: '~comment', arg: 're', meaning: 'comment text', group: 'Annotations' },
  { op: '~proto', arg: 're', meaning: 'protocol', group: 'Connection' }, { op: '~conn', arg: 're', meaning: 'TCP connection', group: 'Connection' },
  { op: '~stream', arg: 're', meaning: 'HTTP/2 stream', group: 'Connection' }, { op: '~meta', arg: 'key=re', meaning: 'metadata', group: 'Connection' },
]
export const MESSAGE_TERMS: HelpTerm[] = [
  { op: '~b', arg: 're', meaning: 'payload', group: 'Frame' }, { op: '~op', arg: 're', meaning: 'opcode', group: 'Frame' },
  { op: '~from', arg: 're', meaning: 'client or server', group: 'Frame' }, { op: '~meta', arg: 'key=re', meaning: 'metadata', group: 'Frame' },
  { op: '~fav', meaning: 'favorited', group: 'Annotations' }, { op: '~mark', arg: 're', meaning: 'mark colour', group: 'Annotations' },
  { op: '~tag', arg: 're', meaning: 'tag', group: 'Annotations' }, { op: '~group', arg: 're', meaning: 'group', group: 'Annotations' },
  { op: '~comment', arg: 're', meaning: 'comment text', group: 'Annotations' },
]
export const FLOW_EXAMPLES = [
  ['Errors', '~c [45]..'], ['No response', '~q'], ['JSON', '~t json'], ['POST', '~m POST'], ['Favorites', '~fav'],
  ['JWT', '~h eyJ[A-Za-z0-9_-]*\\.'], ['Encoded URL', '~u %[0-9A-Fa-f]{2}'],
]
export const MESSAGE_EXAMPLES = [['From client', '~from client'], ['Text frames', '~op text'], ['No pings', '!~op ping|pong']]

export function wordAtCaret(expr: string, caret: number): { start: number; end: number; word: string } {
  const start = caret > 0 ? expr.lastIndexOf(' ', caret - 1) + 1 : 0
  const space = expr.indexOf(' ', caret)
  const end = space < 0 ? expr.length : space
  return { start, end, word: expr.slice(start, end) }
}

// The op being typed at the caret: what narrows the help popover. In argument position a `~`
// is the start of a regex, not an op.
export function opAtCaret(expr: string, caret: number): { start: number; end: number; prefix: string } | null {
  const { start, end } = wordAtCaret(expr, caret)
  const m = /^!?(~\w*)$/.exec(expr.slice(start, caret))
  if (!m || halfTyped(expr.slice(0, start))) return null
  return { start: start + (caret - start - m[1].length), end, prefix: m[1] }
}
