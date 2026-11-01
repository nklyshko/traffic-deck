// Protojson renders 64-bit numbers as strings and omits zeros.
export const num = (v: string | number | undefined | null): number => Number(v ?? 0)

export function formatBytes(n: number): string {
  if (!n) return ''
  if (n < 1024) return `${n}B`
  if (n < 1024 * 1024) return `${Math.floor(n / 1024)}K`
  return `${(n / (1024 * 1024)).toFixed(1)}M`
}

export function formatDuration(us: number): string {
  if (!us) return ''
  if (us < 1_000_000) return `${Math.floor(us / 1000)}ms`
  if (us < 60_000_000) return `${(us / 1_000_000).toFixed(1)}s`
  const s = Math.floor(us / 1_000_000)
  return `${Math.floor(s / 60)}m${String(s % 60).padStart(2, '0')}s`
}

export const preciseDuration = (us: number): string => `${(us / 1000).toFixed(3)} ms`

export function formatTime(us: number): string {
  const d = new Date(us / 1000)
  const p = (n: number, w = 2) => String(n).padStart(w, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`
}

export const formatDateTime = (ms: number): string => (ms ? new Date(ms).toLocaleString() : '—')
export const formatMatched = (n: number, capped?: boolean): string => `${n.toLocaleString('en-US')}${capped ? '+' : ''}`

export function formatCount(n: number): string {
  if (n < 1000) return String(n)
  // Rounded before choosing the unit, or 999,950 would read 1000.0K.
  const k = Math.round(n / 100) / 10
  return k < 1000 ? `${k.toFixed(1)}K` : `${(n / 1e6).toFixed(1)}M`
}

const REASONS: Record<number, string> = {
  100: 'Continue', 101: 'Switching Protocols', 102: 'Processing', 103: 'Early Hints',
  200: 'OK', 201: 'Created', 202: 'Accepted', 203: 'Non-Authoritative Information', 204: 'No Content',
  205: 'Reset Content', 206: 'Partial Content', 207: 'Multi-Status', 208: 'Already Reported', 226: 'IM Used',
  300: 'Multiple Choices', 301: 'Moved Permanently', 302: 'Found', 303: 'See Other', 304: 'Not Modified',
  305: 'Use Proxy', 307: 'Temporary Redirect', 308: 'Permanent Redirect',
  400: 'Bad Request', 401: 'Unauthorized', 402: 'Payment Required', 403: 'Forbidden', 404: 'Not Found',
  405: 'Method Not Allowed', 406: 'Not Acceptable', 407: 'Proxy Authentication Required', 408: 'Request Timeout',
  409: 'Conflict', 410: 'Gone', 411: 'Length Required', 412: 'Precondition Failed', 413: 'Content Too Large',
  414: 'URI Too Long', 415: 'Unsupported Media Type', 416: 'Range Not Satisfiable', 417: 'Expectation Failed',
  421: 'Misdirected Request', 422: 'Unprocessable Content', 423: 'Locked', 424: 'Failed Dependency',
  425: 'Too Early', 426: 'Upgrade Required', 428: 'Precondition Required', 429: 'Too Many Requests',
  431: 'Request Header Fields Too Large', 451: 'Unavailable For Legal Reasons',
  500: 'Internal Server Error', 501: 'Not Implemented', 502: 'Bad Gateway', 503: 'Service Unavailable',
  504: 'Gateway Timeout', 505: 'HTTP Version Not Supported', 506: 'Variant Also Negotiates',
  507: 'Insufficient Storage', 508: 'Loop Detected', 510: 'Not Extended', 511: 'Network Authentication Required',
}
const CLASSES = ['', 'Informational', 'Success', 'Redirection', 'Client Error', 'Server Error']
export const reasonPhrase = (code: number): string => REASONS[code] ?? CLASSES[Math.floor(code / 100)] ?? ''

export type Tone = 'green' | 'blue' | 'amber' | 'red' | 'purple' | 'cyan' | 'orange' | 'pink' | 'grey'

export function methodTone(m?: string): Tone {
  return ({ GET: 'green', POST: 'blue', PUT: 'orange', DELETE: 'red', PATCH: 'purple' } as Record<string, Tone>)[m ?? ''] ?? 'grey'
}
export function statusTone(code: number): Tone {
  return (['grey', 'blue', 'green', 'blue', 'amber', 'red'] as Tone[])[Math.floor(code / 100)] ?? 'grey'
}
export function durationTone(us: number): Tone | null {
  if (!us) return null
  if (us <= 500_000) return 'green'
  return us <= 2_000_000 ? 'amber' : 'red'
}
export const shortMethod = (m?: string): string => ({ CONNECT: 'CONN', DELETE: 'DEL', OPTIONS: 'OPT' } as Record<string, string>)[m ?? ''] ?? (m ?? '')
export const shortProto = (p?: string): string => (p ?? '').replace(/^HTTP\//, 'H/')

const FIT_CHAR_PX = 6.7
const FIT_PADDING = 12
const FIT_MIN = 44
const FIT_MAX = 180

// Default width for a column of monospace values: a short sequence number shouldn't get
// the room a long name needs.
export function fitWidth(label: string, values: Iterable<string>): number {
  let longest = label.length
  for (const v of values) longest = Math.max(longest, v.length)
  return Math.min(FIT_MAX, Math.max(FIT_MIN, Math.ceil(longest * FIT_CHAR_PX) + FIT_PADDING))
}
