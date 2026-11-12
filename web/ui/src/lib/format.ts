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

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

// Local and 24 h whatever the browser's locale: a capture's times are compared across screens.
export function formatDateTime(ms: number): string {
  if (!ms) return '—'
  const d = new Date(ms)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}, ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
export const formatMatched = (n: number, capped?: boolean): string => `${n.toLocaleString('en-US')}${capped ? '+' : ''}`

/** At most 4 characters, so it fits the messages chip: one decimal below 10, none from 10. */
export function formatCount(n: number): string {
  if (n < 1000) return String(n)
  // Rounded before choosing the unit or the decimal, or 9,950 would read 10.0K.
  const unit = (v: number, u: string) => (Math.round(v * 10) < 100 ? `${(Math.round(v * 10) / 10).toFixed(1)}${u}` : `${Math.round(v)}${u}`)
  return Math.round(n / 1000) < 1000 ? unit(n / 1000, 'K') : unit(n / 1e6, 'M')
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

// Each hue means one thing (SPEC §8.3): a method, a 1xx or 3xx and a fast flow are read from
// their words, so only success, warning and error take a colour.
export function statusTone(code: number): Tone {
  return (['grey', 'grey', 'green', 'grey', 'amber', 'red'] as Tone[])[Math.floor(code / 100)] ?? 'grey'
}
export function durationTone(us: number): Tone | null {
  if (!us) return null
  if (us <= 500_000) return 'grey'
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

const HIDDEN: Record<string, string> = {
  dns: 'DNS lookup',
  proxy_tunnel: 'proxy tunnel',
  tls_rejected: 'the client rejected the TLS handshake (certificate pinned?)',
  no_request: 'connection closed before any request',
  udp_undecoded: 'UDP no decoder reads',
}

/** Why the gateway hides a flow by default, in words, or null when it does not. The gateway
 *  decides (Flow.hidden_reason); a code this list doesn't know yet shows as itself. */
export const hiddenReason = (code?: string): string | null => (code ? (HIDDEN[code] ?? code) : null)
