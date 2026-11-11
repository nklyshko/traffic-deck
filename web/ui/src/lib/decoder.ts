// Pure value decoding: runs in the browser, nothing is sent anywhere.
import { hexDump } from './http'
import { idnDecoded } from './idn'
import { bytesFromText, describe as describeHello, looksLikeClientHello, parseClientHello, type ClientHello } from './tlshello'

export type Kind = 'jwt' | 'b64' | 'url' | 'idn' | 'hex' | 'ts' | 'tls'
export const KINDS: Kind[] = ['jwt', 'b64', 'url', 'idn', 'hex', 'ts', 'tls']

export interface Claim { name: string; when: string; expired: boolean }
export interface Output {
  kind: Kind
  text?: string // decoded text; JSON when isJson
  isJson?: boolean
  jwt?: { header: unknown; payload: unknown; claims: Claim[] }
  time?: string
  binaryLabel?: string
  hex?: string
  tls?: { hello: ClientHello; view: Record<string, unknown> }
}
export interface Decoded { steps: Kind[]; output: Output }

export function stripWrappers(value: string): string {
  let s = value.trim().replace(/^(Bearer|Basic|Token)\s+/i, '')
  if (s.length >= 2 && (s[0] === '"' || s[0] === "'") && s[s.length - 1] === s[0]) s = s.slice(1, -1)
  return s
}

const JWT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/
const B64_RE = /^[A-Za-z0-9+/_-]+={0,2}$/
const TIME_NAME = /(^|[_-])(ts|time|timestamp|exp|iat|nbf|created|updated)([_-]|$)/i

function b64Bytes(s: string): Uint8Array | null {
  const bare = s.replace(/=+$/, '')
  if (!B64_RE.test(s) || bare.length % 4 === 1) return null
  try {
    return Uint8Array.from(atob(bare.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
  } catch {
    return null
  }
}

function utf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return null
  }
}

function printable(text: string | null): text is string {
  return text !== null && !/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text)
}

function jsonObject(text: string | null): Record<string, unknown> | null {
  if (text === null) return null
  try {
    const v = JSON.parse(text)
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null
  } catch {
    return null
  }
}

function jwtParts(s: string) {
  if (!JWT_RE.test(s)) return null
  const [h, p] = s.split('.')
  const hb = b64Bytes(h), pb = b64Bytes(p)
  if (!hb || !pb) return null
  const header = jsonObject(utf8(hb)), payload = jsonObject(utf8(pb))
  if (!header || !payload || typeof header.alg !== 'string') return null
  return { header, payload }
}

const FULL_URL = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i
const DELIMITER = /(%2F|%3F|%23|%26|%3D)/i

// On a full URL only the path, query and fragment decode, and escaped delimiters stay encoded,
// as an address bar does: `?q=a%26b` must not read as `?q=a&b`.
function percentDecoded(s: string): string {
  const head = FULL_URL.exec(s)?.[0]
  if (head === undefined) return decodeURIComponent(s)
  return head + s.slice(head.length).split(DELIMITER).map((p, i) => (i % 2 ? p : decodeURIComponent(p))).join('')
}

function urlDecoded(s: string): string | null {
  if (!/%[0-9A-Fa-f]{2}/.test(s)) return null
  try {
    let out = percentDecoded(s)
    if (/%[0-9A-Fa-f]{2}/.test(out)) out = percentDecoded(out)
    return out === s ? null : out
  } catch {
    return null
  }
}

function hexBytes(s: string): Uint8Array | null {
  if (s.length % 2 !== 0 || s.length === 0 || !/^[0-9a-fA-F]+$/.test(s)) return null
  return Uint8Array.from(s.match(/../g)!, (b) => parseInt(b, 16))
}

// A TLS ClientHello as hex, a hex dump or base64, with or without record framing.
function clientHello(s: string): ClientHello | null {
  const bytes = bytesFromText(s)
  if (!bytes || !looksLikeClientHello(bytes)) return null
  try {
    return parseClientHello(bytes)
  } catch {
    return null
  }
}

const timestampMs = (s: string): number | null => (/^\d{10}$/.test(s) ? Number(s) * 1000 : /^\d{13}$/.test(s) ? Number(s) : null)

function b64Strict(s: string): boolean {
  if (s.length < 12) return false
  const shaped = s.endsWith('=') || (/[a-z]/.test(s) && /[A-Z]/.test(s)) || (/[a-zA-Z]/.test(s) && /\d/.test(s))
  if (!shaped) return false
  const bytes = b64Bytes(s)
  return !!bytes && printable(utf8(bytes))
}

function hexStrict(s: string): boolean {
  if (s.length < 16) return false
  const bytes = hexBytes(s)
  return !!bytes && printable(utf8(bytes))
}

// What a value looks like, confidently enough to badge it. `name` gates timestamps: ten
// digits are too common to call a time without the field saying so.
export function guessKind(rawValue: string, name = ''): Kind | null {
  const s = stripWrappers(rawValue)
  if (jwtParts(s)) return 'jwt'
  const ms = timestampMs(s)
  if (ms !== null && TIME_NAME.test(name)) {
    const sec = ms / 1000
    if (sec >= 1_100_000_000 && sec <= 1_900_000_000) return 'ts'
  }
  if (clientHello(s)) return 'tls'
  if (idnDecoded(s) !== null) return 'idn'
  if (urlDecoded(s) !== null) return 'url'
  if (b64Strict(s)) return 'b64'
  if (hexStrict(s)) return 'hex'
  return null
}

export function canDecode(rawValue: string, kind: Kind): boolean {
  const s = stripWrappers(rawValue)
  switch (kind) {
    case 'jwt': return !!jwtParts(s)
    case 'b64': return !!b64Bytes(s)
    case 'url': return urlDecoded(s) !== null
    case 'idn': return idnDecoded(s) !== null
    case 'hex': return !!hexBytes(s)
    case 'ts': return timestampMs(s) !== null
    case 'tls': return !!clientHello(s)
  }
}

export function ago(ms: number, now: number): string {
  const d = Math.abs(ms - now)
  const m = Math.floor(d / 60000), h = Math.floor(d / 3600000), day = Math.floor(d / 86400000)
  const span = day ? `${day}d` : h ? `${h}h` : m ? `${m}m` : `${Math.floor(d / 1000)}s`
  return ms > now ? `in ${span}` : `${span} ago`
}

export function formatWhen(ms: number, now: number): string {
  const d = new Date(ms)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())} (${ago(ms, now)})`
}

function textOutput(kind: Kind, text: string): Output {
  const t = text.trim()
  if (t.startsWith('{') || t.startsWith('[')) {
    try {
      JSON.parse(t)
      return { kind, text: t, isJson: true }
    } catch { /* plain text that merely starts like JSON */ }
  }
  return { kind, text }
}

function bytesOutput(kind: Kind, bytes: Uint8Array): Output {
  const text = utf8(bytes)
  if (printable(text)) return textOutput(kind, text)
  return { kind, binaryLabel: `${kind} · ${bytes.length} bytes, not text`, hex: hexDump(bytes, 2048) }
}

function decodeOnce(rawValue: string, kind: Kind, now: number): Output | null {
  const s = stripWrappers(rawValue)
  switch (kind) {
    case 'jwt': {
      const p = jwtParts(s)
      if (!p) return null
      const claims: Claim[] = []
      for (const name of ['iat', 'nbf', 'exp']) {
        const v = p.payload[name]
        if (typeof v === 'number') claims.push({ name, when: formatWhen(v * 1000, now), expired: name === 'exp' && v * 1000 < now })
      }
      return { kind, jwt: { ...p, claims } }
    }
    case 'b64': {
      const b = b64Bytes(s)
      return b && bytesOutput(kind, b)
    }
    case 'hex': {
      const b = hexBytes(s)
      return b && bytesOutput(kind, b)
    }
    case 'url': {
      const t = urlDecoded(s)
      return t === null ? null : textOutput(kind, t)
    }
    case 'idn': {
      const t = idnDecoded(s)
      return t === null ? null : { kind, text: t }
    }
    case 'ts': {
      const ms = timestampMs(s)
      return ms === null ? null : { kind, time: formatWhen(ms, now) }
    }
    case 'tls': {
      const hello = clientHello(s)
      return hello && { kind, tls: { hello, view: describeHello(hello) } }
    }
  }
}

// Decodes as `kind`, then keeps guessing while the result is still plain text, so
// url → base64 → JSON takes one click. Binary output stops the chain, and so does `chain` false.
export function decodeAs(value: string, kind: Kind, now = Date.now(), chain = true): Decoded | null {
  let output = decodeOnce(value, kind, now)
  if (!output) return null
  const steps = [kind]
  while (chain && steps.length < 3 && output.text !== undefined && !output.isJson) {
    const next = guessKind(output.text)
    if (!next) break
    const o = decodeOnce(output.text, next, now)
    if (!o) break
    output = o
    steps.push(next)
  }
  return { steps, output }
}

/** idn and url undo the two encodings of one address (§7.5): picked from the switch, each
 *  shows its own alone; guessed, they chain so a URL with both reads in one click. */
export const chainsAfter = (override: Kind | null): boolean => override !== 'idn' && override !== 'url'

export function pickKind(value: string, name: string, override: Kind | null): Kind | null {
  if (override && canDecode(value, override)) return override
  return guessKind(value, name) ?? KINDS.find((k) => canDecode(value, k)) ?? null
}

/** A host, path or URL as it reads: its punycode host in Unicode, its escapes undone. */
export function readable(value: string): string {
  const host = idnDecoded(value) ?? value
  return urlDecoded(host) ?? host
}
