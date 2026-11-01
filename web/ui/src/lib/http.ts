import type { Cookie, Flow, Header } from './types'

// HTTP/2 and HTTP/3 clients split Cookie into one field per cookie. Rejoined at the first
// crumb's position; only the raw export shows the wire.
export function rejoinCookies(headers: Header[]): Header[] {
  const crumbs = headers.filter((h) => h.name?.toLowerCase() === 'cookie')
  if (crumbs.length < 2) return headers
  const value = crumbs.map((h) => h.value ?? '').join('; ')
  const out: Header[] = []
  let placed = false
  for (const h of headers) {
    if (h.name?.toLowerCase() !== 'cookie') out.push(h)
    else if (!placed) {
      out.push({ name: h.name, value })
      placed = true
    }
  }
  return out
}

export function cookiePairs(headers: Header[]): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = []
  for (const h of headers) {
    if (h.name?.toLowerCase() !== 'cookie') continue
    for (const part of (h.value ?? '').split(';')) {
      const s = part.trim()
      if (!s) continue
      const eq = s.indexOf('=')
      out.push(eq < 0 ? { name: s, value: '' } : { name: s.slice(0, eq), value: s.slice(eq + 1) })
    }
  }
  return out
}

export function cookieAttrs(c: Cookie): string[] {
  const out: string[] = []
  if (c.path) out.push(`Path=${c.path}`)
  if (c.domain) out.push(`Domain=${c.domain}`)
  if (c.expires) out.push(`Expires=${c.expires}`)
  if (c.maxAge) out.push(`Max-Age=${c.maxAge}`)
  if (c.secure) out.push('Secure')
  if (c.httpOnly) out.push('HttpOnly')
  if (c.sameSite) out.push(`SameSite=${c.sameSite}`)
  return out
}

export function queryPairs(query?: string): { name: string; value: string }[] {
  if (!query) return []
  const decode = (s: string) => {
    try {
      return decodeURIComponent(s.replace(/\+/g, ' '))
    } catch {
      return s
    }
  }
  return query.split('&').filter(Boolean).map((part) => {
    const eq = part.indexOf('=')
    return eq < 0 ? { name: decode(part), value: '' } : { name: decode(part.slice(0, eq)), value: decode(part.slice(eq + 1)) }
  })
}

export function flowUrl(f: Flow): string {
  const q = f.query ? `?${f.query}` : ''
  return f.authority ? `${f.scheme || 'https'}://${f.authority}${f.path ?? ''}${q}` : `${f.path ?? ''}${q}`
}

const shQuote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`

export function curlCommand(f: Flow, body: { text?: string; binary?: boolean } = {}): string {
  const parts = [`curl -X ${f.method || 'GET'} ${shQuote(flowUrl(f))}`]
  if (f.protocol === 'HTTP/2') parts.push('--http2')
  if (f.protocol === 'HTTP/1.1') parts.push('--http1.1')
  for (const h of rejoinCookies(f.requestHeaders ?? [])) {
    if (h.name?.startsWith(':') || h.name?.toLowerCase() === 'host') continue
    parts.push(`-H ${shQuote(`${h.name}: ${h.value ?? ''}`)}`)
  }
  if (body.binary) parts.push(`--data-binary @${f.id}-request.body`)
  else if (body.text) parts.push(`--data-binary ${shQuote(body.text)}`)
  return parts.join(' \\\n  ')
}

const headerBlock = (hs?: Header[]) => (hs ?? []).map((h) => `${h.name}: ${h.value ?? ''}`).join('\n')

export function rawExchange(f: Flow, req: string, rsp: string): string {
  const q = f.query ? `?${f.query}` : ''
  const proto = f.protocol || 'HTTP/1.1'
  const request = `${f.method ?? ''} ${f.path ?? ''}${q} ${proto}\n${headerBlock(f.requestHeaders)}\n\n${req}`
  const response = `${proto} ${f.status ?? ''}\n${headerBlock(f.responseHeaders)}\n\n${rsp}`
  return `${request}\n${'='.repeat(60)}\n${response}`
}

const EXT: Record<string, string> = {
  plain: 'txt', javascript: 'js', 'x-javascript': 'js', ecmascript: 'js', jpeg: 'jpg', 'svg+xml': 'svg',
  'xhtml+xml': 'html', 'octet-stream': 'bin', 'x-www-form-urlencoded': 'txt',
}
export function bodyExt(contentType?: string): string {
  const sub = (contentType ?? '').split(';')[0].trim().toLowerCase().split('/')[1] ?? ''
  if (EXT[sub]) return EXT[sub]
  const plus = sub.lastIndexOf('+')
  const ext = (plus >= 0 ? sub.slice(plus + 1) : sub).replace(/^x-/, '')
  return /^[a-z0-9][a-z0-9.-]{1,7}$/.test(ext) ? ext : 'bin'
}

export function looksTextual(bytes: Uint8Array): boolean {
  const head = bytes.subarray(0, 1024)
  if (head.includes(0)) return false
  try {
    // stream: a multi-byte character cut at the 1 KiB boundary is not "binary".
    new TextDecoder('utf-8', { fatal: true }).decode(head, { stream: true })
    return true
  } catch {
    return false
  }
}

export function hexDump(bytes: Uint8Array, limit = 4096): string {
  const lines: string[] = []
  const end = Math.min(bytes.length, limit)
  for (let off = 0; off < end; off += 16) {
    const row = bytes.subarray(off, Math.min(off + 16, end))
    const hex = [...row].map((b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47)
    const ascii = [...row].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('')
    lines.push(`${off.toString(16).padStart(8, '0')}  ${hex}  ${ascii}`)
  }
  return lines.join('\n')
}

export function base64Bytes(b64?: string): Uint8Array {
  if (!b64) return new Uint8Array()
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
}

export function saveBlob(name: string, data: BlobPart): void {
  const url = URL.createObjectURL(new Blob([data], { type: 'application/octet-stream' }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  // Revoking synchronously cancels large downloads in some browsers.
  setTimeout(() => URL.revokeObjectURL(url), 0)
}

const NAME_TAIL = 12
const NAME_TAIL_MAX = 18

// Where a long name's ellipsis may fall: on a word boundary when one is close to the end.
export function nameCut(name: string): number {
  const from = Math.max(0, name.length - NAME_TAIL_MAX)
  const at = name.slice(from).search(/[-_.]/)
  return at >= 0 && from > 0 ? from + at : Math.max(0, name.length - NAME_TAIL)
}
