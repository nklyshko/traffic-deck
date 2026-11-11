// Punycode hosts (RFC 3492) to the Unicode a browser shows. IDNA applies to domain names only, so
// in a URL only the host converts (SPEC §7.5).

const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700

function adapt(delta: number, points: number, first: boolean): number {
  delta = first ? Math.floor(delta / DAMP) : delta >> 1
  delta += Math.floor(delta / points)
  let k = 0
  while (delta > ((BASE - TMIN) * TMAX) >> 1) {
    delta = Math.floor(delta / (BASE - TMIN))
    k += BASE
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW))
}

function digit(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 22
  if (c >= 0x41 && c <= 0x5a) return c - 0x41
  if (c >= 0x61 && c <= 0x7a) return c - 0x61
  return BASE
}

/** The code points a punycode label (without `xn--`) encodes, or null when it is malformed. */
export function punycodeDecode(input: string): string | null {
  const out: number[] = []
  const basic = input.lastIndexOf('-')
  for (let j = 0; j < Math.max(basic, 0); j++) {
    const c = input.charCodeAt(j)
    if (c >= 0x80) return null
    out.push(c)
  }
  let n = 128, i = 0, bias = 72
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
    const old = i
    for (let w = 1, k = BASE; ; k += BASE) {
      if (idx >= input.length) return null
      const d = digit(input.charCodeAt(idx++))
      if (d >= BASE) return null
      i += d * w
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias
      if (d < t) break
      w *= BASE - t
      if (i > 0x10ffff * 64) return null
    }
    bias = adapt(i - old, out.length + 1, old === 0)
    n += Math.floor(i / (out.length + 1))
    i %= out.length + 1
    if (n > 0x10ffff) return null
    out.splice(i++, 0, n)
  }
  return String.fromCodePoint(...out)
}

const HOST = /^[A-Za-z0-9.-]+$/

/** A host with at least one `xn--` label in Unicode, or null. Valid only when the browser's own
 *  URL parser (UTS #46) encodes the result back to the same host, so a label a browser would
 *  refuse to show, or punycode that only looks like it, stays as sent. */
export function unicodeHost(host: string): string | null {
  if (!HOST.test(host) || !/(^|\.)xn--/i.test(host)) return null
  const labels: string[] = []
  for (const label of host.split('.')) {
    if (!/^xn--/i.test(label)) {
      labels.push(label)
      continue
    }
    const u = punycodeDecode(label.slice(4))
    if (!u || !/[^\x00-\x7f]/.test(u) || u !== u.normalize('NFC') || /[\p{C}\p{Z}./:@%]/u.test(u)) return null
    labels.push(u)
  }
  const unicode = labels.join('.')
  try {
    return new URL(`http://${unicode}/`).hostname === host.toLowerCase() ? unicode : null
  } catch {
    return null
  }
}

const AUTHORITY = /^([^:]+)(:\d+)?$/
const URL_PARTS = /^([a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?)([^:/?#]+)(:\d+)?([/?#].*)?$/is

/** A host, `host:port` or full URL with its punycode host in Unicode; everything else as sent. */
export function idnDecoded(value: string): string | null {
  const url = URL_PARTS.exec(value)
  if (url) {
    const host = unicodeHost(url[2])
    return host && `${url[1]}${host}${url[3] ?? ''}${url[4] ?? ''}`
  }
  const auth = AUTHORITY.exec(value)
  const host = auth && unicodeHost(auth[1])
  return host && `${host}${auth[2] ?? ''}`
}
