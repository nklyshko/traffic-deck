// What an image body is, from its magic bytes and never its Content-Type (SPEC §5.7.1):
// the format, the size its header declares and whether it can be transparent, all read
// without decoding pixels, so a decoding bomb can be refused before the browser sees it.

export type ImageFormat = 'png' | 'jpeg' | 'gif' | 'webp' | 'avif' | 'ico' | 'bmp' | 'svg'

export interface ImageInfo {
  format: ImageFormat
  width?: number // from the header; absent when it doesn't say
  height?: number
  transparent?: boolean
}

export const IMAGE_MIME: Record<ImageFormat, string> = {
  png: 'image/png', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', avif: 'image/avif',
  ico: 'image/x-icon', bmp: 'image/bmp', svg: 'image/svg+xml',
}
// Other names a Content-Type may give the same format.
const ALIASES: Record<string, ImageFormat> = {
  'image/jpg': 'jpeg', 'image/pjpeg': 'jpeg', 'image/vnd.microsoft.icon': 'ico', 'image/ico': 'ico',
  'image/x-ms-bmp': 'bmp', 'image/x-bmp': 'bmp', 'image/apng': 'png', 'image/x-png': 'png',
}

export const IMAGE_MAX_BYTES = 5 * 1024 * 1024
export const IMAGE_MAX_SIDE = 16_384

const ascii = (b: Uint8Array, at: number, n: number) => String.fromCharCode(...b.subarray(at, at + n))
const be32 = (b: Uint8Array, at: number) => ((b[at] << 24) >>> 0) + (b[at + 1] << 16) + (b[at + 2] << 8) + b[at + 3]
const be16 = (b: Uint8Array, at: number) => (b[at] << 8) | b[at + 1]
const le16 = (b: Uint8Array, at: number) => b[at] | (b[at + 1] << 8)
const le24 = (b: Uint8Array, at: number) => b[at] | (b[at + 1] << 8) | (b[at + 2] << 16)
const le32s = (b: Uint8Array, at: number) => b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)

function png(b: Uint8Array): ImageInfo {
  // IHDR is the first chunk; colour types 4 and 6 carry alpha, any other only via tRNS.
  const info: ImageInfo = { format: 'png' }
  if (b.length >= 26 && ascii(b, 12, 4) === 'IHDR') {
    info.width = be32(b, 16)
    info.height = be32(b, 20)
    info.transparent = b[25] === 4 || b[25] === 6
  }
  for (let at = 8; !info.transparent && at + 8 <= b.length;) {
    const type = ascii(b, at + 4, 4)
    if (type === 'tRNS') info.transparent = true
    if (type === 'IDAT' || type === 'IEND') break
    at += 12 + be32(b, at)
  }
  return info
}

function gif(b: Uint8Array): ImageInfo {
  const info: ImageInfo = { format: 'gif', width: le16(b, 6), height: le16(b, 8), transparent: false }
  // A graphic control extension's transparent-colour flag.
  for (let at = 13; at + 3 < b.length; at++) {
    if (b[at] === 0x21 && b[at + 1] === 0xf9 && b[at + 2] === 0x04) {
      info.transparent = (b[at + 3] & 1) === 1
      break
    }
  }
  return info
}

function jpeg(b: Uint8Array): ImageInfo {
  const info: ImageInfo = { format: 'jpeg', transparent: false }
  for (let at = 2; at + 9 < b.length;) {
    if (b[at] !== 0xff) break
    const marker = b[at + 1]
    if (marker === 0xff) { at++; continue }
    // SOF0–SOF15, except DHT (C4), JPG (C8) and DAC (CC).
    if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
      info.height = be16(b, at + 5)
      info.width = be16(b, at + 7)
      break
    }
    at += 2 + be16(b, at + 2)
  }
  return info
}

function webp(b: Uint8Array): ImageInfo {
  const info: ImageInfo = { format: 'webp' }
  const chunk = ascii(b, 12, 4)
  if (chunk === 'VP8X' && b.length >= 30) {
    info.transparent = (b[20] & 0x10) !== 0
    info.width = le24(b, 24) + 1
    info.height = le24(b, 27) + 1
  } else if (chunk === 'VP8L' && b.length >= 25) {
    const bits = b[21] | (b[22] << 8) | (b[23] << 16) | (b[24] << 24)
    info.width = (bits & 0x3fff) + 1
    info.height = ((bits >>> 14) & 0x3fff) + 1
    info.transparent = ((bits >>> 28) & 1) === 1
  } else if (chunk === 'VP8 ' && b.length >= 30) {
    info.width = le16(b, 26) & 0x3fff
    info.height = le16(b, 28) & 0x3fff
    info.transparent = false
  }
  return info
}

function avif(b: Uint8Array): ImageInfo {
  // The first image spatial extents property: version/flags, then width and height.
  const info: ImageInfo = { format: 'avif' }
  const end = Math.min(b.length, 64 * 1024)
  for (let at = 4; at + 16 <= end; at++) {
    if (b[at] === 0x69 && ascii(b, at, 4) === 'ispe') {
      info.width = be32(b, at + 8)
      info.height = be32(b, at + 12)
      break
    }
  }
  return info
}

function ico(b: Uint8Array): ImageInfo {
  // The first directory entry; 0 stands for 256.
  return { format: 'ico', width: b[6] || 256, height: b[7] || 256 }
}

function bmp(b: Uint8Array): ImageInfo {
  return { format: 'bmp', width: Math.abs(le32s(b, 18)), height: Math.abs(le32s(b, 22)), transparent: false }
}

const SVG_ROOT = /^(?:﻿)?\s*(?:<\?xml[^>]*\?>\s*)?(?:<!--[\s\S]*?-->\s*|<!DOCTYPE[^>]*>\s*)*<svg[\s>]/i
const number = (v: string | null) => (v && /^\s*[\d.]+\s*(px)?\s*$/.test(v) ? parseFloat(v) : undefined)

/** SVG: textual bytes that parse as XML with an <svg> root; its size from width and height,
 *  else the viewBox. */
export function svgInfo(text: string): ImageInfo | null {
  if (!SVG_ROOT.test(text)) return null
  const doc = new DOMParser().parseFromString(text, 'image/svg+xml')
  const root = doc.documentElement
  if (root.localName !== 'svg' || doc.getElementsByTagName('parsererror').length) return null
  const box = (root.getAttribute('viewBox') ?? '').trim().split(/[\s,]+/).map(Number)
  const [vw, vh] = box.length === 4 && box.every(Number.isFinite) ? [box[2], box[3]] : []
  return { format: 'svg', width: number(root.getAttribute('width')) ?? vw, height: number(root.getAttribute('height')) ?? vh }
}

export function sniffImage(b: Uint8Array, text?: string): ImageInfo | null {
  if (b.length < 12) return null
  if (b[0] === 0x89 && ascii(b, 1, 3) === 'PNG' && b[4] === 0x0d && b[5] === 0x0a) return png(b)
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return jpeg(b)
  if (ascii(b, 0, 6) === 'GIF87a' || ascii(b, 0, 6) === 'GIF89a') return gif(b)
  if (ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 4) === 'WEBP') return webp(b)
  if (ascii(b, 4, 4) === 'ftyp' && /^avi[fs]$/.test(ascii(b, 8, 4))) return avif(b)
  if (b[0] === 0 && b[1] === 0 && b[2] === 1 && b[3] === 0 && le16(b, 4) > 0) return ico(b)
  if (ascii(b, 0, 2) === 'BM' && b.length >= 26 && le32s(b, 2) <= b.length * 2) return bmp(b)
  return text !== undefined ? svgInfo(text) : null
}

/** The format a Content-Type names, or the bare type when it names none of ours. */
export function declaredImage(contentType?: string): ImageFormat | string | undefined {
  const t = contentType?.split(';')[0].trim().toLowerCase()
  if (!t) return undefined
  return (Object.entries(IMAGE_MIME).find(([, m]) => m === t)?.[0] as ImageFormat | undefined) ?? ALIASES[t] ?? t
}

/** The amber note's type when the Content-Type names something other than the bytes. */
export function sentAs(info: ImageInfo | null, contentType?: string): string | undefined {
  const declared = declaredImage(contentType)
  if (!declared) return undefined
  if (info) return declared === info.format ? undefined : contentType!.split(';')[0].trim()
  return declared.startsWith('image/') || declared in IMAGE_MIME ? contentType!.split(';')[0].trim() : undefined
}

/** Why an image is not drawn, or null when it may be. */
export function tooLarge(info: ImageInfo, size: number): string | null {
  if (size > IMAGE_MAX_BYTES) return 'over 5 MiB'
  if ((info.width ?? 0) > IMAGE_MAX_SIDE || (info.height ?? 0) > IMAGE_MAX_SIDE) return `${info.width} × ${info.height} px, over ${IMAGE_MAX_SIDE.toLocaleString('en-US')} a side`
  return null
}
