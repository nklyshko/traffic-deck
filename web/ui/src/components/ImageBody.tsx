import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import { IMAGE_MIME, tooLarge, type ImageInfo } from '../lib/image'
import { useScale } from '../lib/scale'
import { Badge, cx } from './ui'

const MAX_H = 240
// The longer side a small image is enlarged to, by a whole factor: a tracking pixel must show.
const MIN_RASTER = 32
const MIN_SVG = 96

/** The amber note when the Content-Type names another type than the bytes are. */
export const SentAs = ({ type }: { type?: string }) => (type ? <Badge tone="amber" size="sm">≈ sent as {type}</Badge> : null)

export function Caption({ text, sentAs }: { text: string; sentAs?: string }) {
  return <div className="flex items-center gap-2 min-h-4.5 flex-wrap"><span className="font-mono text-10 text-faint">{text}</span><SentAs type={sentAs} /></div>
}

const sizeText = (w?: number, h?: number) => (w && h ? ` · ${w} × ${h}` : '')

/** The Image view of a Body card (§5.7.1). Drawn only by <img> from a blob URL, never inline: an
 *  SVG in <img> runs no scripts and loads nothing. */
export function ImageView({ bytes, info, sentAs, onBroken, saveButton }: {
  bytes: Uint8Array; info: ImageInfo; sentAs?: string; onBroken: () => void; saveButton: ReactNode
}) {
  const refused = tooLarge(info, bytes.length)
  const [url, setUrl] = useState<string | null>(null)
  useEffect(() => {
    if (refused) return
    const u = URL.createObjectURL(new Blob([bytes.slice()], { type: IMAGE_MIME[info.format] }))
    setUrl(u)
    return () => URL.revokeObjectURL(u)
  }, [bytes, info.format, refused])

  const stage = useRef<HTMLDivElement>(null)
  const [room, setRoom] = useState(0)
  useLayoutEffect(() => {
    const el = stage.current
    if (!el) return
    const measure = () => {
      const css = getComputedStyle(el)
      setRoom(el.clientWidth - parseFloat(css.paddingLeft) - parseFloat(css.paddingRight))
    }
    // Before paint as well: the observer reports a frame late, and the image would show at full size.
    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(el)
    return () => observer.disconnect()
  }, [refused])
  const scale = useScale()
  const [natural, setNatural] = useState<[number, number] | null>(null)

  if (refused) return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-center h-18 px-3 rounded-md bg-well text-12 text-muted text-center">Not shown: {refused}. Save it to view it in your image viewer.</div>
      <Caption text={`${info.format}${sizeText(info.width, info.height)} · read from its header`} sentAs={sentAs} />
      {saveButton}
    </div>
  )

  const svg = info.format === 'svg'
  const [w, h] = info.width && info.height ? [info.width, info.height] : natural ?? [0, 0]
  const longer = Math.max(w, h)
  const min = svg ? MIN_SVG : MIN_RASTER
  const factor = longer && longer < min ? Math.ceil(min / longer) : 1
  const fit = w && room ? Math.min(1, room / (w * factor), (MAX_H * scale) / (h * factor)) : 1
  const shown = [w * factor * fit, h * factor * fit]
  const ratio = (w * factor * fit) / (w || 1)
  const scaleText = !w ? '' : fit < 1 ? ` · fitted, ${Math.round(ratio * 100)}%` : factor > 1 ? ` · ×${factor}` : ' · 100%'
  const caption = `${info.format}${sizeText(w, h)}${info.transparent ? ' · transparent' : ''}${scaleText}${svg ? ' · drawn as an image: no scripts, nothing loaded' : ''}`
  return (
    <div className="space-y-1.5">
      <div ref={stage} className="flex items-center justify-center p-3 rounded-md bg-well">
        {url && (
          <img src={url} alt="" draggable={false} onError={onBroken}
            onLoad={(e) => setNatural([e.currentTarget.naturalWidth, e.currentTarget.naturalHeight])}
            // An enlarged image gets a dashed edge: a white tracking pixel on a light well is otherwise invisible.
            className={cx((svg || info.transparent) && 'checker', factor > 1 && !svg && '[image-rendering:pixelated] outline-1 outline-dashed outline-muted')}
            style={w ? { width: `${shown[0]}px`, height: `${shown[1]}px` } : { maxWidth: '100%', maxHeight: `${MAX_H * scale}px` }} />
        )}
      </div>
      <Caption text={caption} sentAs={sentAs} />
    </div>
  )
}
