import { useEffect, useRef, useState } from 'react'
import { scaleNow, rem } from '../lib/scale'
import { Button, cx } from './ui'

const MIN_COLUMN = 36
const MAX_COLUMN = 800
const MIN_STRETCH = 80

// Widths are layout px (lib/scale), so a saved width keeps its meaning at any text size.
export const columnStyle = (width: number | null) => (width === null ? { flex: 1, minWidth: 0 } : { width: rem(width), flexShrink: 0 })

export function HeaderCell({ label, title, width, className, onResize, onReset }: {
  label: string; title?: string; width: number | null; className?: string; onResize: (width: number) => void; onReset: () => void
}) {
  const startDrag = (e: React.PointerEvent<HTMLSpanElement>) => {
    e.preventDefault()
    const handle = e.currentTarget
    handle.setPointerCapture(e.pointerId)
    const startX = e.clientX
    // The DOM measures in real px; widths are stored in layout px.
    const scale = scaleNow()
    const startWidth = handle.parentElement!.offsetWidth / scale
    // The stretching column pays for a wider one, and stops paying while it is still readable.
    const stretch = handle.closest('[role=row]')?.querySelector<HTMLElement>('[data-stretch]')
    const max = stretch ? startWidth + Math.max(0, stretch.offsetWidth / scale - MIN_STRETCH) : MAX_COLUMN
    const move = (ev: PointerEvent) => onResize(Math.min(max, Math.max(MIN_COLUMN, Math.round(startWidth + (ev.clientX - startX) / scale))))
    const up = () => {
      handle.removeEventListener('pointermove', move)
      handle.removeEventListener('pointerup', up)
      handle.removeEventListener('pointercancel', up)
    }
    handle.addEventListener('pointermove', move)
    handle.addEventListener('pointerup', up)
    handle.addEventListener('pointercancel', up)
  }
  return (
    <div data-stretch={width === null ? '' : undefined} style={columnStyle(width)} title={title} className={cx('relative self-stretch leading-8 truncate pr-2', className)}>
      {label}
      {width !== null && (
        <span aria-hidden title="Drag to resize, double-click to reset" onPointerDown={startDrag} onDoubleClick={onReset}
          className="group/handle absolute top-0 bottom-0 right-0 w-2 flex justify-end cursor-col-resize touch-none">
          <span className="my-2 w-px bg-edge-strong group-hover/handle:w-0.5 group-hover/handle:bg-accent" />
        </span>
      )}
    </div>
  )
}

export function Popover({ label, icon, small, children }: { label: string; icon: React.ReactNode; small?: boolean; children: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const close = (e: Event) => { if (!root.current?.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', close)
    // Tabbing away too: one popover at a time, and the filter's help opens on focus.
    document.addEventListener('focusin', close)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('focusin', close)
    }
  }, [open])
  return (
    <div ref={root} className="relative">
      <Button aria-label={label} aria-expanded={open} title={label} size={small ? 'sm' : 'md'} onClick={() => setOpen(!open)} className="px-2!">{icon}</Button>
      {/* A child that opens a dialog says so, or this stays open behind the scrim. */}
      {open && <div onClick={(e) => { if ((e.target as Element).closest('[data-closes-popover]')) setOpen(false) }} className="absolute z-30 right-0 top-[calc(100%+6px)] w-48 max-h-96 overflow-auto p-2 rounded-lg border border-edge bg-toast text-12 text-body space-y-1.5" style={{ boxShadow: '0 8px 24px var(--shadow)' }}>{children}</div>}
    </div>
  )
}

export const Check = ({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) => (
  <label className="flex items-center gap-2 cursor-pointer"><input type="checkbox" className="accent-[var(--accent)]" checked={checked} onChange={(e) => onChange(e.target.checked)} /><span className="truncate" title={label}>{label}</span></label>
)

export const ResetColumns = ({ onReset }: { onReset: () => void }) => (
  <button type="button" onClick={onReset} className="w-full pt-1.5 border-t border-line text-left text-muted hover:text-ink">Reset columns</button>
)
