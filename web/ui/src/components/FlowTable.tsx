import { useVirtualizer } from '@tanstack/react-virtual'
import { Check } from 'lucide-react'
import { memo, useEffect, useLayoutEffect, useRef } from 'react'
import { useCatalog, userTags } from '../lib/catalog'
import { durationTone, formatTime, num, shortProto, type Tone } from '../lib/format'
import type { Flow, Tag, Group } from '../lib/types'
import { EDGE_ROWS } from '../lib/window'
import { Button, cx, DurationBadge, MethodBadge, Spinner, StatusBadge } from './ui'

export interface Column { id: string; label: string; width: number | null; default: boolean }
export const COLUMNS: Column[] = [
  { id: 'flags', label: 'Flags', width: 62, default: true }, { id: 'time', label: 'Time', width: 116, default: true },
  { id: 'method', label: 'Method', width: 68, default: true }, { id: 'status', label: 'Status', width: 60, default: true },
  { id: 'duration', label: 'Dur', width: 56, default: true }, { id: 'protocol', label: 'Proto', width: 56, default: true },
  { id: 'authority', label: 'Authority', width: 200, default: true }, { id: 'path', label: 'Path', width: null, default: true },
  { id: 'conn', label: 'Conn', width: 90, default: false }, { id: 'stream', label: 'Stream', width: 70, default: false },
]

interface FlagItem { glyph: string; title: string; tone: string }

// Fixed order, packed from the left; selection and mark aren't flags because the row shows them.
export function flagsOf(f: Flow, tags: Map<string, Tag>, groups: Map<string, Group>): FlagItem[] {
  const out: FlagItem[] = []
  if (f.websocket) out.push({ glyph: '⇅', title: `WebSocket — ${num(f.messageCount)} messages`, tone: 'text-blue-fg' })
  if (f.redirectLocation) out.push({ glyph: '↪', title: `Redirects to ${f.redirectLocation}`, tone: 'text-blue-fg' })
  else if (f.redirectedFromId) out.push({ glyph: '↪', title: 'Arrived here via a redirect', tone: 'text-blue-fg' })
  if (f.favorite) out.push({ glyph: '★', title: 'Favorite', tone: 'text-amber-fg' })
  if (f.proxy?.addr) out.push({ glyph: '⇄', title: `Through proxy ${f.proxy.addr}`, tone: 'text-muted' })
  const ts = userTags(f.tagIds)
  if (ts.length) out.push({ glyph: '#', title: ts.map((id) => tags.get(id)?.name ?? id).join(', '), tone: 'text-purple-fg' })
  if (f.comments?.length) out.push({ glyph: '✎', title: f.comments.map((c) => c.body).join('\n'), tone: 'text-muted' })
  if (f.groupIds?.length) out.push({ glyph: '⬡', title: f.groupIds.map((id) => groups.get(id)?.name ?? id).join(', '), tone: 'text-cyan-fg' })
  return out
}

function Flags({ flow }: { flow: Flow }) {
  const { tags, groups } = useCatalog()
  const items = flagsOf(flow, tags, groups)
  const shown = items.length > 3 ? items.slice(0, 2) : items
  const rest = items.length > 3 ? items.slice(2) : []
  return (
    <span className="flex items-center gap-1.5 font-mono text-xs">
      {shown.map((f) => <span key={f.glyph} title={f.title} className={f.tone}>{f.glyph}{f.glyph === '⇅' && flow.messageCount ? <span className="text-[10px] ml-0.5">{num(flow.messageCount)}</span> : null}</span>)}
      {rest.length > 0 && <span className="text-muted" title={rest.map((f) => f.title).join('\n')}>⋯</span>}
    </span>
  )
}

function Rail({ flow }: { flow: Flow }) {
  const tone: Tone | null = durationTone(num(flow.durationMicros))
  return <span aria-hidden className="absolute right-0 top-[3px] bottom-[3px] w-0.5" style={{ background: `var(--${tone ?? 'grey'})` }} />
}

interface RowProps {
  flow: Flow; columns: Column[]; selected: boolean; picked: boolean; flash: boolean; zebra: boolean
  onSelect: (id: string) => void; onPick: (f: Flow) => void
}

const cellStyle = (c: Column) => (c.width === null ? { flex: 1, minWidth: 0 } : { width: c.width, flexShrink: 0 })

function Cell({ c, f }: { c: Column; f: Flow }) {
  switch (c.id) {
    case 'flags': return <Flags flow={f} />
    case 'time': return <span className="text-muted">{formatTime(num(f.tsUnixMicros))}</span>
    case 'method': return <MethodBadge method={f.method} />
    case 'status': return <StatusBadge status={f.status} error={f.error} />
    case 'duration': return <DurationBadge micros={f.durationMicros} />
    case 'protocol': return <span title={f.protocol} className={cx('block truncate', f.protocol?.startsWith('HTTP') ? 'text-muted' : 'text-purple-fg')}>{shortProto(f.protocol)}</span>
    case 'authority': return <span title={f.authority} className="block truncate text-body">{f.authority}</span>
    case 'path': return <span title={`${f.path ?? ''}${f.query ? `?${f.query}` : ''}`} className="block truncate text-ink">{f.path}{f.query && <span className="text-faint">?{f.query}</span>}</span>
    case 'conn': return <span title={f.connectionId} className="block truncate text-muted">{f.connectionId}</span>
    case 'stream': return <span className="block text-right text-muted">{f.streamId}</span>
  }
  return null
}

const Row = memo(function Row({ flow: f, columns, selected, picked, flash, zebra, onSelect, onPick }: RowProps) {
  const mark = f.markColor
  return (
    <div role="row" aria-selected={selected} onClick={() => onSelect(f.id)}
      className={cx('relative flex items-center h-full pl-3 pr-3 gap-0 font-mono text-xs cursor-default', flash && 'row-new', mark && `mark-${mark} tint [--a:10%]`,
        !mark && selected && 'tone-blue tint [--a:12%]', !mark && !selected && (zebra ? 'bg-panel hover:bg-rowhover' : 'hover:bg-rowhover'))}>
      {(mark || selected) && <span aria-hidden className="absolute left-0 inset-y-0 w-1" style={{ background: 'var(--t)' }} />}
      <button type="button" role="checkbox" aria-checked={picked} aria-label="Pick for compare" onClick={(e) => { e.stopPropagation(); onPick(f) }}
        className={cx('flex items-center justify-center w-4 h-4 rounded border shrink-0 mr-2', picked ? 'bg-green border-green text-onsolid' : 'border-edge-check')}>
        {picked && <Check size={12} strokeWidth={3} />}
      </button>
      {columns.map((c) => <div key={c.id} style={cellStyle(c)} className="pr-2"><Cell c={c} f={f} /></div>)}
      <Rail flow={f} />
    </div>
  )
})


interface Props {
  rows: Flow[]; columns: Column[]; selected: string | null; picks: Set<string>; flashed: ReadonlySet<string>
  compact: boolean; hasOlder: boolean; hasNewer: boolean; loading: boolean; filtered: boolean; follow: boolean
  active: boolean; scrollTo: { kind: 'bottom' | 'top' | 'delta'; delta?: number; seq: number }
  onSelect: (id: string) => void; onPick: (f: Flow) => void; onExtend: (dir: 'older' | 'newer') => void; onClearFilter: () => void
}

export function FlowTable({ rows, columns, selected, picks, flashed, compact, hasOlder, hasNewer, loading, filtered, follow, active, scrollTo, onSelect, onPick, onExtend, onClearFilter }: Props) {
  const scroller = useRef<HTMLDivElement>(null)
  const rowHeight = compact ? 30 : 44
  const virtual = useVirtualizer({ count: rows.length, getScrollElement: () => scroller.current, estimateSize: () => rowHeight, overscan: 12 })
  useEffect(() => { virtual.measure() }, [rowHeight, virtual])

  // Before paint, so the rows under the reader don't move when rows change above them.
  const applied = useRef(0)
  useLayoutEffect(() => {
    if (scrollTo.seq === applied.current || !scroller.current) return
    applied.current = scrollTo.seq
    const el = scroller.current
    if (scrollTo.kind === 'bottom') el.scrollTop = el.scrollHeight
    else if (scrollTo.kind === 'top') el.scrollTop = 0
    else el.scrollTop += (scrollTo.delta ?? 0) * rowHeight
  }, [scrollTo, rowHeight])

  // Only when already at the bottom: reading back is never fought.
  const atBottom = useRef(true)
  const prevLast = useRef<string | undefined>(undefined)
  const last = rows[rows.length - 1]?.id
  useLayoutEffect(() => {
    if (last !== prevLast.current && follow && atBottom.current && scroller.current) scroller.current.scrollTop = scroller.current.scrollHeight
    prevLast.current = last
  }, [last, follow, rows.length])

  // A hidden tab has zero height; re-measure on return or it renders no rows.
  useEffect(() => { if (active) virtual.measure() }, [active, virtual])

  const items = virtual.getVirtualItems()
  const first = items[0]?.index
  const lastIndex = items[items.length - 1]?.index
  useEffect(() => {
    if (first === undefined || !active) return
    if (first <= EDGE_ROWS && hasOlder) onExtend('older')
    else if (lastIndex >= rows.length - 1 - EDGE_ROWS && hasNewer) onExtend('newer')
  }, [first, lastIndex, rows.length, hasOlder, hasNewer, active, onExtend])

  useEffect(() => {
    if (!selected) return
    const i = rows.findIndex((r) => r.id === selected)
    if (i >= 0) virtual.scrollToIndex(i, { align: 'auto' })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected])

  return (
    <div className="flex flex-col flex-1 min-w-0 min-h-0" role="table" aria-label="Flows">
      <div role="row" className="flex items-center h-8 pl-3 pr-3 shrink-0 bg-head border-b border-line text-[11px] font-medium text-muted">
        <span className="w-6 shrink-0" />
        {columns.map((c) => <div key={c.id} style={cellStyle(c)} className={cx('pr-2', c.id === 'stream' && 'text-right')}>{c.label}</div>)}
      </div>
      <div ref={scroller} className="flex-1 min-h-0 overflow-y-auto overflow-x-hidden relative" onScroll={(e) => {
        const el = e.currentTarget
        atBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < rowHeight * 2
      }}>
        {rows.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-muted">
            {loading ? <Spinner size={20} /> : filtered ? <><span>No flows match this filter</span><Button size="sm" onClick={onClearFilter}>Clear filter</Button></> : <span>No flows yet</span>}
          </div>
        ) : (
          <div style={{ height: virtual.getTotalSize(), position: 'relative' }}>
            {items.map((v) => {
              const f = rows[v.index]
              return (
                <div key={f.id} style={{ position: 'absolute', top: 0, left: 0, right: 0, height: rowHeight, transform: `translateY(${v.start}px)` }}>
                  <Row flow={f} columns={columns} selected={f.id === selected} picked={picks.has(f.id)} flash={flashed.has(f.id)} zebra={v.index % 2 === 1} onSelect={onSelect} onPick={onPick} />
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

