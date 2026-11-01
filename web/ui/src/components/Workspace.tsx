import { ArrowDown, ArrowLeft, ArrowUp, Columns3, Eye, PanelRightClose, RefreshCw, Settings as Gear, Square, Star, X } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import * as api from '../lib/api'
import { dropTerm, FLOW_EXAMPLES, halfTyped, FLOW_TERMS, parseFilter, readStatus, readTerm, STATUS_OPTIONS, termLabel, writeStatus, writeTerm } from '../lib/filter'
import { fitWidth, formatMatched } from '../lib/format'
import { declaredColumns } from '../lib/sessions'
import { useSetting } from '../lib/settings'
import type { DecodeProgress, Flow, Session } from '../lib/types'
import { useFlowWindow } from '../lib/useFlowWindow'
import { MAX_ROWS } from '../lib/window'
import { MARKS, DetailsPanel } from './Details'
import { FilterInput } from './FilterInput'
import { Check, Popover, ResetColumns } from './Columns'
import { FlowTable, tableColumns, type Column } from './FlowTable'
import { Button, cx, IconButton, Pill } from './ui'

export const isLive = (s?: Session) => s?.status === 'SESSION_STATUS_OPEN' || s?.status === 'SESSION_STATUS_DECODING'

export interface Pick { session: string; sessionLabel: string; id: string; label: string }

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE']
const TYPES: [string, string][] = [['JSON', 'json'], ['HTML', 'html'], ['JavaScript', 'javascript'], ['CSS', 'css'], ['Image', 'image/'], ['Font', 'font'], ['XML', 'xml']]

function FilterSelect({ label, value, options, onChange }: { label: string; value: string; options: [string, string][]; onChange: (v: string) => void }) {
  return (
    <select aria-label={label} value={value} onChange={(e) => onChange(e.target.value)}
      className={cx('td-select h-8 pl-3 pr-6 rounded-md border text-xs', value ? 'tone-blue tint border-accent' : 'bg-raised border-edge text-body')}>
      <option value="">{label}</option>
      {options.map(([l, v]) => <option key={v} value={v}>{l}</option>)}
    </select>
  )
}

interface Props {
  session: Session
  active: boolean
  picks: Pick[]
  onBack: () => void
  onTogglePick: (p: Pick) => void
  onCompare: () => void
  onClearPicks: () => void
  onDecoder: (initial?: string) => void
  onOpenMessages: (session: string, flow: Flow) => void
  onSessionsChanged: () => void
  onStuck: (id: string, stuck: boolean) => void
}

export function Workspace({ session, active, picks, onBack, onTogglePick, onCompare, onClearPicks, onDecoder, onOpenMessages, onSessionsChanged, onStuck }: Props) {
  const id = session.id
  const [text, setText] = useState('')
  const [filter, setFilter] = useState('')
  useEffect(() => {
    if (halfTyped(text)) return
    const t = setTimeout(() => setFilter(text), 350)
    return () => clearTimeout(t)
  }, [text])

  const [closed, setClosed] = useState(false)
  const live = isLive(session) && !closed
  const [follow, setFollow] = useState(live)
  const [progress, setProgress] = useState<DecodeProgress | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [stopError, setStopError] = useState('')
  // Stable: a table row is memoized.
  const openMessages = useCallback((f: Flow) => onOpenMessages(id, f), [onOpenMessages, id])
  const onClosed = useCallback(() => {
    setClosed(true)
    onSessionsChanged()
  }, [onSessionsChanged])
  const [showHidden, setShowHidden] = useSetting('showHidden')
  const win = useFlowWindow({ session: id, filter, hidden: showHidden, live, follow, onClosed, onProgress: setProgress })
  const { rows, refill, extend, patchRow } = win

  const [compact, setCompact] = useSetting('compact')
  const [overrides, setOverrides] = useSetting('columnOverrides')
  const [detailsWidth, setDetailsWidth] = useSetting('detailsWidth')
  const [collapsed, setCollapsed] = useSetting('detailsCollapsed')

  const [widths, setWidths] = useSetting('columnWidths')
  const declared = useMemo(() => declaredColumns(session), [session])
  // Sized once rows arrive and not again, so a column doesn't change width as the window moves.
  const [sample, setSample] = useState<Flow[]>([])
  if (!sample.length && rows.length) setSample(rows.slice(0, 200))
  const allColumns = useMemo(() => tableColumns(declared, (k) => fitWidth(k, sample.map((r) => r.metadata?.[k] ?? ''))), [declared, sample])
  const visible = useCallback((c: Column) => overrides[c.id] ?? c.default, [overrides])
  const columns = useMemo(() => allColumns.filter(visible).map((c) => (c.width === null ? c : { ...c, width: widths[c.id] ?? c.width })), [allColumns, visible, widths])
  const setWidth = useCallback((id: string, width: number | null) => setWidths(({ [id]: _, ...rest }) => (width === null ? rest : { ...rest, [id]: width })), [setWidths])

  const flow = useMemo(() => rows.find((r) => r.id === selected), [rows, selected])
  const pickedHere = useMemo(() => new Set(picks.filter((p) => p.session === id).map((p) => p.id)), [picks, id])
  const togglePick = useCallback((f: Flow) => {
    onTogglePick({ session: id, sessionLabel: session.label || id, id: f.id, label: `${f.method ?? ''} ${f.authority ?? ''} ${f.path ?? ''}`.trim() })
  }, [id, session.label, onTogglePick])

  const jumpEnd = () => {
    setFollow(live)
    void refill('last')
  }
  const jumpStart = () => {
    setFollow(false)
    void refill('first')
  }
  const toggleFollow = () => {
    const on = !follow
    setFollow(on)
    if (on) void refill('last')
  }
  const stop = async () => {
    try {
      await api.stopCapture(id)
      setStopError('')
      onStuck(id, false)
      onSessionsChanged()
    } catch (e) {
      setStopError((e as Error).message)
      onStuck(id, true)
    }
  }

  // Keyboard, for the visible tab only and never while typing.
  const rowsRef = useRef(rows)
  rowsRef.current = rows
  useEffect(() => {
    if (!active) return
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement
      if (t.closest('input, textarea, select, [contenteditable]')) return
      const list = rowsRef.current
      const at = list.findIndex((r) => r.id === selected)
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault()
        const next = at + (e.key === 'ArrowDown' ? 1 : -1)
        if (next >= 0 && next < list.length) setSelected(list[next].id)
        else void extend(next < 0 ? 'older' : 'newer')
      } else if (e.key === 'Home' && list.length) {
        e.preventDefault()
        setSelected(list[0].id)
      } else if (e.key === 'End' && list.length) {
        e.preventDefault()
        setSelected(list[list.length - 1].id)
      } else if (e.key === 'Escape') setSelected(null)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [active, selected, extend])

  const split = useRef<HTMLDivElement>(null)
  const startDrag = (e: React.MouseEvent) => {
    e.preventDefault()
    const body = document.body.style
    body.cursor = 'col-resize'
    body.userSelect = 'none'
    const move = (ev: MouseEvent) => {
      const r = split.current!.getBoundingClientRect()
      setDetailsWidth(Math.min(80, Math.max(20, Math.round(((r.right - ev.clientX) / r.width) * 100))))
    }
    const up = () => {
      body.cursor = ''
      body.userSelect = ''
      document.removeEventListener('mousemove', move)
      document.removeEventListener('mouseup', up)
    }
    document.addEventListener('mousemove', move)
    document.addEventListener('mouseup', up)
  }

  const terms = parseFilter(text)
  const statusLabel = readStatus(text)
  const showDetails = !collapsed
  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-2.5 h-[52px] px-3 shrink-0 border-b border-line">
        <IconButton label="Back to sessions" className="border border-edge" onClick={onBack}><ArrowLeft size={15} /></IconButton>
        <div className="min-w-0 max-w-52">
          <div className="text-[13px] font-semibold text-ink truncate">{session.label || id.slice(0, 8)}</div>
          <div className="font-mono text-[10px] text-faint truncate">{id}</div>
        </div>
        {live && <Pill tone="green" dot>Live</Pill>}
        {live && <Button variant="danger" icon={<Square size={9} fill="currentColor" />} onClick={() => void stop()} title={stopError}>Stop</Button>}
        <FilterInput value={text} onChange={setText} terms={FLOW_TERMS} examples={FLOW_EXAMPLES} placeholder="~d example.test !~t image" />
        <span className="shrink-0 text-xs text-muted" data-tooltip="Capped by the gateway's scan cap when shown as N+"><span className="font-mono font-medium text-ink">{formatMatched(win.matched, win.capped)}</span> matching</span>
        <Button variant={follow ? 'active' : 'default'} aria-pressed={follow} icon={<ArrowDown size={13} />} onClick={toggleFollow}>Follow</Button>
        <Button disabled={picks.length !== 2} onClick={onCompare}>Compare <span className="px-1.5 rounded tint tone-green font-mono text-[11px]">{picks.length}/2</span></Button>
        {picks.length > 0 && <IconButton label="Clear picks" size={22} onClick={onClearPicks}><X size={12} /></IconButton>}
        <IconButton label="Refetch" className="border border-edge" onClick={() => void refill(follow ? 'last' : 'first')}><RefreshCw size={14} /></IconButton>
        <Button onMouseDown={(e) => e.preventDefault()} onClick={() => onDecoder(getSelection()?.toString().slice(0, 20000))} className="font-mono" icon={<span>{'{ }'}</span>}><span className="font-sans">Decoder</span></Button>
        <Popover label="Settings" icon={<Gear size={14} />}><Check label="Compact rows" checked={compact} onChange={setCompact} /></Popover>
        <Popover label="Columns" icon={<Columns3 size={14} />}>
          {allColumns.map((c) => <Check key={c.id} label={c.label} checked={visible(c)} onChange={(v) => setOverrides((o) => ({ ...o, [c.id]: v }))} />)}
          <ResetColumns onReset={() => { setOverrides({}); setWidths({}) }} />
        </Popover>
      </div>
      <div className="flex items-center gap-2 h-10 px-3 shrink-0 border-b border-line">
        <FilterSelect label="Method" value={readTerm(text, '~m') ?? ''} options={METHODS.map((m) => [m, m])} onChange={(v) => setText(writeTerm(text, '~m', v || null))} />
        <FilterSelect label="Type" value={readTerm(text, '~t') ?? ''} options={TYPES} onChange={(v) => setText(writeTerm(text, '~t', v || null))} />
        <FilterSelect label="Mark" value={readTerm(text, '~mark') ?? ''} options={MARKS.map((m) => [m, m])} onChange={(v) => setText(writeTerm(text, '~mark', v || null))} />
        <FilterSelect label="Status" value={statusLabel} options={STATUS_OPTIONS.map((o) => [o.label, o.label])} onChange={(v) => setText(writeStatus(text, v))} />
        <Button variant={readTerm(text, '~fav') !== null ? 'active' : 'default'} icon={<Star size={13} />} onClick={() => setText(writeTerm(text, '~fav', readTerm(text, '~fav') !== null ? null : ''))}>Favorites</Button>
        <Button variant={showHidden ? 'active' : 'default'} aria-pressed={showHidden} icon={<Eye size={13} />} title="DNS lookups and connections nothing decoded" onClick={() => setShowHidden(!showHidden)}>
          Hidden{win.hiddenMatched > 0 && <span className="font-mono text-[11px] text-faint">{formatMatched(win.hiddenMatched, win.capped)}</span>}
        </Button>
        <Button variant="ghost" onClick={() => setText('')}>Reset</Button>
        <span className="flex-1" />
        <span className="text-[11px] text-faint">Details</span>
        <span className="inline-flex h-8 rounded-md border border-edge overflow-hidden">
          {[30, 40, 50].map((w) => (
            <button key={w} type="button" onClick={() => { setDetailsWidth(w); setCollapsed(false) }} className={cx('px-3 font-mono text-[11px]', detailsWidth === w && !collapsed ? 'bg-sel text-ink' : 'text-muted')}>{w}%</button>
          ))}
        </span>
        <IconButton label={collapsed ? 'Show details' : 'Collapse details'} className="border border-edge" onClick={() => setCollapsed(!collapsed)}><PanelRightClose size={14} /></IconButton>
      </div>
      {terms.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 min-h-[34px] px-3 py-1 shrink-0 border-b border-line">
          {terms.map((t, i) => (
            <span key={i} className="inline-flex items-center gap-1.5 h-6 pl-2.5 pr-1.5 rounded-full bg-raised border border-edge text-[11px] text-muted">
              <span className="font-mono text-body">{termLabel(t)}</span>
              <button type="button" aria-label={`Remove ${termLabel(t)}`} onClick={() => setText(dropTerm(text, i))} className="hover:text-ink"><X size={11} /></button>
            </span>
          ))}
        </div>
      )}
      {progress && <div className="h-0.5 shrink-0 bg-line" title={progress.stage}><div className="h-full bg-accent" style={{ width: `${progress.percent ?? 0}%` }} /></div>}
      {win.hints.map((h, i) => <div key={i} className="px-3 py-1 shrink-0 tint tone-amber text-[11px]">{h}</div>)}
      {win.error && <div className="px-3 py-1 shrink-0 tint tone-red text-[11px]">{win.error}</div>}
      {stopError && <div className="px-3 py-1 shrink-0 tint tone-red text-[11px]">Stop failed: {stopError}. Force close is on the Sessions screen.</div>}
      <div ref={split} className="flex flex-1 min-h-0">
        <FlowTable rows={rows} columns={columns} selected={selected} picks={pickedHere} flashed={win.flashed} compact={compact} hasOlder={win.hasOlder} hasNewer={win.hasNewer}
          loading={win.loading} filtered={!!filter} follow={follow} active={active} scrollTo={win.scrollTo} onSelect={setSelected} onPick={togglePick} onOpenMessages={openMessages} onExtend={extend} onClearFilter={() => setText('')} onColumnWidth={setWidth} />
        {showDetails && <>
          <div role="separator" aria-orientation="vertical" onMouseDown={startDrag} className="w-[5px] shrink-0 cursor-col-resize bg-head hover:bg-accent" />
          <div className="shrink-0 min-w-0" style={{ width: `${detailsWidth}%` }}>
            {flow ? <DetailsPanel key={flow.id} session={id} summary={flow} onClose={() => setSelected(null)} onPatch={patchRow} onDecode={onDecoder} onOpenMessages={openMessages} />
              : <div className="flex items-center justify-center h-full bg-panel text-muted">Select a flow</div>}
          </div>
        </>}
      </div>
      <div className="flex items-center gap-3 h-7 px-3 shrink-0 border-t border-line bg-chrome font-mono text-[11px] text-muted">
        <span>showing {rows.length.toLocaleString('en-US')} of {formatMatched(win.matched, win.capped)}</span>
        {follow && <span className="text-blue-fg">⇣ follow</span>}
        {win.pending > 0 && <button type="button" onClick={jumpEnd} className="h-[18px] px-2 rounded-full bg-primary text-white font-sans font-semibold text-[10px]">{win.pending} new</button>}
        <span className="flex-1" />
        <button type="button" onClick={jumpStart} className="inline-flex items-center gap-1 hover:text-ink"><ArrowUp size={11} />first</button>
        <button type="button" onClick={jumpEnd} className="inline-flex items-center gap-1 hover:text-ink"><ArrowDown size={11} />last</button>
        <span className="text-faint">buffer {MAX_ROWS}</span>
      </div>
    </div>
  )
}
