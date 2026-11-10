import { useVirtualizer } from '@tanstack/react-virtual'
import { ArrowDown, Check as Tick, Columns3, MoveLeft, MoveRight, X } from 'lucide-react'
import { rem, useScale } from '../lib/scale'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import * as api from '../lib/api'
import { MESSAGE_EXAMPLES, MESSAGE_TERMS, readsAnnotations } from '../lib/filter'
import { fitWidth, formatBytes, formatTime, num } from '../lib/format'
import { base64Bytes, bodyExt, hexDump, looksTextual, saveBlob, HEX_CAP, TEXT_CAP } from '../lib/http'
import { NOTHING, select, type Selection } from '../lib/selection'
import { useSetting } from '../lib/settings'
import type { Flow, MessageEvent_, WsMessage } from '../lib/types'
import { patchFlow } from '../lib/window'
import { Check, columnStyle, HeaderCell, Popover, ResetColumns } from './Columns'
import { FilterInput } from './FilterInput'
import { JsonTree } from './Json'
import { AnnotationBar, NameValue, nameColumn, parseJson, type Annotated } from './Details'
import { Flags, FLAGS_WIDTH } from './FlowTable'
import type { Pick } from './Workspace'
import { Banner, Button, Card, CopyButton, cx, IconButton, Modal, Pill, Spinner } from './ui'

const FRAME_ROW = 30

function preview(m: WsMessage): string {
  const bytes = base64Bytes(m.payload?.inline)
  if (!bytes.length || !looksTextual(bytes)) return ''
  return new TextDecoder().decode(bytes.subarray(0, 800)).slice(0, 200).replace(/\r?\n/g, '⏎')
}

interface FrameColumn { id: string; label: string; width: number | null; meta?: string }

const FRAME_START: FrameColumn[] = [
  { id: 'flags', label: 'Flags', width: FLAGS_WIDTH }, { id: 'time', label: 'Time', width: 90 }, { id: 'dir', label: 'Dir', width: 30 },
  { id: 'opcode', label: 'Opcode', width: 56 }, { id: 'len', label: 'Len', width: 48 },
]
// Blue against neutral reads apart under any colour-vision deficiency, which cyan against purple
// did not, and leaves the warm hues to the binary opcode beside it.
const DIR_TONE = { client: 'text-blue-fg', server: 'text-body' }
const FRAME_END: FrameColumn = { id: 'preview', label: 'Preview', width: null }

function FrameCell({ c, m }: { c: FrameColumn; m: WsMessage }) {
  if (c.meta !== undefined) return <span className="block truncate" title={m.metadata?.[c.meta]}>{m.metadata?.[c.meta]}</span>
  switch (c.id) {
    case 'flags': return <Flags flow={m} />
    case 'time': return <span className="text-muted">{formatTime(num(m.tsUnixMicros))}</span>
    case 'dir': return m.fromClient
      ? <MoveRight size={rem(18)} strokeWidth={2.5} aria-label="client" className={cx('block', DIR_TONE.client)} />
      : <MoveLeft size={rem(18)} strokeWidth={2.5} aria-label="server" className={cx('block', DIR_TONE.server)} />
    case 'opcode': return <span className={cx('block truncate', m.opcode === 'binary' ? 'text-orange-fg' : 'text-body')}>{m.opcode}</span>
    case 'len': return <span className="text-muted">{formatBytes(num(m.payload?.size)) || '0B'}</span>
    case 'preview': return <span className="block truncate text-muted">{preview(m)}</span>
  }
  return null
}

function Payload({ session, message }: { session: string; message: WsMessage }) {
  const hasRaw = num(message.raw?.size) > 0
  const [raw, setRaw] = useState(false)
  const body = raw ? message.raw : message.payload
  const [bytes, setBytes] = useState<Uint8Array | null | undefined>(undefined)
  const [error, setError] = useState('')
  // By value: a re-read after an annotation brings a new but equal body, which must not refetch.
  const inline = body?.inline, size = num(body?.size)
  useEffect(() => {
    setBytes(undefined)
    setError('')
    if (inline) setBytes(base64Bytes(inline))
    else if (size) api.getMessageBody(session, message.id, raw).then(setBytes, (e: Error) => setError(e.message))
    else setBytes(null)
  }, [session, message.id, raw, inline, size])
  const textual = !!bytes && looksTextual(bytes)
  const text = useMemo(() => (textual && bytes ? new TextDecoder().decode(bytes) : ''), [bytes, textual])
  const json = useMemo(() => (text.length > TEXT_CAP ? undefined : parseJson(text)), [text])
  const ext = bodyExt(body?.contentType)
  const name = `${message.id}-${raw ? 'raw' : 'payload'}.${ext}`
  const save = () => bytes && saveBlob(name, bytes.slice())
  const capped = bytes ? (textual ? text.length - TEXT_CAP : bytes.length - HEX_CAP) : 0
  return (
    <>
      <div className="flex items-center gap-2 mb-3">
        <span className={cx('font-mono text-11 font-medium', message.fromClient ? DIR_TONE.client : DIR_TONE.server)}>{message.fromClient ? '→ client' : '← server'}</span>
        <span className="px-1.5 rounded bg-sel font-mono text-11 text-ink">{message.opcode}</span>
        <span className="font-mono text-11 text-faint">{formatTime(num(message.tsUnixMicros))} · {formatBytes(num(body?.size)) || '0B'}</span>
        <span className="flex-1" />
        {hasRaw && <span className="inline-flex rounded bg-well border border-line p-px text-11">
          {[false, true].map((v) => <button key={String(v)} type="button" onClick={() => setRaw(v)} className={cx('h-5 px-2 rounded-sm', raw === v ? 'bg-sel text-ink' : 'text-muted')}>{v ? 'raw' : 'payload'}</button>)}
        </span>}
        <Button size="xs" onClick={save} disabled={!bytes}>save</Button>
      </div>
      {message.metadata && Object.keys(message.metadata).length > 0 && (
        <div className="mb-3"><Card title="Metadata">
          <div style={nameColumn(Object.keys(message.metadata))}>{Object.entries(message.metadata).map(([k, v]) => <NameValue key={k} name={k} value={v} decode={false} />)}</div>
        </Card></div>
      )}
      <Card title={raw ? 'Raw' : 'Payload'} meta={body?.contentType} actions={text ? <CopyButton text={text} label="Copy" /> : undefined}>
        <div className="px-3 pb-1.5">
          {error ? <p className="text-11 text-red-fg">{error}</p> : bytes === undefined ? <Spinner />
            : !bytes?.length ? <p className="text-11 text-faint">Empty.</p>
              : json !== undefined ? <JsonTree value={json} />
                : <pre className="font-mono text-11 leading-4.5 text-body whitespace-pre-wrap break-all">{textual ? text.slice(0, TEXT_CAP) : hexDump(bytes, HEX_CAP)}</pre>}
          {capped > 0 && <button type="button" onClick={save} className="w-full h-7 mt-2 rounded border border-dashed border-edge-strong text-11 text-muted hover:text-ink">… {capped.toLocaleString('en-US')} more {textual ? 'characters' : 'bytes'} — save the whole payload as .{ext}</button>}
        </div>
      </Card>
    </>
  )
}

export function TimelineModal({ session, sessionLabel, flow, picks, onTogglePick, onCompare, onClearPicks, onClose }: {
  session: string; sessionLabel: string; flow: Flow; picks: Pick[]; onTogglePick: (p: Pick) => void; onCompare: () => void; onClearPicks: () => void; onClose: () => void
}) {
  const [text, setText] = useState('')
  const [filter, setFilter] = useState('')
  const [rows, setRows] = useState<WsMessage[]>([])
  const [hints, setHints] = useState<string[]>([])
  const [selection, setSelection] = useState<Selection>({ anchor: null, set: NOTHING })
  const selected = selection.anchor
  // Bumped to subscribe again with the same filter, when an annotation may change what matches.
  const [epoch, setEpoch] = useState(0)
  const [live, setLive] = useState(true)
  const [lost, setLost] = useState(false)
  const [follow, setFollow] = useState(true)
  const list = useRef<HTMLDivElement>(null)

  // During render, so no frame shows the old filter's rows under the new one.
  const [prev, setPrev] = useState(filter)
  if (prev !== filter) {
    setPrev(filter)
    setRows([])
    setHints([])
    setSelection({ anchor: null, set: NOTHING })
    setLive(true)
    setLost(false)
  }

  useEffect(() => {
    const source = new EventSource(api.messageStreamUrl(session, flow.id, filter))
    let buffer: WsMessage[] = []
    let timer: ReturnType<typeof setTimeout> | undefined
    const flush = () => {
      timer = undefined
      const batch = buffer
      buffer = []
      setRows((cur) => {
        const seen = new Set(cur.map((m) => m.id))
        const fresh = batch.filter((m) => !seen.has(m.id) && seen.add(m.id))
        return fresh.length ? [...cur, ...fresh] : cur
      })
    }
    source.onmessage = (e) => {
      const ev = JSON.parse(e.data) as MessageEvent_
      if (ev.messageAdded) {
        buffer.push(ev.messageAdded)
        timer ??= setTimeout(flush, 50)
      } else if (ev.filterHints) setHints(ev.filterHints.hints ?? [])
      else if (ev.sessionEvent) setLive(false)
    }
    // A session closed before subscribing sends no session event; `end` is the signal.
    source.addEventListener('end', () => {
      source.close()
      setLive(false)
    })
    source.addEventListener('error', () => {
      source.close()
      setLost(true)
      setLive(false)
    })
    return () => {
      source.close()
      clearTimeout(timer)
    }
  }, [session, flow.id, filter, epoch])

  useEffect(() => {
    if (follow && list.current) list.current.scrollTop = list.current.scrollHeight
    // On new frames only: an annotation patches a row in place and must not move the list.
  }, [rows.length, follow])

  const metaKeys = useMemo(() => [...new Set(rows.flatMap((m) => Object.keys(m.metadata ?? {})))].sort(), [rows])
  const [overrides, setOverrides] = useSetting('frameColumnOverrides')
  const [widths, setWidths] = useSetting('frameColumnWidths')
  const setWidth = useCallback((id: string, width: number | null) => setWidths(({ [id]: _, ...rest }) => (width === null ? rest : { ...rest, [id]: width })), [setWidths])
  const allColumns = useMemo(() => [
    ...FRAME_START,
    ...metaKeys.map((k) => ({ id: `meta:${k}`, label: k, meta: k, width: fitWidth(k, rows.map((m) => m.metadata?.[k] ?? '')) })),
    FRAME_END,
  ], [metaKeys, rows])
  const columns = useMemo(() => allColumns.filter((c) => overrides[c.id] ?? true).map((c) => (c.width === null ? c : { ...c, width: widths[c.id] ?? c.width })), [allColumns, overrides, widths])
  const message = rows.find((m) => m.id === selected)
  const targets = useMemo(() => (selection.set.size ? rows.filter((m) => selection.set.has(m.id)) : message ? [message] : []), [rows, selection.set, message])
  const patchRows = useCallback((fresh: Annotated[]) => {
    const byId = new Map(fresh.map((m) => [m.id, m]))
    setRows((cur) => cur.map((m) => (byId.has(m.id) ? patchFlow(m, byId.get(m.id) as WsMessage) : m)))
  }, [])
  // A closed session has no stream to bring the change, so the frame is read back. Under a
  // filter that reads annotations the change can also add or drop frames, so it subscribes again.
  const annotated = useCallback(async () => {
    if (readsAnnotations(filter)) {
      setRows([])
      setEpoch((e) => e + 1)
      return
    }
    if (selected) patchRows([await api.getMessage(session, selected)])
  }, [filter, selected, session, patchRows])
  const ids = useMemo(() => rows.map((m) => m.id), [rows])
  // Virtual rows are positioned in real px.
  const frameRow = FRAME_ROW * useScale()
  const virtual = useVirtualizer({ count: rows.length, getScrollElement: () => list.current, estimateSize: () => frameRow, overscan: 20 })
  useEffect(() => { virtual.measure() }, [frameRow, virtual])
  const framePicks = picks.filter((p) => p.message)
  const pick = (m: WsMessage) => onTogglePick({
    session, sessionLabel, id: m.id, label: `${flow.method ?? ''} ${flow.authority ?? ''} ${flow.path ?? ''}`.trim(),
    message: { flowId: flow.id, openMicros: num(flow.tsUnixMicros), frame: m },
  })
  const metaHelp = `~meta key alone: the key is present${metaKeys.length ? ` · keys here: ${metaKeys.join(', ')}` : ''}`
  return (
    <Modal flush title="Messages" width={1360} height={860} onClose={onClose} headerExtra={<>
      <span className="font-mono text-11 text-muted truncate min-w-0 max-w-72">{flow.method} {flow.authority}{flow.path}</span>
      {live && <Pill tone="green" dot>live</Pill>}
      <FilterInput value={text} onChange={setText} onSubmit={() => setFilter(text)} terms={MESSAGE_TERMS} examples={MESSAGE_EXAMPLES} bareMatches="payload" extraHelp={metaHelp}
        placeholder={metaKeys[0] ? `~meta ${metaKeys[0]}=` : '~from client'} trailing={<span className="text-10 text-faint shrink-0">↵ to apply</span>} />
      <Button variant={follow ? 'active' : 'default'} aria-pressed={follow} icon={<ArrowDown size={rem(13)} />} onClick={() => setFollow(!follow)}>Follow</Button>
      <Button disabled={framePicks.length !== 2} onClick={onCompare}>Compare <span className="px-1.5 rounded tint tone-green font-mono text-11">{framePicks.length}/2</span></Button>
      {framePicks.length > 0 && <IconButton label="Clear picks" size={22} onClick={onClearPicks}><X size={rem(12)} /></IconButton>}
      <Popover label="Columns" icon={<Columns3 size={rem(14)} />}>
        {allColumns.map((c) => <Check key={c.id} label={c.label} checked={overrides[c.id] ?? true} onChange={(v) => setOverrides((o) => ({ ...o, [c.id]: v }))} />)}
        <ResetColumns onReset={() => { setOverrides({}); setWidths({}) }} />
      </Popover>
    </>}>
      {hints.map((h, i) => <div key={i} className="px-3 py-1 tint tone-amber text-11">{h}</div>)}
      {lost && <div className="p-2"><Banner>stream lost — reopen the timeline to resync</Banner></div>}
      <div className="flex flex-1 min-h-0">
        <div className="flex-1 min-w-0 flex flex-col">
          <div role="row" className="flex items-center h-8 px-3 shrink-0 bg-head border-b border-line text-11 font-medium text-muted">
            <span className="w-6 shrink-0" />
            {columns.map((c) => <HeaderCell key={c.id} label={c.label} title={c.label} width={c.width} className={c.meta !== undefined ? 'text-purple-fg' : undefined} onResize={(w) => setWidth(c.id, w)} onReset={() => setWidth(c.id, null)} />)}
          </div>
          <div ref={list} className="flex-1 min-h-0 overflow-auto font-mono text-11">
            <div style={{ height: virtual.getTotalSize(), position: 'relative' }}>
              {virtual.getVirtualItems().map((v) => {
                const m = rows[v.index]
                const picked = framePicks.some((p) => p.id === m.id)
                const on = m.id === selected || selection.set.has(m.id)
                const mark = m.markColor
                return (
                  <div key={m.id} role="row" aria-selected={on} onClick={(e) => setSelection((cur) => select(ids, cur, m.id, { shift: e.shiftKey, toggle: e.ctrlKey || e.metaKey }))}
                    // Shift would otherwise drag a text selection across the rows.
                    onMouseDown={(e) => { if (e.shiftKey) e.preventDefault() }}
                    style={{ position: 'absolute', top: 0, left: 0, right: 0, height: frameRow, transform: `translateY(${v.start}px)` }}
                    className={cx('relative flex items-center px-3 cursor-default', mark && `mark-${mark} tint [--a:10%]`, !mark && on && 'tone-blue tint [--a:12%]', !mark && !on && 'hover:bg-rowhover text-body')}>
                    {(mark || on) && <span aria-hidden className="absolute left-0 inset-y-0 w-1" style={{ background: 'var(--t)' }} />}
                    <button type="button" role="checkbox" aria-checked={picked} aria-label="Pick for compare" onClick={(e) => { e.stopPropagation(); pick(m) }}
                      className={cx('flex items-center justify-center w-4 h-4 rounded border shrink-0 mr-2', picked ? 'bg-green border-green text-onsolid' : 'border-edge-check')}>
                      {picked && <Tick size={rem(12)} strokeWidth={3} />}
                    </button>
                    {columns.map((c) => <div key={c.id} style={columnStyle(c.width)} className="pr-2 overflow-hidden"><FrameCell c={c} m={m} /></div>)}
                  </div>
                )
              })}
            </div>
          </div>
        </div>
        <div className="shrink-0 w-[42%] border-l border-line flex flex-col">
          <div className="flex-1 min-h-0 overflow-auto p-3">
            {message ? <Payload key={message.id} session={session} message={message} /> : <p className="py-10 text-center text-muted">Select a frame</p>}
          </div>
          {message && <AnnotationBar record={message} targets={targets} session={session} noun="frames" onChanged={() => void annotated().catch(() => {})} onPatch={patchRows} />}
        </div>
      </div>
      <footer className="flex items-center gap-2 h-9 px-4 shrink-0 border-t border-line font-mono text-11 text-muted rounded-b-xl">
        {rows.length.toLocaleString('en-US')} frames{live && <span className="text-green-fg">· live</span>}
      </footer>
    </Modal>
  )
}
