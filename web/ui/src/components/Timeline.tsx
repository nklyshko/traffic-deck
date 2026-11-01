import { ArrowDown } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import * as api from '../lib/api'
import { MESSAGE_EXAMPLES, MESSAGE_TERMS } from '../lib/filter'
import { formatBytes, formatTime, num } from '../lib/format'
import { base64Bytes, bodyExt, hexDump, looksTextual, saveBlob } from '../lib/http'
import type { Flow, MessageEvent_, WsMessage } from '../lib/types'
import { FilterInput } from './FilterInput'
import { JsonTree } from './Json'
import { parseJson } from './Details'
import { Banner, Button, Card, CopyButton, cx, Modal, Pill, Spinner } from './ui'

const TEXT_CAP = 50_000
const HEX_CAP = 4096

function preview(m: WsMessage): string {
  const bytes = base64Bytes(m.payload?.inline)
  if (!bytes.length || !looksTextual(bytes)) return ''
  return new TextDecoder().decode(bytes.subarray(0, 800)).slice(0, 200).replace(/\r?\n/g, '⏎')
}

function Payload({ session, message }: { session: string; message: WsMessage }) {
  const hasRaw = num(message.raw?.size) > 0
  const [raw, setRaw] = useState(false)
  const body = raw ? message.raw : message.payload
  const [bytes, setBytes] = useState<Uint8Array | null | undefined>(undefined)
  const [error, setError] = useState('')
  useEffect(() => {
    setBytes(undefined)
    setError('')
    if (body?.inline) setBytes(base64Bytes(body.inline))
    else if (num(body?.size)) api.getMessageBody(session, message.id, raw).then(setBytes, (e: Error) => setError(e.message))
    else setBytes(null)
  }, [session, message.id, raw, body])
  const textual = !!bytes && looksTextual(bytes)
  const text = useMemo(() => (textual && bytes ? new TextDecoder().decode(bytes) : ''), [bytes, textual])
  const json = useMemo(() => parseJson(text), [text])
  const ext = bodyExt(body?.contentType)
  const name = `${message.id}-${raw ? 'raw' : 'payload'}.${ext}`
  const save = () => bytes && saveBlob(name, bytes.slice())
  const capped = bytes ? (textual ? text.length - TEXT_CAP : bytes.length - HEX_CAP) : 0
  return (
    <>
      <div className="flex items-center gap-2 mb-3">
        <span className={cx('font-mono text-[11px] font-medium', message.fromClient ? 'text-cyan-fg' : 'text-purple-fg')}>{message.fromClient ? '→ client' : '← server'}</span>
        <span className="px-1.5 rounded bg-sel font-mono text-[11px] text-ink">{message.opcode}</span>
        <span className="font-mono text-[11px] text-faint">{formatTime(num(message.tsUnixMicros))} · {formatBytes(num(body?.size)) || '0B'}</span>
        <span className="flex-1" />
        {hasRaw && <span className="inline-flex rounded bg-well border border-line p-px text-[11px]">
          {[false, true].map((v) => <button key={String(v)} type="button" onClick={() => setRaw(v)} className={cx('h-5 px-2 rounded-sm', raw === v ? 'bg-sel text-ink' : 'text-muted')}>{v ? 'raw' : 'payload'}</button>)}
        </span>}
        <Button size="xs" onClick={save} disabled={!bytes}>save</Button>
      </div>
      {message.metadata && Object.keys(message.metadata).length > 0 && (
        <div className="mb-3"><Card title="Metadata">
          {Object.entries(message.metadata).map(([k, v]) => <div key={k} className="flex gap-2 px-3 py-0.5 font-mono text-[11px]"><span className="w-28 shrink-0 text-muted break-all">{k}</span><span className="text-body break-all">{v}</span></div>)}
        </Card></div>
      )}
      <Card title={raw ? 'Raw' : 'Payload'} meta={body?.contentType} actions={text ? <CopyButton text={text} label="Copy" /> : undefined}>
        <div className="px-3 pb-1.5">
          {error ? <p className="text-[11px] text-red-fg">{error}</p> : bytes === undefined ? <Spinner />
            : !bytes?.length ? <p className="text-[11px] text-faint">Empty.</p>
              : json !== undefined ? <JsonTree value={json} />
                : <pre className="font-mono text-[11px] leading-[18px] text-body whitespace-pre-wrap break-all">{textual ? text.slice(0, TEXT_CAP) : hexDump(bytes, HEX_CAP)}</pre>}
          {capped > 0 && <button type="button" onClick={save} className="w-full h-7 mt-2 rounded border border-dashed border-edge-strong text-[11px] text-muted hover:text-ink">… {capped.toLocaleString('en-US')} more {textual ? 'characters' : 'bytes'} — save the whole payload as .{ext}</button>}
        </div>
      </Card>
    </>
  )
}

export function TimelineModal({ session, flow, onClose }: { session: string; flow: Flow; onClose: () => void }) {
  const [text, setText] = useState('')
  const [filter, setFilter] = useState('')
  const [rows, setRows] = useState<WsMessage[]>([])
  const [hints, setHints] = useState<string[]>([])
  const [selected, setSelected] = useState<string | null>(null)
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
    setSelected(null)
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
        const fresh = batch.filter((m) => !seen.has(m.id))
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
  }, [session, flow.id, filter])

  useEffect(() => {
    if (follow && list.current) list.current.scrollTop = list.current.scrollHeight
  }, [rows, follow])

  const metaKeys = useMemo(() => [...new Set(rows.flatMap((m) => Object.keys(m.metadata ?? {})))].sort(), [rows])
  const message = rows.find((m) => m.id === selected)
  const metaHelp = metaKeys.length ? `~meta keys here: ${metaKeys.join(', ')}` : undefined
  return (
    <Modal flush title="Messages" width={1360} height="min(860px, 100%)" onClose={onClose} headerExtra={<>
      <span className="font-mono text-[11px] text-muted truncate min-w-0 max-w-72">{flow.method} {flow.authority}{flow.path}</span>
      {live && <Pill tone="green" dot>live</Pill>}
      <FilterInput value={text} onChange={setText} onSubmit={() => setFilter(text)} terms={MESSAGE_TERMS} examples={MESSAGE_EXAMPLES} extraHelp={metaHelp}
        placeholder={metaKeys[0] ? `~meta ${metaKeys[0]}=` : '~from client'} trailing={<span className="text-[10px] text-faint shrink-0">↵ to apply</span>} />
      <Button variant={follow ? 'active' : 'default'} aria-pressed={follow} icon={<ArrowDown size={13} />} onClick={() => setFollow(!follow)}>Follow</Button>
    </>}>
      {hints.map((h, i) => <div key={i} className="px-3 py-1 tint tone-amber text-[11px]">{h}</div>)}
      {lost && <div className="p-2"><Banner>stream lost — reopen the timeline to resync</Banner></div>}
      <div className="flex flex-1 min-h-0">
        <div className="flex-1 min-w-0 flex flex-col">
          <div className="flex items-center h-8 px-3 shrink-0 bg-head border-b border-line text-[11px] font-medium text-muted">
            <span className="w-28 shrink-0">Time</span><span className="w-9 shrink-0">Dir</span><span className="w-16 shrink-0">Opcode</span><span className="w-14 shrink-0">Len</span>
            {metaKeys.map((k) => <span key={k} className="w-20 shrink-0 truncate text-purple-fg" title={k}>{k}</span>)}
            <span className="flex-1">Preview</span>
          </div>
          <div ref={list} className="flex-1 min-h-0 overflow-auto font-mono text-[11px]">
            {rows.map((m) => (
              <div key={m.id} role="row" aria-selected={m.id === selected} onClick={() => setSelected(m.id)}
                className={cx('flex items-center h-[30px] px-3 cursor-default', m.id === selected ? 'tone-blue tint [--a:12%]' : 'hover:bg-rowhover text-body')}>
                <span className="w-28 shrink-0 text-muted">{formatTime(num(m.tsUnixMicros))}</span>
                <span className={cx('w-9 shrink-0', m.fromClient ? 'text-cyan-fg' : 'text-purple-fg')}>{m.fromClient ? '→' : '←'}</span>
                <span className={cx('w-16 shrink-0', m.opcode === 'binary' ? 'text-orange-fg' : 'text-body')}>{m.opcode}</span>
                <span className="w-14 shrink-0 text-muted">{formatBytes(num(m.payload?.size)) || '0B'}</span>
                {metaKeys.map((k) => <span key={k} className="w-20 shrink-0 truncate" title={m.metadata?.[k]}>{m.metadata?.[k]}</span>)}
                <span className="flex-1 min-w-0 truncate text-muted">{preview(m)}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="shrink-0 w-[42%] border-l border-line overflow-auto p-3">
          {message ? <Payload key={message.id} session={session} message={message} /> : <p className="py-10 text-center text-muted">Select a frame</p>}
        </div>
      </div>
      <footer className="flex items-center gap-2 h-9 px-4 shrink-0 border-t border-line font-mono text-[11px] text-muted rounded-b-xl">
        {rows.length.toLocaleString('en-US')} frames{live && <span className="text-green-fg">· live</span>}
      </footer>
    </Modal>
  )
}
