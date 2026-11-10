import { ArrowDown, ArrowLeft, ChevronRight, FileText, Play, RefreshCw, Square } from 'lucide-react'
import { rem } from '../lib/scale'
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import * as api from '../lib/api'
import { formatBytes, formatDateTime, num, type Tone } from '../lib/format'
import { classifyLogLine, type LogLine } from '../lib/logs'
import type { LogInfo, ServiceInfo } from '../lib/types'
import { Banner, Button, cx, Modal, Pill, SectionLabel, Spinner } from './ui'

const TAIL_BYTES = 200_000

function ServiceCard({ service: s, busy, onToggle }: { service: ServiceInfo; busy: boolean; onToggle: () => void }) {
  // Only http(s): the gateway's string becomes an href in this page.
  const link = s.url && /^https?:\/\//i.test(s.url)
  return (
    <div className="p-3 space-y-2 rounded-lg border border-edge-card bg-raised">
      <div className="flex items-center gap-2.5">
        <span aria-hidden className="w-2 h-2 rounded-full shrink-0" style={{ background: s.running ? 'var(--green)' : 'var(--dim)' }} />
        <span className="text-13 font-semibold text-ink truncate">{s.label || s.name}</span>
        <Pill tone={s.running ? 'green' : 'grey'}>{s.running ? 'running' : 'stopped'}</Pill>
        <span className="flex-1" />
        {s.url && (link ? <a href={s.url} target="_blank" rel="noreferrer" className="min-w-0 truncate font-mono text-11 text-blue-fg hover:underline">{s.url}</a> : <span className="min-w-0 truncate font-mono text-11 text-blue-fg">{s.url}</span>)}
        {s.running
          ? <Button size="sm" variant="danger" disabled={busy} icon={<Square size={rem(9)} fill="currentColor" />} onClick={onToggle}>Stop</Button>
          : <Button size="sm" disabled={busy} icon={<Play size={rem(10)} className="text-green-fg" fill="currentColor" />} onClick={onToggle}>Start</Button>}
      </div>
      {/* In full, and loudest while stopped: this is what Start is about to do. */}
      {s.detail && (s.running
        ? <p className="pl-4.5 text-12 text-muted">{s.detail}</p>
        : <Banner tone="amber">{s.detail}</Banner>)}
    </div>
  )
}

const LINE_TONE: Partial<Record<Tone, string>> = { red: 'text-red-fg', amber: 'text-amber-fg', blue: 'text-blue-fg', grey: 'text-faint' }

function Line({ line }: { line: LogLine }) {
  if (line.run) return <div className="font-bold text-green-fg">{line.message}</div>
  return (
    <div className={cx('whitespace-pre-wrap break-all', line.tone ? LINE_TONE[line.tone] : 'text-body')}>
      {line.time && <span className="mr-2.5 text-dim">{line.time}</span>}{line.message}
    </div>
  )
}

function LogTail({ log, onBack, onClose }: { log: LogInfo; onBack: () => void; onClose: () => void }) {
  const [text, setText] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [follow, setFollow] = useState(true)
  const end = useRef<HTMLDivElement>(null)
  const size = num(log.sizeBytes)
  const load = useCallback(async () => {
    try {
      setText(await api.getLog(log.name, TAIL_BYTES))
      setError('')
    } catch (e) {
      setError((e as Error).message)
    }
  }, [log.name])
  useEffect(() => { void load() }, [load])
  const lines = useMemo(() => {
    const all = (text ?? '').split('\n')
    if (all[all.length - 1] === '') all.pop()
    // A tail starts wherever the byte count fell, usually inside a line.
    if (size > TAIL_BYTES) all.shift()
    return all.map(classifyLogLine)
  }, [text, size])
  useLayoutEffect(() => { if (follow) end.current?.scrollIntoView({ block: 'end' }) }, [lines, follow])
  return (
    <Modal flush title={log.label || log.name} width={1360} height={840} onClose={onClose} headerExtra={<>
      <span className="font-mono text-11 text-faint">{formatBytes(size)} · last {TAIL_BYTES / 1000} KB</span>
      <span className="flex-1" />
      <Button size="sm" variant={follow ? 'active' : 'default'} aria-pressed={follow} icon={<ArrowDown size={rem(12)} />} onClick={() => setFollow(!follow)}>Follow</Button>
      <Button size="sm" icon={<RefreshCw size={rem(12)} />} onClick={() => void load()}>Refresh</Button>
      <Button size="sm" variant="ghost" icon={<ArrowLeft size={rem(12)} />} onClick={onBack}>Services &amp; logs</Button>
    </>}>
      {error && <div className="p-3"><Banner>{error}</Banner></div>}
      <div className="flex-1 min-h-0 overflow-auto px-5 py-3.5 bg-well rounded-b-xl font-mono text-11 leading-5">
        {text === null && !error ? <Spinner /> : lines.length === 0 && !error ? <p className="text-faint">Empty.</p> : lines.map((l, i) => <Line key={i} line={l} />)}
        <div ref={end} />
      </div>
    </Modal>
  )
}

export function ServicesModal({ onClose }: { onClose: () => void }) {
  const [services, setServices] = useState<ServiceInfo[] | null>(null)
  const [logs, setLogs] = useState<LogInfo[] | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [tail, setTail] = useState<LogInfo | null>(null)
  const fail = (e: Error) => setError(e.message)
  const reloadServices = useCallback(() => api.listServices().then(setServices), [])
  useEffect(() => {
    reloadServices().catch(fail)
    api.listLogs().then(setLogs, fail)
  }, [reloadServices])
  const toggle = async (s: ServiceInfo) => {
    setBusy(s.name)
    setError('')
    try {
      await (s.running ? api.stopService(s.name) : api.startService(s.name))
      await reloadServices()
    } catch (e) {
      fail(e as Error)
    } finally {
      setBusy('')
    }
  }
  if (tail) return <LogTail log={tail} onBack={() => setTail(null)} onClose={onClose} />
  return (
    <Modal title="Services & logs" width={640} onClose={onClose}>
      {error && <Banner onDismiss={() => setError('')}>{error}</Banner>}
      <div className="space-y-2.5">
        <SectionLabel>Services</SectionLabel>
        {services === null ? (!error && <Spinner />) : services.length === 0 ? <p className="text-12 text-muted">No services.</p>
          : services.map((s) => <ServiceCard key={s.name} service={s} busy={!!busy} onToggle={() => void toggle(s)} />)}
      </div>
      <div className="space-y-2.5">
        <div className="flex items-center justify-between"><SectionLabel>Logs</SectionLabel><span className="text-11 text-faint">click to open the tail</span></div>
        {logs === null ? (!error && <Spinner />) : logs.length === 0 ? <p className="text-12 text-muted">No logs.</p> : (
          <div className="p-1 space-y-0.5 rounded-lg border border-edge-card bg-app">
            {logs.map((l) => (
              <button key={l.name} type="button" onClick={() => setTail(l)} className="flex items-center gap-2.5 w-full h-9 px-3 rounded-md text-left hover:bg-rowhover">
                <FileText size={rem(13)} className="text-faint shrink-0" />
                <span className="flex-1 min-w-0 truncate font-mono text-12 text-ink">{l.label || l.name}</span>
                <span className="font-mono text-11 text-faint">{formatDateTime(num(l.modifiedUnixMs))}</span>
                <span className="w-14 text-right font-mono text-11 text-muted">{formatBytes(num(l.sizeBytes))}</span>
                <ChevronRight size={rem(14)} className="text-faint shrink-0" />
              </button>
            ))}
          </div>
        )}
      </div>
    </Modal>
  )
}
