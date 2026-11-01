import { useEffect, useMemo, useState } from 'react'
import * as api from '../lib/api'
import { compareFlows, compareMessages, cookieOrder, diffText, goSlice, headerOrder, messagePosition, MISSING, positionLines, prettyPayload, pseudoOrder, unifiedDiff, type Position, type Section, type UnifiedDiff } from '../lib/compare'
import { num } from '../lib/format'
import { base64Bytes, hexDump, looksTextual } from '../lib/http'
import type { Flow, WsMessage } from '../lib/types'
import type { Pick } from './Workspace'
import { Banner, Button, CopyButton, cx, Modal, Spinner } from './ui'

const LONG = 120

function Value({ text, open, onToggle }: { text: string | null; open: boolean; onToggle: () => void }) {
  if (text === null) return null
  if (text.length <= LONG) return <span className="break-all">{text}</span>
  return (
    <button type="button" aria-expanded={open} onClick={onToggle} className="text-left break-all">
      {open ? `▼ ${text}` : `▶ ${text.slice(0, 60)}… (${text.length} chars)`}
    </button>
  )
}

function Cell({ side, text, same, name, open, onToggle }: { side: 'a' | 'b'; text: string | null; same: boolean; name?: string; open: boolean; onToggle: () => void }) {
  const absent = text === null
  return (
    <div className={cx('flex-1 min-w-0 min-h-[22px] flex gap-2 px-2 py-0.5 rounded font-mono text-[11px]', !same && !absent && (side === 'a' ? 'tint tone-red' : 'tint tone-green'), same && 'text-body')}>
      <span className="w-2.5 shrink-0">{same || absent ? '' : side === 'a' ? '-' : '+'}</span>
      {name !== undefined && !absent && <span className="text-muted shrink-0">{name}</span>}
      <Value text={text} open={open} onToggle={onToggle} />
    </div>
  )
}

function Row({ a, b, same, name }: { a: string | null; b: string | null; same: boolean; name?: string }) {
  const [open, setOpen] = useState(false)
  const toggle = () => setOpen(!open)
  return <div className="flex gap-2"><Cell side="a" text={a} same={same} name={name} open={open} onToggle={toggle} /><Cell side="b" text={b} same={same} name={name} open={open} onToggle={toggle} /></div>
}

function EqualCookie({ name, value }: { name: string; value: string }) {
  const [open, setOpen] = useState(false)
  return <div className="flex gap-2 px-2 py-0.5 font-mono text-[11px] text-body"><span className="w-2.5" /><span className="text-muted shrink-0">{name}</span><Value text={value} open={open} onToggle={() => setOpen(!open)} /></div>
}

const Verdict = ({ match }: { match: boolean }) => <span className={cx('inline-flex items-center h-5 px-2 rounded-full tint text-[10px]', match ? 'tone-green' : 'tone-red')}>{match ? '✓ match' : '✗ differ'}</span>

function SectionCard({ s, n }: { s: Section; n: number }) {
  return (
    <section className="rounded-lg border border-edge-card bg-panel p-3 space-y-1">
      <header className="flex items-center gap-2">
        <h3 className="text-xs font-medium text-ink">{n} {s.title}</h3>
        <span className="flex-1" />
        <Verdict match={s.match} />
      </header>
      {s.rows?.map((r, i) => <Row key={i} a={r.a} b={r.b} same={r.same} />)}
      {/* Equal cookie rows render once across both columns. */}
      {s.pairs?.map((r, i) => (s.title === 'Cookie values' && r.same
        ? <EqualCookie key={i} name={r.name} value={r.a} />
        : <Row key={i} a={r.a} b={r.b} same={r.same} name={r.name} />))}
      {s.pairs?.length === 0 && <p className="px-2 font-mono text-[11px] text-faint">{MISSING}</p>}
    </section>
  )
}

function Banners({ picks, lines }: { picks: Pick[]; lines?: string[] }) {
  return (
    <div className="flex gap-2 px-4 py-2 shrink-0">
      {picks.map((p, i) => (
        <div key={p.id} className={cx('flex-1 min-w-0 flex items-center gap-3 p-2.5 rounded-lg border tint [--a:8%]', i === 0 ? 'tone-cyan' : 'tone-pink')} style={{ borderColor: 'color-mix(in srgb, var(--t) 30%, transparent)' }}>
          <span className="flex items-center justify-center w-7 h-7 rounded-md font-semibold text-onsolid" style={{ background: 'var(--t)' }}>{i === 0 ? 'A' : 'B'}</span>
          <span className="min-w-0"><span className="block text-xs font-medium text-ink truncate">{p.sessionLabel}</span><span className="block font-mono text-[11px] text-muted truncate">{lines?.[i] ?? p.label}</span></span>
        </div>
      ))}
    </div>
  )
}

function FlowCompare({ picks, onClose, onClear }: Props) {
  const [flows, setFlows] = useState<[Flow, Flow] | null>(null)
  const [error, setError] = useState('')
  const [side, setSide] = useState<0 | 1>(0)
  useEffect(() => {
    Promise.all([api.getFlow(picks[0].session, picks[0].id), api.getFlow(picks[1].session, picks[1].id)]).then(setFlows, (e: Error) => setError(e.message))
  }, [picks])
  const sections = useMemo(() => (flows ? compareFlows(flows[0], flows[1]) : []), [flows])
  const chosen = flows?.[side]
  return (
    <Modal flush title="A/B compare" width={1200} height="min(880px, 100%)" onClose={onClose} headerExtra={<>
      <span className="text-[11px] text-faint">order-sensitive · nothing sorted or normalised</span>
    </>}>
      <div className="flex items-center gap-2 px-4 py-2 shrink-0 border-b border-line text-[11px] text-muted">
        <span>Copy as Go slice</span>
        <span className="inline-flex rounded bg-well border border-line p-px">
          {(['A', 'B'] as const).map((l, i) => <button key={l} type="button" onClick={() => setSide(i as 0 | 1)} className={cx('w-6 h-5 rounded-sm font-mono', side === i ? 'bg-sel text-ink' : 'text-muted')}>{l}</button>)}
        </span>
        {chosen && <>
          <CopyChip label="header order" text={goSlice(headerOrder(chosen))} />
          <CopyChip label="pseudo order" text={goSlice(pseudoOrder(chosen))} />
          <CopyChip label="cookie order" text={goSlice(cookieOrder(chosen))} />
        </>}
        <span className="flex-1" />
        <Button size="xs" variant="ghost" className="text-red-fg!" onClick={onClear}>Clear picks</Button>
      </div>
      <Banners picks={picks} />
      <div className="flex-1 min-h-0 overflow-auto px-4 pb-4 space-y-2">
        {error && <Banner>{error}</Banner>}
        {!flows && !error && <Spinner />}
        {sections.map((s, i) => <SectionCard key={s.title} s={s} n={i + 1} />)}
      </div>
    </Modal>
  )
}

async function payloadLines(session: string, m: WsMessage): Promise<string[]> {
  const bytes = m.payload?.inline ? base64Bytes(m.payload.inline) : num(m.payload?.size) ? await api.getMessageBody(session, m.id, false) : null
  if (!bytes?.length) return []
  return (looksTextual(bytes) ? prettyPayload(new TextDecoder().decode(bytes)) : hexDump(bytes, bytes.length)).split('\n')
}

function PayloadDiff({ diff, n }: { diff: UnifiedDiff; n: number }) {
  const same = diff.removed + diff.added === 0
  return (
    <section className="rounded-lg border border-edge-card bg-panel p-3 space-y-1">
      <header className="flex items-center gap-2">
        <h3 className="text-xs font-medium text-ink">{n} Payload</h3>
        {!same && <span className="font-mono text-[11px]"><span className="text-red-fg">−{diff.removed}</span> <span className="text-green-fg">+{diff.added}</span></span>}
        <span className="flex-1" />
        <Verdict match={same} />
      </header>
      {same ? <p className="px-2 font-mono text-[11px] text-faint">Identical.</p> : diff.hunks.map((h) => (
        <div key={h.header} className="font-mono text-[11px] leading-[18px]">
          <div className="px-2 text-blue-fg">{h.header}</div>
          {h.lines.map((l, i) => (
            <div key={i} className={cx('flex px-2 rounded-sm', l.kind === '-' && 'tint tone-red', l.kind === '+' && 'tint tone-green', l.kind === ' ' && 'text-body')}>
              <span className="w-10 shrink-0 text-right text-faint select-none">{l.a}</span>
              <span className="w-10 shrink-0 text-right text-faint select-none">{l.b}</span>
              <span className="w-5 shrink-0 text-center select-none">{l.kind === ' ' ? '' : l.kind === '-' ? '−' : '+'}</span>
              <span className="flex-1 min-w-0 whitespace-pre-wrap break-all">{l.text}</span>
            </div>
          ))}
        </div>
      ))}
    </section>
  )
}

function MessageCompare({ picks, onClose, onClear }: Props) {
  const [a, b] = picks
  const [loaded, setLoaded] = useState<{ positions: (Position | null)[]; diff: UnifiedDiff } | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    const position = async (p: Pick) => messagePosition(await api.listMessages(p.session, p.message!.flowId), p.id, p.message!.openMicros)
    const lines = (p: Pick) => payloadLines(p.session, p.message!.frame)
    Promise.all([position(a), position(b), lines(a), lines(b)])
      .then(([pa, pb, la, lb]) => setLoaded({ positions: [pa, pb], diff: unifiedDiff(la, lb) }), (e: Error) => setError(e.message))
  }, [a, b])
  const sections = useMemo(() => compareMessages(a.message!.frame, b.message!.frame), [a, b])
  const banner = (p: Pick, i: number) => {
    const at = loaded?.positions[i]
    return `${p.message!.frame.fromClient ? '→' : '←'} ${at ? `#${at.index} · ` : ''}${p.label}`
  }
  return (
    <Modal flush title="A/B compare" width={1200} height="min(880px, 100%)" onClose={onClose} headerExtra={<>
      <span className="text-[11px] text-faint">order-sensitive · position is context, not compared</span>
    </>}>
      <div className="flex items-center gap-2 px-4 py-2 shrink-0 border-b border-line text-[11px] text-muted">
        {loaded && <CopyChip label="Copy diff" text={diffText(loaded.diff)} />}
        <span className="flex-1" />
        <Button size="xs" variant="ghost" className="text-red-fg!" onClick={onClear}>Clear picks</Button>
      </div>
      <Banners picks={picks} lines={picks.map(banner)} />
      <div className="flex-1 min-h-0 overflow-auto px-4 pb-4 space-y-2">
        {error && <Banner>{error}</Banner>}
        {!loaded && !error && <Spinner />}
        {loaded && (
          <section className="rounded-lg border border-edge-card bg-panel p-3 space-y-1">
            <h3 className="text-xs font-medium text-ink">Position</h3>
            <div className="flex gap-2">
              {loaded.positions.map((p, i) => <div key={i} className="flex-1 min-w-0 px-2 font-mono text-[11px] text-body">{p ? positionLines(p).map((l) => <div key={l}>{l}</div>) : MISSING}</div>)}
            </div>
          </section>
        )}
        {sections.map((s, i) => <SectionCard key={s.title} s={s} n={i + 1} />)}
        {loaded && <PayloadDiff diff={loaded.diff} n={sections.length + 1} />}
      </div>
    </Modal>
  )
}

interface Props { picks: Pick[]; onClose: () => void; onClear: () => void }

export function CompareModal(props: Props) {
  return props.picks[0].message ? <MessageCompare {...props} /> : <FlowCompare {...props} />
}

function CopyChip({ label, text }: { label: string; text: string }) {
  return <span className="inline-flex items-center h-6 px-2 rounded-md border border-edge"><CopyButton text={text} label={label} /></span>
}
