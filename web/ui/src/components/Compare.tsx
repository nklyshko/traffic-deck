import { useEffect, useMemo, useState } from 'react'
import * as api from '../lib/api'
import { bodyDiffText, bodyText, compareBodies, fitLines, renderBudget, compareFlows, compareMessages, cookieOrder, diffParts, diffText, goSlice, headerOrder, messagePosition, MISSING, positionLines, prettyPayload, pseudoOrder, splitRows, unifiedDiff, type BodyComparison, type BodyVerdict, type DiffLine, type DiffPart, type FormRow, type Position, type Section, type UnifiedDiff } from '../lib/compare'
import { num } from '../lib/format'
import { base64Bytes, HEX_CAP, hexDump, looksTextual, TEXT_CAP } from '../lib/http'
import { useSetting } from '../lib/settings'
import type { Flow, WsMessage } from '../lib/types'
import { DecodeAffordance, Decoded } from './Decode'
import type { Pick } from './Workspace'
import { Banner, Button, CopyButton, cx, Modal, SectionLabel, Spinner } from './ui'

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
    <div className={cx('flex-1 min-w-0 min-h-5.5 flex gap-2 px-2 py-0.5 rounded font-mono text-11', !same && !absent && (side === 'a' ? 'tint tone-red' : 'tint tone-green'), same && 'text-body')}>
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
  return <div className="flex gap-2 px-2 py-0.5 font-mono text-11 text-body"><span className="w-2.5" /><span className="text-muted shrink-0">{name}</span><Value text={value} open={open} onToggle={() => setOpen(!open)} /></div>
}

const VERDICTS: Record<BodyVerdict, [string, string]> = {
  match: ['✓ match', 'tone-green'], layout: ['≈ layout only', 'tone-amber'], encoding: ['≈ encoding only', 'tone-amber'], differ: ['✗ differ', 'tone-red'],
}
const Verdict = ({ match, body }: { match?: boolean; body?: BodyVerdict }) => {
  const [label, tone] = VERDICTS[body ?? (match ? 'match' : 'differ')]
  return <span className={cx('inline-flex items-center h-5 px-2 shrink-0 rounded-full tint text-10 whitespace-nowrap', tone)}>{label}</span>
}

function SectionCard({ s, n }: { s: Section; n: number }) {
  return (
    <section className="rounded-lg border border-edge-card bg-panel p-3 space-y-1">
      <header className="flex items-center gap-2">
        <h3 className="text-12 font-medium text-ink">{n} {s.title}</h3>
        <span className="flex-1" />
        <Verdict match={s.match} />
      </header>
      {s.rows?.map((r, i) => <Row key={i} a={r.a} b={r.b} same={r.same} />)}
      {/* Equal cookie rows render once across both columns. */}
      {s.pairs?.map((r, i) => (s.title === 'Cookie values' && r.same
        ? <EqualCookie key={i} name={r.name} value={r.a} />
        : <Row key={i} a={r.a} b={r.b} same={r.same} name={r.name} />))}
      {s.pairs?.length === 0 && <p className="px-2 font-mono text-11 text-faint">{MISSING}</p>}
    </section>
  )
}

function Banners({ picks, lines }: { picks: Pick[]; lines?: string[] }) {
  return (
    <div className="flex gap-2 px-4 py-2 shrink-0">
      {picks.map((p, i) => (
        <div key={p.id} className={cx('flex-1 min-w-0 flex items-center gap-3 p-2.5 rounded-lg border tint [--a:8%]', i === 0 ? 'tone-cyan' : 'tone-pink')} style={{ borderColor: 'color-mix(in srgb, var(--t) 30%, transparent)' }}>
          <span className="flex items-center justify-center w-7 h-7 rounded-md font-semibold text-onsolid" style={{ background: 'var(--t)' }}>{i === 0 ? 'A' : 'B'}</span>
          <span className="min-w-0"><span className="block text-12 font-medium text-ink truncate">{p.sessionLabel}</span><span className="block font-mono text-11 text-muted truncate">{lines?.[i] ?? p.label}</span></span>
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
  const [bodies, setBodies] = useState<Bodies | null>(null)
  const [bodyError, setBodyError] = useState('')
  useEffect(() => {
    if (!flows) return
    Promise.all([requestBody(picks[0], flows[0]), requestBody(picks[1], flows[1])])
      .then(([a, b]) => setBodies({ a, b, c: compareBodies(a, b, requestType(flows[0]), requestType(flows[1])) }), (e: Error) => setBodyError(e.message))
  }, [flows, picks])
  const sections = useMemo(() => (flows ? compareFlows(flows[0], flows[1]) : []), [flows])
  const chosen = flows?.[side]
  return (
    <Modal flush title="A/B compare" width={1200} height={880} onClose={onClose} headerExtra={<>
      <span className="text-11 text-faint">order-sensitive · nothing sorted or normalised</span>
    </>}>
      <div className="flex items-center gap-2 px-4 py-2 shrink-0 border-b border-line text-11 text-muted">
        <span>Copy as Go slice</span>
        <span className="inline-flex rounded bg-well border border-line p-px">
          {(['A', 'B'] as const).map((l, i) => <button key={l} type="button" onClick={() => setSide(i as 0 | 1)} className={cx('w-6 h-5 rounded-sm font-mono', side === i ? 'bg-sel text-ink' : 'text-muted')}>{l}</button>)}
        </span>
        {chosen && <>
          <CopyChip label="header order" text={goSlice(headerOrder(chosen))} />
          <CopyChip label="pseudo order" text={goSlice(pseudoOrder(chosen))} />
          <CopyChip label="cookie order" text={goSlice(cookieOrder(chosen))} />
        </>}
        {bodies && (bodies.c.diff || bodies.c.form || bodies.c.alone) && <>
          <span className="w-px h-4 bg-edge" />
          <CopyChip label="Copy body diff" text={bodyDiffText(bodies.c)} />
        </>}
        <span className="flex-1" />
        <Button size="xs" variant="ghost" className="text-red-fg!" onClick={onClear}>Clear picks</Button>
      </div>
      <Banners picks={picks} />
      <div className="flex-1 min-h-0 overflow-auto px-4 pb-4 space-y-2">
        {error && <Banner>{error}</Banner>}
        {!flows && !error && <Spinner />}
        {sections.map((s, i) => <SectionCard key={s.title} s={s} n={i + 1} />)}
        {flows && <BodySection n={sections.length + 1} bodies={bodies} error={bodyError} />}
      </div>
    </Modal>
  )
}

async function payloadLines(session: string, m: WsMessage): Promise<{ lines: string[]; binary: boolean }> {
  const bytes = m.payload?.inline ? base64Bytes(m.payload.inline) : num(m.payload?.size) ? await api.getMessageBody(session, m.id, false) : null
  if (!bytes?.length) return { lines: [], binary: false }
  const binary = !looksTextual(bytes)
  return { lines: (binary ? hexDump(bytes, bytes.length) : prettyPayload(new TextDecoder().decode(bytes))).split('\n'), binary }
}

// One setting for every diff in the app: the request body and the message payload.
function DiffViewSwitch() {
  const [view, setView] = useSetting('diffView')
  return (
    <span className="inline-flex shrink-0 rounded-md bg-well border border-line p-px" role="group" aria-label="Diff view">
      {([['inline', 'Inline'], ['split', 'Side by side']] as const).map(([v, label]) => (
        <button key={v} type="button" aria-pressed={view === v} onClick={() => setView(v)} className={cx('h-5 px-2 rounded-sm text-11', view === v ? 'bg-sel text-ink' : 'text-muted hover:text-ink')}>{label}</button>
      ))}
    </span>
  )
}

const sign = (l: DiffLine) => (l.kind === ' ' ? '' : l.kind === '-' ? '−' : '+')
const lineTone = (l: DiffLine) => cx(l.kind === '-' && 'tint tone-red', l.kind === '+' && 'tint tone-green', l.kind === ' ' && 'text-body')

function SplitLine({ l, side }: { l: DiffLine | null; side: 'a' | 'b' }) {
  if (!l) return <div className="flex-1 min-w-0 rounded-sm bg-well" />
  return (
    <div className={cx('flex-1 min-w-0 flex px-2 rounded-sm', lineTone(l))}>
      <span className="w-10 shrink-0 text-right text-faint select-none">{l[side]}</span>
      <span className="w-5 shrink-0 text-center select-none">{sign(l)}</span>
      <span className="flex-1 min-w-0 whitespace-pre-wrap break-all">{l.text}</span>
    </div>
  )
}

const REVEAL_STEP = 20
const NONE: ReadonlySet<number> = new Set()

// A run of unchanged lines the hunks left out; it opens all at once when short, else in
// steps from the side of the hunk it borders.
function DiffGap({ gap, onReveal }: { gap: Extract<DiffPart, { kind: 'gap' }>; onReveal: (from: number, to: number) => void }) {
  const n = gap.to - gap.from
  const link = 'px-1.5 rounded text-blue-fg hover:bg-hover'
  return (
    <div className="flex items-center gap-2 h-5.5 px-2 rounded-sm bg-well font-sans text-11 text-faint">
      <span className="w-25 shrink-0 text-center select-none">⋯</span>
      {n <= REVEAL_STEP
        ? <button type="button" className={link} onClick={() => onReveal(gap.from, gap.to)}>Show {n} unchanged {n === 1 ? 'line' : 'lines'}</button>
        : <>
          <span>{n.toLocaleString('en-US')} unchanged lines</span>
          {gap.above && <button type="button" className={link} onClick={() => onReveal(gap.from, gap.from + REVEAL_STEP)}>↓ {REVEAL_STEP} more</button>}
          {gap.below && <button type="button" className={link} onClick={() => onReveal(gap.to - REVEAL_STEP, gap.to)}>↑ {REVEAL_STEP} more</button>}
          <button type="button" className={link} onClick={() => onReveal(gap.from, gap.to)}>Show all</button>
        </>}
    </div>
  )
}

// The cut note for a list that stopped at the render budget; Copy has the rest.
function Cut({ binary, copy }: { binary: boolean; copy: string }) {
  return <p className="px-2 py-1 font-sans text-11 text-faint">Shown up to {binary ? `${HEX_CAP / 1024} KiB of hex` : `${TEXT_CAP.toLocaleString('en-US')} characters`}; {copy} takes all of it.</p>
}

function DiffHunks({ diff, binary, copy }: { diff: UnifiedDiff; binary: boolean; copy: string }) {
  const [view] = useSetting('diffView')
  // Reset with the diff, so lines opened on one pair never carry over to the next.
  const [opened, setOpened] = useState<{ diff: UnifiedDiff; lines: ReadonlySet<number> }>({ diff, lines: NONE })
  const revealed = opened.diff === diff ? opened.lines : NONE
  const parts = useMemo(() => diffParts(diff, revealed), [diff, revealed])
  const reveal = (from: number, to: number) => {
    const next = new Set(revealed)
    for (let i = from; i < to; i++) next.add(i)
    setOpened({ diff, lines: next })
  }
  // Revealed lines spend the budget too, so opening a gap can move the cut up.
  const shown = useMemo(() => {
    let left = renderBudget(binary)
    const out: { part: DiffPart; lines: DiffLine[] }[] = []
    for (const part of parts) {
      if (part.kind === 'gap') {
        out.push({ part, lines: [] })
        continue
      }
      const lines = diff.script.slice(part.from, part.to)
      const fit = fitLines(lines.map((l) => l.text), left)
      left -= fit.used
      out.push({ part, lines: lines.slice(0, fit.count) })
      if (fit.count < lines.length) return { out, cut: true }
    }
    return { out, cut: false }
  }, [parts, diff, binary])
  return (
    <div className="font-mono text-11 leading-4.5 space-y-px">
      {shown.out.map(({ part: p, lines }) => {
        if (p.kind === 'gap') return <DiffGap key={`g${p.from}`} gap={p} onReveal={reveal} />
        return (
          <div key={`b${p.from}`} className="space-y-px">
            <div className="px-2 text-blue-fg">{p.header}</div>
            {view === 'split'
              ? splitRows(lines).map(([a, b], i) => <div key={i} className="flex gap-2"><SplitLine l={a} side="a" /><SplitLine l={b} side="b" /></div>)
              : lines.map((l, i) => (
                <div key={i} className={cx('flex px-2 rounded-sm', lineTone(l))}>
                  <span className="w-10 shrink-0 text-right text-faint select-none">{l.a}</span>
                  <span className="w-10 shrink-0 text-right text-faint select-none">{l.b}</span>
                  <span className="w-5 shrink-0 text-center select-none">{sign(l)}</span>
                  <span className="flex-1 min-w-0 whitespace-pre-wrap break-all">{l.text}</span>
                </div>
              ))}
          </div>
        )
      })}
      {shown.cut && <Cut binary={binary} copy={copy} />}
    </div>
  )
}

const changes = (d: UnifiedDiff) => `−${d.removed} +${d.added}`

function PayloadDiff({ diff, binary, n }: { diff: UnifiedDiff; binary: boolean; n: number }) {
  const same = diff.removed + diff.added === 0
  return (
    <section className="rounded-lg border border-edge-card bg-panel p-3 space-y-1">
      <header className="flex items-center gap-2">
        <h3 className="text-12 font-medium text-ink">{n} Payload</h3>
        {!same && <span className="font-mono text-11"><span className="text-red-fg">−{diff.removed}</span> <span className="text-green-fg">+{diff.added}</span></span>}
        <span className="flex-1" />
        {!same && <DiffViewSwitch />}
        <Verdict match={same} />
      </header>
      {same ? <p className="px-2 font-mono text-11 text-faint">Identical.</p> : <DiffHunks diff={diff} binary={binary} copy="Copy diff" />}
    </section>
  )
}

// --- request body (§5.9.2) ---

export interface Bodies { c: BodyComparison; a: Uint8Array | null; b: Uint8Array | null }

const sideTone = (side: 'a' | 'b') => (side === 'a' ? 'text-cyan-fg' : 'text-pink-fg')
const Letter = ({ side }: { side: 'a' | 'b' }) => <span className={cx('text-10 font-semibold', sideTone(side))}>{side.toUpperCase()}</span>

// What the prepared comparison below cannot say: whether the bytes were the same, and for
// JSON and XML how each side was laid out. Boxed apart so it never reads as a row.
function AsSent({ c, a, b }: Bodies) {
  const [open, setOpen] = useState(false)
  const size = (n: number | null) => (n === null ? 'no body' : `${n.toLocaleString('en-US')} B`)
  const original = (side: 'a' | 'b', bytes: Uint8Array | null) => {
    const text = bytes?.length ? bodyText(bytes) : ''
    const binary = !!bytes?.length && !looksTextual(bytes)
    const shown = binary ? hexDump(bytes!, HEX_CAP) : text.slice(0, TEXT_CAP)
    const rest = binary ? bytes!.length - HEX_CAP : text.length - TEXT_CAP
    return (
      <div className="flex-1 min-w-0 p-2.5 space-y-1.5 rounded-md border border-edge-card bg-raised">
        <div className="flex items-center"><Letter side={side} /><span className="flex-1" />{text && <CopyButton text={text} label={`Copy ${side.toUpperCase()}`} />}</div>
        {text ? <pre className="max-h-72 overflow-auto font-mono text-11 text-body whitespace-pre-wrap break-all">{shown}{rest > 0 && <span className="text-faint">{`\n… ${rest.toLocaleString('en-US')} more ${binary ? 'bytes' : 'characters'}; Copy takes all of it`}</span>}</pre>
          : <p className="text-11 text-faint">No body.</p>}
      </div>
    )
  }
  return (
    <div className="p-1.5 pl-2.5 space-y-2 rounded-md border border-edge-card bg-app">
      <div className="flex items-center gap-2.5 flex-wrap min-h-7">
        <SectionLabel>As sent</SectionLabel>
        <span className={cx('inline-flex items-center h-5 px-2 rounded-full tint text-10', c.identical ? 'tone-green' : 'tone-red')}>{c.identical ? '= byte-identical' : '≠ not byte-identical'}</span>
        <span className="font-mono text-10 text-faint">{size(c.sizes[0])} │ {size(c.sizes[1])}</span>
        {c.layout && <>
          <span className="w-px h-3.5 bg-edge" />
          <span className="flex items-center gap-1.5"><Letter side="a" /><span className="font-mono text-11 text-body">{c.layout[0]}</span></span>
          <span className="flex items-center gap-1.5"><Letter side="b" /><span className="font-mono text-11 text-body">{c.layout[1]}</span></span>
          {c.layout[0] !== c.layout[1] && <span className="inline-flex items-center h-4.5 px-1.5 rounded tint tone-amber text-10">≈ layout differs</span>}
        </>}
        <span className="flex-1" />
        {(a?.length || b?.length) ? <Button size="sm" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? 'Hide original ▴' : 'Show original ▾'}</Button> : null}
      </div>
      {open && <div className="flex gap-2 items-start">{original('a', a)}{original('b', b)}</div>}
    </div>
  )
}

function FormValue({ side, name, value, tone, open, onToggle, span }: { side?: 'a' | 'b'; name: string; value: string | null; tone: 'same' | 'a' | 'b'; open: boolean; onToggle: () => void; span?: boolean }) {
  if (value === null) return <div className="min-w-0 pl-6.5 py-0.5 font-mono text-11 text-faint">{MISSING}</div>
  return (
    <div className={cx('min-w-0 flex items-start gap-2 px-2 py-0.5 rounded font-mono text-11', span && 'col-span-2', tone === 'a' && 'tint tone-red', tone === 'b' && 'tint tone-green', tone === 'same' && 'text-body')}>
      <span className="w-2.5 shrink-0">{tone === 'a' ? '-' : tone === 'b' ? '+' : ''}</span>
      <span className="min-w-0 break-all">{value}</span>
      {value && <span className="shrink-0" data-side={side}><DecodeAffordance value={value} name={name} open={open} onToggle={onToggle} /></span>}
    </div>
  )
}

const FORM_GRID = 'grid grid-cols-[120px_minmax(0,1fr)_minmax(0,1fr)_20px] gap-x-2 items-start'

function FormField({ r }: { r: FormRow }) {
  const [open, setOpen] = useState<'a' | 'b' | null>(null)
  const toggle = (side: 'a' | 'b') => setOpen(open === side ? null : side)
  const shown = open === 'a' ? r.a : open === 'b' ? r.b : null
  return (
    <div className="group">
      <div className={FORM_GRID}>
        <span title={r.name} className="py-0.5 font-mono text-11 text-muted truncate">{r.name}</span>
        {/* An equal value renders once, across both columns. */}
        {r.same ? <FormValue name={r.name} value={r.a} tone="same" span open={open === 'a'} onToggle={() => toggle('a')} />
          : <>
            <FormValue side="a" name={r.name} value={r.a} tone="a" open={open === 'a'} onToggle={() => toggle('a')} />
            <FormValue side="b" name={r.name} value={r.b} tone="b" open={open === 'b'} onToggle={() => toggle('b')} />
          </>}
        <span className="flex justify-center py-0.5">
          {r.sameDecoded && <span data-tooltip="Decoded values are the same" aria-label="Decoded values are the same" className="font-mono text-13 font-medium leading-4 text-amber-fg">≈</span>}
        </span>
      </div>
      {shown !== null && (
        <div className={FORM_GRID}>
          <span />
          <div className="col-span-2 my-1 p-3 rounded-lg border border-edge-input bg-well"><Decoded value={shown} name={r.name} /></div>
        </div>
      )}
    </div>
  )
}

function FormTable({ form }: { form: NonNullable<BodyComparison['form']> }) {
  const [a, b] = form.order.map((o) => o.join(' · '))
  return (
    <div className="space-y-1">
      <div className={FORM_GRID}>
        <span className="py-0.5 font-mono text-11 text-muted">order</span>
        {a === b ? <FormValue name="" value={a} tone="same" span open={false} onToggle={() => {}} />
          : <><div className="min-w-0 flex gap-2 px-2 py-0.5 rounded font-mono text-11 tint tone-red"><span className="w-2.5">-</span><span className="break-all">{a || MISSING}</span></div>
            <div className="min-w-0 flex gap-2 px-2 py-0.5 rounded font-mono text-11 tint tone-green"><span className="w-2.5">+</span><span className="break-all">{b || MISSING}</span></div></>}
      </div>
      <div className="h-px bg-edge-card" />
      <div className={cx(FORM_GRID, 'text-10 font-semibold')}>
        <span className="text-faint">FIELD</span><span className="pl-6.5 text-cyan-fg">A&nbsp;&nbsp;VALUE</span><span className="pl-6.5 text-pink-fg">B&nbsp;&nbsp;VALUE</span>
      </div>
      {form.rows.map((r, i) => <FormField key={i} r={r} />)}
    </div>
  )
}

function bodyMeta(c: BodyComparison): string {
  if (c.form) return `form · ${c.form.rows.length} ${c.form.rows.length === 1 ? 'field' : 'fields'} · values as sent`
  if (!c.kind) return ''
  const kept = c.kind === 'xml' ? 'attribute order kept' : 'key order kept'
  const what = c.kind === 'json' || c.kind === 'xml' ? `${c.kind} · pretty-printed for the diff, ${kept}` : c.kind === 'binary' ? 'binary · hex dump' : 'text'
  return c.diff && !c.identical ? `${what} · ${changes(c.diff)}` : what
}

function AloneBody({ lines, binary }: { lines: string[]; binary: boolean }) {
  const { count } = fitLines(lines, renderBudget(binary))
  return (
    <div className="max-h-96 overflow-auto">
      <pre className="px-2 font-mono text-11 text-body whitespace-pre-wrap break-all">{lines.slice(0, count).join('\n')}</pre>
      {count < lines.length && <Cut binary={binary} copy="Copy body diff" />}
    </div>
  )
}

function BodySection({ n, bodies, error }: { n: number; bodies: Bodies | null; error: string }) {
  const c = bodies?.c
  const diffShown = !!c?.diff && !c.identical && c.diff.removed + c.diff.added > 0
  return (
    <section className="rounded-lg border border-edge-card bg-panel p-3 space-y-1.5">
      <header className="flex items-center gap-2.5">
        <h3 className="text-12 font-medium text-ink shrink-0">{n} Request body</h3>
        <span className="flex-1 min-w-0 truncate font-mono text-10 text-faint">{c && bodyMeta(c)}</span>
        {diffShown && <DiffViewSwitch />}
        {c && <Verdict body={c.verdict} />}
      </header>
      {error && <Banner>{error}</Banner>}
      {!bodies && !error && <Spinner />}
      {bodies && c && <>
        <AsSent {...bodies} />
        {c.bytesOnly && <p className="px-2 text-11 text-faint">A body is over 1 MiB or the diff is too large to lay out, so the bodies were compared byte for byte only.</p>}
        {c.alone && <>
          <p className="px-2 text-11 text-faint">Only {c.alone.side.toUpperCase()} has a body.</p>
          <AloneBody lines={c.alone.lines} binary={c.kind === 'binary'} />
        </>}
        {c.form && <FormTable form={c.form} />}
        {c.diff && c.verdict === 'layout' && <p className="px-2 text-11 text-faint">Pretty-printed, the bodies are the same.</p>}
        {diffShown && <DiffHunks diff={c.diff!} binary={c.kind === 'binary'} copy="Copy body diff" />}
      </>}
    </section>
  )
}

const requestType = (f: Flow) => f.requestBody?.contentType || f.requestHeaders?.find((h) => h.name?.toLowerCase() === 'content-type')?.value

async function requestBody(p: Pick, f: Flow): Promise<Uint8Array | null> {
  if (!num(f.requestBody?.size)) return null
  return f.requestBody?.inline ? base64Bytes(f.requestBody.inline) : api.getBody(p.session, f.id, false)
}

function MessageCompare({ picks, onClose, onClear }: Props) {
  const [a, b] = picks
  const [loaded, setLoaded] = useState<{ positions: (Position | null)[]; diff: UnifiedDiff; binary: boolean } | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    const position = async (p: Pick) => messagePosition(await api.listMessages(p.session, p.message!.flowId), p.id, p.message!.openMicros)
    const lines = (p: Pick) => payloadLines(p.session, p.message!.frame)
    Promise.all([position(a), position(b), lines(a), lines(b)])
      .then(([pa, pb, la, lb]) => setLoaded({ positions: [pa, pb], diff: unifiedDiff(la.lines, lb.lines), binary: la.binary || lb.binary }), (e: Error) => setError(e.message))
  }, [a, b])
  const sections = useMemo(() => compareMessages(a.message!.frame, b.message!.frame), [a, b])
  const banner = (p: Pick, i: number) => {
    const at = loaded?.positions[i]
    return `${p.message!.frame.fromClient ? '→' : '←'} ${at ? `#${at.index} · ` : ''}${p.label}`
  }
  return (
    <Modal flush title="A/B compare" width={1200} height={880} onClose={onClose} headerExtra={<>
      <span className="text-11 text-faint">order-sensitive · position is context, not compared</span>
    </>}>
      <div className="flex items-center gap-2 px-4 py-2 shrink-0 border-b border-line text-11 text-muted">
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
            <h3 className="text-12 font-medium text-ink">Position</h3>
            <div className="flex gap-2">
              {loaded.positions.map((p, i) => <div key={i} className="flex-1 min-w-0 px-2 font-mono text-11 text-body">{p ? positionLines(p).map((l) => <div key={l}>{l}</div>) : MISSING}</div>)}
            </div>
          </section>
        )}
        {sections.map((s, i) => <SectionCard key={s.title} s={s} n={i + 1} />)}
        {loaded && <PayloadDiff diff={loaded.diff} binary={loaded.binary} n={sections.length + 1} />}
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
