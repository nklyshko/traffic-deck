import { useEffect, useMemo, useState, type ReactNode } from 'react'
import * as api from '../lib/api'
import { bodyDiffText, bodyText, compareBodies, fitLines, renderBudget, compareFlows, compareMessages, cookieOrder, diffParts, diffText, goSlice, headerOrder, messagePosition, MISSING, positionSection, prettyPayload, pseudoOrder, splitRows, unifiedDiff, differingParts, type BodyComparison, type BodyVerdict, type CmpRow, type DiffLine, type DiffPart, type FormRow, type Position, type Section, type UnifiedDiff } from '../lib/compare'
import { num } from '../lib/format'
import { base64Bytes, HEX_CAP, hexDump, looksTextual, TEXT_CAP } from '../lib/http'
import { useSetting } from '../lib/settings'
import type { Flow, WsMessage } from '../lib/types'
import { DecodeAffordance, Decoded } from './Decode'
import type { Pick } from './Workspace'
import { Banner, Button, CopyButton, cx, Modal, SectionLabel, Spinner } from './ui'

const LONG = 120

// One grid for every compare table: the name once, A and B, and a note column kept on every
// row so the value columns line up whether or not a row has a note.
const GRID = 'grid grid-cols-[10.5rem_minmax(0,1fr)_minmax(0,1fr)_1.25rem] gap-x-2 items-start'
type Side = 'a' | 'b'
const SIDE: Record<Side, string> = { a: 'side-a', b: 'side-b' }

// Only the characters that differ, each side marking its own, found as git's --word-diff.
function Marked({ side, text, other }: { side: Side; text: string; other: string }) {
  const parts = useMemo(() => (side === 'a' ? differingParts(text, other) : differingParts(other, text)), [side, text, other])
  const own = side === 'a' ? '-' : '+'
  if (!parts) return <>{text}</>
  return <>{parts.map((p, i) => (p.kind === ' ' ? <span key={i}>{p.text}</span>
    : p.kind === own ? <span key={i} className={cx('tint [--a:20%] rounded-[3px] font-medium', SIDE[side])}>{p.text}</span> : null))}</>
}

function Value({ text, other, side, full, open, onToggle }: { text: string; other?: string; side?: Side; full?: boolean; open: boolean; onToggle: () => void }) {
  const body = side && other !== undefined ? <Marked side={side} text={text} other={other} /> : text
  if (full || text.length <= LONG) return <span className="min-w-0 break-all">{body}</span>
  return (
    <button type="button" aria-expanded={open} onClick={onToggle} className="min-w-0 text-left break-all">
      {open ? <>▼ {body}</> : `▶ ${text.slice(0, 60)}… (${text.length} chars)`}
    </button>
  )
}

const present = (v: string | null): v is string => v !== null && v !== MISSING

/** A compare table row: the name once, then one cell when equal or A │ B when not. A context
 *  row splits untinted, as each side has its own value without differing. */
export function CmpLine({ row: r, context, tails, note, children }: {
  row: CmpRow; context?: boolean; tails?: [ReactNode, ReactNode]; note?: ReactNode; children?: ReactNode
}) {
  const [open, setOpen] = useState(false)
  const toggle = () => setOpen(!open)
  const cell = 'min-w-0 min-h-5.5 flex items-start gap-2 px-2 py-0.5 rounded font-mono text-11'
  const side = (s: Side) => {
    const v = r[s], other = r[s === 'a' ? 'b' : 'a']
    // An ordered list leaves the place blank; a named value one side lacks is a faint ∅.
    if (v === null) return <div className={cell} />
    if (v === MISSING) return <div className={cx(cell, 'text-faint')}>{MISSING}</div>
    return (
      <div className={cx(cell, context ? 'text-body' : cx('tint [--a:10%] text-ink', SIDE[s]))}>
        <Value text={v} other={!context && present(other) ? other : undefined} side={s} full={r.full} open={open} onToggle={toggle} />
        {tails?.[s === 'a' ? 0 : 1]}
      </div>
    )
  }
  return (
    <>
      <div className={GRID}>
        <span title={r.name} className="py-0.5 font-mono text-11 text-muted truncate">{r.name}</span>
        {r.same && !context
          ? <div className={cx(cell, 'col-span-2 text-body', r.a === MISSING && 'text-faint')}><Value text={r.a ?? ''} full={r.full} open={open} onToggle={toggle} />{tails?.[0]}</div>
          : <>{side('a')}{side('b')}</>}
        <span className="flex justify-center py-0.5">{note}</span>
      </div>
      {children}
    </>
  )
}

const VERDICTS: Record<BodyVerdict, [string, string]> = {
  match: ['✓ match', 'tone-green'], layout: ['≈ layout only', 'tone-amber'], encoding: ['≈ encoding only', 'tone-amber'], differ: ['✗ differ', 'tone-red'],
}
const Verdict = ({ match, body }: { match?: boolean; body?: BodyVerdict }) => {
  const [label, tone] = VERDICTS[body ?? (match ? 'match' : 'differ')]
  return <span className={cx('inline-flex items-center h-5 px-2 shrink-0 rounded-full tint text-10 whitespace-nowrap', tone)}>{label}</span>
}

function SectionCard({ s, n }: { s: Section; n: number | string }) {
  const [open, setOpen] = useState(false)
  const title = <h3 className="text-12 font-medium text-ink">{n} {s.title}</h3>
  // A match folds to one line, its value once, so the scroll goes to what differs.
  if (s.match && !s.context) return (
    <section className="flex items-center gap-2 min-h-10 px-3 py-2 rounded-lg border border-edge-card bg-panel">
      <span className="w-42 shrink-0">{title}</span>
      <div className="flex-1 min-w-0 flex px-2 font-mono text-11 text-body"><Value text={s.fold} open={open} onToggle={() => setOpen(!open)} /></div>
      <span className="w-5 shrink-0" />
      <Verdict match />
    </section>
  )
  return (
    <section className="rounded-lg border border-edge-card bg-panel p-3 space-y-0.75">
      <header className="flex items-center gap-2">
        {title}
        <span className="flex-1" />
        {!s.context && <Verdict match={s.match} />}
      </header>
      {s.rows.map((r, i) => (r.decode ? <DecodeLine key={i} row={r} /> : <CmpLine key={i} row={r} context={s.context} />))}
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
          <CopyChip label="Header order" text={goSlice(headerOrder(chosen))} />
          <CopyChip label="Pseudo order" text={goSlice(pseudoOrder(chosen))} />
          <CopyChip label="Cookie order" text={goSlice(cookieOrder(chosen))} />
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

// The unified diff is the one place both sides share a column, so only it keeps −/+, in the
// side colours; side by side the column says the side.
const sign = (l: DiffLine) => (l.kind === ' ' ? '' : l.kind === '-' ? '−' : '+')
const signTone = (l: DiffLine) => (l.kind === '-' ? 'text-cyan-fg' : 'text-pink-fg')
const lineTone = (l: DiffLine) => (l.kind === ' ' ? 'text-body' : cx('tint [--a:10%] text-ink', l.kind === '-' ? 'side-a' : 'side-b'))

function SplitLine({ l, side }: { l: DiffLine | null; side: 'a' | 'b' }) {
  if (!l) return <div className="flex-1 min-w-0 rounded-sm bg-well" />
  return (
    <div className={cx('flex-1 min-w-0 flex px-2 rounded-sm', lineTone(l))}>
      <span className="w-10 shrink-0 text-right text-faint select-none">{l[side]}</span>
      <span className="w-3 shrink-0" />
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
            {/* Not cyan: cyan is side A's alone. */}
            <div className="px-2 rounded-sm bg-well text-muted">{p.header}</div>
            {view === 'split'
              ? splitRows(lines).map(([a, b], i) => <div key={i} className="flex gap-2"><SplitLine l={a} side="a" /><SplitLine l={b} side="b" /></div>)
              : lines.map((l, i) => (
                <div key={i} className={cx('flex px-2 rounded-sm', lineTone(l))}>
                  <span className="w-10 shrink-0 text-right text-faint select-none">{l.a}</span>
                  <span className="w-10 shrink-0 text-right text-faint select-none">{l.b}</span>
                  <span className={cx('w-5 shrink-0 text-center font-medium select-none', signTone(l))}>{sign(l)}</span>
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
        {!same && <span className="font-mono text-11"><span className="text-cyan-fg">−{diff.removed}</span> <span className="text-pink-fg">+{diff.added}</span></span>}
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

/** A row whose values each get a decoder chip; one side's decoder opens under the row at a time. */
function DecodeLine({ row: r }: { row: CmpRow }) {
  const [open, setOpen] = useState<Side | null>(null)
  const name = r.name ?? ''
  const shown = open ? r[open] : null
  const chip = (s: Side) => {
    const v = r[s]
    return present(v) ? <span className="shrink-0" data-side={s}><DecodeAffordance value={v} name={name} open={open === s} onToggle={() => setOpen(open === s ? null : s)} /></span> : null
  }
  return (
    <div className="group">
      <CmpLine row={r} tails={[chip('a'), chip('b')]}
        note={r.sameDecoded && <span data-tooltip="Decoded values are the same" aria-label="Decoded values are the same" className="font-mono text-13 font-medium leading-4 text-amber-fg">≈</span>}>
        {present(shown) && (
          <div className={GRID}>
            <span />
            <div className="col-span-2 my-1 p-3 rounded-lg border border-edge-input bg-well"><Decoded value={shown} name={name} /></div>
          </div>
        )}
      </CmpLine>
    </div>
  )
}

const FormField = ({ r }: { r: FormRow }) =>
  <DecodeLine row={{ name: r.name, a: r.a ?? MISSING, b: r.b ?? MISSING, same: r.same, sameDecoded: r.sameDecoded }} />

function FormTable({ form }: { form: NonNullable<BodyComparison['form']> }) {
  const [a, b] = form.order.map((o) => o.join(' · ') || MISSING)
  return (
    <div className="space-y-0.75">
      <CmpLine row={{ name: 'order', a, b, same: a === b }} />
      <div className="h-px bg-edge-card" />
      <div className={cx(GRID, 'text-10 font-semibold')}>
        <span className="text-faint">FIELD</span><span className="px-2 text-cyan-fg">A&nbsp;&nbsp;VALUE</span><span className="px-2 text-pink-fg">B&nbsp;&nbsp;VALUE</span>
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
        {loaded && <SectionCard s={positionSection(loaded.positions[0], loaded.positions[1])} n="·" />}
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
