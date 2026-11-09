import { useCallback, useEffect, useRef, useState } from 'react'
import * as api from '../lib/api'
import { matchesTerms, plural, searchTerms } from '../lib/search'
import type { CaptureSourceInfo, Param, SourceDescriptor } from '../lib/types'
import { ChoiceSelect, Highlight, SearchBox, type Choice } from './Choice'
import { Banner, Button, cx, Field, inputClass, Modal, SectionLabel, Spinner } from './ui'

const MAX_RESEEDS = 3
const SETUP_FILTER_FROM = 6

const choicesOf = (p: Param): Choice[] => (p.choices ?? []).map((c) => ({ value: c.value ?? '', label: c.label || c.value || '' }))

function ParamField({ p, value, onChange }: { p: Param; value: string; onChange: (v: string) => void }) {
  const label = p.label || p.key
  switch (p.type) {
    case 'PARAM_TYPE_BOOL':
      return <label className="flex items-center gap-2 text-xs text-body"><input type="checkbox" className="accent-[var(--accent)]" checked={value === 'true'} onChange={(e) => onChange(String(e.target.checked))} />{label}{p.required && <span className="text-red-fg">*</span>}</label>
    case 'PARAM_TYPE_CHOICE':
      return (
        <Field label={label} required={p.required}>
          <ChoiceSelect choices={choicesOf(p)} value={value} onChange={onChange} optional={!p.required} noun={plural(label)} />
        </Field>
      )
    default:
      return <Field label={label} required={p.required}><input type={p.type === 'PARAM_TYPE_INT' ? 'number' : 'text'} spellCheck={false} className={inputClass} value={value} onChange={(e) => onChange(e.target.value)} /></Field>
  }
}

// The form is rendered from what the source describes, never per source: a third-party
// source gets the same UI as a built-in one.
export function NewCaptureDialog({ onClose, onStarted }: { onClose: () => void; onStarted: (sessionId: string) => void }) {
  const [sources, setSources] = useState<CaptureSourceInfo[] | null>(null)
  const [source, setSource] = useState('')
  const [params, setParams] = useState<Record<string, string>>({})
  const [touched, setTouched] = useState<Set<string>>(new Set())
  const [staged, setStaged] = useState<Record<string, string>>({})
  const [setupQuery, setSetupQuery] = useState<Record<string, string>>({})
  const [descriptor, setDescriptor] = useState<SourceDescriptor | null>(null)
  const [describing, setDescribing] = useState(false)
  const [label, setLabel] = useState('')
  const [error, setError] = useState('')
  const [starting, setStarting] = useState(false)
  const generation = useRef(0)

  useEffect(() => { api.listSources().then(setSources, (e: Error) => setError(e.message)) }, [])

  const paramsRef = useRef(params)
  paramsRef.current = params
  const touchedRef = useRef(touched)
  touchedRef.current = touched

  const touch = (keys: string[]) => {
    const next = new Set([...touchedRef.current, ...keys])
    touchedRef.current = next
    setTouched(next)
  }

  const describe = useCallback(async (name: string, values: Record<string, string>, reseeds = 0): Promise<void> => {
    const gen = ++generation.current
    setDescribing(true)
    try {
      const d = await api.describeSource(name, values)
      if (gen !== generation.current) return // superseded by a later change
      setError('')
      setDescriptor(d)
      const provisioning = d.readiness === 'READINESS_PROVISION_REQUIRED'
      const seeded: Record<string, string> = {}
      for (const p of d.params ?? []) {
        const only = p.choices?.length === 1 ? p.choices[0].value : undefined
        const dflt = p.default || (provisioning ? only : undefined)
        if (dflt && values[p.key] !== dflt && !touchedRef.current.has(p.key)) seeded[p.key] = dflt
      }
      // Provisioning can cost a large download, so its defaults are staged, never sent.
      if (provisioning) setStaged((s) => ({ ...seeded, ...s }))
      else if (Object.keys(seeded).length) {
        const next = { ...values, ...seeded }
        paramsRef.current = next
        setParams(next)
        // A seeded answer cascades like a typed one. Bounded, as describing spawns the source
        // and a third-party one could answer with defaults that never settle.
        if (reseeds < MAX_RESEEDS) void describe(name, next, reseeds + 1)
      }
    } catch (e) {
      if (gen === generation.current) setError((e as Error).message)
    } finally {
      if (gen === generation.current) setDescribing(false)
    }
  }, [])

  const pick = (name: string) => {
    setSource(name)
    setParams({})
    setTouched(new Set())
    setStaged({})
    setSetupQuery({})
    setDescriptor(null)
    void describe(name, {})
  }
  const change = (key: string, value: string) => {
    const next = { ...params, [key]: value }
    setParams(next)
    touch([key])
    void describe(source, next)
  }

  const provisioning = descriptor?.readiness === 'READINESS_PROVISION_REQUIRED'
  const asked = descriptor?.params ?? []
  const settingUp = provisioning && asked.length === 0
  useEffect(() => {
    if (!settingUp) return
    const t = setInterval(() => void describe(source, paramsRef.current), 2000)
    return () => clearInterval(t)
  }, [settingUp, source, describe])

  const setUp = () => {
    const next = { ...params, ...staged }
    setParams(next)
    touch(Object.keys(staged))
    setStaged({})
    void describe(source, next)
  }
  const start = async () => {
    setStarting(true)
    setError('')
    try {
      const r = await api.startCapture(source, label, params)
      if (r.sessionId) onStarted(r.sessionId)
      else setError('The source returned no session.')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setStarting(false)
    }
  }

  // Later params depend on earlier answers, so stop at the first unanswered required one.
  const firstMissing = asked.findIndex((p) => p.required && !params[p.key])
  const shown = firstMissing < 0 ? asked : asked.slice(0, firstMissing + 1)
  const missing = asked.filter((p) => p.required && !params[p.key])
  const crumbs = Object.entries(params).filter(([k, v]) => v && !asked.some((p) => p.key === k))
  const canStart = !!source && !!descriptor && !provisioning && missing.length === 0 && !starting

  // Filtering never unstages, so a staged answer the filter hides is still named.
  const hiddenStaged = provisioning ? asked.flatMap((p) => {
    const terms = searchTerms(setupQuery[p.key] ?? ''), c = choicesOf(p).find((c) => c.value === staged[p.key])
    return c && !matchesTerms(terms, [c.label, c.value]) ? [c.label] : []
  }) : []
  const footerNote = settingUp ? `waiting for ${source} to finish setting up`
    : hiddenStaged.length ? `Staged: ${hiddenStaged.join(', ')} — hidden by the filter. Nothing is sent until Set up.`
      : provisioning ? 'Selecting stages the answer — nothing is sent until Set up.'
        : missing.length ? `needs ${missing.map((p) => p.label || p.key).join(', ')}` : ''
  return (
    <Modal title="New capture" width={560} onClose={onClose} footer={<>
      <span className={cx('mr-auto text-[11px]', provisioning ? 'text-faint' : 'text-amber-fg')}>{footerNote}</span>
      <Button onClick={onClose}>Cancel</Button>
      {provisioning && !settingUp
        ? <Button variant="primary" disabled={asked.some((p) => p.required && !staged[p.key])} onClick={setUp}>Set up</Button>
        : <Button variant="primary" disabled={!canStart} onClick={() => void start()}>{starting ? 'Starting…' : 'Start capture'}</Button>}
    </>}>
      <div>
        <div className="mb-1.5"><SectionLabel>Source</SectionLabel></div>
        {sources === null ? <Spinner /> : (
          <div className="flex flex-wrap gap-1.5">
            {sources.map((s) => <Button key={s.name} size="sm" variant={source === s.name ? 'active' : 'default'} onClick={() => pick(s.name)}>{s.label || s.name}</Button>)}
          </div>
        )}
      </div>
      {error && <Banner onDismiss={() => setError('')}>{error}</Banner>}
      {source && !descriptor && describing && <p className="flex items-center gap-2 text-[11px] text-muted"><Spinner size={12} />Asking {source} what it needs…</p>}
      {descriptor?.message && (
        <div className={cx('flex items-center gap-2 px-2.5 py-2 rounded-md border text-[11px]', provisioning ? 'tint tone-amber [--a:8%]' : 'border-edge-card bg-panel text-muted')}>
          {settingUp && <Spinner size={12} />}{descriptor.message}
        </div>
      )}
      {crumbs.length > 0 && <div className="flex flex-wrap gap-1.5">{crumbs.map(([k, v]) => <span key={k} className="px-1.5 h-5 inline-flex items-center rounded border border-edge font-mono text-[10px] text-muted">{k}: {v}</span>)}</div>}
      {provisioning && asked.map((p) => (
        <div key={p.key}>
          <span className="block mb-1.5 text-xs text-body">{p.label || p.key}{p.required && <span className="text-red-fg"> *</span>}</span>
          {p.type === 'PARAM_TYPE_CHOICE' ? (
            <SetupChoices p={p} staged={staged[p.key]} query={setupQuery[p.key] ?? ''} onQuery={(q) => setSetupQuery({ ...setupQuery, [p.key]: q })}
              onStage={(v) => setStaged({ ...staged, [p.key]: v })} />
          ) : <ParamField p={p} value={staged[p.key] ?? ''} onChange={(v) => setStaged({ ...staged, [p.key]: v })} />}
        </div>
      ))}
      {descriptor && !provisioning && <>
        <Field label="Label"><input className={inputClass} value={label} onChange={(e) => setLabel(e.target.value)} /></Field>
        {shown.map((p) => <ParamField key={p.key} p={p} value={params[p.key] ?? ''} onChange={(v) => change(p.key, v)} />)}
      </>}
    </Modal>
  )
}

// The setup step's rows stage an answer each; a long list gets a filter box over them.
function SetupChoices({ p, staged, query, onQuery, onStage }: { p: Param; staged?: string; query: string; onQuery: (q: string) => void; onStage: (v: string) => void }) {
  const choices = choicesOf(p)
  const terms = searchTerms(query)
  const shown = choices.filter((c) => matchesTerms(terms, [c.label, c.value]))
  const label = p.label || p.key
  return (
    <div className="space-y-1.5">
      {choices.length >= SETUP_FILTER_FROM && <SearchBox tall query={query} onQuery={onQuery} shown={shown.length} total={choices.length} label={`Filter ${plural(label)}`} placeholder="Filter" />}
      <div role="radiogroup" aria-label={label} className="space-y-1">
        {shown.map((c) => (
          <button key={c.value} type="button" role="radio" aria-checked={staged === c.value} onClick={() => onStage(c.value)}
            className={cx('flex items-center gap-2.5 w-full min-h-10 px-3 py-1.5 rounded-md border text-left text-xs', staged === c.value ? 'tone-blue tint border-accent' : 'bg-well border-edge text-body')}>
            <span className={cx('w-3 h-3 rounded-full border shrink-0', staged === c.value ? 'border-accent bg-accent' : 'border-edge-check')} />
            <Highlight text={c.label} terms={terms} />
          </button>
        ))}
        {!shown.length && <p className="px-1 py-2 text-xs text-muted">No {plural(label)} match “{query.trim()}”. <span className="text-[11px] text-faint">Search reads labels and values.</span></p>}
      </div>
    </div>
  )
}
