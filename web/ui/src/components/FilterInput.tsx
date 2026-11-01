import { Search } from 'lucide-react'
import { useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { opAtCaret, type HelpTerm } from '../lib/filter'
import { cx } from './ui'

function Highlight({ text }: { text: string }) {
  // Split keeping the spaces, so the mirror's width matches the input's character for character.
  return <>{text.split(/(\s+)/).map((tok, i) => {
    const m = /^(!?)(~\w+)$/.exec(tok)
    if (!m) return <span key={i} className="text-ink">{tok}</span>
    return <span key={i}><span className="text-red-fg">{m[1]}</span><span className="text-purple-fg">{m[2]}</span></span>
  })}</>
}

function TermRow({ term, active, onPick }: { term: HelpTerm; active?: boolean; onPick: () => void }) {
  return (
    <button type="button" onMouseDown={(e) => e.preventDefault()} onClick={onPick}
      className={cx('flex items-center w-full h-5 px-2 rounded text-left text-[11px]', active ? 'bg-sel' : 'hover:bg-hover')}>
      <span className="w-[92px] font-mono shrink-0"><span className="text-purple-fg">{term.op}</span>{term.arg && <span className="text-dim"> {term.arg}</span>}</span>
      <span className="text-muted truncate">{term.meaning}</span>
      {active && <kbd className="ml-auto px-1 rounded bg-well text-faint font-mono text-[10px]">⇥</kbd>}
    </button>
  )
}

const Key = ({ children }: { children: ReactNode }) => <kbd className="px-1 mx-0.5 rounded border border-edge bg-well font-mono text-[10px] text-muted">{children}</kbd>

function Legend() {
  return (
    <div className="px-3 py-2 border-t border-line text-[11px] text-faint">
      <div>space = AND · ! negates</div>
      <div>arguments are unanchored RE2 regexes · a bare word matches the {'URL'}</div>
      <div className="flex items-center mt-1.5"><Key>↑↓</Key>move<span className="w-2" /><Key>⇥</Key>insert<span className="w-2" /><Key>Esc</Key>close<span className="flex-1" /><Key>Ctrl Space</Key>reopen</div>
    </div>
  )
}

interface Props {
  value: string
  onChange: (v: string) => void
  onSubmit?: () => void
  terms: HelpTerm[]
  examples: string[][]
  placeholder: string
  trailing?: ReactNode
  extraHelp?: string
}

// The input shows one expression; a mirror behind transparent text colours its terms.
export function FilterInput({ value, onChange, onSubmit, terms, examples, placeholder, trailing, extraHelp }: Props) {
  const input = useRef<HTMLInputElement>(null)
  const mirror = useRef<HTMLDivElement>(null)
  const [open, setOpen] = useState(false)
  const [caret, setCaret] = useState(0)
  const [active, setActive] = useState(0)

  const typing = opAtCaret(value, caret)
  const matches = useMemo(() => (typing ? terms.filter((t) => t.op.startsWith(typing.prefix)).sort((a, b) => a.op.length - b.op.length) : []), [typing, terms])
  const mode: 'all' | 'narrow' | null = !open ? null : !value.trim() ? 'all' : matches.length ? 'narrow' : null
  const flat = mode === 'all' ? terms : matches
  const groups = useMemo(() => [...new Set(terms.map((t) => t.group))], [terms])

  useLayoutEffect(() => {
    if (mirror.current && input.current) mirror.current.scrollLeft = input.current.scrollLeft
  })

  const change = (next: string, at: number) => {
    onChange(next)
    setCaret(at)
    setActive(0)
    setOpen(true)
  }
  const insert = (term: HelpTerm) => {
    const start = typing ? typing.start : caret
    const end = typing ? typing.start + typing.prefix.length : caret
    const sep = !typing && start > 0 && value[start - 1] !== ' ' ? ' ' : ''
    const text = `${sep}${term.op} `
    const next = value.slice(0, start) + text + value.slice(end)
    const at = start + text.length
    onChange(next)
    setCaret(at)
    setOpen(false)
    requestAnimationFrame(() => {
      input.current?.focus()
      input.current?.setSelectionRange(at, at)
    })
  }
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.ctrlKey && e.key === ' ') {
      e.preventDefault()
      setOpen(true)
    } else if (mode && e.key === 'Escape') {
      e.preventDefault()
      e.stopPropagation()
      setOpen(false)
    } else if (mode && e.key === 'ArrowDown') {
      e.preventDefault()
      setActive((a) => (a + 1) % flat.length)
    } else if (mode && e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((a) => (a - 1 + flat.length) % flat.length)
    } else if (mode && e.key === 'Tab' && flat[active]) {
      e.preventDefault()
      insert(flat[active])
    } else if (e.key === 'Enter') {
      setOpen(false)
      onSubmit?.()
    }
  }

  return (
    <div className="relative flex-1 min-w-[180px]">
      <div className="flex items-center gap-2 h-8 px-2.5 rounded-md bg-well border border-edge-input focus-within:border-accent focus-within:shadow-[0_0_0_1px_var(--accent)]">
        <Search size={13} className="text-faint shrink-0" />
        <div className="relative flex-1 min-w-0 h-full font-mono text-xs">
          <div ref={mirror} aria-hidden className="absolute inset-0 flex items-center overflow-hidden whitespace-pre pointer-events-none">
            {value ? <span><Highlight text={value} /></span> : <span className="text-dim">{placeholder}</span>}
          </div>
          <input ref={input} value={value} aria-label="Filter expression" spellCheck={false} autoComplete="off"
            className="absolute inset-0 w-full bg-transparent text-transparent caret-[var(--text)] outline-none! border-0! shadow-none! font-mono text-xs"
            onChange={(e) => change(e.target.value, e.target.selectionStart ?? 0)}
            onFocus={() => setOpen(true)} onBlur={() => setOpen(false)}
            onSelect={(e) => setCaret(e.currentTarget.selectionStart ?? 0)}
            onScroll={(e) => { if (mirror.current) mirror.current.scrollLeft = e.currentTarget.scrollLeft }}
            onKeyDown={onKey} />
        </div>
        {trailing}
      </div>
      {mode === 'all' && (
        <div className="absolute z-30 top-[calc(100%+6px)] left-0 w-[640px] max-w-[85vw] rounded-lg border border-edge bg-toast" style={{ boxShadow: '0 8px 24px var(--shadow)' }}>
          <div className="px-3 py-2.5 border-b border-line">
            <div className="mb-1.5 text-[10px] uppercase tracking-wide text-faint">Examples</div>
            <div className="flex flex-wrap gap-1.5">
              {examples.map(([label, expr]) => (
                <button key={label} type="button" onMouseDown={(e) => e.preventDefault()} onClick={() => { onChange(expr); setOpen(false) }}
                  className="inline-flex items-center gap-1.5 h-6 px-2 rounded-full bg-well border border-edge text-[11px] text-body hover:border-edge-strong">
                  {label} <span className="font-mono text-purple-fg">{expr}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="columns-2 gap-3 px-1.5 py-2">
            {groups.map((g) => (
              <div key={g} className="break-inside-avoid mb-2">
                <div className="px-2 mb-0.5 text-[10px] uppercase tracking-wide text-faint">{g}</div>
                {terms.filter((t) => t.group === g).map((t) => <TermRow key={t.op} term={t} active={flat[active] === t} onPick={() => insert(t)} />)}
              </div>
            ))}
          </div>
          {extraHelp && <div className="px-3 pb-2 text-[11px] text-faint">{extraHelp}</div>}
          <Legend />
        </div>
      )}
      {mode === 'narrow' && (
        <div className="absolute z-30 top-[calc(100%+6px)] left-8 w-[360px] max-w-[85vw] rounded-lg border border-edge bg-toast" style={{ boxShadow: '0 8px 24px var(--shadow)' }}>
          <div className="p-1.5">{matches.map((t, i) => <TermRow key={t.op} term={t} active={i === active} onPick={() => insert(t)} />)}</div>
          <Legend />
        </div>
      )}
    </div>
  )
}
