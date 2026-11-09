import { Check, ChevronDown, ChevronUp, Search, X } from 'lucide-react'
import { useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { matchesTerms, matchRuns, searchTerms } from '../lib/search'
import { cx, IconButton, inputClass } from './ui'

export const CHOICE_SEARCH_FROM = 8
const VISIBLE_ROWS = 8
const ROW = 28

export interface Choice { value: string; label: string }

export function Highlight({ text, terms, className }: { text: string; terms: string[]; className?: string }) {
  if (!terms.length) return <span className={className}>{text}</span>
  return <span className={className}>{matchRuns(text, terms).map((r, i) => r.hit ? <span key={i} className="font-semibold text-blue-fg">{r.text}</span> : r.text)}</span>
}

export function SearchBox({ query, onQuery, shown, total, label, placeholder = 'Search', inputRef, onKeyDown, tall }: {
  query: string; onQuery: (q: string) => void; shown: number; total: number; label: string; placeholder?: string
  inputRef?: React.RefObject<HTMLInputElement | null>; onKeyDown?: (e: React.KeyboardEvent<HTMLInputElement>) => void; tall?: boolean
}) {
  return (
    // On its own, Esc clears a query before the dialog gets it; in a choice list the list owns it.
    <div data-owns-escape={(!onKeyDown && query) || undefined} className={cx('flex items-center gap-2 pl-2 pr-1 rounded-md bg-well border border-edge-input focus-within:border-accent', tall ? 'h-8' : 'h-7')}>
      <Search size={13} className="text-faint shrink-0" />
      <input ref={inputRef} type="search" aria-label={label} spellCheck={false} value={query} placeholder={placeholder}
        onChange={(e) => onQuery(e.target.value)} onKeyDown={onKeyDown ?? ((e) => { if (e.key === 'Escape' && query) onQuery('') })}
        className="flex-1 min-w-0 h-full bg-transparent text-xs text-ink placeholder:text-dim outline-none! border-0! shadow-none! [&::-webkit-search-cancel-button]:hidden" />
      {query && <>
        <span className="shrink-0 text-[11px] text-faint">{shown} of {total}</span>
        <IconButton label="Clear search" size={20} onClick={() => { onQuery(''); inputRef?.current?.focus() }}><X size={13} /></IconButton>
      </>}
    </div>
  )
}

const Key = ({ children }: { children: ReactNode }) => <kbd className="px-1 rounded border border-edge bg-well font-mono text-[10px] text-muted">{children}</kbd>

// A select that opens a list, searchable once it is long (SPEC §5.3). The list is portalled,
// as the dialog's body scrolls and would clip it.
export function ChoiceSelect({ choices, value, onChange, optional, noun }: {
  choices: Choice[]; value: string; onChange: (v: string) => void; optional: boolean; noun: string
}) {
  const [open, setOpen] = useState(false)
  const trigger = useRef<HTMLButtonElement>(null)
  const current = choices.find((c) => c.value === value)
  const close = () => { setOpen(false); trigger.current?.focus() }
  return (
    <>
      <button ref={trigger} type="button" aria-haspopup="listbox" aria-expanded={open} data-owns-escape={open || undefined}
        onClick={() => setOpen(!open)} onKeyDown={(e) => { if (!open && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) { e.preventDefault(); setOpen(true) } }}
        className={cx(inputClass, 'flex items-center gap-2 text-left', open && 'border-accent')}>
        <span className={cx('flex-1 truncate', !value && 'text-dim')}>{value ? (current?.label || value) : '—'}</span>
        {open ? <ChevronUp size={14} className="text-muted shrink-0" /> : <ChevronDown size={14} className="text-muted shrink-0" />}
      </button>
      {open && trigger.current && (
        <ChoiceList anchor={trigger.current} choices={choices} value={value} optional={optional} noun={noun}
          onPick={(v) => { close(); if (v !== value) onChange(v) }} onClose={close} />
      )}
    </>
  )
}

function ChoiceList({ anchor, choices, value, optional, noun, onPick, onClose }: {
  anchor: HTMLElement; choices: Choice[]; value: string; optional: boolean; noun: string; onPick: (v: string) => void; onClose: () => void
}) {
  const searchable = choices.length >= CHOICE_SEARCH_FROM
  const [query, setQuery] = useState('')
  const terms = useMemo(() => searchTerms(query), [query])
  // The clear row only while browsing: it names no choice a query could find.
  const rows = useMemo(() => {
    const found = choices.filter((c) => matchesTerms(terms, [c.label, c.value]))
    return optional && !terms.length ? [{ value: '', label: '—' }, ...found] : found
  }, [choices, terms, optional])
  const [active, setActive] = useState(() => Math.max(0, rows.findIndex((r) => r.value === value)))
  const [below, setBelow] = useState(0)
  const panel = useRef<HTMLDivElement>(null)
  const list = useRef<HTMLDivElement>(null)
  const search = useRef<HTMLInputElement>(null)
  const [place, setPlace] = useState<React.CSSProperties>({ visibility: 'hidden' })

  useLayoutEffect(() => {
    const at = () => {
      const r = anchor.getBoundingClientRect(), h = panel.current?.offsetHeight ?? 0
      const up = window.innerHeight - r.bottom < h + 8 && r.top > window.innerHeight - r.bottom
      setPlace({ left: r.left, width: r.width, ...(up ? { bottom: window.innerHeight - r.top + 4 } : { top: r.bottom + 4 }) })
    }
    at()
    window.addEventListener('resize', at)
    window.addEventListener('scroll', at, true)
    return () => { window.removeEventListener('resize', at); window.removeEventListener('scroll', at, true) }
  }, [anchor, rows.length])

  const closeRef = useRef(onClose)
  useEffect(() => { closeRef.current = onClose })
  useEffect(() => {
    // After the click that opened the list has finished focusing the field.
    const f = requestAnimationFrame(() => search.current?.focus())
    const outside = (e: MouseEvent) => {
      if (!panel.current?.contains(e.target as Node) && !anchor.contains(e.target as Node)) closeRef.current()
    }
    document.addEventListener('mousedown', outside)
    return () => { cancelAnimationFrame(f); document.removeEventListener('mousedown', outside) }
  }, [anchor])

  useEffect(() => { list.current?.querySelector(`[data-row="${active}"]`)?.scrollIntoView({ block: 'nearest' }) }, [active])
  const measure = () => {
    const l = list.current
    if (l) setBelow(Math.max(0, rows.length - Math.ceil((l.scrollTop + l.clientHeight) / (ROW + 1))))
  }
  useLayoutEffect(measure, [rows.length])

  const keys = (e: React.KeyboardEvent | KeyboardEvent) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      if (rows.length) setActive((a) => (a + (e.key === 'ArrowDown' ? 1 : rows.length - 1)) % rows.length)
    } else if (e.key === 'Enter') {
      e.preventDefault()
      if (rows[active]) onPick(rows[active].value)
    } else if (e.key === 'Escape') {
      e.preventDefault()
      onClose()
    } else if (e.key === 'Tab') onClose()
  }
  // Without a search box focus stays on the field, so the keys are read there.
  useEffect(() => {
    if (searchable) return
    anchor.addEventListener('keydown', keys)
    return () => anchor.removeEventListener('keydown', keys)
  })

  return createPortal(
    <div ref={panel} data-owns-escape className="fixed z-50 flex flex-col rounded-lg border border-edge-strong bg-toast overflow-hidden shadow-[0_12px_32px_var(--shadow)]" style={place}>
      {searchable && (
        <div className="p-1.5 border-b border-edge">
          <SearchBox inputRef={search} query={query} label={`Search ${noun}`} shown={rows.length} total={choices.length}
            onQuery={(q) => { setQuery(q); setActive(0) }} onKeyDown={keys} />
        </div>
      )}
      {rows.length ? (
        <div ref={list} role="listbox" onScroll={measure} className="p-1 space-y-px overflow-y-auto" style={{ maxHeight: VISIBLE_ROWS * (ROW + 1) + 8 }}>
          {rows.map((c, i) => (
            <div key={c.value} data-row={i} role="option" aria-selected={c.value === value} onMouseMove={() => setActive(i)} onClick={() => onPick(c.value)}
              className={cx('flex items-center gap-1.5 h-7 pl-1.5 pr-2 rounded text-xs text-ink cursor-default', i === active && 'tint tone-blue [--a:14%]')}>
              <span className="w-3.5 shrink-0 flex justify-center text-accent">{c.value === value && <Check size={12} strokeWidth={3} />}</span>
              <Highlight text={c.label} terms={terms} className={cx('truncate text-ink', !c.value && 'text-dim', c.value === value && 'font-medium')} />
              <span className="flex-1" />
              {c.value && c.value !== c.label && <Highlight text={c.value} terms={terms} className="truncate max-w-[50%] font-mono text-[11px] text-faint" />}
            </div>
          ))}
        </div>
      ) : (
        <div className="px-3.5 py-3 space-y-1">
          <p className="text-xs text-muted">No {noun} match “{query.trim()}”.</p>
          <p className="text-[11px] text-faint">Search reads labels and values.</p>
        </div>
      )}
      {below > 0 && <p className="pl-[30px] pr-2 h-6 flex items-center text-[11px] text-faint">{below} more — scroll{searchable ? ' or type to narrow' : ''}</p>}
      <div className="flex items-center gap-1.5 px-2.5 py-1.5 border-t border-edge bg-head text-[11px] text-faint">
        <Key>↑↓</Key>move <Key>↵</Key>choose <Key>Esc</Key>close
      </div>
    </div>,
    document.body,
  )
}
