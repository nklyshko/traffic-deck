import { Check, Copy, X } from 'lucide-react'
import { useEffect, useRef, useState, type ButtonHTMLAttributes, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { formatDuration, durationTone, methodTone, num, preciseDuration, reasonPhrase, shortMethod, statusTone, type Tone } from '../lib/format'

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ')
}

type Variant = 'default' | 'primary' | 'active' | 'danger' | 'destructive' | 'ghost'
const VARIANTS: Record<Variant, string> = {
  default: 'bg-raised border border-edge text-body hover:border-edge-strong',
  primary: 'bg-primary border border-transparent text-white font-semibold',
  active: 'tone-blue tint [--a:15%] border border-[color-mix(in_srgb,var(--blue)_40%,transparent)]',
  danger: 'tone-red tint [--a:10%] border border-[color-mix(in_srgb,var(--red)_30%,transparent)]',
  destructive: 'bg-red border border-transparent text-white font-semibold',
  ghost: 'border border-transparent text-muted hover:text-ink hover:bg-hover',
}
const SIZES = { md: 'h-8 px-3 text-xs rounded-md gap-1.5', sm: 'h-[26px] px-2.5 text-[11px] rounded-md gap-1.5', xs: 'h-[22px] px-2 text-[11px] rounded-[5px] gap-1' }

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: keyof typeof SIZES
  icon?: ReactNode
  tooltip?: string
}
export function Button({ variant = 'default', size = 'md', icon, tooltip, className, children, ...rest }: ButtonProps) {
  return (
    <button type="button" data-tooltip={tooltip} {...rest}
      className={cx('inline-flex items-center justify-center whitespace-nowrap shrink-0 disabled:opacity-40', VARIANTS[variant], SIZES[size], className)}>
      {icon}{children}
    </button>
  )
}

export function IconButton({ label, className, size = 32, children, ...rest }: Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'aria-label'> & { label: string; size?: number }) {
  return (
    <button type="button" title={label} aria-label={label} style={{ width: size, height: size }} {...rest}
      className={cx('inline-flex items-center justify-center shrink-0 rounded-md text-muted hover:text-ink hover:bg-hover disabled:opacity-30', className)}>
      {children}
    </button>
  )
}

const BADGE = { sm: 'h-[18px] text-[10px] px-1.5', md: 'h-5 text-[11px] px-1.5', lg: 'h-[22px] text-xs px-[7px]' }
export function Badge({ tone = 'grey', size = 'md', title, children }: { tone?: Tone; size?: keyof typeof BADGE; title?: string; children: ReactNode }) {
  return <span title={title} className={cx('inline-flex items-center gap-1 rounded font-mono font-medium tint shrink-0', `tone-${tone}`, BADGE[size])}>{children}</span>
}

export function MethodBadge({ method, size }: { method?: string; size?: keyof typeof BADGE }) {
  if (!method) return <span className="text-dim font-mono">—</span>
  return <Badge tone={methodTone(method)} size={size}>{shortMethod(method)}</Badge>
}

export function StatusBadge({ status, error, size }: { status?: number; error?: string; size?: keyof typeof BADGE }) {
  if (!status && error) return <Badge tone="red" size={size} title={error}>err</Badge>
  if (!status) return <span className="text-faint font-mono">···</span>
  const title = `${status} ${reasonPhrase(status)}${error ? `\n${error}` : ''}`
  return <Badge tone={statusTone(status)} size={size} title={title}>{status}{error ? <span aria-label="error">⚠</span> : null}</Badge>
}

export function DurationBadge({ micros }: { micros?: string }) {
  const us = num(micros)
  const tone = durationTone(us)
  if (!tone) return <span className="text-dim font-mono">—</span>
  return <Badge tone={tone} title={preciseDuration(us)}>{formatDuration(us)}</Badge>
}

export function Pill({ tone = 'grey', dot, children }: { tone?: Tone; dot?: boolean; children: ReactNode }) {
  return (
    <span className={cx('inline-flex items-center gap-1.5 h-[22px] px-2.5 rounded-[11px] tint text-[11px] font-medium shrink-0', `tone-${tone}`)}>
      {dot && <span className="w-1.5 h-1.5 rounded-full pulse" style={{ background: 'var(--t)' }} />}{children}
    </span>
  )
}

export function Banner({ tone = 'red', onDismiss, children }: { tone?: Tone; onDismiss?: () => void; children: ReactNode }) {
  return (
    <div role="alert" className={cx('flex items-start gap-2 px-3 py-2 rounded-lg tint [--a:8%] border text-xs', `tone-${tone}`)} style={{ borderColor: 'color-mix(in srgb, var(--t) 30%, transparent)' }}>
      <span className="font-bold">!</span>
      <span className="flex-1 min-w-0 break-words">{children}</span>
      {onDismiss && <button type="button" aria-label="Dismiss" onClick={onDismiss} className="opacity-70 hover:opacity-100"><X size={13} /></button>}
    </div>
  )
}

export function Spinner({ size = 14 }: { size?: number }) {
  return <span aria-label="Loading" className="inline-block rounded-full border-2 border-edge-strong border-t-accent spin" style={{ width: size, height: size }} />
}

export function Field({ label, required, help, children }: { label: string; required?: boolean; help?: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="block mb-1.5 text-xs text-body">{label}{required && <span className="text-red-fg"> *</span>}</span>
      {children}
      {help && <span className="block mt-1 text-[11px] text-faint">{help}</span>}
    </label>
  )
}

export const inputClass = 'w-full h-8 px-2.5 rounded-md bg-well border border-edge-input text-ink font-mono text-xs placeholder:text-dim disabled:opacity-50'
export const selectClass = cx(inputClass, 'td-select pr-6')

export function SectionLabel({ children, count }: { children: ReactNode; count?: number }) {
  return <span className="text-[10px] font-medium tracking-wide uppercase text-faint">{children}{count ? <span className="ml-1.5 text-dim normal-case">{count}</span> : null}</span>
}

export function Card({ title, count, meta, actions, children, tone }: { title?: ReactNode; count?: number; meta?: ReactNode; actions?: ReactNode; children?: ReactNode; tone?: Tone }) {
  return (
    <section className={cx('rounded-lg border bg-panel', tone ? `tone-${tone}` : 'border-edge-card')} style={tone ? { borderColor: 'color-mix(in srgb, var(--t) 40%, transparent)' } : undefined}>
      {(title || actions) && (
        <header className="flex items-center gap-2 h-8 px-3">
          <SectionLabel count={count}>{title}</SectionLabel>
          {meta && <span className="text-[11px] text-faint truncate min-w-0">{meta}</span>}
          <span className="flex-1" />
          {actions}
        </header>
      )}
      <div className="pb-1.5">{children}</div>
    </section>
  )
}

export function CopyButton({ text, label, size = 13 }: { text: string | (() => string); label?: string; size?: number }) {
  const [done, setDone] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  useEffect(() => () => clearTimeout(timer.current), [])
  const copy = async () => {
    await navigator.clipboard.writeText(typeof text === 'string' ? text : text())
    setDone(true)
    clearTimeout(timer.current)
    timer.current = setTimeout(() => setDone(false), 1200)
  }
  if (label) return <button type="button" onClick={copy} className="text-[11px] text-muted hover:text-ink">{done ? '✓ Copied' : label}</button>
  return <IconButton label="Copy" size={26} onClick={copy}>{done ? <Check size={size} className="text-green-fg" /> : <Copy size={size} />}</IconButton>
}

// Escape closes the topmost modal only; capture phase, so it can't also clear the flow
// selection underneath.
const stack: symbol[] = []
export function Modal({ title, width, height, headerExtra, footer, onClose, children, flush }: {
  title: ReactNode; width: number; height?: number | string; headerExtra?: ReactNode; footer?: ReactNode
  onClose: () => void; children: ReactNode; flush?: boolean
}) {
  const closeRef = useRef(onClose)
  useEffect(() => { closeRef.current = onClose })
  useEffect(() => {
    const id = Symbol()
    stack.push(id)
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && stack[stack.length - 1] === id) {
        e.stopPropagation()
        closeRef.current()
      }
    }
    document.addEventListener('keydown', onKey, true)
    return () => {
      stack.splice(stack.indexOf(id), 1)
      document.removeEventListener('keydown', onKey, true)
    }
  }, [])
  return createPortal(
    <div className="fixed inset-0 z-40 flex items-center justify-center p-6" style={{ background: 'color-mix(in srgb, var(--scrim) 80%, transparent)' }}>
      <div role="dialog" aria-modal="true" className="flex flex-col max-w-full max-h-full rounded-xl border border-edge bg-raised" style={{ width, height, boxShadow: '0 16px 40px var(--shadow)' }}>
        <header className="flex items-center gap-3 h-[52px] px-4 shrink-0 border-b border-line">
          <h2 className="text-sm font-semibold text-ink whitespace-nowrap">{title}</h2>
          {headerExtra}
          <span className="flex-1" />
          <IconButton label="Close" size={24} onClick={onClose}><X size={14} /></IconButton>
        </header>
        <div className={cx('flex-1 min-h-0', flush ? 'flex flex-col' : 'overflow-auto p-4 space-y-3.5')}>{children}</div>
        {footer && <footer className="flex items-center justify-end gap-2 px-4 py-3 shrink-0 border-t border-line bg-head rounded-b-xl">{footer}</footer>}
      </div>
    </div>,
    document.body,
  )
}
