import { memo, useState } from 'react'

// Selecting and copying must yield valid indented JSON: indentation is real spaces, toggles
// are user-select:none, and a collapsed node keeps its compact JSON in a hidden span.
const hidden = 'absolute w-px h-px overflow-hidden [clip-path:inset(50%)] whitespace-pre'

function Scalar({ value }: { value: unknown }) {
  const cls = value === null ? 'text-muted' : typeof value === 'string' ? 'text-[var(--syntax-str)]' : typeof value === 'number' ? 'text-[var(--syntax-num)]' : 'text-[var(--syntax-bool)]'
  return <span className={cls}>{JSON.stringify(value)}</span>
}

const Node = memo(function Node({ value, depth, name, comma }: { value: unknown; depth: number; name?: string; comma: boolean }) {
  const isObject = value !== null && typeof value === 'object'
  const [open, setOpen] = useState(depth <= 2)
  const pad = ' '.repeat(depth * 2)
  const key = name !== undefined && <><span className="text-[var(--syntax-key)]">{JSON.stringify(name)}</span><span className="text-faint">: </span></>
  if (!isObject) return <div className="relative">{pad}{key}<Scalar value={value} />{comma && <span className="text-faint">,</span>}</div>
  const array = Array.isArray(value)
  const entries = array ? (value as unknown[]).map((v, i) => [String(i), v] as const) : Object.entries(value as object)
  const [l, r] = array ? '[]' : '{}'
  const toggle = <button type="button" aria-expanded={open} onClick={() => setOpen(!open)} className="absolute select-none text-faint hover:text-ink" style={{ marginLeft: '-0.875rem' }}>{open ? '▼' : '▶'}</button>
  if (entries.length === 0) return <div className="relative">{pad}{key}<span className="text-faint">{l}{r}</span>{comma && <span className="text-faint">,</span>}</div>
  if (!open) {
    return (
      <div className="relative">
        {pad}{toggle}{key}
        <span className="text-muted select-none">{array ? `[${entries.length} items]` : `{${entries.length} keys}`}</span>
        <span className={hidden}>{JSON.stringify(value)}</span>
        {comma && <span className="text-faint">,</span>}
      </div>
    )
  }
  return (
    <div className="relative">
      <div>{pad}{toggle}{key}<span className="text-faint">{l}</span></div>
      {entries.map(([k, v], i) => <Node key={k} value={v} depth={depth + 1} name={array ? undefined : k} comma={i < entries.length - 1} />)}
      <div>{pad}<span className="text-faint">{r}</span>{comma && <span className="text-faint">,</span>}</div>
    </div>
  )
})

export function JsonTree({ value }: { value: unknown }) {
  return <div className="font-mono text-11 leading-4.5 whitespace-pre-wrap break-all pl-4 text-body"><Node value={value} depth={0} comma={false} /></div>
}
