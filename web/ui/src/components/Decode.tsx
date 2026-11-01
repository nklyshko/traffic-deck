import { ScanSearch } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { canDecode, decodeAs, guessKind, KINDS, pickKind, type Kind, type Output } from '../lib/decoder'
import { JsonTree } from './Json'
import { Badge, Card, CopyButton, cx, Modal } from './ui'
import type { Tone } from '../lib/format'

const CLIP = 20_000
const KIND_TONE: Record<Kind, Tone> = { jwt: 'purple', b64: 'cyan', url: 'blue', hex: 'orange', ts: 'green' }

function Block({ title, text, json }: { title: string; text: string; json?: boolean }) {
  const parsed = useMemo(() => {
    if (!json) return undefined
    try {
      return JSON.parse(text)
    } catch {
      return undefined
    }
  }, [json, text])
  return (
    <Card title={title} actions={<CopyButton text={text} label="Copy" />}>
      <div className="px-3 pb-1.5">
        {parsed !== undefined ? <JsonTree value={parsed} /> : <pre className="font-mono text-[11px] whitespace-pre-wrap break-all text-body">{text.slice(0, CLIP)}</pre>}
      </div>
    </Card>
  )
}

function OutputView({ o }: { o: Output }) {
  if (o.jwt) {
    return (
      <>
        <Block title="Header" text={JSON.stringify(o.jwt.header, null, 2)} json />
        <Block title="Payload" text={JSON.stringify(o.jwt.payload, null, 2)} json />
        <Card title="Claims" actions={<CopyButton text={o.jwt.claims.map((c) => `${c.name} ${c.when}`).join('\n')} label="Copy" />}>
          <div className="px-3 pb-1.5 font-mono text-[11px] space-y-1">
            {o.jwt.claims.map((c) => (
              <div key={c.name} className="flex gap-3"><span className="w-8 text-muted">{c.name}</span><span className={c.expired ? 'text-red-fg' : 'text-body'}>{c.when}{c.expired ? ' — expired' : ''}</span></div>
            ))}
            <div className="text-amber-fg">Signature is not verified.</div>
          </div>
        </Card>
      </>
    )
  }
  if (o.time) return <Block title="Time" text={o.time} />
  if (o.hex) return <Block title={o.binaryLabel ?? 'binary'} text={o.hex} />
  return <Block title={o.isJson ? 'JSON' : 'Text'} text={o.text ?? ''} json={o.isJson} />
}

export function Decoded({ value, name = '' }: { value: string; name?: string }) {
  const [override, setOverride] = useState<Kind | null>(null)
  const kind = pickKind(value, name, override)
  const result = useMemo(() => (kind ? decodeAs(value, kind) : null), [value, kind])
  return (
    <div className="space-y-2.5">
      {result && result.steps.length > 1 && (
        <div className="flex items-center gap-1.5 text-[11px] text-faint">chain {result.steps.map((s, i) => <span key={i} className="flex items-center gap-1.5">{i > 0 && '→'}<Badge tone={KIND_TONE[s]} size="sm">{s}</Badge></span>)}</div>
      )}
      <div className="inline-flex rounded-md bg-well border border-line p-0.5" role="group" aria-label="Decode as">
        {KINDS.map((k) => {
          const ok = canDecode(value, k)
          return (
            <button key={k} type="button" disabled={!ok} title={ok ? undefined : `Not decodable as ${k}`} onClick={() => setOverride(k)}
              className={cx('h-6 px-2.5 rounded font-mono text-[11px]', k === kind ? 'bg-sel text-ink' : ok ? 'text-muted hover:text-ink' : 'text-dim')}>{k}</button>
          )
        })}
      </div>
      {result ? <OutputView o={result.output} /> : <p className="text-[11px] text-faint">Nothing here decodes.</p>}
    </div>
  )
}

export function DecodeAffordance({ value, name, open, onToggle }: { value: string; name: string; open: boolean; onToggle: () => void }) {
  const kind = useMemo(() => guessKind(value, name), [value, name])
  if (kind) return <button type="button" aria-expanded={open} onClick={onToggle} title={`Decode ${kind}`}><Badge tone={KIND_TONE[kind]} size="sm">{kind}</Badge></button>
  return (
    <button type="button" aria-label="Decode" title="Decode" aria-expanded={open} onClick={onToggle} className={cx('text-faint hover:text-ink', !open && 'opacity-0 group-hover:opacity-100 focus:opacity-100')}>
      <ScanSearch size={13} />
    </button>
  )
}

export function DecoderModal({ initial, onClose }: { initial: string; onClose: () => void }) {
  const [text, setText] = useState(initial)
  const [value, setValue] = useState(initial)
  useEffect(() => {
    const t = setTimeout(() => setValue(text), 200)
    return () => clearTimeout(t)
  }, [text])
  return (
    <Modal title="Decoder" width={760} height="min(760px, 100%)" onClose={onClose}
      headerExtra={<span className="inline-flex items-center gap-1.5 h-5 px-2 rounded-full tint tone-green text-[10px]">runs in your browser — nothing is sent anywhere</span>}>
      <textarea autoFocus spellCheck={false} value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste a JWT, base64, URL-encoded, hex or timestamp value"
        className="w-full h-24 p-2.5 rounded-lg bg-well border border-edge-input font-mono text-xs text-ink resize-y" />
      {value.trim() && <Decoded key={value} value={value} />}
    </Modal>
  )
}
