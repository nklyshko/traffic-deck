import { ScanSearch } from 'lucide-react'
import { rem } from '../lib/scale'
import { useEffect, useMemo, useState } from 'react'
import { canDecode, decodeAs, guessKind, KINDS, pickKind, type Kind, type Output } from '../lib/decoder'
import { alpn, serverName, toBase64, toHex, toRecords, type ClientHello } from '../lib/tlshello'
import { JsonTree } from './Json'
import { Badge, Card, CopyButton, cx, Field, Modal } from './ui'

const CLIP = 20_000

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
        {parsed !== undefined ? <JsonTree value={parsed} /> : <pre className="font-mono text-11 whitespace-pre-wrap break-all text-body">{text.slice(0, CLIP)}</pre>}
      </div>
    </Card>
  )
}

// Copies the ClientHello in the forms other tools take: hex and base64 of the handshake
// message as TLS stores it, and the same wrapped in a TLS record for Wireshark, openssl or a
// replay. A TLS 1.3 client puts 0x0301 on its first ClientHello's record, 0x0303 after a retry.
export function ClientHelloCopy({ message, retry = false }: { message: Uint8Array; retry?: boolean }) {
  return (
    <span className="flex items-center gap-2.5">
      <span className="text-11 text-faint">Copy</span>
      <CopyButton text={() => toHex(message)} label="hex" />
      <CopyButton text={() => toBase64(message)} label="base64" />
      <CopyButton text={() => toHex(toRecords(message, retry ? 0x0303 : 0x0301))} label="As record" />
    </span>
  )
}

export function helloSummary(h: ClientHello): string {
  const name = serverName(h), protocols = alpn(h)
  return [`${h.message.length} bytes`, name, protocols.length ? protocols.join(', ') : undefined, h.record && `${h.record.count} record${h.record.count > 1 ? 's' : ''}`].filter(Boolean).join(' · ')
}

function ClientHelloView({ hello, view }: { hello: ClientHello; view: Record<string, unknown> }) {
  return (
    <Card title="ClientHello" meta={helloSummary(hello)} actions={<span className="flex items-center gap-2.5"><ClientHelloCopy message={hello.message} /><CopyButton text={() => JSON.stringify(view, null, 2)} label="JSON" /></span>}>
      <div className="px-3 pb-1.5">
        {hello.warnings.map((w) => <p key={w} className="text-11 text-amber-fg">{w}</p>)}
        <JsonTree value={view} />
      </div>
    </Card>
  )
}

function OutputView({ o }: { o: Output }) {
  if (o.tls) return <ClientHelloView hello={o.tls.hello} view={o.tls.view} />
  if (o.jwt) {
    return (
      <>
        <Block title="Header" text={JSON.stringify(o.jwt.header, null, 2)} json />
        <Block title="Payload" text={JSON.stringify(o.jwt.payload, null, 2)} json />
        <Card title="Claims" actions={<CopyButton text={o.jwt.claims.map((c) => `${c.name} ${c.when}`).join('\n')} label="Copy" />}>
          <div className="px-3 pb-1.5 font-mono text-11 space-y-1">
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
        <div className="flex items-center gap-1.5 text-11 text-faint">chain {result.steps.map((s, i) => <span key={i} className="flex items-center gap-1.5">{i > 0 && '→'}<Badge size="sm">{s}</Badge></span>)}</div>
      )}
      <div className="inline-flex rounded-md bg-well border border-line p-0.5" role="group" aria-label="Decode as">
        {KINDS.map((k) => {
          const ok = canDecode(value, k)
          return (
            <button key={k} type="button" disabled={!ok} title={ok ? undefined : `Not decodable as ${k}`} onClick={() => setOverride(k)}
              className={cx('h-6 px-2.5 rounded font-mono text-11', k === kind ? 'bg-sel text-ink' : ok ? 'text-muted hover:text-ink' : 'text-dim')}>{k}</button>
          )
        })}
      </div>
      {result ? <OutputView o={result.output} /> : <p className="text-11 text-faint">Nothing here decodes.</p>}
    </div>
  )
}

export function DecodeAffordance({ value, name, open, onToggle }: { value: string; name: string; open: boolean; onToggle: () => void }) {
  const kind = useMemo(() => guessKind(value, name), [value, name])
  if (kind) return <button type="button" aria-expanded={open} onClick={onToggle} title={`Decode ${kind}`}><Badge size="sm">{kind}</Badge></button>
  return (
    <button type="button" aria-label="Decode" title="Decode" aria-expanded={open} onClick={onToggle} className={cx('text-faint hover:text-ink', !open && 'opacity-0 group-hover:opacity-100 focus:opacity-100')}>
      <ScanSearch size={rem(13)} />
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
    <Modal title="Decoder" width={760} height={760} onClose={onClose}
      headerExtra={<span className="inline-flex items-center gap-1.5 h-5 px-2 rounded-full tint tone-green text-10">runs in your browser — nothing is sent anywhere</span>}>
      {/* A permanent label, not a placeholder that typing removes. */}
      <Field label="Value" help="A JWT, base64, URL-encoded, hex or timestamp value, or a TLS ClientHello as hex, a hex dump or base64.">
        <textarea autoFocus spellCheck={false} value={text} onChange={(e) => setText(e.target.value)}
          className="w-full h-24 p-2.5 rounded-lg bg-well border border-edge-input font-mono text-12 text-ink resize-y" />
      </Field>
      {value.trim() && <Decoded key={value} value={value} />}
    </Modal>
  )
}
