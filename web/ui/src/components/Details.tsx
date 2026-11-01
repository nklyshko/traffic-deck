import { ChevronDown, ChevronRight, ChevronUp, Copy, Download, Pencil, Star, X } from 'lucide-react'
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type CSSProperties } from 'react'
import * as api from '../lib/api'
import { FAVORITE_TAG, loadCatalog, unknownIds, useCatalog, userTags } from '../lib/catalog'
import { base64Bytes, bodyExt, cookieAttrs, cookiePairs, curlCommand, flowUrl, hexDump, looksTextual, nameCut, queryPairs, rawExchange, rejoinCookies, saveBlob } from '../lib/http'
import { formatBytes, num, preciseDuration, reasonPhrase } from '../lib/format'
import { useSetting } from '../lib/settings'
import type { Body, Comment, Flow, Header } from '../lib/types'
import { DecodeAffordance, Decoded } from './Decode'
import { JsonTree } from './Json'
import { Badge, Button, Card, cx, DurationBadge, IconButton, inputClass, MethodBadge, Spinner, StatusBadge } from './ui'

const TEXT_CAP = 50_000
const HEX_CAP = 4096
const DECODE_CAP = 20_000
export const MARKS = ['red', 'yellow', 'green', 'blue', 'magenta', 'cyan']

// The column fits the card's longest name, up to a share the value can live with. Names are
// monospace, so ch measures them without touching the DOM.
export const nameColumn = (names: string[]) => ({ '--name-col': `min(${Math.max(1, ...names.map((n) => n.length))}ch, 42%)` }) as CSSProperties

export function NameValue({ name, value, decode = true }: { name: string; value: string; decode?: boolean }) {
  const [open, setOpen] = useState(false)
  const [expanded, setExpanded] = useState(false)
  const [clipped, setClipped] = useState(false)
  const valueEl = useRef<HTMLSpanElement>(null)
  // Measured, not guessed from the length: whether a value fits depends on the panel's width.
  useLayoutEffect(() => {
    const el = valueEl.current
    if (!el || expanded) return
    const measure = () => setClipped(el.scrollWidth > el.clientWidth || value.includes('\n'))
    const observer = new ResizeObserver(measure)
    observer.observe(el)
    return () => observer.disconnect()
  }, [value, expanded])
  // Ellipsis in the middle: access-control-allow-* differ only at the end.
  const cut = nameCut(name)
  return (
    <div className="group">
      <div className="flex items-start gap-2 px-3 py-1 hover:bg-hover font-mono text-[11px] leading-4">
        {/* Inline, not flex: a selection across flex items copies with a newline in the name. */}
        <span title={name} className="shrink-0 block overflow-hidden text-muted whitespace-pre" style={{ width: 'var(--name-col, 132px)' }}>
          <span className="inline-block align-top truncate" style={{ maxWidth: `calc(100% - ${name.length - cut}ch)` }}>{name.slice(0, cut)}</span>{name.slice(cut)}
        </span>
        {/* A drag that selects part of the value must not also toggle it. */}
        <span ref={valueEl} onClick={() => { if (clipped && !getSelection()?.toString()) setExpanded(!expanded) }}
          className={cx('flex-1 min-w-0 text-body', expanded ? 'break-all whitespace-pre-wrap' : 'truncate', clipped && 'cursor-pointer')}>{value}</span>
        {clipped && (
          <button type="button" aria-label={expanded ? 'Collapse value' : 'Show full value'} aria-expanded={expanded} title={expanded ? 'Collapse' : 'Show full value'} onClick={() => setExpanded(!expanded)} className="shrink-0 h-4 text-faint hover:text-ink">
            <ChevronRight size={13} className={cx(expanded && 'rotate-90')} />
          </button>
        )}
        {decode && value && <DecodeAffordance value={value} name={name} open={open} onToggle={() => setOpen(!open)} />}
      </div>
      {open && <div className="mx-3 my-1 p-3 rounded-lg border border-edge-input bg-well"><Decoded value={value} name={name} /></div>}
    </div>
  )
}

function Headers({ headers }: { headers: Header[] }) {
  return (
    <Card title="Headers" count={headers.length}>
      {headers.length === 0 ? <p className="px-3 text-[11px] text-faint">None.</p>
        : <div style={nameColumn(headers.map((h) => h.name ?? ''))}>{headers.map((h, i) => <NameValue key={i} name={h.name ?? ''} value={h.value ?? ''} />)}</div>}
    </Card>
  )
}

export function BodyCard({ title, body, load, filename, onDecode }: {
  title: string; body?: Body; load: () => Promise<Uint8Array | null>; filename: string; onDecode: (text: string) => void
}) {
  const size = num(body?.size)
  const [bytes, setBytes] = useState<Uint8Array | null | undefined>(body?.inline ? base64Bytes(body.inline) : undefined)
  const [error, setError] = useState('')
  const [view, setView] = useState<'text' | 'hex'>('text')
  useEffect(() => {
    if (body?.inline || !size) return
    load().then(setBytes, (e: Error) => setError(e.message))
  }, [body?.inline, size, load])

  const textual = useMemo(() => !!bytes && looksTextual(bytes), [bytes])
  const text = useMemo(() => (textual && bytes ? new TextDecoder().decode(bytes) : ''), [bytes, textual])
  // Over the cap the tree would put the whole body in the DOM, so it falls back to capped text.
  const json = useMemo(() => (text.length > TEXT_CAP ? undefined : parseJson(text)), [text])

  if (!size) return <Card title={title}><p className="px-3 text-[11px] text-faint">No body.</p></Card>
  const ext = bodyExt(body?.contentType)
  const save = () => bytes && saveBlob(`${filename}.${ext}`, bytes.slice())
  const meta = [formatBytes(size), body?.contentType, body?.contentEncoding].filter(Boolean).join(' · ')
  const hex = !textual || view === 'hex'
  const capped = bytes ? (hex ? bytes.length - HEX_CAP : text.length - TEXT_CAP) : 0
  return (
    <Card title={title} meta={meta} actions={bytes && (
      <span className="flex items-center gap-2.5 text-[11px]">
        {textual && (
          <span className="inline-flex rounded bg-well border border-line p-px">
            {(['text', 'hex'] as const).map((v) => <button key={v} type="button" onClick={() => setView(v)} className={cx('h-5 px-2 rounded-sm capitalize', view === v ? 'bg-sel text-ink' : 'text-muted')}>{v}</button>)}
          </span>
        )}
        <button type="button" className="text-muted hover:text-ink" onClick={() => void navigator.clipboard.writeText(textual && !hex ? text : hexDump(bytes, bytes.length))}>Copy</button>
        <button type="button" className="text-muted hover:text-ink" onClick={save}>Save</button>
        {/* preventDefault keeps the selection until click, which the keyboard can also reach. */}
        <button type="button" className="text-muted hover:text-ink" onMouseDown={(e) => e.preventDefault()} onClick={() => onDecode((getSelection()?.toString() || (hex ? hexDump(bytes, HEX_CAP) : text)).slice(0, DECODE_CAP))}>Decode</button>
      </span>
    )}>
      <div className="px-3 pb-1.5 max-h-[420px] overflow-auto">
        {error ? <p className="text-[11px] text-red-fg">{error}</p>
          : bytes === undefined ? <Spinner />
            : bytes === null ? <p className="text-[11px] text-faint">No body.</p>
              : !hex && json !== undefined ? <JsonTree value={json} />
                : <pre className="font-mono text-[11px] leading-[18px] text-body whitespace-pre-wrap break-all">{hex ? hexDump(bytes, HEX_CAP) : text.slice(0, TEXT_CAP)}</pre>}
        {capped > 0 && (
          <button type="button" onClick={save} className="w-full h-7 mt-2 rounded border border-dashed border-edge-strong text-[11px] text-muted hover:text-ink">
            … {capped.toLocaleString('en-US')} more {hex ? 'bytes' : 'characters'} — save the whole body as .{ext}
          </button>
        )}
      </div>
    </Card>
  )
}

export function parseJson(text: string): unknown {
  const t = text.trimStart()
  if (!t.startsWith('{') && !t.startsWith('[')) return undefined
  try {
    return JSON.parse(t)
  } catch {
    return undefined
  }
}

function MetaTab({ f }: { f: Flow }) {
  const rows: [string, string | undefined][] = [
    ['duration', f.durationMicros ? preciseDuration(num(f.durationMicros)) : undefined],
    ['client', f.srcAddr], ['server', f.dstAddr], ['connection', f.connectionId], ['stream', f.streamId], ['protocol', f.protocol],
    ['TLS decrypted', f.tlsDecrypted ? 'yes' : 'no'], ['TLS client', f.tlsClientName], ['JA3', f.ja3], ['JA4', f.ja4],
    ['HTTP/2 fingerprint', f.http2Fingerprint], ['ClientHello', f.tlsClientHello],
    ['proxy', f.proxy?.addr ? `${f.proxy.addr}${f.proxy.type ? ` (${f.proxy.type})` : ''}` : undefined],
    ['WebSocket frames', f.websocket ? String(num(f.messageCount)) : undefined], ['user agent', f.userAgent],
    ...Object.entries(f.metadata ?? {}),
  ]
  const shown = rows.filter(([, v]) => v)
  return <Card title="Meta"><div style={nameColumn(shown.map(([n]) => n))}>{shown.map(([n, v]) => <NameValue key={n} name={n} value={v!} decode={false} />)}</div></Card>
}

const without = (ids: string[] | undefined, id: string, add: boolean) => (add ? [...new Set([...(ids ?? []), id])] : (ids ?? []).filter((x) => x !== id))

function CommentRow({ comment: c, onSave, onDelete }: { comment: Comment; onSave: (body: string) => Promise<void>; onDelete: () => void }) {
  const [draft, setDraft] = useState<string | null>(null)
  const save = () => {
    const body = draft?.trim()
    if (body && body !== c.body) void onSave(body).then(() => setDraft(null))
    else setDraft(null)
  }
  if (draft !== null) return (
    <form onSubmit={(e) => { e.preventDefault(); save() }}>
      <input autoFocus aria-label="Edit comment" value={draft} onChange={(e) => setDraft(e.target.value)} onBlur={save} onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); setDraft(null) } }} className={inputClass} />
    </form>
  )
  return (
    <div className="flex items-start gap-2 text-[11px] text-body">
      <span className="flex-1 break-words whitespace-pre-wrap">{c.body}</span>
      <IconButton label="Edit comment" size={20} onClick={() => setDraft(c.body ?? '')}><Pencil size={11} /></IconButton>
      <IconButton label="Delete comment" size={20} onClick={onDelete}><X size={11} /></IconButton>
    </div>
  )
}

function Annotations({ flow, targets, session, onChanged, onPatch }: { flow: Flow; targets: Flow[]; session: string; onChanged: () => void; onPatch: (flows: Flow[]) => void }) {
  const { tags, groups } = useCatalog()
  const [open, setOpen] = useSetting('annotationsOpen')
  const [error, setError] = useState('')
  const [newTag, setNewTag] = useState('')
  const [comment, setComment] = useState('')
  const flowTags = userTags(flow.tagIds)
  const flowGroups = flow.groupIds ?? []
  const comments = flow.comments ?? []
  const ids = targets.map((t) => t.id)
  const many = targets.length > 1
  const every = (test: (f: Flow) => boolean) => targets.every(test)
  const hasTag = (id: string) => every((f) => !!f.tagIds?.includes(id))
  const hasGroup = (id: string) => every((f) => !!f.groupIds?.includes(id))
  const run = async (op: () => Promise<unknown>, change?: (f: Flow) => Partial<Flow>) => {
    try {
      await op()
      setError('')
      onChanged()
      // Only the anchor is re-read; a closed session has no stream to bring the others.
      if (many && change) onPatch(targets.filter((t) => t.id !== flow.id).map((t) => ({ markColor: t.markColor, favorite: t.favorite, tagIds: t.tagIds, groupIds: t.groupIds, comments: t.comments, ...change(t), id: t.id })))
    } catch (e) {
      setError((e as Error).message)
    }
  }
  const summary = [flowTags.length && `${flowTags.length} tag${flowTags.length > 1 ? 's' : ''}`, flowGroups.length && `${flowGroups.length} group${flowGroups.length > 1 ? 's' : ''}`, comments.length && `${comments.length} comment${comments.length > 1 ? 's' : ''}`].filter(Boolean).join(' · ') || 'Notes'
  const chip = (active: boolean) => cx('inline-flex items-center h-[22px] px-2 rounded-full border text-[11px]', active ? 'tone-blue tint border-accent' : 'border-edge text-muted hover:text-ink')
  return (
    <div className="shrink-0 border-t border-line bg-panel">
      <div className="flex items-center gap-2.5 h-10 px-3">
        <IconButton label="Favorite" size={26} aria-pressed={!!flow.favorite} onClick={() => {
          // The gateway's rule: every record favorite clears them all, anything else sets them all.
          const favorite = !every((f) => !!f.favorite)
          void run(() => api.toggleFavorite(session, ids), () => ({ favorite }))
        }}>
          <Star size={15} className={flow.favorite ? 'text-amber-fg fill-current' : ''} />
        </IconButton>
        {MARKS.map((m) => {
          const on = every((f) => f.markColor === m)
          return <button key={m} type="button" title={`Mark ${m}`} aria-label={`Mark ${m}`} aria-pressed={on}
            onClick={() => void run(() => (on ? api.clearMark(session, ids) : api.setMark(session, ids, m)), () => ({ markColor: on ? undefined : m }))}
            className={cx(`mark-${m} w-3.5 h-3.5 rounded-full`, on && 'ring-2 ring-offset-1 ring-offset-[var(--panel)] ring-[var(--t)]')} style={{ background: 'var(--t)' }} />
        })}
        {targets.some((f) => f.markColor) && <IconButton label="Clear mark" size={22} onClick={() => void run(() => api.clearMark(session, ids), () => ({ markColor: undefined }))}><X size={12} /></IconButton>}
        {many && <span className="text-[11px] text-muted">{targets.length} flows</span>}
        <span className="flex-1" />
        <Button size="sm" aria-expanded={open} onClick={() => setOpen(!open)}>{summary}{open ? <ChevronDown size={12} /> : <ChevronUp size={12} />}</Button>
      </div>
      {error && <p className="px-3 pb-2 text-[11px] text-red-fg">{error}</p>}
      {open && (
        <div className="px-3 pb-3 space-y-2 max-h-56 overflow-auto">
          <div className="flex flex-wrap items-center gap-1.5">
            {[...tags.values()].filter((t) => !t.isFavorite && t.id !== FAVORITE_TAG).map((t) => {
              const on = hasTag(t.id)
              return <button key={t.id} type="button" aria-pressed={on} className={chip(on)} onClick={() => void run(() => api.setTags(session, ids, on ? [] : [t.id], on ? [t.id] : []), (f) => ({ tagIds: without(f.tagIds, t.id, !on) }))}># {t.name}</button>
            })}
            {unknownIds(flowTags, tags).map((id) => <button key={id} type="button" aria-pressed title="A deleted tag; click to remove it" className={chip(true)}
              onClick={() => void run(() => api.setTags(session, ids, [], [id]), (f) => ({ tagIds: without(f.tagIds, id, false) }))}># {id}</button>)}
            <form onSubmit={(e) => {
              e.preventDefault()
              const name = newTag.trim()
              let created = ''
              if (name) void run(async () => {
                const t = await api.createTag(name, 'blue')
                created = t.id
                await loadCatalog(true)
                await api.setTags(session, ids, [t.id], [])
                setNewTag('')
              }, (f) => ({ tagIds: without(f.tagIds, created, true) }))
            }}><input aria-label="New tag" value={newTag} onChange={(e) => setNewTag(e.target.value)} placeholder="new tag" className={cx(inputClass, 'h-[22px]! w-28 text-[11px]!')} /></form>
          </div>
          {groups.size + unknownIds(flowGroups, groups).length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              {[...groups.values()].map((g) => {
                const on = hasGroup(g.id)
                return <button key={g.id} type="button" aria-pressed={on} className={chip(on)} onClick={() => void run(() => api.setGroups(session, ids, on ? [] : [g.id], on ? [g.id] : []), (f) => ({ groupIds: without(f.groupIds, g.id, !on) }))}>⬡ {g.name}</button>
              })}
              {unknownIds(flowGroups, groups).map((id) => <button key={id} type="button" aria-pressed title="A deleted group; click to remove it" className={chip(true)}
                onClick={() => void run(() => api.setGroups(session, ids, [], [id]), (f) => ({ groupIds: without(f.groupIds, id, false) }))}>⬡ {id}</button>)}
            </div>
          )}
          {comments.map((c) => (
            <CommentRow key={c.id} comment={c} onSave={(body) => run(() => api.editComment(session, c.id, body))} onDelete={() => void run(() => api.deleteComment(session, c.id))} />
          ))}
          <form onSubmit={(e) => {
            e.preventDefault()
            const body = comment.trim()
            if (body) void run(async () => {
              await api.addComment(session, flow.id, body)
              setComment('')
            })
          }}><input aria-label="Add a comment" value={comment} onChange={(e) => setComment(e.target.value)} placeholder={many ? 'add a comment to the anchor row' : 'add a comment'} className={inputClass} /></form>
        </div>
      )}
    </div>
  )
}

function Footer({ flow, session, onOpenMessages }: { flow: Flow; session: string; onOpenMessages: () => void }) {
  const [note, setNote] = useState('')
  const flashNote = (t: string) => {
    setNote(t)
    setTimeout(() => setNote(''), 1500)
  }
  const bodyOf = async (b: Body | undefined, response: boolean) => {
    if (!num(b?.size)) return null
    return b?.inline ? base64Bytes(b.inline) : api.getBody(session, flow.id, response)
  }
  const asText = (bytes: Uint8Array | null) => (!bytes ? '' : looksTextual(bytes) ? new TextDecoder().decode(bytes) : `<${bytes.length} binary bytes>`)
  const curl = async () => {
    try {
      const bytes = await bodyOf(flow.requestBody, false)
      const binary = !!bytes && !looksTextual(bytes)
      await navigator.clipboard.writeText(curlCommand(flow, { binary, text: binary || !bytes ? undefined : new TextDecoder().decode(bytes) }))
      if (binary) saveBlob(`${flow.id}-request.body`, bytes.slice())
      flashNote('✓ curl copied')
    } catch (e) {
      setNote((e as Error).message)
    }
  }
  const raw = async () => {
    try {
      const [req, rsp] = await Promise.all([bodyOf(flow.requestBody, false), bodyOf(flow.responseBody, true)])
      saveBlob(`${flow.id}.http`, rawExchange(flow, asText(req), asText(rsp)))
      flashNote('✓ saved')
    } catch (e) {
      setNote((e as Error).message)
    }
  }
  return (
    <div className="flex items-center gap-2 h-12 px-3 shrink-0 border-t border-line bg-chrome">
      <DurationBadge micros={flow.durationMicros} />
      <button type="button" title="Copy flow id" onClick={() => void navigator.clipboard.writeText(flow.id).then(() => flashNote('✓ id copied'))} className="font-mono text-[11px] text-muted truncate min-w-0 hover:text-ink">{flow.id}</button>
      <span className="flex-1 text-right text-[11px] text-faint truncate">{note}</span>
      <Button size="sm" icon={<Copy size={12} />} className="font-mono" onClick={() => void curl()}>curl</Button>
      <Button size="sm" icon={<Download size={12} />} className="font-mono" onClick={() => void raw()}>raw</Button>
      {flow.websocket && <Button size="sm" onClick={onOpenMessages}>messages ({num(flow.messageCount)})</Button>}
    </div>
  )
}

type TabName = 'Request' | 'Cookies' | 'Response' | 'Meta'

export function DetailsPanel({ session, summary, targets, onClose, onPatch, onDecode, onOpenMessages }: {
  session: string; summary: Flow; targets: Flow[]; onClose: () => void; onPatch: (flows: Flow[]) => void; onDecode: (text: string) => void; onOpenMessages: (f: Flow) => void
}) {
  const [full, setFull] = useState<Flow | null>(null)
  const [tab, setTab] = useState<TabName>('Response')
  const [error, setError] = useState('')
  const reread = useCallback(async () => {
    try {
      const f = await api.getFlow(session, summary.id)
      setFull(f)
      onPatch([f])
    } catch (e) {
      setError((e as Error).message)
    }
  }, [session, summary.id, onPatch])
  useEffect(() => { void reread() }, [reread])

  const f = full ?? summary
  const request = useMemo(() => rejoinCookies(f.requestHeaders ?? []), [f.requestHeaders])
  const sent = useMemo(() => cookiePairs(request), [request])
  const received = f.responseCookies ?? []
  const loadRequest = useCallback(async () => api.getBody(session, summary.id, false), [session, summary.id])
  const loadResponse = useCallback(async () => api.getBody(session, summary.id, true), [session, summary.id])
  const counts: Partial<Record<TabName, number>> = { Cookies: sent.length + received.length }
  const query = queryPairs(f.query)
  return (
    <div className="flex flex-col h-full min-w-0 bg-panel">
      <div className="flex items-center gap-2 h-11 px-3 shrink-0">
        <MethodBadge method={f.method} /><StatusBadge status={f.status} error={f.error} />
        {f.error && !f.status && <span title={f.error} className="text-red-fg">⚠</span>}
        <span title={flowUrl(f)} className="flex-1 min-w-0 truncate font-mono text-xs text-ink">{f.authority}{f.path}{f.query ? `?${f.query}` : ''}</span>
        <IconButton label="Close details" size={24} onClick={onClose}><X size={13} /></IconButton>
      </div>
      <div role="tablist" className="flex items-center gap-5 h-9 px-3 shrink-0 border-b border-line">
        {(['Request', 'Cookies', 'Response', 'Meta'] as TabName[]).map((t) => (
          <button key={t} type="button" role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
            className={cx('relative h-full text-xs', tab === t ? 'text-ink font-semibold' : 'text-muted hover:text-ink')}>
            {t}{counts[t] ? <span className="ml-1 text-[10px] text-faint">{counts[t]}</span> : null}
            {tab === t && <span className="absolute left-0 right-0 bottom-0 h-0.5 bg-accent" />}
          </button>
        ))}
      </div>
      <div className="flex-1 min-h-0 overflow-auto p-3 space-y-3">
        {error && <p className="text-[11px] text-red-fg">{error}</p>}
        {!full && !error && <Spinner />}
        {tab === 'Request' && <>
          <Card title="URL"><p className="px-3 font-mono text-[11px] text-body break-all">{flowUrl(f)}</p></Card>
          {query.length > 0 && <Card title="Query" count={query.length}><div style={nameColumn(query.map((q) => q.name))}>{query.map((q, i) => <NameValue key={i} name={q.name} value={q.value} />)}</div></Card>}
          {full && <>
            <Headers headers={request} />
            <BodyCard title="Body" body={f.requestBody} load={loadRequest} filename={`${f.id}-request`} onDecode={onDecode} />
          </>}
        </>}
        {full && tab === 'Cookies' && (sent.length + received.length === 0 ? <p className="text-[11px] text-faint">No cookies in either direction.</p> : <>
          <Card title="Sent" count={sent.length}><div style={nameColumn(sent.map((c) => c.name))}>{sent.map((c, i) => <NameValue key={i} name={c.name} value={c.value} />)}</div></Card>
          <Card title="Set-Cookie" count={received.length}>
            <div style={nameColumn(received.map((c) => c.name ?? ''))}>
              {received.map((c, i) => (
                <div key={i}>
                  <NameValue name={c.name ?? ''} value={c.value ?? ''} />
                  {cookieAttrs(c).length > 0 && <div className="flex flex-wrap gap-1 px-3 pb-1">{cookieAttrs(c).map((a) => <Badge key={a} size="sm">{a}</Badge>)}</div>}
                </div>
              ))}
            </div>
          </Card>
        </>)}
        {tab === 'Response' && <>
          {f.error && <Card title="Error" tone="red"><p className="px-3 text-xs break-words">{f.error}</p></Card>}
          <Card>
            <div className="flex items-center gap-2 h-10 px-3 -mb-1.5">
              <span className="text-[10px] uppercase tracking-wide text-faint">Status</span>
              {f.status ? <><StatusBadge status={f.status} size="lg" /><span className="text-sm text-ink">{reasonPhrase(f.status)}</span></> : <span className="text-xs text-muted">No response</span>}
              <span className="ml-auto text-[11px] text-faint">{[f.protocol, f.tlsDecrypted && 'TLS decrypted'].filter(Boolean).join(' · ')}</span>
            </div>
          </Card>
          {full && <>
            <Headers headers={f.responseHeaders ?? []} />
            <BodyCard title="Body" body={f.responseBody} load={loadResponse} filename={`${f.id}-response`} onDecode={onDecode} />
          </>}
        </>}
        {tab === 'Meta' && <MetaTab f={f} />}
      </div>
      <Annotations flow={f} targets={targets} session={session} onChanged={() => void reread()} onPatch={onPatch} />
      <Footer flow={f} session={session} onOpenMessages={() => onOpenMessages(f)} />
    </div>
  )
}
