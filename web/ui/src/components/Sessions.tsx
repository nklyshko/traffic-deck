import { Check, Copy, Download, Pencil, Plus, RefreshCw, Square, Trash2, Upload } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import * as api from '../lib/api'
import { formatBytes, formatDateTime, num, type Tone } from '../lib/format'
import { inScope, resolveScope, SCOPE_ALL, SCOPE_UNGROUPED, sessionScopes, type Scope } from '../lib/sessions'
import { useSetting } from '../lib/settings'
import type { Session, SessionArtifacts } from '../lib/types'
import { isLive } from './Workspace'
import { Banner, Button, CopyButton, cx, Field, IconButton, inputClass, Modal, Pill, SectionLabel, Spinner } from './ui'

const STATUS: Record<string, [string, Tone]> = {
  SESSION_STATUS_OPEN: ['capturing', 'green'], SESSION_STATUS_DECODING: ['decoding', 'blue'],
  SESSION_STATUS_CLOSED: ['closed', 'grey'], SESSION_STATUS_ERROR: ['error', 'red'],
}

function RenameDialog({ session, groups, onClose, onSaved }: { session: Session; groups: string[]; onClose: () => void; onSaved: () => void }) {
  const [label, setLabel] = useState(session.label ?? '')
  const [group, setGroup] = useState(session.group ?? '')
  const [artifacts, setArtifacts] = useState<SessionArtifacts | null>(null)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  useEffect(() => { api.sessionArtifacts(session.id).then(setArtifacts, () => {}) }, [session.id])
  const save = async () => {
    setSaving(true)
    try {
      await api.setLabel(session.id, label)
      await api.setGroup(session.id, group.trim())
      onSaved()
    } catch (e) {
      setError((e as Error).message)
      setSaving(false)
    }
  }
  const remote = artifacts?.hostname && !['localhost', '127.0.0.1'].includes(location.hostname) && artifacts.hostname !== location.hostname
  const paths: [string, string | undefined, string | undefined][] = [['pcap', artifacts?.pcapPath, artifacts?.pcapBytes], ['key log', artifacts?.keylogPath, artifacts?.keylogBytes]]
  return (
    <Modal title="Rename / group" width={560} onClose={onClose} footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={saving} onClick={() => void save()}>{saving ? 'Saving…' : 'Save'}</Button></>}>
      {error && <Banner onDismiss={() => setError('')}>{error}</Banner>}
      <Field label="Label"><input autoFocus className={inputClass} value={label} onChange={(e) => setLabel(e.target.value)} /></Field>
      <Field label="Group" help="Pick a group or type a new one. Empty clears it."><input list="session-groups" className={inputClass} value={group} onChange={(e) => setGroup(e.target.value)} /></Field>
      <datalist id="session-groups">{groups.map((g) => <option key={g} value={g} />)}</datalist>
      {(artifacts?.pcapPath || artifacts?.keylogPath) && (
        <div className="rounded-lg border border-edge-card bg-panel p-2.5 space-y-1.5">
          <div className="flex items-center justify-between"><SectionLabel>Artifacts</SectionLabel><span className="font-mono text-[10px] text-faint">{artifacts.hostname}</span></div>
          {paths.filter(([, p]) => p).map(([name, path, size]) => (
            <div key={name} className="flex items-center gap-2 font-mono text-[11px]">
              <span className="w-12 text-muted shrink-0">{name}</span>
              <span className="flex-1 min-w-0 break-all text-body">{path}{remote && <span className="block text-amber-fg">on {artifacts.hostname}</span>}</span>
              <span className="text-faint">{formatBytes(num(size))}</span>
              <CopyButton text={path!} />
            </div>
          ))}
        </div>
      )}
    </Modal>
  )
}

// Confirming hands the delete to the list, whose busy indicator and error banner cover it
// like every other row action.
function DeleteDialog({ session, onClose, onDelete }: { session: Session; onClose: () => void; onDelete: () => void }) {
  return (
    <Modal title="Delete session?" width={520} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="destructive" onClick={onDelete}>Delete session</Button></>}>
      <div className="flex items-center gap-3 rounded-lg border border-edge-card bg-panel p-3">
        <div className="flex-1 min-w-0">
          <div className="text-xs font-medium text-ink truncate">{session.label || session.id}</div>
          <div className="font-mono text-[10px] text-faint truncate">{session.id.slice(0, 8)} · {session.source} · {formatDateTime(num(session.createdAtUnixMs))}</div>
        </div>
        <span className="font-mono text-[11px] text-muted">{num(session.flowCount)} flows · {formatBytes(num(session.pcapBytes)) || '0'}</span>
      </div>
      <Banner>This removes the {num(session.flowCount)} flows, the pcap and the key log, with their tags and comments. It cannot be undone.</Banner>
      <div className="flex items-center gap-2 text-[11px] text-muted">Keep a copy first:
        <a href={api.exportUrl(session.id)} className="inline-flex items-center gap-1 h-[22px] px-2 rounded-[5px] border border-edge text-body"><Download size={11} />Export bundle</a>
      </div>
    </Modal>
  )
}

function ImportPcapDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [pcap, setPcap] = useState('')
  const [keylog, setKeylog] = useState('')
  const [label, setLabel] = useState('')
  const [engine, setEngine] = useState('native')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const run = async () => {
    setBusy(true)
    setError('')
    try {
      await api.importCapture(pcap, keylog, label, engine)
      onDone()
    } catch (e) {
      setError((e as Error).message)
      setBusy(false)
    }
  }
  return (
    <Modal title="Import pcap" width={560} onClose={onClose}
      footer={<><Button disabled={busy} onClick={onClose}>Cancel</Button><Button variant="primary" disabled={busy || !pcap.trim()} onClick={() => void run()}>{busy ? 'Decoding…' : 'Import'}</Button></>}>
      <div className="px-2.5 py-2 rounded-md tint tone-blue text-[11px]">Paths are read on the gateway host, not on this computer.</div>
      {error && <Banner>{error}</Banner>}
      <Field label="pcap path" required><input autoFocus disabled={busy} spellCheck={false} className={inputClass} value={pcap} onChange={(e) => setPcap(e.target.value)} /></Field>
      <Field label="Key log path" help="Optional. SSLKEYLOGFILE lines let TLS traffic be decrypted."><input disabled={busy} spellCheck={false} className={inputClass} value={keylog} onChange={(e) => setKeylog(e.target.value)} /></Field>
      <Field label="Label"><input disabled={busy} className={inputClass} value={label} onChange={(e) => setLabel(e.target.value)} /></Field>
      <div>
        <span className="block mb-1.5 text-xs text-body">Decoder engine</span>
        <div className="flex gap-1.5">{['native', 'tshark'].map((x) => <Button key={x} size="sm" disabled={busy} variant={engine === x ? 'active' : 'default'} onClick={() => setEngine(x)}>{x}</Button>)}</div>
        <span className="block mt-1 text-[11px] text-faint">native decodes in-process; tshark needs Wireshark installed on the gateway host.</span>
      </div>
    </Modal>
  )
}

function ScopeRail({ scopes, active, onSelect }: { scopes: Scope[]; active: string; onSelect: (key: string) => void }) {
  const item = (s: Scope) => (
    <button key={s.key} type="button" title={s.label} aria-current={s.key === active ? 'true' : undefined} onClick={() => onSelect(s.key)}
      className={cx('flex items-center gap-2 w-full h-8 px-2.5 rounded-md text-left text-xs', s.key === active ? 'bg-hover text-ink font-semibold' : 'text-body hover:bg-panel')}>
      <span className="flex-1 min-w-0 truncate">{s.label}</span>
      {s.live > 0 && <span aria-label={`${s.live} live`} className="w-1.5 h-1.5 rounded-full pulse shrink-0" style={{ background: 'var(--green)' }} />}
      <span className="font-mono text-[11px] text-faint">{s.count.toLocaleString('en-US')}</span>
    </button>
  )
  const builtIn = (s: Scope) => s.key === SCOPE_ALL || s.key === SCOPE_UNGROUPED
  return (
    <nav aria-label="Session groups" className="w-56 shrink-0 overflow-auto pb-4 space-y-0.5">
      {scopes.filter(builtIn).map(item)}
      <div className="px-2.5 pt-4 pb-1"><SectionLabel>Groups</SectionLabel></div>
      {scopes.filter((s) => !builtIn(s)).map(item)}
    </nav>
  )
}

function SessionRow({ s, showGroup, stuck, busy, onOpen, onStop, onForceClose, onRename, onDelete }: {
  s: Session; showGroup: boolean; stuck: boolean; busy: boolean; onOpen: () => void; onStop: () => void; onForceClose: () => void; onRename: () => void; onDelete: () => void
}) {
  const live = isLive(s)
  const [label, tone] = STATUS[s.status ?? ''] ?? ['unknown', 'grey' as Tone]
  const [copied, setCopied] = useState(false)
  const stop = (e: React.MouseEvent) => e.stopPropagation()
  return (
    <div role="button" tabIndex={0} onClick={onOpen} onKeyDown={(e) => { if (e.key === 'Enter') onOpen() }}
      className="flex items-center gap-4 min-h-[60px] px-4 py-2 rounded-lg cursor-pointer hover:bg-panel">
      <span aria-hidden className={cx('w-2 h-2 rounded-full shrink-0', live && 'pulse')} style={{ background: live ? `var(--${tone})` : 'var(--dim)' }} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-[13px] font-medium text-ink truncate">{s.label || s.id}</span>
          {showGroup && s.group && <span title={s.group} className="max-w-40 shrink-0 truncate px-1.5 rounded border border-edge text-[10px] leading-4 text-muted">{s.group}</span>}
        </div>
        <div className="font-mono text-[11px] text-faint truncate">{s.id.slice(0, 8)} · {s.source || 'unknown'} · {formatDateTime(num(s.createdAtUnixMs))}</div>
      </div>
      {stuck && <Button size="sm" variant="danger" disabled={busy} onClick={(e) => { stop(e); onForceClose() }}>Force close</Button>}
      <span className={cx('w-24 text-right font-mono text-xs', num(s.flowCount) ? 'text-body' : 'text-faint')}>{num(s.flowCount).toLocaleString('en-US')} flows</span>
      <span className="w-16 text-right font-mono text-xs text-muted">{formatBytes(num(s.pcapBytes))}</span>
      <span className="w-20 flex justify-center"><Pill tone={tone}>{label}</Pill></span>
      <div className="flex items-center gap-0.5" onClick={stop}>
        <IconButton label="Copy id" size={30} onClick={() => void navigator.clipboard.writeText(s.id).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1200) })}>
          {copied ? <Check size={14} className="text-green-fg" /> : <Copy size={14} />}
        </IconButton>
        {live ? <IconButton label="Stop capture" size={30} disabled={busy} onClick={onStop}><Square size={11} className="text-red fill-current" /></IconButton> : <span className="w-[30px]" />}
        <IconButton label="Rename / group" size={30} onClick={onRename}><Pencil size={13} /></IconButton>
        <a href={api.exportUrl(s.id)} title="Export bundle" aria-label="Export bundle" className="inline-flex items-center justify-center w-[30px] h-[30px] rounded-md text-muted hover:text-ink hover:bg-hover"><Download size={14} /></a>
        <span data-tooltip={live ? 'Stop the capture first' : undefined}>
          <IconButton label="Delete" size={30} disabled={live} className={live ? '' : 'text-red-fg!'} onClick={onDelete}><Trash2 size={14} /></IconButton>
        </span>
      </div>
    </div>
  )
}

interface Props {
  sessions: Session[]
  loaded: boolean
  loadError: string
  refresh: () => Promise<void>
  stuck: ReadonlySet<string>
  onStuck: (id: string, stuck: boolean) => void
  onOpen: (s: Session) => void
  onNewCapture: () => void
}

export function SessionsScreen({ sessions, loaded, loadError, refresh, stuck, onStuck, onOpen, onNewCapture }: Props) {
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [dismissedLoad, setDismissedLoad] = useState('')
  const [renaming, setRenaming] = useState<Session | null>(null)
  const [deleting, setDeleting] = useState<Session | null>(null)
  const [importing, setImporting] = useState(false)
  const file = useRef<HTMLInputElement>(null)

  const act = async (what: string, op: () => Promise<unknown>) => {
    setBusy(what)
    setError('')
    try {
      await op()
      await refresh()
    } catch (e) {
      setError(`${(e as Error).message}`)
      throw e
    } finally {
      setBusy('')
    }
  }
  const stop = (s: Session) => act('stopping…', () => api.stopCapture(s.id)).then(() => onStuck(s.id, false), (e: Error) => {
    // Stop routes through the source that started the capture. Only now is Force close safe
    // to offer: on a healthy capture it would leave a source writing into a closed session.
    onStuck(s.id, true)
    setError(`Stop failed for ${s.id.slice(0, 8)}: ${e.message}. Force close is now available on that row.`)
  })
  const forceClose = (s: Session) => act('closing…', () => api.forceClose(s.id)).then(() => onStuck(s.id, false), () => {})

  const [storedScope, setScope] = useSetting('sessionScope')
  const scopes = useMemo(() => sessionScopes(sessions, isLive), [sessions])
  const scope = resolveScope(scopes, storedScope)
  const groups = useMemo(() => [...new Set(sessions.flatMap((s) => (s.group ? [s.group] : [])))].sort(), [sessions])
  const row = (s: Session) => (
    <SessionRow key={s.id} s={s} showGroup={scope === SCOPE_ALL} stuck={stuck.has(s.id) && isLive(s)} busy={!!busy} onOpen={() => onOpen(s)} onStop={() => void stop(s)} onForceClose={() => void forceClose(s)} onRename={() => setRenaming(s)} onDelete={() => setDeleting(s)} />
  )
  const liveCount = sessions.filter(isLive).length
  const shownError = error || (loadError === dismissedLoad ? '' : loadError)
  return (
    <div className="h-full flex flex-col px-6 pt-4">
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        <div className="mr-auto">
          <h1 className="text-lg font-semibold text-ink leading-6">Sessions</h1>
          <p className="text-[11px] text-faint">{liveCount} live · {sessions.length} total</p>
        </div>
        {busy && <span className="inline-flex items-center gap-1.5 text-xs text-muted"><Spinner size={12} />{busy}</span>}
        <Button variant="primary" icon={<Plus size={13} />} onClick={onNewCapture}>New capture</Button>
        <Button icon={<Upload size={13} />} onClick={() => file.current?.click()}>Import bundle</Button>
        <input ref={file} type="file" accept=".gz,.tar.gz" className="hidden" onChange={(e) => {
          const f = e.target.files?.[0]
          e.target.value = '' // so the same file can be picked again
          if (f) void act('importing…', () => api.importBundle(f)).catch(() => {})
        }} />
        <Button icon={<Upload size={13} />} onClick={() => setImporting(true)}>Import pcap</Button>
        <IconButton label="Refresh" className="border border-edge" onClick={() => void refresh()}><RefreshCw size={14} /></IconButton>
      </div>
      {shownError && <div className="mb-3"><Banner onDismiss={() => (error ? setError('') : setDismissedLoad(loadError))}>{shownError}</Banner></div>}
      {!loaded ? <div className="flex justify-center py-16"><Spinner size={20} /></div>
        : sessions.length === 0 ? (!loadError && <p className="py-16 text-center text-muted">No sessions yet — start a capture.</p>)
          : <div className="flex-1 min-h-0 flex gap-4">
            {scopes.length > 0 && <ScopeRail scopes={scopes} active={scope} onSelect={setScope} />}
            {/* Always newest first: grouping scopes this list and never reorders it. */}
            <div className="flex-1 min-w-0 overflow-auto pb-4">{sessions.filter((s) => inScope(s, scope)).map(row)}</div>
          </div>}
      {renaming && <RenameDialog session={renaming} groups={groups} onClose={() => setRenaming(null)} onSaved={() => { setRenaming(null); void refresh() }} />}
      {deleting && <DeleteDialog session={deleting} onClose={() => setDeleting(null)} onDelete={() => {
        setDeleting(null)
        act('deleting…', () => api.deleteSession(deleting.id)).catch(() => {})
      }} />}
      {importing && <ImportPcapDialog onClose={() => setImporting(false)} onDone={() => { setImporting(false); void refresh() }} />}
    </div>
  )
}
