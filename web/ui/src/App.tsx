import { List, Moon, Sun, X } from 'lucide-react'
import { useCallback, useEffect, useLayoutEffect, useState } from 'react'
import { CatalogModal } from './components/Catalog'
import { CompareModal } from './components/Compare'
import { DecoderModal } from './components/Decode'
import { NewCaptureDialog } from './components/NewCapture'
import { ServicesModal } from './components/Services'
import { SessionsScreen } from './components/Sessions'
import { TimelineModal } from './components/Timeline'
import { IconButton, cx } from './components/ui'
import { UpdateToast, useUpdates } from './components/Updates'
import { isLive, Workspace, type Pick } from './components/Workspace'
import { listSessions } from './lib/api'
import { useSetting } from './lib/settings'
import type { Flow, Session } from './lib/types'

const POLL_MS = 5000

export function App() {
  const [dark, setDark] = useSetting('dark')
  useLayoutEffect(() => { document.documentElement.classList.toggle('dark', dark) }, [dark])

  const [sessions, setSessions] = useState<Session[]>([])
  const [loaded, setLoaded] = useState(false)
  const [loadError, setLoadError] = useState('')
  const refresh = useCallback(async () => {
    try {
      setSessions(await listSessions())
      setLoadError('')
    } catch (e) {
      setLoadError((e as Error).message)
    } finally {
      setLoaded(true)
    }
  }, [])
  useEffect(() => {
    void refresh()
    const t = setInterval(() => void refresh(), POLL_MS)
    return () => clearInterval(t)
  }, [refresh])

  // Tabs hold the session as opened, so a tab outlives its row leaving the list.
  const [tabs, setTabs] = useState<Session[]>([])
  const [active, setActive] = useState<string | null>(null)
  const open = useCallback((s: Session) => {
    setTabs((t) => (t.some((x) => x.id === s.id) ? t : [...t, s]))
    setActive(s.id)
  }, [])
  const close = (id: string) => {
    const at = tabs.findIndex((t) => t.id === id)
    const next = tabs.filter((t) => t.id !== id)
    setTabs(next)
    if (active === id) setActive(next[Math.min(at, next.length - 1)]?.id ?? null)
  }

  // Here, not on the Sessions screen: Stop can fail in a workspace too.
  const [stuck, setStuck] = useState<ReadonlySet<string>>(new Set<string>())
  const markStuck = useCallback((id: string, on: boolean) => setStuck((cur) => {
    const next = new Set(cur)
    if (on) next.add(id)
    else next.delete(id)
    return next
  }), [])

  const [picks, setPicks] = useState<Pick[]>([])
  const togglePick = useCallback((p: Pick) => {
    // One kind at a time: a flow and a frame have nothing to compare.
    setPicks((cur) => (cur.some((x) => x.id === p.id) ? cur.filter((x) => x.id !== p.id) : [...cur.filter((x) => !x.message === !p.message), p].slice(-2)))
  }, [])

  const [comparing, setComparing] = useState(false)
  const [decoder, setDecoder] = useState<string | null>(null)
  const [newCapture, setNewCapture] = useState(false)
  const [services, setServices] = useState(false)
  const [managing, setManaging] = useState(false)
  const updates = useUpdates()
  const [timeline, setTimeline] = useState<{ session: string; flow: Flow } | null>(null)
  const onDecoder = useCallback((initial?: string) => setDecoder(initial ?? ''), [])
  const onOpenMessages = useCallback((session: string, flow: Flow) => setTimeline({ session, flow }), [])

  const toSessions = useCallback(() => setActive(null), [])
  const startCompare = useCallback(() => setComparing(true), [])
  const manageCatalog = useCallback(() => setManaging(true), [])
  const clearPicks = useCallback(() => setPicks([]), [])

  const sessionLabel = (id: string) => { const s = sessions.find((x) => x.id === id); return s?.label || id }
  const current = (t: Session) => sessions.find((s) => s.id === t.id) ?? t
  return (
    <div className="flex flex-col h-full">
      <nav role="tablist" className="flex items-center h-[38px] shrink-0 pl-2 pr-3 bg-chrome border-b border-line overflow-hidden">
        <button type="button" role="tab" aria-selected={active === null} onClick={() => setActive(null)}
          className={cx('flex items-center gap-2 h-full px-3 text-xs', active === null ? 'bg-app text-ink font-semibold' : 'text-muted hover:text-ink')}><List size={13} />Sessions</button>
        {tabs.map((tab) => {
          const t = current(tab)
          const count = picks.filter((p) => p.session === t.id).length
          return (
            <div key={t.id} className={cx('flex items-center gap-2 h-full pl-3 pr-1.5 min-w-0 max-w-56 text-xs', active === t.id ? 'bg-app text-ink font-semibold' : 'text-muted')}>
              <span aria-hidden className={cx('w-1.5 h-1.5 rounded-full shrink-0', isLive(t) && 'pulse')} style={{ background: isLive(t) ? 'var(--green)' : 'var(--dim)' }} />
              <button type="button" role="tab" aria-selected={active === t.id} onClick={() => setActive(t.id)} className="truncate min-w-0 hover:text-ink">{t.label || t.id.slice(0, 8)}</button>
              {count > 0 && <span title={`${count} compare pick${count > 1 ? 's' : ''}`} className="px-1.5 rounded tint tone-blue font-mono text-[10px]">{count}</span>}
              <IconButton label="Close tab" size={20} onClick={() => close(t.id)}><X size={11} /></IconButton>
            </div>
          )
        })}
        <span className="flex-1" />
        <span className="mr-3 text-xs text-ghost font-medium">TrafficDeck</span>
        <IconButton label="Toggle theme" size={26} className="border border-edge" onClick={() => setDark(!dark)}>{dark ? <Moon size={13} /> : <Sun size={13} />}</IconButton>
      </nav>
      <main className="flex-1 min-h-0 relative">
        <div className="h-full" style={{ display: active === null ? undefined : 'none' }}>
          <SessionsScreen sessions={sessions} loaded={loaded} loadError={loadError} refresh={refresh} stuck={stuck} onStuck={markStuck} onOpen={open} onNewCapture={() => setNewCapture(true)}
            onServices={() => setServices(true)} onUpdates={updates.check} checkingUpdates={updates.checking} />
        </div>
        {/* Every tab stays mounted: a hidden one keeps its filter, scroll and live subscription. */}
        {tabs.map((tab) => (
          <div key={tab.id} className="h-full" style={{ display: active === tab.id ? undefined : 'none' }}>
            <Workspace session={current(tab)} active={active === tab.id} picks={picks} onBack={toSessions} onTogglePick={togglePick}
              onCompare={startCompare} onClearPicks={clearPicks} onDecoder={onDecoder} onManageCatalog={manageCatalog} onOpenMessages={onOpenMessages} onSessionsChanged={refresh} onStuck={markStuck} />
          </div>
        ))}
      </main>
      {decoder !== null && <DecoderModal initial={decoder} onClose={() => setDecoder(null)} />}
      {timeline && <TimelineModal session={timeline.session} sessionLabel={sessionLabel(timeline.session)} flow={timeline.flow} picks={picks} onTogglePick={togglePick} onCompare={startCompare} onClearPicks={clearPicks} onClose={() => setTimeline(null)} />}
      {/* After the timeline: its Compare opens over it. */}
      {comparing && picks.length === 2 && <CompareModal picks={picks} onClose={() => setComparing(false)} onClear={() => { setPicks([]); setComparing(false) }} />}
      {services && <ServicesModal onClose={() => setServices(false)} />}
      {managing && <CatalogModal onClose={() => setManaging(false)} />}
      {updates.notice && <UpdateToast notice={updates.notice} checking={updates.checking} onCheck={updates.check} onHide={updates.hide} />}
      {newCapture && <NewCaptureDialog onClose={() => setNewCapture(false)} onStarted={(id) => {
        setNewCapture(false)
        void listSessions().then((list) => {
          setSessions(list)
          const s = list.find((x) => x.id === id)
          if (s) open(s)
        })
      }} />}
    </div>
  )
}
