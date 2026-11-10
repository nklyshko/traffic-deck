import { RefreshCw, X } from 'lucide-react'
import { rem } from '../lib/scale'
import { useCallback, useEffect, useRef, useState } from 'react'
import { checkUpdates } from '../lib/api'
import { setting, update } from '../lib/settings'
import { checkedAgo, refreshDue, updateNotice, type Notice } from '../lib/updates'
import { Button, cx, IconButton } from './ui'

const HIDE_MS = { amber: 15000, blue: 6000 }

export function useUpdates() {
  const [checking, setChecking] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  const inFlight = useRef(false)

  const run = useCallback(async (manual: boolean) => {
    if (inFlight.current) return
    inFlight.current = true
    const now = Date.now()
    const refresh = manual || refreshDue(setting('updates.checkedAt'), now)
    // Before the call, so a remote that times out doesn't retry on every reload.
    if (refresh) update('updates.checkedAt', now)
    setChecking(true)
    try {
      const n = updateNotice(await checkUpdates(refresh))
      if (manual || (n.key && n.key !== setting('updates.dismissed'))) setNotice(n)
    } catch (e) {
      if (manual) setNotice({ tone: 'amber', headline: `update check failed: ${(e as Error).message}`, details: [], key: '', checkedMs: 0 })
    } finally {
      inFlight.current = false
      setChecking(false)
    }
  }, [])

  // No timers: the viewer owns the cadence, and these are its only triggers.
  useEffect(() => {
    void run(false)
    const onVisible = () => { if (document.visibilityState === 'visible') void run(false) }
    document.addEventListener('visibilitychange', onVisible)
    return () => document.removeEventListener('visibilitychange', onVisible)
  }, [run])

  const check = useCallback(() => void run(true), [run])
  const hide = useCallback(() => setNotice(null), [])
  return { checking, notice, check, hide }
}

export function UpdateToast({ notice, checking, onCheck, onHide }: { notice: Notice; checking: boolean; onCheck: () => void; onHide: () => void }) {
  const [hovered, setHovered] = useState(false)
  useEffect(() => {
    if (hovered || checking) return
    const t = setTimeout(onHide, HIDE_MS[notice.tone])
    return () => clearTimeout(t)
  }, [notice, hovered, checking, onHide])
  const dismiss = () => {
    if (notice.key) update('updates.dismissed', notice.key)
    onHide()
  }
  return (
    <div role="status" aria-live="polite" onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}
      className={cx('fixed z-50 right-6 bottom-6 w-95 max-w-[calc(100vw-32px)] p-3 space-y-2 rounded-[10px] border bg-toast', `tone-${notice.tone}`)}
      style={{ borderColor: 'color-mix(in srgb, var(--t) 40%, transparent)', boxShadow: '0 8px 24px var(--shadow)' }}>
      <div className="flex items-start gap-2">
        <span aria-hidden className="w-2 h-2 mt-1 rounded-full shrink-0" style={{ background: 'var(--t)' }} />
        <span className="flex-1 min-w-0 text-13 font-semibold text-ink break-words">{notice.headline}</span>
        <IconButton label="Dismiss" size={20} onClick={dismiss}><X size={rem(12)} /></IconButton>
      </div>
      {notice.action && <code className="block px-2.5 py-1.5 rounded-md bg-well border border-line font-mono text-11 text-ink select-all break-all">{notice.action}</code>}
      {notice.details.map((d, i) => <p key={i} className="font-mono text-11 text-muted break-words">{d}</p>)}
      <div className="flex items-center gap-2">
        <Button size="xs" disabled={checking} icon={<RefreshCw size={rem(11)} className={checking ? 'spin' : undefined} />} onClick={onCheck}>Check again</Button>
        <span className="flex-1" />
        {notice.checkedMs > 0 && <span className="text-10 text-faint">checked {checkedAgo(notice.checkedMs, Date.now())}</span>}
      </div>
    </div>
  )
}
