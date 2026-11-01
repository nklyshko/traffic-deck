import { num } from './format'
import type { UpdateStatus } from './types'

export interface Notice {
  tone: 'amber' | 'blue'
  headline: string
  action?: string
  details: string[]
  key: string
  checkedMs: number
}

// Calendar days, not 24 hours: setDate keeps 08:00 across DST and month ends.
export function lastEightAm(now: number): number {
  const d = new Date(now)
  d.setHours(8, 0, 0, 0)
  if (d.getTime() > now) d.setDate(d.getDate() - 1)
  return d.getTime()
}

export const refreshDue = (stamp: number, now: number): boolean => stamp < lastEightAm(now)

function errorLines(failed: { name: string; error: string }[]): string[] {
  const errors = new Set(failed.map((c) => c.error))
  if (failed.length > 1 && errors.size === 1) return [`could not check ${failed.map((c) => c.name).join(', ')} (${failed[0].error})`]
  return failed.map((c) => `could not check ${c.name} (${c.error})`)
}

export function updateNotice(status: UpdateStatus | null): Notice {
  if (!status) return { tone: 'amber', headline: 'no update answer yet — checks may be off', details: [], key: '', checkedMs: 0 }
  const checkedMs = num(status.checkedUnixMs)
  const components = (status.components ?? []).map((c) => ({ ...c, name: c.name ?? '', error: c.error ?? '' }))
  if (!components.length) return { tone: 'blue', headline: 'nothing is enrolled for update checks', details: [], key: '', checkedMs }
  const behind = components.filter((c) => c.updateAvailable)
  const failed = components.filter((c) => c.error)
  const errors = errorLines(failed)
  if (behind.length) {
    const hints = new Set(behind.map((c) => c.updateHint ?? ''))
    const shared = hints.size === 1 ? [...hints][0] : ''
    const details = behind.map((c) => {
      const line = `${c.name} ${c.localRev || '?'} → ${c.remoteRev || '?'}`
      return !shared && c.updateHint ? `${line} — ${c.updateHint}` : line
    })
    return {
      tone: 'amber', headline: 'update available', action: shared || undefined, details: [...details, ...errors],
      key: behind.map((c) => `${c.name}@${c.remoteRev ?? ''}`).join(' '), checkedMs,
    }
  }
  if (!failed.length) return { tone: 'blue', headline: 'everything is up to date', details: [], key: '', checkedMs }
  // Offline is not up to date, so a partial answer never claims it.
  const headline = failed.length < components.length ? 'nothing new where it could be checked' : 'could not check for updates'
  return { tone: 'amber', headline, details: errors, key: '', checkedMs }
}

export function checkedAgo(ms: number, now: number): string {
  const minutes = Math.floor(Math.max(0, now - ms) / 60000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes} min ago`
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`
  return `${Math.floor(minutes / 1440)}d ago`
}
