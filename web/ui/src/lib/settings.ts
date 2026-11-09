import { useCallback, useSyncExternalStore } from 'react'

// One store, so every mounted tab sees a change at once: per-component copies drift between
// hidden tabs.
export interface Settings {
  dark: boolean
  compact: boolean
  showHidden: boolean
  columnOverrides: Record<string, boolean>
  columnWidths: Record<string, number>
  frameColumnOverrides: Record<string, boolean>
  frameColumnWidths: Record<string, number>
  detailsWidth: number
  detailsCollapsed: boolean
  annotationsOpen: boolean
  sessionScope: string
  diffView: 'inline' | 'split'
  'updates.checkedAt': number
  'updates.dismissed': string
}

const systemDark = () => typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: dark)').matches
const DEFAULTS = (): Settings => ({
  dark: systemDark(), compact: false, showHidden: false, columnOverrides: {}, columnWidths: {}, frameColumnOverrides: {}, frameColumnWidths: {}, detailsWidth: 40, detailsCollapsed: false, annotationsOpen: false, sessionScope: 'all', diffView: 'inline', 'updates.checkedAt': 0, 'updates.dismissed': '',
})

// typeof alone would let null and arrays through, and those crash whoever indexes them.
export function accepts(key: string, v: unknown, dflt: unknown): boolean {
  if (typeof v !== typeof dflt) return false
  if (key === 'detailsWidth') return (v as number) >= 20 && (v as number) <= 80
  if (key === 'diffView') return v === 'inline' || v === 'split'
  return typeof dflt !== 'object' || (v !== null && !Array.isArray(v))
}

function load(): Settings {
  const out = DEFAULTS() as unknown as Record<string, unknown>
  for (const key of Object.keys(out)) {
    try {
      const raw = localStorage.getItem(`td.${key}`)
      if (raw !== null) {
        const v = JSON.parse(raw)
        if (accepts(key, v, out[key])) out[key] = v
      }
    } catch { /* corrupt or blocked storage reads as the default */ }
  }
  return out as unknown as Settings
}

let state = load()
const listeners = new Set<() => void>()

export const setting = <K extends keyof Settings>(key: K): Settings[K] => state[key]

export function update<K extends keyof Settings>(key: K, value: Settings[K] | ((cur: Settings[K]) => Settings[K])): void {
  const next = typeof value === 'function' ? (value as (c: Settings[K]) => Settings[K])(state[key]) : value
  state = { ...state, [key]: next }
  try {
    localStorage.setItem(`td.${key}`, JSON.stringify(next))
  } catch { /* preferences simply don't persist */ }
  listeners.forEach((l) => l())
}

const subscribe = (l: () => void) => {
  listeners.add(l)
  return () => { listeners.delete(l) }
}

export function useSetting<K extends keyof Settings>(key: K): [Settings[K], (v: Settings[K] | ((c: Settings[K]) => Settings[K])) => void] {
  const value = useSyncExternalStore(subscribe, () => state[key])
  return [value, useCallback((v) => update(key, v), [key])]
}
