import { useCallback, useSyncExternalStore } from 'react'

// One store, so every mounted tab sees a change at once: per-component copies drift between
// hidden tabs.
export interface Settings {
  dark: boolean
  compact: boolean
  columnOverrides: Record<string, boolean>
  detailsWidth: number
  detailsCollapsed: boolean
  annotationsOpen: boolean
}

const systemDark = () => typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: dark)').matches
const DEFAULTS = (): Settings => ({
  dark: systemDark(), compact: false, columnOverrides: {}, detailsWidth: 40, detailsCollapsed: false, annotationsOpen: false,
})

function load(): Settings {
  const out = DEFAULTS() as unknown as Record<string, unknown>
  for (const key of Object.keys(out)) {
    try {
      const raw = localStorage.getItem(`td.${key}`)
      if (raw !== null) {
        const v = JSON.parse(raw)
        if (typeof v === typeof out[key]) out[key] = v
      }
    } catch { /* corrupt or blocked storage reads as the default */ }
  }
  return out as unknown as Settings
}

let state = load()
const listeners = new Set<() => void>()

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
