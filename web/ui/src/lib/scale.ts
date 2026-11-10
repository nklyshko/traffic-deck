import { useSyncExternalStore } from 'react'
import { setting, subscribeSetting, update, type Settings } from './settings'

// Layout is written in px at the browser's default text size, 16 px to the rem. rem() turns
// such a count into rem, so it grows with the root font size: the user's browser setting and
// the Text size choice both act there.
export const REM = 16
export const rem = (px: number) => `${px / REM}rem`

export type TextSize = Settings['textSize']
export const TEXT_SIZES: { id: TextSize; label: string; percent: number }[] = [
  { id: 'small', label: 'Small', percent: 87.5 },
  { id: 'default', label: 'Default', percent: 100 },
  { id: 'large', label: 'Large', percent: 112.5 },
  { id: 'larger', label: 'Larger', percent: 125 },
]

// A percentage of the browser's size, never px, which would override the user's own setting.
export function applyTextSize(size: TextSize) {
  const percent = TEXT_SIZES.find((s) => s.id === size)?.percent ?? 100
  document.documentElement.style.fontSize = percent === 100 ? '' : `${percent}%`
}

/** Restyles the root before the store notifies, so whoever re-renders reads the new scale. */
export function setTextSize(size: TextSize) {
  applyTextSize(size)
  update('textSize', size)
}

const rootPx = () => parseFloat(getComputedStyle(document.documentElement).fontSize) || REM

/** Real px per layout px, for code that must measure or position in px: virtual rows, drags. */
export const scaleNow = () => rootPx() / REM

export function useScale(): number {
  // The root is restyled when the setting changes, so the setting is the signal to re-read it.
  useSyncExternalStore(subscribeSetting, () => setting('textSize'))
  return scaleNow()
}
