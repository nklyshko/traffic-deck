import type { Annotations, Flow } from './types'

export const PAGE_SIZE = 250
export const MAX_ROWS = 5000
export const EDGE_ROWS = 10

export const cursorOf = (f: Flow): string => `${f.tsUnixMicros ?? 0}:${f.frameNumber ?? 0}`

export interface Extension<T> {
  rows: T[]
  frontDelta: number // rows added (+) or removed (−) above the first old row
  trimmedFar: boolean
}

// Extends a contiguous window by one page, deduping by id. Over `max`, the far end is trimmed
// and not cached: scrolling back re-queries it by cursor.
export function extendWindow<T extends { id: string }>(cur: T[], incoming: T[], dir: 'older' | 'newer', max: number): Extension<T> {
  const have = new Set(cur.map((r) => r.id))
  const fresh = incoming.filter((r) => !have.has(r.id))
  if (fresh.length === 0) return { rows: cur, frontDelta: 0, trimmedFar: false }
  if (dir === 'older') {
    const rows = [...fresh, ...cur]
    const trimmedFar = rows.length > max
    return { rows: trimmedFar ? rows.slice(0, max) : rows, frontDelta: fresh.length, trimmedFar }
  }
  const rows = [...cur, ...fresh]
  const over = rows.length - max
  return over > 0 ? { rows: rows.slice(over), frontDelta: -over, trimmedFar: true } : { rows, frontDelta: 0, trimmedFar: false }
}

// When merging a re-read record, fields that may have been cleared must leave the cached copy
// first: protojson omits them, so a plain spread would keep a cleared mark.
export function patchFlow<T extends object>(cached: T, fresh: T): T {
  const kept: Partial<T> & Annotations = { ...cached }
  delete kept.markColor
  delete kept.favorite
  delete kept.tagIds
  delete kept.groupIds
  delete kept.comments
  return { ...kept, ...fresh }
}
