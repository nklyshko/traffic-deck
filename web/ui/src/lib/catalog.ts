import { useSyncExternalStore } from 'react'
import { listGroups, listTags } from './api'
import type { Group, Tag } from './types'

export const FAVORITE_TAG = '__favorite__'

interface Catalog { tags: Map<string, Tag>; groups: Map<string, Group> }
let catalog: Catalog = { tags: new Map(), groups: new Map() }
let loading: Promise<void> | null = null
const listeners = new Set<() => void>()

// Names are a nicety, so failures are swallowed: the table works with bare ids.
export function loadCatalog(force = false): Promise<void> {
  if (loading && !force) return loading
  loading = Promise.all([listTags().catch(() => null), listGroups().catch(() => null)]).then(([tags, groups]) => {
    catalog = {
      tags: tags ? new Map(tags.map((t) => [t.id, t])) : catalog.tags,
      groups: groups ? new Map(groups.map((g) => [g.id, g])) : catalog.groups,
    }
    listeners.forEach((l) => l())
  })
  return loading
}

export function useCatalog(): Catalog {
  return useSyncExternalStore((l) => {
    listeners.add(l)
    void loadCatalog()
    return () => { listeners.delete(l) }
  }, () => catalog)
}

export const userTags = (ids?: string[]) => (ids ?? []).filter((id) => id !== FAVORITE_TAG)
