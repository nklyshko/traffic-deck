import type { Session } from './types'

export const SCOPE_ALL = 'all'
export const SCOPE_UNGROUPED = 'ungrouped'
// Prefixed, because a group is free text and could be called "all".
export const groupScope = (group: string) => `group:${group}`

export interface Scope { key: string; label: string; count: number; live: number }

/** The rail's entries; empty until a first group exists, so an unused feature costs no width. */
export function sessionScopes(sessions: Session[], isLive: (s: Session) => boolean): Scope[] {
  const names = [...new Set(sessions.flatMap((s) => (s.group ? [s.group] : [])))]
  if (!names.length) return []
  const scope = (key: string, label: string, members: Session[]): Scope => ({ key, label, count: members.length, live: members.filter(isLive).length })
  const ungrouped = sessions.filter((s) => !s.group)
  return [
    scope(SCOPE_ALL, 'All sessions', sessions),
    ...(ungrouped.length ? [scope(SCOPE_UNGROUPED, 'Ungrouped', ungrouped)] : []),
    // Alphabetical, as in the TUI and MCP: a group holds its place while captures land in it.
    ...names.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())).map((g) => scope(groupScope(g), g, sessions.filter((s) => s.group === g))),
  ]
}

/** A remembered scope can outlive its group: groups exist only while a session names them. */
export const resolveScope = (scopes: Scope[], stored: string) => (scopes.some((s) => s.key === stored) ? stored : SCOPE_ALL)

export function inScope(s: Session, scope: string): boolean {
  if (scope === SCOPE_ALL) return true
  return scope === SCOPE_UNGROUPED ? !s.group : scope === groupScope(s.group ?? '')
}

/** The columns a capture source asks the flow table to show (`viewer.columns`): built-in ids
 *  such as `conn`, or else the flow metadata keys it attaches. */
export const declaredColumns = (s: Session) => [...new Set((s.metadata?.['viewer.columns'] ?? '').split(',').map((k) => k.trim()).filter(Boolean))]
