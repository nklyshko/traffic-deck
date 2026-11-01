export interface Selection { anchor: string | null; set: ReadonlySet<string> }
export const NOTHING: ReadonlySet<string> = new Set<string>()

export function select(ids: string[], cur: Selection, id: string, mods: { shift?: boolean; toggle?: boolean }): Selection {
  if (mods.shift && cur.anchor !== null) {
    const from = ids.indexOf(cur.anchor), to = ids.indexOf(id)
    if (from >= 0 && to >= 0) return { anchor: cur.anchor, set: new Set(ids.slice(Math.min(from, to), Math.max(from, to) + 1)) }
  }
  if (!mods.toggle) return { anchor: id, set: NOTHING }
  const set = new Set(cur.set.size ? cur.set : cur.anchor === null ? [] : [cur.anchor])
  if (set.delete(id)) return { anchor: id === cur.anchor ? ([...set].pop() ?? null) : cur.anchor, set }
  set.add(id)
  return { anchor: id, set }
}
