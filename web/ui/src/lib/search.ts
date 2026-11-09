// One matching rule for every search box in the app (SPEC §5.2.1b, §5.3): each
// whitespace-separated term must appear, case ignored, in at least one field.

export const searchTerms = (query: string) => query.toLowerCase().split(/\s+/).filter(Boolean)

export function matchesTerms(terms: string[], fields: (string | undefined)[]): boolean {
  if (!terms.length) return true
  const lower = fields.flatMap((f) => (f ? [f.toLowerCase()] : []))
  return terms.every((t) => lower.some((f) => f.includes(t)))
}

export interface Run { text: string; hit: boolean }

/** Splits text into runs, marking every occurrence of every term, so the eye finds why it matched. */
export function matchRuns(text: string, terms: string[]): Run[] {
  const marks = new Array<boolean>(text.length).fill(false)
  const lower = text.toLowerCase()
  for (const t of terms) {
    for (let i = lower.indexOf(t); i >= 0; i = lower.indexOf(t, i + 1)) marks.fill(true, i, i + t.length)
  }
  const runs: Run[] = []
  for (let i = 0; i < text.length; i++) {
    const last = runs[runs.length - 1]
    if (last && last.hit === marks[i]) last.text += text[i]
    else runs.push({ text: text[i], hit: marks[i] })
  }
  return runs
}

/** "Browser binary" → "browser binaries", for "No browser binaries match …". */
export function plural(label: string): string {
  const w = label.toLowerCase()
  if (/[^aeiou]y$/.test(w)) return w.slice(0, -1) + 'ies'
  if (/(s|x|z|ch|sh)$/.test(w)) return w + 'es'
  return w + 's'
}
