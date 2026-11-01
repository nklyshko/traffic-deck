import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { flowStreamUrl, queryFlows } from './api'
import { num } from './format'
import type { DecodeProgress, Flow, FlowEvent, FlowPage, SessionEvent } from './types'
import { cursorOf, extendWindow, MAX_ROWS, PAGE_SIZE, patchFlow } from './window'

export type Anchor = 'first' | 'last'

interface State {
  rows: Flow[]
  hasOlder: boolean
  hasNewer: boolean
  matched: number
  capped: boolean
  hiddenMatched: number
  hints: string[]
  pending: number
  error: string
  loading: boolean
}
const EMPTY: State = { rows: [], hasOlder: false, hasNewer: false, matched: 0, capped: false, hiddenMatched: 0, hints: [], pending: 0, error: '', loading: true }
const STREAM_FLUSH_MS = 50
const RETRY_MS = 2000
const MAX_RETRY_MS = 30000

function fromPage(page: FlowPage): State {
  return {
    rows: page.flows ?? [], hasOlder: !!page.prev, hasNewer: !!page.next, matched: num(page.matched),
    capped: !!page.countCapped, hiddenMatched: num(page.hiddenMatched), hints: page.hints ?? [], pending: 0, error: '', loading: false,
  }
}

interface Options {
  session: string
  filter: string
  hidden: boolean
  live: boolean
  follow: boolean
  onClosed: (e: SessionEvent) => void
  onProgress: (p: DecodeProgress | null) => void
}

// One contiguous window of the matching set: never a page, never the whole session.
export function useFlowWindow({ session, filter, hidden, live, follow, onClosed, onProgress }: Options) {
  const [state, setState] = useState<State>(EMPTY)
  const [flashed, setFlashed] = useState<ReadonlySet<string>>(new Set<string>())
  const [scrollTo, setScrollTo] = useState<{ kind: 'bottom' | 'top' | 'delta'; delta?: number; seq: number }>({ kind: 'top', seq: 0 })
  const seq = useRef(0)
  const nudge = (kind: 'bottom' | 'top' | 'delta', delta?: number) => setScrollTo({ kind, delta, seq: ++seq.current })

  // Reset during render, not in an effect: no frame may show old rows under a new filter.
  const key = `${session}\0${filter}\0${hidden}`
  const [prevKey, setPrevKey] = useState(key)
  if (key !== prevKey) {
    setPrevKey(key)
    setState(EMPTY)
  }

  const stateRef = useRef(state)
  useLayoutEffect(() => { stateRef.current = state })
  // Written through at once, so a batch can compute what it did before React renders it.
  const commit = useCallback((next: State) => {
    stateRef.current = next
    setState(next)
  }, [])
  const refillGen = useRef(0)
  const bufferGen = useRef(0)
  const extending = useRef(false)

  const refill = useCallback(async (anchor: Anchor) => {
    const gen = ++refillGen.current
    bufferGen.current++
    setState((s) => ({ ...s, loading: true }))
    try {
      const page = await queryFlows({ session, filter, hidden, limit: PAGE_SIZE, last: anchor === 'last' })
      if (gen !== refillGen.current) return
      bufferGen.current++
      setState(fromPage(page))
      nudge(anchor === 'last' ? 'bottom' : 'top')
    } catch (e) {
      if (gen === refillGen.current) setState((s) => ({ ...s, loading: false, error: (e as Error).message }))
    }
  }, [session, filter, hidden])

  const refillRef = useRef(refill)
  useLayoutEffect(() => { refillRef.current = refill })
  const followRef = useRef(follow)
  useLayoutEffect(() => { followRef.current = follow })
  useEffect(() => { void refill(followRef.current ? 'last' : 'first') }, [refill])

  const extend = useCallback(async (dir: 'older' | 'newer') => {
    const s = stateRef.current
    if (extending.current || s.rows.length === 0 || !(dir === 'older' ? s.hasOlder : s.hasNewer)) return
    extending.current = true
    const gen = bufferGen.current
    try {
      const page = await queryFlows({
        session, filter, hidden, limit: PAGE_SIZE,
        ...(dir === 'older' ? { before: cursorOf(s.rows[0]) } : { after: cursorOf(s.rows[s.rows.length - 1]) }),
      })
      // Merging into a replaced buffer would splice a gap into a contiguous window.
      if (gen !== bufferGen.current) return
      const cur = stateRef.current
      const ext = extendWindow(cur.rows, page.flows ?? [], dir, MAX_ROWS)
      commit({
        ...cur, rows: ext.rows,
        hasOlder: dir === 'older' ? !!page.prev : cur.hasOlder || ext.trimmedFar,
        hasNewer: dir === 'newer' ? !!page.next : cur.hasNewer || ext.trimmedFar,
      })
      if (ext.frontDelta) nudge('delta', ext.frontDelta)
    } catch (e) {
      setState((cur) => ({ ...cur, error: (e as Error).message }))
    } finally {
      extending.current = false
    }
  }, [session, filter, hidden, commit])

  // In a ref: a caller's new function must not tear down the subscription.
  const handlers = useRef({ onClosed, onProgress })
  useLayoutEffect(() => { handlers.current = { onClosed, onProgress } })

  const applyEvents = useCallback((events: FlowEvent[]) => {
    let frontDelta = 0
    const added: string[] = []
    const s = stateRef.current
    let { rows, matched, pending, hasOlder } = s
    // Copied once per batch and indexed once, so a burst costs one pass over the buffer.
    const next = rows.slice()
    const index = new Map(next.map((r, i) => [r.id, i]))
    const removed = new Set<string>()
    for (const ev of events) {
      if (ev.flowAdded) {
        matched++
        if (s.hasNewer) pending++
        else if (!index.has(ev.flowAdded.id)) {
          index.set(ev.flowAdded.id, next.length)
          next.push(ev.flowAdded)
          added.push(ev.flowAdded.id)
        }
      } else if (ev.flowUpdated) {
        const at = index.get(ev.flowUpdated.id)
        // Streamed updates carry no annotations, so there is nothing cleared to drop.
        if (at !== undefined) next[at] = { ...next[at], ...ev.flowUpdated }
      } else if (ev.flowUnmatched) {
        if (index.has(ev.flowUnmatched)) removed.add(ev.flowUnmatched)
        matched = Math.max(0, matched - 1)
      }
    }
    rows = removed.size ? next.filter((r) => !removed.has(r.id)) : next
    frontDelta -= Math.max(0, next.findIndex((r) => !removed.has(r.id)))
    if (rows.length > MAX_ROWS) {
      frontDelta -= rows.length - MAX_ROWS
      rows = rows.slice(rows.length - MAX_ROWS)
      hasOlder = true
    }
    commit({ ...s, rows, matched, pending, hasOlder })
    for (const ev of events) {
      // The subscription is live. A flow published between the first page and this point is
      // in neither, and only a query made now can pick it up.
      if (ev.sessionEvent?.status === 'SESSION_STATUS_OPEN') void refillRef.current(followRef.current ? 'last' : 'first')
      if (ev.sessionEvent?.status === 'SESSION_STATUS_CLOSED' || ev.sessionEvent?.status === 'SESSION_STATUS_ERROR') handlers.current.onClosed(ev.sessionEvent)
      if (ev.decodeProgress) handlers.current.onProgress(ev.decodeProgress.done ? null : ev.decodeProgress)
    }
    if (frontDelta) nudge('delta', frontDelta)
    if (added.length) {
      setFlashed((f) => new Set([...f, ...added]))
      setTimeout(() => setFlashed((f) => {
        const next = new Set(f)
        added.forEach((id) => next.delete(id))
        return next
      }), 1800)
    }
  }, [commit])

  // Batched: at 200 events/s a render per event would drop frames. A timer rather than
  // requestAnimationFrame, which stops in a hidden browser tab.
  useEffect(() => {
    if (!live) return
    let source: EventSource
    let buffer: FlowEvent[] = []
    let timer: ReturnType<typeof setTimeout> | undefined
    let retry: ReturnType<typeof setTimeout> | undefined
    let delay = RETRY_MS
    const flush = () => {
      timer = undefined
      const batch = buffer
      buffer = []
      applyEvents(batch)
    }
    const connect = () => {
      source = new EventSource(flowStreamUrl(session, filter, hidden))
      source.onmessage = (e) => {
        delay = RETRY_MS
        buffer.push(JSON.parse(e.data))
        timer ??= setTimeout(flush, STREAM_FLUSH_MS)
      }
      source.addEventListener('end', () => source.close())
      // Missed deltas cannot be replayed, so a lost stream refetches. It also subscribes again:
      // the session is still live, and closing the source ended the browser's own retry.
      source.onerror = () => {
        source.close()
        void refill(followRef.current ? 'last' : 'first')
        retry = setTimeout(connect, delay)
        delay = Math.min(delay * 2, MAX_RETRY_MS)
      }
    }
    connect()
    return () => {
      source.close()
      clearTimeout(timer)
      clearTimeout(retry)
    }
  }, [session, filter, hidden, live, applyEvents, refill])

  const patchRow = useCallback((flow: Flow) => {
    const s = stateRef.current
    const at = s.rows.findIndex((r) => r.id === flow.id)
    if (at < 0) return
    const rows = s.rows.slice()
    rows[at] = patchFlow(rows[at], flow)
    commit({ ...s, rows })
  }, [commit])

  return useMemo(() => ({ ...state, flashed, scrollTo, refill, extend, patchRow }), [state, flashed, scrollTo, refill, extend, patchRow])
}
