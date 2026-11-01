import type {
  CaptureSourceInfo, Comment, Flow, FlowPage, Group, LogInfo, ServiceInfo, Session, SessionArtifacts, SourceDescriptor, Tag, UpdateStatus, WsMessage,
} from './types'
import { num } from './format'

async function failure(r: Response): Promise<Error> {
  const text = (await r.text().catch(() => '')).trim()
  return new Error(text || `HTTP ${r.status}`)
}

async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  const r = await fetch(path, { signal })
  if (!r.ok) throw await failure(r)
  return r.json()
}

export function qs(params: Record<string, string | number | boolean | undefined>): string {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '' && v !== false) q.set(k, v === true ? '1' : String(v))
  return q.toString()
}

export async function rpc<T = unknown>(method: string, body: unknown = {}, signal?: AbortSignal): Promise<T> {
  const r = await fetch(`/api/rpc/${method}`, {
    method: 'POST',
    signal,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!r.ok) throw await failure(r)
  return r.json()
}

export const listSessions = () => getJSON<{ sessions?: Session[] }>('/api/sessions').then((r) => r.sessions ?? [])

export interface FlowQuery { session: string; filter: string; hidden?: boolean; limit?: number; last?: boolean; after?: string; before?: string }
export const queryFlows = (q: FlowQuery, signal?: AbortSignal) => getJSON<FlowPage>(`/api/flows?${qs({ ...q })}`, signal)
export const listMessages = (session: string, flow: string) => getJSON<{ messages?: WsMessage[] }>(`/api/messages?${qs({ session, flow })}`).then((r) => r.messages ?? [])
export const getFlow = (session: string, id: string) => getJSON<Flow>(`/api/flow?${qs({ session, id })}`)

// null: a flow with no stored body is an ordinary answer, not an error.
async function getBytes(url: string): Promise<Uint8Array | null> {
  const r = await fetch(url)
  if (r.status === 404) return null
  if (!r.ok) throw await failure(r)
  return new Uint8Array(await r.arrayBuffer())
}
export const getBody = (session: string, id: string, response: boolean) => getBytes(`/api/body?${qs({ session, id, response })}`)
export const getMessageBody = (session: string, id: string, raw: boolean) => getBytes(`/api/message/body?${qs({ session, id, raw })}`)

export async function importBundle(file: File): Promise<void> {
  const r = await fetch('/api/session/import', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: file })
  if (!r.ok) throw await failure(r)
}

export const exportUrl = (session: string) => `/api/session/export?${qs({ session })}`
export const flowStreamUrl = (session: string, filter: string, hidden: boolean) => `/api/stream?${qs({ session, filter, hidden })}`
export const messageStreamUrl = (session: string, flow: string, filter: string) => `/api/messages/stream?${qs({ session, flow, filter })}`

export const listSources = () => rpc<{ sources?: CaptureSourceInfo[] }>('ListCaptureSources').then((r) => r.sources ?? [])
export const describeSource = (source: string, params: Record<string, string>) => rpc<SourceDescriptor>('DescribeCaptureSource', { source, params })
export const startCapture = (source: string, label: string, params: Record<string, string>) =>
  rpc<{ sessionId?: string }>('StartCapture', { source, label, params })
export const stopCapture = (sessionId: string) => rpc('StopCapture', { sessionId })
export const forceClose = (sessionId: string) => rpc('ForceCloseSession', { sessionId })
export const deleteSession = (sessionId: string) => rpc('DeleteSession', { sessionId })
export const setLabel = (sessionId: string, label: string) => rpc('SetSessionLabel', { sessionId, label })
export const setGroup = (sessionId: string, group: string) => rpc('SetSessionGroup', { sessionId, group })
export const importCapture = (pcapPath: string, keylogPath: string, label: string, engine: string) =>
  rpc('ImportCapture', { pcapPath, keylogPath, label, engine })
export const sessionArtifacts = (sessionId: string) => rpc<SessionArtifacts>('GetSessionArtifacts', { sessionId })

export const listTags = () => rpc<{ tags?: Tag[] }>('ListTags').then((r) => r.tags ?? [])
export const listGroups = () => rpc<{ groups?: Group[] }>('ListGroups').then((r) => r.groups ?? [])
export const createTag = (name: string, color: string) => rpc<Tag>('CreateTag', { name, color })
export const setTags = (sessionId: string, recordIds: string[], addTagIds: string[], removeTagIds: string[]) =>
  rpc('SetTags', { sessionId, recordIds, addTagIds, removeTagIds })
export const setGroups = (sessionId: string, recordIds: string[], addGroupIds: string[], removeGroupIds: string[]) =>
  rpc('SetGroups', { sessionId, recordIds, addGroupIds, removeGroupIds })
export const toggleFavorite = (sessionId: string, recordIds: string[]) => rpc('ToggleFavorite', { sessionId, recordIds })
export const setMark = (sessionId: string, recordIds: string[], color: string) => rpc('SetMark', { sessionId, recordIds, color })
export const clearMark = (sessionId: string, recordIds: string[]) => rpc('ClearMark', { sessionId, recordIds })
export const addComment = (sessionId: string, recordId: string, body: string) => rpc<Comment>('AddComment', { sessionId, recordId, body })
export const editComment = (sessionId: string, id: string, body: string) => rpc<Comment>('EditComment', { sessionId, id, body })
export const deleteTag = (id: string) => rpc('DeleteTag', { id })
export const createGroup = (name: string, color: string, parentId: string) => rpc<Group>('CreateGroup', { name, color, parentId })
// The gateway writes every field, so a rename has to send the colour and parent back.
export const updateGroup = (g: Group) => rpc<Group>('UpdateGroup', { id: g.id, name: g.name, color: g.color, parentId: g.parentId })
export const deleteGroup = (id: string) => rpc('DeleteGroup', { id })
export const deleteComment = (sessionId: string, id: string) => rpc('DeleteComment', { sessionId, id })

export const listServices = () => rpc<{ services?: ServiceInfo[] }>('ListServices').then((r) => r.services ?? [])
export const startService = (name: string) => rpc('StartService', { name })
export const stopService = (name: string) => rpc('StopService', { name })
export const listLogs = () => rpc<{ logs?: LogInfo[] }>('ListLogs').then((r) => r.logs ?? [])
export async function getLog(name: string, max: number): Promise<string> {
  const r = await fetch(`/api/log?${qs({ name, max })}`)
  if (!r.ok) throw await failure(r)
  return r.text()
}

// A refresh waits on each git remote, so it gets a deadline.
const UPDATE_DEADLINE_MS = 30000
// No completed check is not "up to date": null here, so no caller can mistake the two.
export const checkUpdates = (refresh: boolean) => rpc<UpdateStatus>('CheckUpdates', { refresh }, AbortSignal.timeout(UPDATE_DEADLINE_MS))
  .then((s) => (num(s.checkedUnixMs) ? s : null))
