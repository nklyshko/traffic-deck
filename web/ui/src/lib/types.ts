// Client types mirror protojson, where every zero value is omitted: all fields optional.
export type Str64 = string

export interface Session {
  id: string; label?: string; source?: string; status?: SessionStatus
  createdAtUnixMs?: Str64; closedAtUnixMs?: Str64; pcapBytes?: Str64; keylogBytes?: Str64
  flowCount?: number; group?: string; metadata?: Record<string, string>
}
export type SessionStatus = 'SESSION_STATUS_UNSPECIFIED' | 'SESSION_STATUS_OPEN' | 'SESSION_STATUS_DECODING' | 'SESSION_STATUS_CLOSED' | 'SESSION_STATUS_ERROR'

export interface Header { name?: string; value?: string }
export interface Cookie {
  name?: string; value?: string; domain?: string; path?: string; expires?: string
  maxAge?: Str64; secure?: boolean; httpOnly?: boolean; sameSite?: string
}
export interface Body { size?: Str64; contentType?: string; inline?: string; objectRef?: string; contentEncoding?: string }
export interface Comment { id: string; recordId?: string; body?: string; createdAtUnixMs?: Str64; updatedAtUnixMs?: Str64 }
export interface Proxy { addr?: string; type?: string; username?: string; password?: string }

export interface Annotations {
  markColor?: string; favorite?: boolean; tagIds?: string[]; groupIds?: string[]; comments?: Comment[]
}
export interface Flow extends Annotations {
  id: string; sessionId?: string; frameNumber?: Str64; tsUnixMicros?: Str64
  method?: string; scheme?: string; authority?: string; path?: string; query?: string; protocol?: string
  status?: number; srcAddr?: string; dstAddr?: string; userAgent?: string; contentType?: string
  tlsDecrypted?: boolean; connectionId?: string; streamId?: string
  requestHeaders?: Header[]; responseHeaders?: Header[]; requestCookies?: Cookie[]; responseCookies?: Cookie[]
  requestBody?: Body; responseBody?: Body; websocket?: boolean; messageCount?: number; proxy?: Proxy
  metadata?: Record<string, string>; error?: string; durationMicros?: Str64
  redirectLocation?: string; redirectedFromId?: string
  http2Fingerprint?: string; ja3?: string; ja4?: string; tlsClientHello?: string; tlsClientName?: string
  clientHellos?: string[] // base64; only from GetFlow, never in a page or the stream
  tlsHrr?: boolean
}
export interface FlowCursor { tsMicros?: Str64; frameNumber?: Str64 }
export interface FlowPage {
  flows?: Flow[]; next?: FlowCursor; prev?: FlowCursor; matched?: Str64; countCapped?: boolean
  scanned?: Str64; hints?: string[]; hiddenMatched?: Str64
}
export interface SessionEvent { sessionId?: string; status?: SessionStatus }
export interface DecodeProgress { sessionId?: string; percent?: number; stage?: string; done?: boolean }
export interface FlowEvent {
  flowAdded?: Flow; flowUpdated?: Flow; sessionEvent?: SessionEvent; decodeProgress?: DecodeProgress; flowUnmatched?: string
}
export interface WsMessage extends Annotations {
  id: string; sessionId?: string; flowId?: string; frameNumber?: Str64; tsUnixMicros?: Str64
  fromClient?: boolean; opcode?: string; payload?: Body; raw?: Body; metadata?: Record<string, string>
}
export interface MessageEvent_ { messageAdded?: WsMessage; sessionEvent?: SessionEvent; filterHints?: { hints?: string[] } }

export interface Tag { id: string; name?: string; color?: string; isFavorite?: boolean }
export interface Group { id: string; name?: string; color?: string; parentId?: string }

export type ParamType = 'PARAM_TYPE_STRING' | 'PARAM_TYPE_PATH' | 'PARAM_TYPE_BOOL' | 'PARAM_TYPE_INT' | 'PARAM_TYPE_CHOICE'
export interface Param {
  key: string; label?: string; type?: ParamType; choices?: { value?: string; label?: string }[]
  default?: string; required?: boolean
}
export interface SourceDescriptor { params?: Param[]; readiness?: 'READINESS_READY' | 'READINESS_PROVISION_REQUIRED'; message?: string }
export interface CaptureSourceInfo { name: string; label?: string; keepWarm?: boolean }
export interface SessionArtifacts { pcapPath?: string; keylogPath?: string; pcapBytes?: Str64; keylogBytes?: Str64; hostname?: string }

export interface ComponentUpdate { name?: string; updateAvailable?: boolean; localRev?: string; remoteRev?: string; updateHint?: string; error?: string }
export interface UpdateStatus { components?: ComponentUpdate[]; checkedUnixMs?: Str64 }
export interface ServiceInfo { name: string; label?: string; running?: boolean; url?: string; detail?: string }
export interface LogInfo { name: string; label?: string; sizeBytes?: Str64; modifiedUnixMs?: Str64 }
