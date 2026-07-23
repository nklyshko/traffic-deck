from traffic.v1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ListSessionsRequest(_message.Message):
    __slots__ = ("limit", "offset")
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    limit: int
    offset: int
    def __init__(self, limit: _Optional[int] = ..., offset: _Optional[int] = ...) -> None: ...

class SessionList(_message.Message):
    __slots__ = ("sessions",)
    SESSIONS_FIELD_NUMBER: _ClassVar[int]
    sessions: _containers.RepeatedCompositeFieldContainer[_common_pb2.Session]
    def __init__(self, sessions: _Optional[_Iterable[_Union[_common_pb2.Session, _Mapping]]] = ...) -> None: ...

class StreamFlowsRequest(_message.Message):
    __slots__ = ("session_id", "include_backfill", "follow")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_BACKFILL_FIELD_NUMBER: _ClassVar[int]
    FOLLOW_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    include_backfill: bool
    follow: bool
    def __init__(self, session_id: _Optional[str] = ..., include_backfill: bool = ..., follow: bool = ...) -> None: ...

class SessionEvent(_message.Message):
    __slots__ = ("session_id", "status")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    status: _common_pb2.SessionStatus
    def __init__(self, session_id: _Optional[str] = ..., status: _Optional[_Union[_common_pb2.SessionStatus, str]] = ...) -> None: ...

class FlowEvent(_message.Message):
    __slots__ = ("flow_added", "flow_updated", "session_event", "decode_progress")
    FLOW_ADDED_FIELD_NUMBER: _ClassVar[int]
    FLOW_UPDATED_FIELD_NUMBER: _ClassVar[int]
    SESSION_EVENT_FIELD_NUMBER: _ClassVar[int]
    DECODE_PROGRESS_FIELD_NUMBER: _ClassVar[int]
    flow_added: _common_pb2.Flow
    flow_updated: _common_pb2.Flow
    session_event: SessionEvent
    decode_progress: _common_pb2.DecodeProgress
    def __init__(self, flow_added: _Optional[_Union[_common_pb2.Flow, _Mapping]] = ..., flow_updated: _Optional[_Union[_common_pb2.Flow, _Mapping]] = ..., session_event: _Optional[_Union[SessionEvent, _Mapping]] = ..., decode_progress: _Optional[_Union[_common_pb2.DecodeProgress, _Mapping]] = ...) -> None: ...

class GetFlowRequest(_message.Message):
    __slots__ = ("session_id", "flow_id")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    FLOW_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    flow_id: str
    def __init__(self, session_id: _Optional[str] = ..., flow_id: _Optional[str] = ...) -> None: ...

class GetBodyRequest(_message.Message):
    __slots__ = ("session_id", "flow_id", "response")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    FLOW_ID_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    flow_id: str
    response: bool
    def __init__(self, session_id: _Optional[str] = ..., flow_id: _Optional[str] = ..., response: bool = ...) -> None: ...

class BodyChunk(_message.Message):
    __slots__ = ("payload", "truncated")
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    payload: bytes
    truncated: bool
    def __init__(self, payload: _Optional[bytes] = ..., truncated: bool = ...) -> None: ...

class ListMessagesRequest(_message.Message):
    __slots__ = ("session_id", "flow_id")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    FLOW_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    flow_id: str
    def __init__(self, session_id: _Optional[str] = ..., flow_id: _Optional[str] = ...) -> None: ...

class MessageList(_message.Message):
    __slots__ = ("messages",)
    MESSAGES_FIELD_NUMBER: _ClassVar[int]
    messages: _containers.RepeatedCompositeFieldContainer[_common_pb2.WsMessage]
    def __init__(self, messages: _Optional[_Iterable[_Union[_common_pb2.WsMessage, _Mapping]]] = ...) -> None: ...

class StreamMessagesRequest(_message.Message):
    __slots__ = ("session_id", "flow_id", "follow")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    FLOW_ID_FIELD_NUMBER: _ClassVar[int]
    FOLLOW_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    flow_id: str
    follow: bool
    def __init__(self, session_id: _Optional[str] = ..., flow_id: _Optional[str] = ..., follow: bool = ...) -> None: ...

class MessageEvent(_message.Message):
    __slots__ = ("message_added", "session_event")
    MESSAGE_ADDED_FIELD_NUMBER: _ClassVar[int]
    SESSION_EVENT_FIELD_NUMBER: _ClassVar[int]
    message_added: _common_pb2.WsMessage
    session_event: SessionEvent
    def __init__(self, message_added: _Optional[_Union[_common_pb2.WsMessage, _Mapping]] = ..., session_event: _Optional[_Union[SessionEvent, _Mapping]] = ...) -> None: ...

class GetMessageRequest(_message.Message):
    __slots__ = ("session_id", "message_id")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    message_id: str
    def __init__(self, session_id: _Optional[str] = ..., message_id: _Optional[str] = ...) -> None: ...

class GetMessageBodyRequest(_message.Message):
    __slots__ = ("session_id", "message_id", "raw")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    RAW_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    message_id: str
    raw: bool
    def __init__(self, session_id: _Optional[str] = ..., message_id: _Optional[str] = ..., raw: bool = ...) -> None: ...
