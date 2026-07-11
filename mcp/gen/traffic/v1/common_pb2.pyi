from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SourceKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SOURCE_KIND_UNSPECIFIED: _ClassVar[SourceKind]
    SOURCE_KIND_CHROME: _ClassVar[SourceKind]
    SOURCE_KIND_MITMPROXY: _ClassVar[SourceKind]
    SOURCE_KIND_ANDROID_EMULATOR: _ClassVar[SourceKind]
    SOURCE_KIND_ANDROID_DEVICE: _ClassVar[SourceKind]
    SOURCE_KIND_GENERIC: _ClassVar[SourceKind]

class FileKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FILE_KIND_UNSPECIFIED: _ClassVar[FileKind]
    FILE_KIND_PCAP: _ClassVar[FileKind]
    FILE_KIND_KEYLOG: _ClassVar[FileKind]

class SessionStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SESSION_STATUS_UNSPECIFIED: _ClassVar[SessionStatus]
    SESSION_STATUS_OPEN: _ClassVar[SessionStatus]
    SESSION_STATUS_DECODING: _ClassVar[SessionStatus]
    SESSION_STATUS_CLOSED: _ClassVar[SessionStatus]
    SESSION_STATUS_ERROR: _ClassVar[SessionStatus]
SOURCE_KIND_UNSPECIFIED: SourceKind
SOURCE_KIND_CHROME: SourceKind
SOURCE_KIND_MITMPROXY: SourceKind
SOURCE_KIND_ANDROID_EMULATOR: SourceKind
SOURCE_KIND_ANDROID_DEVICE: SourceKind
SOURCE_KIND_GENERIC: SourceKind
FILE_KIND_UNSPECIFIED: FileKind
FILE_KIND_PCAP: FileKind
FILE_KIND_KEYLOG: FileKind
SESSION_STATUS_UNSPECIFIED: SessionStatus
SESSION_STATUS_OPEN: SessionStatus
SESSION_STATUS_DECODING: SessionStatus
SESSION_STATUS_CLOSED: SessionStatus
SESSION_STATUS_ERROR: SessionStatus

class Session(_message.Message):
    __slots__ = ("id", "label", "source_kind", "status", "created_at_unix_ms", "closed_at_unix_ms", "pcap_bytes", "keylog_bytes", "flow_count")
    ID_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    SOURCE_KIND_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CLOSED_AT_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    PCAP_BYTES_FIELD_NUMBER: _ClassVar[int]
    KEYLOG_BYTES_FIELD_NUMBER: _ClassVar[int]
    FLOW_COUNT_FIELD_NUMBER: _ClassVar[int]
    id: str
    label: str
    source_kind: SourceKind
    status: SessionStatus
    created_at_unix_ms: int
    closed_at_unix_ms: int
    pcap_bytes: int
    keylog_bytes: int
    flow_count: int
    def __init__(self, id: _Optional[str] = ..., label: _Optional[str] = ..., source_kind: _Optional[_Union[SourceKind, str]] = ..., status: _Optional[_Union[SessionStatus, str]] = ..., created_at_unix_ms: _Optional[int] = ..., closed_at_unix_ms: _Optional[int] = ..., pcap_bytes: _Optional[int] = ..., keylog_bytes: _Optional[int] = ..., flow_count: _Optional[int] = ...) -> None: ...

class Header(_message.Message):
    __slots__ = ("name", "value")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: str
    def __init__(self, name: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class Cookie(_message.Message):
    __slots__ = ("name", "value")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: str
    def __init__(self, name: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class Body(_message.Message):
    __slots__ = ("size", "content_type", "inline", "object_ref")
    SIZE_FIELD_NUMBER: _ClassVar[int]
    CONTENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    INLINE_FIELD_NUMBER: _ClassVar[int]
    OBJECT_REF_FIELD_NUMBER: _ClassVar[int]
    size: int
    content_type: str
    inline: bytes
    object_ref: str
    def __init__(self, size: _Optional[int] = ..., content_type: _Optional[str] = ..., inline: _Optional[bytes] = ..., object_ref: _Optional[str] = ...) -> None: ...

class Flow(_message.Message):
    __slots__ = ("id", "session_id", "analysis_id", "frame_number", "ts_unix_micros", "method", "scheme", "authority", "path", "query", "protocol", "status", "src_addr", "dst_addr", "user_agent", "content_type", "request_bytes", "tls_decrypted", "tcp_stream", "h2_stream_id", "request_headers", "response_headers", "request_cookies", "request_body", "response_body", "mark_color", "favorite", "tag_ids", "group_ids", "comments", "websocket", "ws_message_count", "proxy", "metadata", "error", "duration_micros", "http2_fingerprint", "ja3", "ja4", "tls_client_hello")
    class MetadataEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ANALYSIS_ID_FIELD_NUMBER: _ClassVar[int]
    FRAME_NUMBER_FIELD_NUMBER: _ClassVar[int]
    TS_UNIX_MICROS_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    SCHEME_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SRC_ADDR_FIELD_NUMBER: _ClassVar[int]
    DST_ADDR_FIELD_NUMBER: _ClassVar[int]
    USER_AGENT_FIELD_NUMBER: _ClassVar[int]
    CONTENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_BYTES_FIELD_NUMBER: _ClassVar[int]
    TLS_DECRYPTED_FIELD_NUMBER: _ClassVar[int]
    TCP_STREAM_FIELD_NUMBER: _ClassVar[int]
    H2_STREAM_ID_FIELD_NUMBER: _ClassVar[int]
    REQUEST_HEADERS_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_HEADERS_FIELD_NUMBER: _ClassVar[int]
    REQUEST_COOKIES_FIELD_NUMBER: _ClassVar[int]
    REQUEST_BODY_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_BODY_FIELD_NUMBER: _ClassVar[int]
    MARK_COLOR_FIELD_NUMBER: _ClassVar[int]
    FAVORITE_FIELD_NUMBER: _ClassVar[int]
    TAG_IDS_FIELD_NUMBER: _ClassVar[int]
    GROUP_IDS_FIELD_NUMBER: _ClassVar[int]
    COMMENTS_FIELD_NUMBER: _ClassVar[int]
    WEBSOCKET_FIELD_NUMBER: _ClassVar[int]
    WS_MESSAGE_COUNT_FIELD_NUMBER: _ClassVar[int]
    PROXY_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    DURATION_MICROS_FIELD_NUMBER: _ClassVar[int]
    HTTP2_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    JA3_FIELD_NUMBER: _ClassVar[int]
    JA4_FIELD_NUMBER: _ClassVar[int]
    TLS_CLIENT_HELLO_FIELD_NUMBER: _ClassVar[int]
    id: str
    session_id: str
    analysis_id: str
    frame_number: int
    ts_unix_micros: int
    method: str
    scheme: str
    authority: str
    path: str
    query: str
    protocol: str
    status: int
    src_addr: str
    dst_addr: str
    user_agent: str
    content_type: str
    request_bytes: int
    tls_decrypted: bool
    tcp_stream: str
    h2_stream_id: str
    request_headers: _containers.RepeatedCompositeFieldContainer[Header]
    response_headers: _containers.RepeatedCompositeFieldContainer[Header]
    request_cookies: _containers.RepeatedCompositeFieldContainer[Cookie]
    request_body: Body
    response_body: Body
    mark_color: str
    favorite: bool
    tag_ids: _containers.RepeatedScalarFieldContainer[str]
    group_ids: _containers.RepeatedScalarFieldContainer[str]
    comments: _containers.RepeatedCompositeFieldContainer[Comment]
    websocket: bool
    ws_message_count: int
    proxy: Proxy
    metadata: _containers.ScalarMap[str, str]
    error: str
    duration_micros: int
    http2_fingerprint: str
    ja3: str
    ja4: str
    tls_client_hello: str
    def __init__(self, id: _Optional[str] = ..., session_id: _Optional[str] = ..., analysis_id: _Optional[str] = ..., frame_number: _Optional[int] = ..., ts_unix_micros: _Optional[int] = ..., method: _Optional[str] = ..., scheme: _Optional[str] = ..., authority: _Optional[str] = ..., path: _Optional[str] = ..., query: _Optional[str] = ..., protocol: _Optional[str] = ..., status: _Optional[int] = ..., src_addr: _Optional[str] = ..., dst_addr: _Optional[str] = ..., user_agent: _Optional[str] = ..., content_type: _Optional[str] = ..., request_bytes: _Optional[int] = ..., tls_decrypted: bool = ..., tcp_stream: _Optional[str] = ..., h2_stream_id: _Optional[str] = ..., request_headers: _Optional[_Iterable[_Union[Header, _Mapping]]] = ..., response_headers: _Optional[_Iterable[_Union[Header, _Mapping]]] = ..., request_cookies: _Optional[_Iterable[_Union[Cookie, _Mapping]]] = ..., request_body: _Optional[_Union[Body, _Mapping]] = ..., response_body: _Optional[_Union[Body, _Mapping]] = ..., mark_color: _Optional[str] = ..., favorite: bool = ..., tag_ids: _Optional[_Iterable[str]] = ..., group_ids: _Optional[_Iterable[str]] = ..., comments: _Optional[_Iterable[_Union[Comment, _Mapping]]] = ..., websocket: bool = ..., ws_message_count: _Optional[int] = ..., proxy: _Optional[_Union[Proxy, _Mapping]] = ..., metadata: _Optional[_Mapping[str, str]] = ..., error: _Optional[str] = ..., duration_micros: _Optional[int] = ..., http2_fingerprint: _Optional[str] = ..., ja3: _Optional[str] = ..., ja4: _Optional[str] = ..., tls_client_hello: _Optional[str] = ...) -> None: ...

class Proxy(_message.Message):
    __slots__ = ("addr", "type", "username", "password")
    ADDR_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    addr: str
    type: str
    username: str
    password: str
    def __init__(self, addr: _Optional[str] = ..., type: _Optional[str] = ..., username: _Optional[str] = ..., password: _Optional[str] = ...) -> None: ...

class WsMessage(_message.Message):
    __slots__ = ("id", "session_id", "flow_id", "frame_number", "ts_unix_micros", "from_client", "opcode", "payload", "raw")
    ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    FLOW_ID_FIELD_NUMBER: _ClassVar[int]
    FRAME_NUMBER_FIELD_NUMBER: _ClassVar[int]
    TS_UNIX_MICROS_FIELD_NUMBER: _ClassVar[int]
    FROM_CLIENT_FIELD_NUMBER: _ClassVar[int]
    OPCODE_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    RAW_FIELD_NUMBER: _ClassVar[int]
    id: str
    session_id: str
    flow_id: str
    frame_number: int
    ts_unix_micros: int
    from_client: bool
    opcode: str
    payload: Body
    raw: Body
    def __init__(self, id: _Optional[str] = ..., session_id: _Optional[str] = ..., flow_id: _Optional[str] = ..., frame_number: _Optional[int] = ..., ts_unix_micros: _Optional[int] = ..., from_client: bool = ..., opcode: _Optional[str] = ..., payload: _Optional[_Union[Body, _Mapping]] = ..., raw: _Optional[_Union[Body, _Mapping]] = ...) -> None: ...

class Tag(_message.Message):
    __slots__ = ("id", "name", "color", "is_favorite", "created_at_unix_ms")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    COLOR_FIELD_NUMBER: _ClassVar[int]
    IS_FAVORITE_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    color: str
    is_favorite: bool
    created_at_unix_ms: int
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., color: _Optional[str] = ..., is_favorite: bool = ..., created_at_unix_ms: _Optional[int] = ...) -> None: ...

class Comment(_message.Message):
    __slots__ = ("id", "record_id", "body", "created_at_unix_ms", "updated_at_unix_ms")
    ID_FIELD_NUMBER: _ClassVar[int]
    RECORD_ID_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    id: str
    record_id: str
    body: str
    created_at_unix_ms: int
    updated_at_unix_ms: int
    def __init__(self, id: _Optional[str] = ..., record_id: _Optional[str] = ..., body: _Optional[str] = ..., created_at_unix_ms: _Optional[int] = ..., updated_at_unix_ms: _Optional[int] = ...) -> None: ...

class Group(_message.Message):
    __slots__ = ("id", "name", "color", "parent_id", "created_at_unix_ms")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    COLOR_FIELD_NUMBER: _ClassVar[int]
    PARENT_ID_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    color: str
    parent_id: str
    created_at_unix_ms: int
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., color: _Optional[str] = ..., parent_id: _Optional[str] = ..., created_at_unix_ms: _Optional[int] = ...) -> None: ...

class DecodeProgress(_message.Message):
    __slots__ = ("session_id", "percent", "stage", "done")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PERCENT_FIELD_NUMBER: _ClassVar[int]
    STAGE_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    percent: int
    stage: str
    done: bool
    def __init__(self, session_id: _Optional[str] = ..., percent: _Optional[int] = ..., stage: _Optional[str] = ..., done: bool = ...) -> None: ...
