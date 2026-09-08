from traffic.v1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CaptureMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CAPTURE_MODE_UNSPECIFIED: _ClassVar[CaptureMode]
    CAPTURE_MODE_STREAMING_LIVE: _ClassVar[CaptureMode]
    CAPTURE_MODE_BATCH_ON_CLOSE: _ClassVar[CaptureMode]
CAPTURE_MODE_UNSPECIFIED: CaptureMode
CAPTURE_MODE_STREAMING_LIVE: CaptureMode
CAPTURE_MODE_BATCH_ON_CLOSE: CaptureMode

class OpenSessionRequest(_message.Message):
    __slots__ = ("label", "shape", "metadata", "source")
    class MetadataEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    LABEL_FIELD_NUMBER: _ClassVar[int]
    SHAPE_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    label: str
    shape: _common_pb2.SourceShape
    metadata: _containers.ScalarMap[str, str]
    source: str
    def __init__(self, label: _Optional[str] = ..., shape: _Optional[_Union[_common_pb2.SourceShape, str]] = ..., metadata: _Optional[_Mapping[str, str]] = ..., source: _Optional[str] = ...) -> None: ...

class SessionHandle(_message.Message):
    __slots__ = ("session_id", "max_chunk_bytes")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    MAX_CHUNK_BYTES_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    max_chunk_bytes: int
    def __init__(self, session_id: _Optional[str] = ..., max_chunk_bytes: _Optional[int] = ...) -> None: ...

class FileMeta(_message.Message):
    __slots__ = ("name", "expected_size")
    NAME_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_SIZE_FIELD_NUMBER: _ClassVar[int]
    name: str
    expected_size: int
    def __init__(self, name: _Optional[str] = ..., expected_size: _Optional[int] = ...) -> None: ...

class UploadBegin(_message.Message):
    __slots__ = ("session_id", "upload_id", "pcap", "keylog", "mode")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    UPLOAD_ID_FIELD_NUMBER: _ClassVar[int]
    PCAP_FIELD_NUMBER: _ClassVar[int]
    KEYLOG_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    upload_id: str
    pcap: FileMeta
    keylog: FileMeta
    mode: CaptureMode
    def __init__(self, session_id: _Optional[str] = ..., upload_id: _Optional[str] = ..., pcap: _Optional[_Union[FileMeta, _Mapping]] = ..., keylog: _Optional[_Union[FileMeta, _Mapping]] = ..., mode: _Optional[_Union[CaptureMode, str]] = ...) -> None: ...

class DataChunk(_message.Message):
    __slots__ = ("kind", "offset", "payload")
    KIND_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    kind: _common_pb2.FileKind
    offset: int
    payload: bytes
    def __init__(self, kind: _Optional[_Union[_common_pb2.FileKind, str]] = ..., offset: _Optional[int] = ..., payload: _Optional[bytes] = ...) -> None: ...

class UploadEnd(_message.Message):
    __slots__ = ("upload_id",)
    UPLOAD_ID_FIELD_NUMBER: _ClassVar[int]
    upload_id: str
    def __init__(self, upload_id: _Optional[str] = ...) -> None: ...

class CaptureChunk(_message.Message):
    __slots__ = ("begin", "data", "end")
    BEGIN_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    END_FIELD_NUMBER: _ClassVar[int]
    begin: UploadBegin
    data: DataChunk
    end: UploadEnd
    def __init__(self, begin: _Optional[_Union[UploadBegin, _Mapping]] = ..., data: _Optional[_Union[DataChunk, _Mapping]] = ..., end: _Optional[_Union[UploadEnd, _Mapping]] = ...) -> None: ...

class UploadAck(_message.Message):
    __slots__ = ("upload_id", "pcap_received", "keylog_received")
    UPLOAD_ID_FIELD_NUMBER: _ClassVar[int]
    PCAP_RECEIVED_FIELD_NUMBER: _ClassVar[int]
    KEYLOG_RECEIVED_FIELD_NUMBER: _ClassVar[int]
    upload_id: str
    pcap_received: int
    keylog_received: int
    def __init__(self, upload_id: _Optional[str] = ..., pcap_received: _Optional[int] = ..., keylog_received: _Optional[int] = ...) -> None: ...

class FlowBatch(_message.Message):
    __slots__ = ("session_id", "flows", "messages")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    FLOWS_FIELD_NUMBER: _ClassVar[int]
    MESSAGES_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    flows: _containers.RepeatedCompositeFieldContainer[_common_pb2.Flow]
    messages: _containers.RepeatedCompositeFieldContainer[_common_pb2.WsMessage]
    def __init__(self, session_id: _Optional[str] = ..., flows: _Optional[_Iterable[_Union[_common_pb2.Flow, _Mapping]]] = ..., messages: _Optional[_Iterable[_Union[_common_pb2.WsMessage, _Mapping]]] = ...) -> None: ...

class PushAck(_message.Message):
    __slots__ = ("accepted",)
    ACCEPTED_FIELD_NUMBER: _ClassVar[int]
    accepted: int
    def __init__(self, accepted: _Optional[int] = ...) -> None: ...

class CloseSessionRequest(_message.Message):
    __slots__ = ("session_id",)
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    def __init__(self, session_id: _Optional[str] = ...) -> None: ...

class SessionSummary(_message.Message):
    __slots__ = ("session",)
    SESSION_FIELD_NUMBER: _ClassVar[int]
    session: _common_pb2.Session
    def __init__(self, session: _Optional[_Union[_common_pb2.Session, _Mapping]] = ...) -> None: ...
