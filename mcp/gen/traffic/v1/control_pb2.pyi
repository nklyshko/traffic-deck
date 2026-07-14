from traffic.v1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Readiness(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    READINESS_UNSPECIFIED: _ClassVar[Readiness]
    READINESS_READY: _ClassVar[Readiness]
    READINESS_PROVISION_REQUIRED: _ClassVar[Readiness]

class ParamType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PARAM_TYPE_UNSPECIFIED: _ClassVar[ParamType]
    PARAM_TYPE_STRING: _ClassVar[ParamType]
    PARAM_TYPE_PATH: _ClassVar[ParamType]
    PARAM_TYPE_BOOL: _ClassVar[ParamType]
    PARAM_TYPE_INT: _ClassVar[ParamType]
    PARAM_TYPE_CHOICE: _ClassVar[ParamType]

class SourceState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SOURCE_STATE_UNSPECIFIED: _ClassVar[SourceState]
    SOURCE_STATE_PROVISIONING: _ClassVar[SourceState]
    SOURCE_STATE_READY: _ClassVar[SourceState]
    SOURCE_STATE_CAPTURING: _ClassVar[SourceState]
READINESS_UNSPECIFIED: Readiness
READINESS_READY: Readiness
READINESS_PROVISION_REQUIRED: Readiness
PARAM_TYPE_UNSPECIFIED: ParamType
PARAM_TYPE_STRING: ParamType
PARAM_TYPE_PATH: ParamType
PARAM_TYPE_BOOL: ParamType
PARAM_TYPE_INT: ParamType
PARAM_TYPE_CHOICE: ParamType
SOURCE_STATE_UNSPECIFIED: SourceState
SOURCE_STATE_PROVISIONING: SourceState
SOURCE_STATE_READY: SourceState
SOURCE_STATE_CAPTURING: SourceState

class Empty(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ServiceRequest(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class ServiceList(_message.Message):
    __slots__ = ("services",)
    SERVICES_FIELD_NUMBER: _ClassVar[int]
    services: _containers.RepeatedCompositeFieldContainer[ServiceInfo]
    def __init__(self, services: _Optional[_Iterable[_Union[ServiceInfo, _Mapping]]] = ...) -> None: ...

class ServiceInfo(_message.Message):
    __slots__ = ("name", "label", "running", "url", "detail")
    NAME_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    RUNNING_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    name: str
    label: str
    running: bool
    url: str
    detail: str
    def __init__(self, name: _Optional[str] = ..., label: _Optional[str] = ..., running: bool = ..., url: _Optional[str] = ..., detail: _Optional[str] = ...) -> None: ...

class CaptureSourceList(_message.Message):
    __slots__ = ("sources",)
    SOURCES_FIELD_NUMBER: _ClassVar[int]
    sources: _containers.RepeatedCompositeFieldContainer[CaptureSourceInfo]
    def __init__(self, sources: _Optional[_Iterable[_Union[CaptureSourceInfo, _Mapping]]] = ...) -> None: ...

class CaptureSourceInfo(_message.Message):
    __slots__ = ("name", "label", "keep_warm")
    NAME_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    KEEP_WARM_FIELD_NUMBER: _ClassVar[int]
    name: str
    label: str
    keep_warm: bool
    def __init__(self, name: _Optional[str] = ..., label: _Optional[str] = ..., keep_warm: bool = ...) -> None: ...

class DescribeCaptureSourceRequest(_message.Message):
    __slots__ = ("source", "params")
    class ParamsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    PARAMS_FIELD_NUMBER: _ClassVar[int]
    source: str
    params: _containers.ScalarMap[str, str]
    def __init__(self, source: _Optional[str] = ..., params: _Optional[_Mapping[str, str]] = ...) -> None: ...

class DescribeRequest(_message.Message):
    __slots__ = ("params",)
    class ParamsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PARAMS_FIELD_NUMBER: _ClassVar[int]
    params: _containers.ScalarMap[str, str]
    def __init__(self, params: _Optional[_Mapping[str, str]] = ...) -> None: ...

class SourceDescriptor(_message.Message):
    __slots__ = ("params", "readiness", "message")
    PARAMS_FIELD_NUMBER: _ClassVar[int]
    READINESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    params: _containers.RepeatedCompositeFieldContainer[Param]
    readiness: Readiness
    message: str
    def __init__(self, params: _Optional[_Iterable[_Union[Param, _Mapping]]] = ..., readiness: _Optional[_Union[Readiness, str]] = ..., message: _Optional[str] = ...) -> None: ...

class Param(_message.Message):
    __slots__ = ("key", "label", "type", "choices", "default", "required")
    KEY_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    CHOICES_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_FIELD_NUMBER: _ClassVar[int]
    key: str
    label: str
    type: ParamType
    choices: _containers.RepeatedCompositeFieldContainer[Choice]
    default: str
    required: bool
    def __init__(self, key: _Optional[str] = ..., label: _Optional[str] = ..., type: _Optional[_Union[ParamType, str]] = ..., choices: _Optional[_Iterable[_Union[Choice, _Mapping]]] = ..., default: _Optional[str] = ..., required: bool = ...) -> None: ...

class Choice(_message.Message):
    __slots__ = ("value", "label")
    VALUE_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    value: str
    label: str
    def __init__(self, value: _Optional[str] = ..., label: _Optional[str] = ...) -> None: ...

class ReleaseSourceRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class StatusRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SourceStatus(_message.Message):
    __slots__ = ("state", "active_sessions", "detail")
    STATE_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_SESSIONS_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    state: SourceState
    active_sessions: _containers.RepeatedScalarFieldContainer[str]
    detail: str
    def __init__(self, state: _Optional[_Union[SourceState, str]] = ..., active_sessions: _Optional[_Iterable[str]] = ..., detail: _Optional[str] = ...) -> None: ...

class StartCaptureRequest(_message.Message):
    __slots__ = ("source_kind", "label", "params", "source")
    class ParamsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SOURCE_KIND_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    PARAMS_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    source_kind: _common_pb2.SourceKind
    label: str
    params: _containers.ScalarMap[str, str]
    source: str
    def __init__(self, source_kind: _Optional[_Union[_common_pb2.SourceKind, str]] = ..., label: _Optional[str] = ..., params: _Optional[_Mapping[str, str]] = ..., source: _Optional[str] = ...) -> None: ...

class StartCaptureResponse(_message.Message):
    __slots__ = ("session_id",)
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    def __init__(self, session_id: _Optional[str] = ...) -> None: ...

class StopCaptureRequest(_message.Message):
    __slots__ = ("session_id",)
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    def __init__(self, session_id: _Optional[str] = ...) -> None: ...

class StopCaptureResponse(_message.Message):
    __slots__ = ("session",)
    SESSION_FIELD_NUMBER: _ClassVar[int]
    session: _common_pb2.Session
    def __init__(self, session: _Optional[_Union[_common_pb2.Session, _Mapping]] = ...) -> None: ...

class ExportSessionRequest(_message.Message):
    __slots__ = ("session_id",)
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    def __init__(self, session_id: _Optional[str] = ...) -> None: ...

class ExportChunk(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class SetSessionGroupRequest(_message.Message):
    __slots__ = ("session_id", "group")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    GROUP_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    group: str
    def __init__(self, session_id: _Optional[str] = ..., group: _Optional[str] = ...) -> None: ...

class SetSessionLabelRequest(_message.Message):
    __slots__ = ("session_id", "label")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    label: str
    def __init__(self, session_id: _Optional[str] = ..., label: _Optional[str] = ...) -> None: ...

class DeleteSessionRequest(_message.Message):
    __slots__ = ("session_id",)
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    def __init__(self, session_id: _Optional[str] = ...) -> None: ...

class ImportChunk(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class ImportSessionResponse(_message.Message):
    __slots__ = ("session",)
    SESSION_FIELD_NUMBER: _ClassVar[int]
    session: _common_pb2.Session
    def __init__(self, session: _Optional[_Union[_common_pb2.Session, _Mapping]] = ...) -> None: ...

class ReDecodeRequest(_message.Message):
    __slots__ = ("session_id",)
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    def __init__(self, session_id: _Optional[str] = ...) -> None: ...

class CreateTagRequest(_message.Message):
    __slots__ = ("name", "color")
    NAME_FIELD_NUMBER: _ClassVar[int]
    COLOR_FIELD_NUMBER: _ClassVar[int]
    name: str
    color: str
    def __init__(self, name: _Optional[str] = ..., color: _Optional[str] = ...) -> None: ...

class DeleteTagRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    def __init__(self, id: _Optional[str] = ...) -> None: ...

class ListTagsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class TagList(_message.Message):
    __slots__ = ("tags",)
    TAGS_FIELD_NUMBER: _ClassVar[int]
    tags: _containers.RepeatedCompositeFieldContainer[_common_pb2.Tag]
    def __init__(self, tags: _Optional[_Iterable[_Union[_common_pb2.Tag, _Mapping]]] = ...) -> None: ...

class SetTagsRequest(_message.Message):
    __slots__ = ("session_id", "record_ids", "add_tag_ids", "remove_tag_ids")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    RECORD_IDS_FIELD_NUMBER: _ClassVar[int]
    ADD_TAG_IDS_FIELD_NUMBER: _ClassVar[int]
    REMOVE_TAG_IDS_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    record_ids: _containers.RepeatedScalarFieldContainer[str]
    add_tag_ids: _containers.RepeatedScalarFieldContainer[str]
    remove_tag_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, session_id: _Optional[str] = ..., record_ids: _Optional[_Iterable[str]] = ..., add_tag_ids: _Optional[_Iterable[str]] = ..., remove_tag_ids: _Optional[_Iterable[str]] = ...) -> None: ...

class ToggleFavoriteRequest(_message.Message):
    __slots__ = ("session_id", "record_ids")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    RECORD_IDS_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    record_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, session_id: _Optional[str] = ..., record_ids: _Optional[_Iterable[str]] = ...) -> None: ...

class AddCommentRequest(_message.Message):
    __slots__ = ("session_id", "record_id", "body")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    RECORD_ID_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    record_id: str
    body: str
    def __init__(self, session_id: _Optional[str] = ..., record_id: _Optional[str] = ..., body: _Optional[str] = ...) -> None: ...

class EditCommentRequest(_message.Message):
    __slots__ = ("session_id", "id", "body")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    id: str
    body: str
    def __init__(self, session_id: _Optional[str] = ..., id: _Optional[str] = ..., body: _Optional[str] = ...) -> None: ...

class DeleteCommentRequest(_message.Message):
    __slots__ = ("session_id", "id")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    id: str
    def __init__(self, session_id: _Optional[str] = ..., id: _Optional[str] = ...) -> None: ...

class SetMarkRequest(_message.Message):
    __slots__ = ("session_id", "record_ids", "color")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    RECORD_IDS_FIELD_NUMBER: _ClassVar[int]
    COLOR_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    record_ids: _containers.RepeatedScalarFieldContainer[str]
    color: str
    def __init__(self, session_id: _Optional[str] = ..., record_ids: _Optional[_Iterable[str]] = ..., color: _Optional[str] = ...) -> None: ...

class ClearMarkRequest(_message.Message):
    __slots__ = ("session_id", "record_ids")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    RECORD_IDS_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    record_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, session_id: _Optional[str] = ..., record_ids: _Optional[_Iterable[str]] = ...) -> None: ...

class CreateGroupRequest(_message.Message):
    __slots__ = ("name", "color", "parent_id")
    NAME_FIELD_NUMBER: _ClassVar[int]
    COLOR_FIELD_NUMBER: _ClassVar[int]
    PARENT_ID_FIELD_NUMBER: _ClassVar[int]
    name: str
    color: str
    parent_id: str
    def __init__(self, name: _Optional[str] = ..., color: _Optional[str] = ..., parent_id: _Optional[str] = ...) -> None: ...

class UpdateGroupRequest(_message.Message):
    __slots__ = ("id", "name", "color", "parent_id")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    COLOR_FIELD_NUMBER: _ClassVar[int]
    PARENT_ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    color: str
    parent_id: str
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., color: _Optional[str] = ..., parent_id: _Optional[str] = ...) -> None: ...

class DeleteGroupRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    def __init__(self, id: _Optional[str] = ...) -> None: ...

class ListGroupsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GroupList(_message.Message):
    __slots__ = ("groups",)
    GROUPS_FIELD_NUMBER: _ClassVar[int]
    groups: _containers.RepeatedCompositeFieldContainer[_common_pb2.Group]
    def __init__(self, groups: _Optional[_Iterable[_Union[_common_pb2.Group, _Mapping]]] = ...) -> None: ...

class SetGroupsRequest(_message.Message):
    __slots__ = ("session_id", "record_ids", "add_group_ids", "remove_group_ids")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    RECORD_IDS_FIELD_NUMBER: _ClassVar[int]
    ADD_GROUP_IDS_FIELD_NUMBER: _ClassVar[int]
    REMOVE_GROUP_IDS_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    record_ids: _containers.RepeatedScalarFieldContainer[str]
    add_group_ids: _containers.RepeatedScalarFieldContainer[str]
    remove_group_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, session_id: _Optional[str] = ..., record_ids: _Optional[_Iterable[str]] = ..., add_group_ids: _Optional[_Iterable[str]] = ..., remove_group_ids: _Optional[_Iterable[str]] = ...) -> None: ...
