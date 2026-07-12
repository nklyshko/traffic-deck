from traffic.v1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Empty(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class StartCaptureRequest(_message.Message):
    __slots__ = ("source_kind", "label", "params")
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
    source_kind: _common_pb2.SourceKind
    label: str
    params: _containers.ScalarMap[str, str]
    def __init__(self, source_kind: _Optional[_Union[_common_pb2.SourceKind, str]] = ..., label: _Optional[str] = ..., params: _Optional[_Mapping[str, str]] = ...) -> None: ...

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

class DeleteSessionRequest(_message.Message):
    __slots__ = ("session_id",)
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    def __init__(self, session_id: _Optional[str] = ...) -> None: ...

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
