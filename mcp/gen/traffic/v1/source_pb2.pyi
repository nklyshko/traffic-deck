from traffic.v1 import control_pb2 as _control_pb2
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
