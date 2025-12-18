# Copyright 2009-present MongoDB, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tools for using Python's :mod:`json` module with BSON documents.

This module provides two helper methods `dumps` and `loads` that wrap the
native :mod:`json` methods and provide explicit BSON conversion to and from
JSON. :class:`~bson.json_util.JSONOptions` provides a way to control how JSON
is emitted and parsed, with the default being the Relaxed Extended JSON format.
:mod:`~bson.json_util` can also generate Canonical or legacy `Extended JSON`_
when :const:`CANONICAL_JSON_OPTIONS` or :const:`LEGACY_JSON_OPTIONS` is
provided, respectively.

.. _Extended JSON: https://github.com/mongodb/specifications/blob/master/source/extended-json/extended-json.md

Example usage (deserialization):

.. doctest::

   >>> from bson.json_util import loads
   >>> loads(
   ...     '[{"foo": [1, 2]}, {"bar": {"hello": "world"}}, {"code": {"$scope": {}, "$code": "function x() { return 1; }"}}, {"bin": {"$type": "80", "$binary": "AQIDBA=="}}]'
   ... )
   [{'foo': [1, 2]}, {'bar': {'hello': 'world'}}, {'code': Code('function x() { return 1; }', {})}, {'bin': Binary(b'...', 128)}]

Example usage with :const:`RELAXED_JSON_OPTIONS` (the default):

.. doctest::

   >>> from bson import Binary, Code
   >>> from bson.json_util import dumps
   >>> dumps(
   ...     [
   ...         {"foo": [1, 2]},
   ...         {"bar": {"hello": "world"}},
   ...         {"code": Code("function x() { return 1; }")},
   ...         {"bin": Binary(b"\x01\x02\x03\x04")},
   ...     ]
   ... )
   '[{"foo": [1, 2]}, {"bar": {"hello": "world"}}, {"code": {"$code": "function x() { return 1; }"}}, {"bin": {"$binary": {"base64": "AQIDBA==", "subType": "00"}}}]'

Example usage (with :const:`CANONICAL_JSON_OPTIONS`):

.. doctest::

   >>> from bson import Binary, Code
   >>> from bson.json_util import dumps, CANONICAL_JSON_OPTIONS
   >>> dumps(
   ...     [
   ...         {"foo": [1, 2]},
   ...         {"bar": {"hello": "world"}},
   ...         {"code": Code("function x() { return 1; }")},
   ...         {"bin": Binary(b"\x01\x02\x03\x04")},
   ...     ],
   ...     json_options=CANONICAL_JSON_OPTIONS,
   ... )
   '[{"foo": [{"$numberInt": "1"}, {"$numberInt": "2"}]}, {"bar": {"hello": "world"}}, {"code": {"$code": "function x() { return 1; }"}}, {"bin": {"$binary": {"base64": "AQIDBA==", "subType": "00"}}}]'

Example usage (with :const:`LEGACY_JSON_OPTIONS`):

.. doctest::

   >>> from bson import Binary, Code
   >>> from bson.json_util import dumps, LEGACY_JSON_OPTIONS
   >>> dumps(
   ...     [
   ...         {"foo": [1, 2]},
   ...         {"bar": {"hello": "world"}},
   ...         {"code": Code("function x() { return 1; }", {})},
   ...         {"bin": Binary(b"\x01\x02\x03\x04")},
   ...     ],
   ...     json_options=LEGACY_JSON_OPTIONS,
   ... )
   '[{"foo": [1, 2]}, {"bar": {"hello": "world"}}, {"code": {"$code": "function x() { return 1; }", "$scope": {}}}, {"bin": {"$binary": "AQIDBA==", "$type": "00"}}]'

Alternatively, you can manually pass the `default` to :func:`json.dumps`.
It won't handle :class:`~bson.binary.Binary` and :class:`~bson.code.Code`
instances (as they are extended strings you can't provide custom defaults),
but it will be faster as there is less recursion.

.. note::
   If your application does not need the flexibility offered by
   :class:`JSONOptions` and spends a large amount of time in the `json_util`
   module, look to
   `python-bsonjs <https://pypi.python.org/pypi/python-bsonjs>`_ for a nice
   performance improvement. `python-bsonjs` is a fast BSON to MongoDB
   Extended JSON converter for Python built on top of
   `libbson <https://github.com/mongodb/libbson>`_. `python-bsonjs` works best
   with PyMongo when using :class:`~bson.raw_bson.RawBSONDocument`.
"""
from __future__ import annotations

import calendar
import decimal

import bsonjs

import base64
import datetime
import json
import math
import re
import uuid
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    Union,
    cast,
)

from bson.binary import ALL_UUID_SUBTYPES, UUID_SUBTYPE, Binary, UuidRepresentation
from bson.code import Code
from bson.codec_options import CodecOptions, DatetimeConversion
from bson.datetime_ms import (
    _MAX_UTC_MS,
    EPOCH_AWARE,
)
from bson.dbref import DBRef
from bson.decimal128 import Decimal128
from bson.int64 import Int64
from bson.max_key import MaxKey
from bson.min_key import MinKey
from bson.objectid import ObjectId
from bson.regex import Regex
from bson.son import RE_TYPE
from bson.timestamp import Timestamp
from bson.tz_util import utc

_RE_OPT_TABLE = {  # FIXME DELETE THIS
    "i": re.I,
    "l": re.L,
    "m": re.M,
    "s": re.S,
    "u": re.U,
    "x": re.X,
}


class JSONOptions:
    pass  # TODO DELETE THIS ASAP


_INT32_MAX = 2**31


# Only these two binary subtypes are supported
BINARY_SUBTYPE = 0
UUID_SUBTYPE = 4


def dumps(obj: Any, *args: Any, **kwargs: Any) -> str:
    """Helper function that wraps :func:`json.dumps`.

    Recursive function that handles main ExtendedJSON types.
    """
    ext_obj = convert_to_extjson(obj)
    return json.dumps(ext_obj, *args, **kwargs)


def loads(s: Union[str, bytes, bytearray], *args: Any, **kwargs: Any) -> Any:
    """Helper function that wraps :func:`json.loads`.

    Recursive function that handles main ExtendedJSON types.
    """
    ext_obj = json.loads(s, *args, **kwargs)
    return convert_from_extjson(ext_obj)


def convert_to_extjson(obj: Any, canonical: bool=True) -> Any:
    """Recursive helper method that converts BSON types so they can be
    converted into json.
    """
    if isinstance(obj, dict):
        return {k: convert_to_extjson(v, canonical=canonical) for k, v in obj.items()}
    elif isinstance(obj, list):  # Tuples are not handled!
        return [convert_to_extjson(v, canonical=canonical) for v in obj]

    return _convert_primitive_to_extjson(obj, canonical=canonical)


def _convert_primitive_to_extjson(obj: Any, canonical: bool) -> Any:
    # First see if the type is already cached. KeyError will only ever
    # happen once per subtype.
    try:
        encoder = _ENCODERS[type(obj)]
        return encoder(obj, canonical=canonical)
    except KeyError:
        pass

    # Then, test each base type. This will only happen once for
    # a subtype of a supported base type.
    for base in _EXTENDED_JSON_BUILT_IN_TYPES:
        if isinstance(obj, base):
            func = _ENCODERS[base]
            # Cache this type for faster subsequent lookup.
            _ENCODERS[type(obj)] = func
            return func(obj, canonical=canonical)

    # We give up and return the object unchanged
    # The "default" handler of json.dumps() might save the day
    return obj


def convert_from_extjson(ext_obj: Any) -> Any:  # FIXME REMOVE CANONICAL!!!
    """Recursive helper method that converts BSON types so they can be
    converted into json.
    """
    if isinstance(ext_obj, dict):
        ext_obj = {k: convert_from_extjson(v) for k, v in ext_obj.items()}
        return _convert_primitive_from_extjson_dict(ext_obj)
    elif isinstance(ext_obj, list):  # Tuples are not handled!
        return [convert_from_extjson(v) for v in ext_obj]
    return ext_obj  # Was already a proper native type


def _convert_primitive_from_extjson_dict(ext_obj_dict: Mapping[str, Any]) -> Any:
    assert isinstance(ext_obj_dict, dict), repr(ext_obj_dict)
    match = None
    if len(ext_obj_dict) != 1:
        return ext_obj_dict  # Not a {$type: ...} dict
    for k in ext_obj_dict:
        if k in _PARSERS_SET:
            match = k
            break
    if match:
        return _PARSERS[match](ext_obj_dict)
    return ext_obj_dict


def _encode_canonical_binary(data: bytes, subtype: int) -> Any:
    return {"$binary": {"base64": base64.b64encode(data).decode(), "subType": "%02x" % subtype}}


def _encode_int(obj: int, canonical: bool) -> Any:
    if canonical:
        if -_INT32_MAX <= obj < _INT32_MAX:
            return {"$numberInt": str(obj)}
        return {"$numberLong": str(obj)}
    return obj


def _encode_noop(obj: Any, canonical: bool) -> Any:
    return obj


def _encode_float(obj: float, canonical: bool) -> Any:
    if math.isnan(obj):
        return {"$numberDouble": "NaN"}
    elif math.isinf(obj):
        representation = "Infinity" if obj > 0 else "-Infinity"
        return {"$numberDouble": representation}
    elif canonical:
        # repr() will return the shortest string guaranteed to produce the
        # original value, when float() is called on it.
        return {"$numberDouble": str(repr(obj))}
    return obj


def _encode_decimal(obj: decimal.decimal, canonical: bool) -> dict:
    # Always use canonical representation for Decimal numbers
    return {"$numberDecimal": str(obj)}


def _encode_datetime(obj: datetime.datetime, canonical: bool) -> dict:
    if not _is_aware_datetime(obj):
        raise TypeError(f"Unsupported naive datetime encountered: {dt}")
    if canonical:
        millis = _datetime_to_millis(obj)
        return {"$date": {"$numberLong": str(millis)}}
    offset: datetime.timedelta = obj.tzinfo.utcoffset(obj)
    tz_string = obj.strftime("%z") if offset else"Z"
    millis = int(obj.microsecond / 1000)
    fracsecs = ".%03d" % (millis,) if millis else ""
    return {
        "$date": "{}{}{}".format(obj.strftime("%Y-%m-%dT%H:%M:%S"), fracsecs, tz_string)
    }


def _encode_bytes(obj: bytes, canonical: bool) -> dict:
    # Always use canonical representation for Bytes numbers
    return _encode_canonical_binary(obj, BINARY_SUBTYPE)


def _encode_uuid(obj: uuid.UUID, canonical: bool) -> dict:
    if canonical:
        return _encode_canonical_binary(obj.bytes, UUID_SUBTYPE)
    return {"$uuid": obj.hex}


# Encoders for BSON types
# Each encoder function's signature is:
#   - obj: a Python data type, e.g. a Python int for _encode_int
#   - json_options: a JSONOptions
_ENCODERS: dict[Type, Callable[[Any, JSONOptions], Any]] = {
    bool: _encode_noop,
    bytes: _encode_bytes,
    uuid.UUID: _encode_uuid,
    datetime.datetime: _encode_datetime,
    float: _encode_float,
    decimal.Decimal: _encode_decimal,
    int: _encode_int,
    str: _encode_noop,
    type(None): _encode_noop,
}

_EXTENDED_JSON_BUILT_IN_TYPES = tuple(t for t in _ENCODERS)


def _parse_canonical_binary(doc: Any) -> Union[bytes, uuid.UUID]:
    binary = doc["$binary"]
    b64 = binary["base64"]
    subtype = binary["subType"]
    if not isinstance(b64, str):
        raise TypeError(f"$binary base64 must be a string: {doc}")
    if not isinstance(subtype, str) or len(subtype) > 2:
        raise TypeError(f"$binary subType must be a string at most 2 characters: {doc}")
    if len(binary) != 2:
        raise TypeError(f'$binary must include only "base64" and "subType" components: {doc}')

    data = base64.b64decode(b64.encode())
    return _binary_or_uuid(data, int(subtype, 16))


def _binary_or_uuid(data: Any, subtype: int) -> Union[Binary, uuid.UUID]:
    if subtype not in (BINARY_SUBTYPE, UUID_SUBTYPE):
        raise TypeError(f"Unsupported binary subtype: {subtype}")
    if subtype == UUID_SUBTYPE:
        return uuid.UUID(bytes=data)
    return data


def _parse_canonical_datetime(
    doc: Any
) -> datetime.datetime:
    """Decode a JSON datetime to python datetime.datetime."""
    dtm = doc["$date"]
    if len(doc) != 1:
        raise TypeError(f"Bad $date, extra field(s): {doc}")  # FIXME MUTUALIZE THIS
    return _millis_to_datetime(int(dtm))  # FIXME why "int()" conversion here?


def _parse_canonical_int32(doc: Any) -> int:
    """Decode a JSON int32 to python int."""
    i_str = doc["$numberInt"]
    if len(doc) != 1:
        raise TypeError(f"Bad $numberInt, extra field(s): {doc}")  # FIXME MUTUALIZE THIS
    if not isinstance(i_str, str):
        raise TypeError(f"$numberInt must be string: {doc}")
    return int(i_str)


def _parse_canonical_int64(doc: Any) -> Int64:
    """Decode a JSON int64 to bson.int64.Int64."""
    l_str = doc["$numberLong"]
    if len(doc) != 1:
        raise TypeError(f"Bad $numberLong, extra field(s): {doc}")
    if not isinstance(l_str, str):
        raise TypeError(f"$numberLong must be string: {doc}")  # FIXME MUTUALIZE
    return int(l_str)  # No need for Int64 type here


def _parse_canonical_double(doc: Any) -> float:
    """Decode a JSON double to python float."""
    d_str = doc["$numberDouble"]
    if len(doc) != 1:
        raise TypeError(f"Bad $numberDouble, extra field(s): {doc}")
    if not isinstance(d_str, str):
        raise TypeError(f"$numberDouble must be string: {doc}")  # FIXME MUTUALIZE
    return float(d_str)


def _parse_canonical_decimal(doc: Any) -> decimal.Decimal:
    d_str = doc["$numberDecimal"]
    if len(doc) != 1:
        raise TypeError(f"Bad $numberDecimal, extra field(s): {doc}")
    if not isinstance(d_str, str):
        raise TypeError(f"$numberDecimal must be string: {doc}")  # FIXME MUTUALIZE
    return decimal.Decimal(d_str)


def _parse_legacy_uuid(doc: Any, json_options: JSONOptions) -> Union[Binary, uuid.UUID]:
    """Decode a JSON legacy $uuid to Python UUID."""
    if len(doc) != 1:
        raise TypeError(f"Bad $uuid, extra field(s): {doc}")
    if not isinstance(doc["$uuid"], str):
        raise TypeError(f"$uuid must be a string: {doc}")
    return uuid.UUID(doc["$uuid"])


_PARSERS: dict[str, Callable[[Any, JSONOptions], Any]] = {
    "$date": _parse_canonical_datetime,
    "$binary": _parse_canonical_binary,
    "$uuid": _parse_legacy_uuid,
    "$undefined": lambda _: None,
    "$numberInt": _parse_canonical_int32,
    "$numberLong": _parse_canonical_int64,
    "$numberDouble": _parse_canonical_double,
    "$numberDecimal": _parse_canonical_decimal,
}
_PARSERS_SET = set(_PARSERS)


EPOCH_AWARE = datetime.datetime.fromtimestamp(0, utc)


def _is_aware_datetime(dt: datetime.datetime) -> bool:
    """Check if a datetime is timezone aware."""
    return dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None


def _assert_is_aware_datetime(dt: datetime.datetime):
    assert _is_aware_datetime(dt), f"Unsupported naive datetime encountered: {dt}"


def _datetime_to_millis(dt: datetime.datetime) -> int:
    """Convert aware datetime to milliseconds since epoch UTC."""
    _assert_is_aware_datetime(dt)
    dt = dt - dt.utcoffset()  # type: ignore
    return int(calendar.timegm(dt.timetuple()) * 1000 + dt.microsecond // 1000)


def _millis_to_datetime(
    millis: int,
) -> datetime.datetime:
    """Convert milliseconds since epoch UTC to aware datetime."""

    diff = ((millis % 1000) + 1000) % 1000
    seconds = (millis - diff) // 1000
    micros = diff * 1000

    dt = EPOCH_AWARE + datetime.timedelta(seconds=seconds, microseconds=micros)

    return dt  # UTC aware datetime
