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
    DatetimeMS,
    _datetime_to_millis,
    _millis_to_datetime,
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

_RE_OPT_TABLE = {
    "i": re.I,
    "l": re.L,
    "m": re.M,
    "s": re.S,
    "u": re.U,
    "x": re.X,
}


class JSONOptions:
    pass  # TODO DELETE THIS ASAP


def dumps(obj: Any, *args: Any, **kwargs: Any) -> str:
    """Helper function that wraps :func:`json.dumps`.

    Recursive function that handles all BSON types including
    :class:`~bson.binary.Binary` and :class:`~bson.code.Code`.

    :param json_options: A :class:`JSONOptions` instance used to modify the
        encoding of MongoDB Extended JSON types. Defaults to
        :const:`DEFAULT_JSON_OPTIONS`.

    .. versionchanged:: 4.0
       Now outputs MongoDB Relaxed Extended JSON by default (using
       :const:`DEFAULT_JSON_OPTIONS`).

    .. versionchanged:: 3.4
       Accepts optional parameter `json_options`. See :class:`JSONOptions`.
    """
    json_options = kwargs.pop("json_options", DEFAULT_JSON_OPTIONS)
    return json.dumps(convert_to_extjson(obj, json_options), *args, **kwargs)


def loads(s: Union[str, bytes, bytearray], *args: Any, **kwargs: Any) -> Any:
    """Helper function that wraps :func:`json.loads`.

    Automatically passes the object_hook for BSON type conversion.

    Raises ``TypeError``, ``ValueError``, ``KeyError``, or
    :exc:`~bson.errors.InvalidId` on invalid MongoDB Extended JSON.

    :param json_options: A :class:`JSONOptions` instance used to modify the
        decoding of MongoDB Extended JSON types. Defaults to
        :const:`DEFAULT_JSON_OPTIONS`.

    .. versionchanged:: 4.0
       Now loads :class:`datetime.datetime` instances as naive by default. To
       load timezone aware instances utilize the `json_options` parameter.
       See :ref:`tz_aware_default_change` for an example.

    .. versionchanged:: 3.5
       Parses Relaxed and Canonical Extended JSON as well as PyMongo's legacy
       format. Now raises ``TypeError`` or ``ValueError`` when parsing JSON
       type wrappers with values of the wrong type or any extra keys.

    .. versionchanged:: 3.4
       Accepts optional parameter `json_options`. See :class:`JSONOptions`.
    """
    json_options = kwargs.pop("json_options", DEFAULT_JSON_OPTIONS)
    # Execution time optimization if json_options.document_class is dict
    if json_options.document_class is dict:
        kwargs["object_hook"] = lambda obj: object_hook(obj, json_options)
    else:
        kwargs["object_pairs_hook"] = lambda pairs: object_pairs_hook(pairs, json_options)
    return json.loads(s, *args, **kwargs)



def convert_to_extjson(obj: Any, json_options: JSONOptions = DEFAULT_JSON_OPTIONS) -> Any:
    """Recursive helper method that converts BSON types so they can be
    converted into json.
    """
    if hasattr(obj, "items"):
        return {k: convert_to_extjson(v, json_options) for k, v in obj.items()}
    elif hasattr(obj, "__iter__") and not isinstance(obj, (str, bytes)):
        return [convert_to_extjson(v, json_options) for v in obj]
    try:
        return _convert_primitive_to_extjson(obj, json_options)
    except TypeError:
        return obj



def _convert_primitive_to_extjson(obj: Any, json_options: JSONOptions = DEFAULT_JSON_OPTIONS) -> Any:
    # First see if the type is already cached. KeyError will only ever
    # happen once per subtype.
    try:
        return _ENCODERS[type(obj)](obj, json_options)
    except KeyError:
        pass

    # Second, fall back to trying _type_marker. This has to be done
    # before the loop below since users could subclass one of our
    # custom types that subclasses a python built-in (e.g. Binary)
    if hasattr(obj, "_type_marker"):
        marker = obj._type_marker
        if marker in _MARKERS:
            func = _MARKERS[marker]
            # Cache this type for faster subsequent lookup.
            _ENCODERS[type(obj)] = func
            return func(obj, json_options)

    # Third, test each base type. This will only happen once for
    # a subtype of a supported base type.
    for base in _BUILT_IN_TYPES:
        if isinstance(obj, base):
            func = _ENCODERS[base]
            # Cache this type for faster subsequent lookup.
            _ENCODERS[type(obj)] = func
            return func(obj, json_options)

    raise TypeError("%r is not JSON serializable" % obj)




def _encode_binary(data: bytes, subtype: int, json_options: JSONOptions) -> Any:
    if json_options.json_mode == JSONMode.LEGACY:
        return {"$binary": base64.b64encode(data).decode(), "$type": "%02x" % subtype}
    return {"$binary": {"base64": base64.b64encode(data).decode(), "subType": "%02x" % subtype}}


def _encode_datetimems(obj: Any, json_options: JSONOptions) -> dict:
    if (
        json_options.datetime_representation == DatetimeRepresentation.ISO8601
        and 0 <= int(obj) <= _MAX_UTC_MS
    ):
        return _encode_datetime(obj.as_datetime(), json_options)
    elif json_options.datetime_representation == DatetimeRepresentation.LEGACY:
        return {"$date": int(obj)}
    return {"$date": {"$numberLong": str(int(obj))}}


def _encode_code(obj: Code, json_options: JSONOptions) -> dict:
    if obj.scope is None:
        return {"$code": str(obj)}
    else:
        return {"$code": str(obj), "$scope": _json_convert(obj.scope, json_options)}


def _encode_int64(obj: Int64, json_options: JSONOptions) -> Any:
    if json_options.strict_number_long:
        return {"$numberLong": str(obj)}
    else:
        return int(obj)


def _encode_noop(obj: Any, dummy0: Any) -> Any:
    return obj


def _encode_regex(obj: Any, json_options: JSONOptions) -> dict:
    flags = ""
    if obj.flags & re.IGNORECASE:
        flags += "i"
    if obj.flags & re.LOCALE:
        flags += "l"
    if obj.flags & re.MULTILINE:
        flags += "m"
    if obj.flags & re.DOTALL:
        flags += "s"
    if obj.flags & re.UNICODE:
        flags += "u"
    if obj.flags & re.VERBOSE:
        flags += "x"
    if isinstance(obj.pattern, str):
        pattern = obj.pattern
    else:
        pattern = obj.pattern.decode("utf-8")
    if json_options.json_mode == JSONMode.LEGACY:
        return {"$regex": pattern, "$options": flags}
    return {"$regularExpression": {"pattern": pattern, "options": flags}}


def _encode_int(obj: int, json_options: JSONOptions) -> Any:
    if json_options.json_mode == JSONMode.CANONICAL:
        if -_INT32_MAX <= obj < _INT32_MAX:
            return {"$numberInt": str(obj)}
        return {"$numberLong": str(obj)}
    return obj


def _encode_float(obj: float, json_options: JSONOptions) -> Any:
    if json_options.json_mode != JSONMode.LEGACY:
        if math.isnan(obj):
            return {"$numberDouble": "NaN"}
        elif math.isinf(obj):
            representation = "Infinity" if obj > 0 else "-Infinity"
            return {"$numberDouble": representation}
        elif json_options.json_mode == JSONMode.CANONICAL:
            # repr() will return the shortest string guaranteed to produce the
            # original value, when float() is called on it.
            return {"$numberDouble": str(repr(obj))}
    return obj


def _encode_datetime(obj: datetime.datetime, json_options: JSONOptions) -> dict:
    if json_options.datetime_representation == DatetimeRepresentation.ISO8601:
        if not obj.tzinfo:
            obj = obj.replace(tzinfo=utc)
            assert obj.tzinfo is not None
        if obj >= EPOCH_AWARE:
            off = obj.tzinfo.utcoffset(obj)
            if (off.days, off.seconds, off.microseconds) == (0, 0, 0):  # type: ignore
                tz_string = "Z"
            else:
                tz_string = obj.strftime("%z")
            millis = int(obj.microsecond / 1000)
            fracsecs = ".%03d" % (millis,) if millis else ""
            return {
                "$date": "{}{}{}".format(obj.strftime("%Y-%m-%dT%H:%M:%S"), fracsecs, tz_string)
            }

    millis = _datetime_to_millis(obj)
    if json_options.datetime_representation == DatetimeRepresentation.LEGACY:
        return {"$date": millis}
    return {"$date": {"$numberLong": str(millis)}}


def _encode_bytes(obj: bytes, json_options: JSONOptions) -> dict:
    return _encode_binary(obj, 0, json_options)


def _encode_binary_obj(obj: Binary, json_options: JSONOptions) -> dict:
    return _encode_binary(obj, obj.subtype, json_options)


def _encode_uuid(obj: uuid.UUID, json_options: JSONOptions) -> dict:
    if json_options.strict_uuid:
        binval = Binary.from_uuid(obj, uuid_representation=json_options.uuid_representation)
        return _encode_binary(binval, binval.subtype, json_options)
    else:
        return {"$uuid": obj.hex}


def _encode_objectid(obj: ObjectId, dummy0: Any) -> dict:
    return {"$oid": str(obj)}


def _encode_timestamp(obj: Timestamp, dummy0: Any) -> dict:
    return {"$timestamp": {"t": obj.time, "i": obj.inc}}


def _encode_decimal128(obj: Timestamp, dummy0: Any) -> dict:
    return {"$numberDecimal": str(obj)}


def _encode_dbref(obj: DBRef, json_options: JSONOptions) -> dict:
    return _json_convert(obj.as_doc(), json_options=json_options)


def _encode_minkey(dummy0: Any, dummy1: Any) -> dict:
    return {"$minKey": 1}


def _encode_maxkey(dummy0: Any, dummy1: Any) -> dict:
    return {"$maxKey": 1}



# Encoders for BSON types
# Each encoder function's signature is:
#   - obj: a Python data type, e.g. a Python int for _encode_int
#   - json_options: a JSONOptions
_ENCODERS: dict[Type, Callable[[Any, JSONOptions], Any]] = {
    bool: _encode_noop,
    bytes: _encode_bytes,
    datetime.datetime: _encode_datetime,
    DatetimeMS: _encode_datetimems,
    float: _encode_float,
    int: _encode_int,
    str: _encode_noop,
    type(None): _encode_noop,
    uuid.UUID: _encode_uuid,
    Binary: _encode_binary_obj,
    Int64: _encode_int64,
    Code: _encode_code,
    DBRef: _encode_dbref,
    MaxKey: _encode_maxkey,
    MinKey: _encode_minkey,
    ObjectId: _encode_objectid,
    Regex: _encode_regex,
    RE_TYPE: _encode_regex,
    Timestamp: _encode_timestamp,
    Decimal128: _encode_decimal128,
}





def object_pairs_hook(
    pairs: Sequence[Tuple[str, Any]], json_options: JSONOptions = DEFAULT_JSON_OPTIONS
) -> Any:
    return object_hook(json_options.document_class(pairs), json_options)  # type:ignore[call-arg]


def object_hook(dct: Mapping[str, Any], json_options: JSONOptions = DEFAULT_JSON_OPTIONS) -> Any:
    match = None
    for k in dct:
        if k in _PARSERS_SET:
            match = k
            break
    if match:
        return _PARSERS[match](dct, json_options)
    return dct




def _parse_canonical_binary(doc: Any, json_options: JSONOptions) -> Union[Binary, uuid.UUID]:
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
    return _binary_or_uuid(data, int(subtype, 16), json_options)


def _parse_canonical_datetime(
    doc: Any, json_options: JSONOptions
) -> Union[datetime.datetime, DatetimeMS]:
    """Decode a JSON datetime to python datetime.datetime."""
    dtm = doc["$date"]
    if len(doc) != 1:
        raise TypeError(f"Bad $date, extra field(s): {doc}")
    # mongoexport 2.6 and newer
    if isinstance(dtm, str):
        try:
            # Parse offset
            if dtm[-1] == "Z":
                dt = dtm[:-1]
                offset = "Z"
            elif dtm[-6] in ("+", "-") and dtm[-3] == ":":
                # (+|-)HH:MM
                dt = dtm[:-6]
                offset = dtm[-6:]
            elif dtm[-5] in ("+", "-"):
                # (+|-)HHMM
                dt = dtm[:-5]
                offset = dtm[-5:]
            elif dtm[-3] in ("+", "-"):
                # (+|-)HH
                dt = dtm[:-3]
                offset = dtm[-3:]
            else:
                dt = dtm
                offset = ""
        except IndexError as exc:
            raise ValueError(f"time data {dtm!r} does not match ISO-8601 datetime format") from exc

        # Parse the optional factional seconds portion.
        dot_index = dt.rfind(".")
        microsecond = 0
        if dot_index != -1:
            microsecond = int(float(dt[dot_index:]) * 1000000)
            dt = dt[:dot_index]

        aware = datetime.datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S").replace(
            microsecond=microsecond, tzinfo=utc
        )

        if offset and offset != "Z":
            if len(offset) == 6:
                hours, minutes = offset[1:].split(":")
                secs = int(hours) * 3600 + int(minutes) * 60
            elif len(offset) == 5:
                secs = int(offset[1:3]) * 3600 + int(offset[3:]) * 60
            elif len(offset) == 3:
                secs = int(offset[1:3]) * 3600
            if offset[0] == "-":
                secs *= -1
            aware = aware - datetime.timedelta(seconds=secs)

        if json_options.tz_aware:
            if json_options.tzinfo:
                aware = aware.astimezone(json_options.tzinfo)
            if json_options.datetime_conversion == DatetimeConversion.DATETIME_MS:
                return DatetimeMS(aware)
            return aware
        else:
            aware_tzinfo_none = aware.replace(tzinfo=None)
            if json_options.datetime_conversion == DatetimeConversion.DATETIME_MS:
                return DatetimeMS(aware_tzinfo_none)
            return aware_tzinfo_none
    return _millis_to_datetime(int(dtm), cast("CodecOptions[Any]", json_options))


def _parse_canonical_int32(doc: Any, dummy0: Any) -> int:
    """Decode a JSON int32 to python int."""
    i_str = doc["$numberInt"]
    if len(doc) != 1:
        raise TypeError(f"Bad $numberInt, extra field(s): {doc}")
    if not isinstance(i_str, str):
        raise TypeError(f"$numberInt must be string: {doc}")
    return int(i_str)


def _parse_canonical_int64(doc: Any, dummy0: Any) -> Int64:
    """Decode a JSON int64 to bson.int64.Int64."""
    l_str = doc["$numberLong"]
    if len(doc) != 1:
        raise TypeError(f"Bad $numberLong, extra field(s): {doc}")
    return Int64(l_str)


def _parse_canonical_double(doc: Any, dummy0: Any) -> float:
    """Decode a JSON double to python float."""
    d_str = doc["$numberDouble"]
    if len(doc) != 1:
        raise TypeError(f"Bad $numberDouble, extra field(s): {doc}")
    if not isinstance(d_str, str):
        raise TypeError(f"$numberDouble must be string: {doc}")
    return float(d_str)


def _parse_canonical_decimal128(doc: Any, dummy0: Any) -> Decimal128:
    """Decode a JSON decimal128 to bson.decimal128.Decimal128."""
    d_str = doc["$numberDecimal"]
    if len(doc) != 1:
        raise TypeError(f"Bad $numberDecimal, extra field(s): {doc}")
    if not isinstance(d_str, str):
        raise TypeError(f"$numberDecimal must be string: {doc}")
    return Decimal128(d_str)

def _parse_timestamp(doc: Any, dummy0: Any) -> Timestamp:
    tsp = doc["$timestamp"]
    return Timestamp(tsp["t"], tsp["i"])


_PARSERS: dict[str, Callable[[Any, JSONOptions], Any]] = {
    "$date": _parse_canonical_datetime,
    "$binary": _parse_canonical_binary,
    "$undefined": lambda _, _1: None,
    "$timestamp": _parse_timestamp,
    "$numberDecimal": _parse_canonical_decimal128,
    "$numberInt": _parse_canonical_int32,
    "$numberLong": _parse_canonical_int64,
    "$numberDouble": _parse_canonical_double,
}
_PARSERS_SET = set(_PARSERS)
