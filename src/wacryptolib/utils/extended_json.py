# TODO ADD LICENSE HEADER


from __future__ import annotations

import calendar
import decimal
import base64
import datetime
import json
import math
import uuid
from typing import (
    Any,
    Callable,
    Mapping,
    Type,
    Union,
)



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
    assert canonical in (True, False), canonical
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
        raise TypeError(f"Unsupported naive datetime encountered: {obj}")
    if canonical:
        millis = _datetime_to_millis(obj)
        return {"$date": {"$numberLong": str(millis)}}
    # We output datetime as "YYYY-MM-DDTHH:MM:SS[.fff]<offset>" (not microseconds)
    timespec = "milliseconds" if obj.microsecond != 0 else "seconds"
    dts = obj.isoformat(sep="T", timespec=timespec)
    dts = dts.replace("+00:00", "Z")  # We ASSUME that 0-offset means UTC...
    return {
        "$date": dts
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
#   - canonical: whether to use canonical Extended JSON representation
_ENCODERS: dict[Type, Callable[[Any, bool], Any]] = {
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
    return _get_as_binary_or_uuid(data, int(subtype, 16))


def _get_as_binary_or_uuid(data: Any, subtype: int) -> Union[bytes, uuid.UUID]:
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
    if isinstance(dtm, str):
        return datetime.datetime.fromisoformat(dtm)
    return _millis_to_datetime(dtm)


def _parse_canonical_int32(doc: Any) -> int:
    """Decode a JSON int32 to python int."""
    i_str = doc["$numberInt"]
    if len(doc) != 1:
        raise TypeError(f"Bad $numberInt, extra field(s): {doc}")  # FIXME MUTUALIZE THIS
    if not isinstance(i_str, str):
        raise TypeError(f"$numberInt must be string: {doc}")
    return int(i_str)


def _parse_canonical_int64(doc: Any) -> int:
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


def _parse_legacy_uuid(doc: Any) -> Union[bytes, uuid.UUID]:
    """Decode a JSON legacy $uuid to Python UUID."""
    if len(doc) != 1:
        raise TypeError(f"Bad $uuid, extra field(s): {doc}")
    if not isinstance(doc["$uuid"], str):
        raise TypeError(f"$uuid must be a string: {doc}")
    return uuid.UUID(doc["$uuid"])


_PARSERS: dict[str, Callable[[Any], Any]] = {
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


_EPOCH_AWARE = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)


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
    assert isinstance(millis, int), repr(millis)
    diff = ((millis % 1000) + 1000) % 1000
    seconds = (millis - diff) // 1000
    micros = diff * 1000

    dt = _EPOCH_AWARE + datetime.timedelta(seconds=seconds, microseconds=micros)

    return dt  # UTC aware datetime
