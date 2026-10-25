"""
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from __future__ import annotations  # Keeps annotations unevaluated (Micropython needs micropython-lib's __future__)

import binascii
import datetime
import json
import math
import sys
import uuid

try:
    from typing import (
        Any,
        Callable,
        Mapping,
        Type,
        Union,
    )
except ImportError:
    # E.g. on Micropython without micropython-lib's typing, where annotations are ignored anyway
    pass


class _FakeDecimal:
    pass


try:
    from decimal import Decimal
except ImportError:
    # E.g. on Micropython without a port of decimal
    Decimal = _FakeDecimal


_INT32_MAX = 2**31

UTF8_ENCODING = "utf8"
UTF8_BOM = b"\xef\xbb\xbf"

IS_MICROPYTHON = sys.implementation.name == "micropython"


# Only these two binary-data subtypes are supported
BINARY_SUBTYPE = 0
UUID_SUBTYPE = 4


# NOTE: we can't provide a "default" handler to use with json.dumps(),
# for non-canonical mode, because of the way NaN/-Inf/+Inf are handled
# without resorting to default()...


def extjson_decoder_object_hook(obj: dict) -> Any:
    return _convert_primitive_from_extjson_dict(obj)


def convert_to_extjson(obj: Any, canonical: bool = False) -> Any:
    """Recursive helper method that converts BSON types so they can be
    converted into json.
    """
    assert canonical in (True, False), canonical
    if isinstance(obj, dict):
        return {k: convert_to_extjson(v, canonical=canonical) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):  # Tuples are treated like lists!
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


def convert_from_extjson(ext_obj: Any) -> Any:
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
        return ext_obj_dict  # We assume it's not a {$type: ...} dict
    for k in ext_obj_dict:
        if k in _PARSERS:
            match = k
            break
    if match:
        return _PARSERS[match](ext_obj_dict)
    return ext_obj_dict  # Leave it untouched


def _encode_canonical_binary(data: bytes, subtype: int) -> Any:
    return {"$binary": {"base64": _simple_b64encode(data).decode("ascii"), "subType": "%02x" % subtype}}


def _encode_int(obj: int, canonical: bool) -> Any:
    if canonical:
        if -_INT32_MAX <= obj < _INT32_MAX:
            # int() strips subclasses, whose __str__ might be overridden
            return {"$numberInt": str(int(obj))}
        return {"$numberLong": str(int(obj))}
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
        # On CPython, repr() returns the shortest string guaranteed to produce the
        # original value when float() is called on it, but Micropython's repr() may
        # lose digits, hence the "%.17g" fallback. float() strips subclasses,
        # whose __repr__ might be overridden (e.g. numpy.float64).
        value = float(obj)
        representation = repr(value)
        if float(representation) != value:
            representation = "%.17g" % value
        return {"$numberDouble": representation}
    return obj


def _encode_decimal(obj: Decimal, canonical: bool) -> dict:
    # Always use canonical representation for Decimal numbers
    return {"$numberDecimal": str(obj)}


def _encode_datetime(obj: datetime.datetime, canonical: bool) -> dict:
    if not _is_aware_datetime(obj):
        raise TypeError(f"Unsupported naive datetime encountered: {obj}")
    if canonical:
        millis = _aware_datetime_to_millis(obj)
        return {"$date": {"$numberLong": str(millis)}}
    # We output datetime as "YYYY-MM-DDTHH:MM:SS[.fff]<offset>" (not microseconds)
    # Note that Python doesn't support dates outside this 'YYYY' year range anyway
    timespec = "milliseconds" if obj.microsecond != 0 else "seconds"
    dts = obj.isoformat(sep="T", timespec=timespec)
    if dts.endswith("+00:00"):  # Beware of offsets with seconds, like "+00:00:30"
        dts = dts[:-6] + "Z"  # We ASSUME that 0-offset means UTC...
    return {"$date": dts}


def _encode_bytes(obj: bytes, canonical: bool) -> dict:
    # Always use canonical representation for Bytes
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
    Decimal: _encode_decimal,
    int: _encode_int,
    str: _encode_noop,
    type(None): _encode_noop,
}


_EXTENDED_JSON_BUILT_IN_TYPES = tuple(_ENCODERS)


def _parse_canonical_binary(doc: Any) -> Union[bytes, uuid.UUID]:
    binary = doc["$binary"]
    if not isinstance(binary, dict) or set(binary.keys()) != {"base64", "subType"}:
        raise TypeError(f"$binary must be a dict with keys 'base64' and 'subType' only: {doc}")
    b64 = binary["base64"]
    subtype = binary["subType"]
    if not isinstance(b64, str):
        raise TypeError(f"$binary base64 must be a string: {doc}")
    if not isinstance(subtype, str) or len(subtype) > 2:
        raise TypeError(f"$binary subType must be a string with at most 2 characters: {doc}")

    data = _simple_b64decode(b64.encode("ascii"))
    return _get_as_binary_or_uuid(data, int(subtype, 16))


def _get_as_binary_or_uuid(data: Any, subtype: int) -> Union[bytes, uuid.UUID]:
    if subtype not in (BINARY_SUBTYPE, UUID_SUBTYPE):
        raise TypeError(f"Unsupported binary subtype: {subtype}")
    if subtype == UUID_SUBTYPE:
        return uuid.UUID(bytes=data)
    return data


def _parse_canonical_datetime(doc: Any) -> datetime.datetime:
    """Decode a JSON datetime to python datetime.datetime.

    Canonical dates are always returned as UTC, whereas isoformat strings are
    returned with their indicated timezone (which MUST exist)."""
    dtm = doc["$date"]
    if not isinstance(dtm, (str, int)) or isinstance(dtm, bool):  # Beware, bool is a subclass of int
        raise TypeError(f"Date must be iso string or millisecond int: {doc}")
    if isinstance(dtm, str):
        if IS_MICROPYTHON and dtm.endswith("Z"):
            # micropython-lib's datetime.fromisoformat has no "Z" support,
            # but does parse numeric UTC offsets.
            dtm = dtm[:-1] + "+00:00"
        res = datetime.datetime.fromisoformat(dtm)
        if not _is_aware_datetime(res):
            raise TypeError(f"Unsupported naive datetime: {dtm}")
        return res
    return _millis_to_utc_datetime(dtm)


def _parse_canonical_int32(doc: Any) -> int:
    """Decode a JSON int32 to python int."""
    i_str = doc["$numberInt"]
    if not isinstance(i_str, str):
        raise TypeError(f"$numberInt must be string: {doc}")
    return int(i_str)


def _parse_canonical_int64(doc: Any) -> int:
    """Decode a JSON int64 to bson.int64.Int64."""
    l_str = doc["$numberLong"]
    if not isinstance(l_str, str):
        raise TypeError(f"$numberLong must be string: {doc}")
    return int(l_str)  # No need for Int64 type here


def _parse_canonical_double(doc: Any) -> float:
    """Decode a JSON double to python float."""
    d_str = doc["$numberDouble"]
    if not isinstance(d_str, str):
        raise TypeError(f"$numberDouble must be string: {doc}")
    return float(d_str)


def _parse_canonical_decimal(doc: Any) -> Decimal:
    d_str = doc["$numberDecimal"]
    if not isinstance(d_str, str):
        raise TypeError(f"$numberDecimal must be string: {doc}")
    if Decimal is _FakeDecimal:
        raise ImportError(f"No 'decimal' module available to decode $numberDecimal: {doc}")
    return Decimal(d_str)


def _parse_legacy_uuid(doc: Any) -> Union[bytes, uuid.UUID]:
    """Decode a JSON legacy $uuid to Python UUID."""
    hex_str = doc["$uuid"]
    if not isinstance(hex_str, str):
        raise TypeError(f"$uuid must be a string: {doc}")
    if IS_MICROPYTHON:
        # micropython-lib's uuid.UUID stub only accepts a raw 16-byte buffer,
        # unlike CPython's uuid.UUID which parses hex strings directly,
        # so we mimic CPython's normalization of these strings.
        hex_str = hex_str.replace("urn:", "").replace("uuid:", "")
        hex_str = hex_str.strip("{}").replace("-", "")
        if len(hex_str) != 32:
            raise ValueError("badly formed hexadecimal UUID string")
        data = binascii.unhexlify(hex_str)
        return uuid.UUID(bytes=data)
    return uuid.UUID(hex_str)


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


# Not built with fromtimestamp(0), since some Micropython ports use 2000-01-01 as their epoch
_EPOCH_AWARE = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def _is_aware_datetime(dt: datetime.datetime) -> bool:
    """Check if a datetime is timezone aware."""
    return dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None


def _aware_datetime_to_millis(dt: datetime.datetime) -> int:
    """Convert aware datetime to milliseconds since epoch UTC."""
    assert _is_aware_datetime(dt), f"Unsupported naive datetime encountered: {dt}"
    # Integer arithmetic only, since float timestamps lack sub-millisecond precision for distant years
    delta = dt - _EPOCH_AWARE
    return (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000


def _millis_to_utc_datetime(
    millis: int,
) -> datetime.datetime:
    """Convert milliseconds since epoch UTC to aware datetime."""
    assert isinstance(millis, int), repr(millis)
    seconds = millis // 1000
    micros = (millis % 1000) * 1000
    dt = _EPOCH_AWARE + datetime.timedelta(seconds=seconds, microseconds=micros)
    return dt  # UTC aware datetime


def _simple_b64encode(s):
    """Encode the bytes-like object s using Base64 and return a bytes object."""
    encoded = binascii.b2a_base64(s, newline=False)
    return encoded


def _simple_b64decode(s):
    """Decode the Base64 encoded bytes-like object or ASCII string s.

    The result is returned as a bytes object.  A binascii.Error is raised if
    s is incorrectly padded.
    """
    assert isinstance(s, bytes)
    return binascii.a2b_base64(s)


# HIGH LEVEL UTILITIES #


def dumps(obj: Any, *args: Any, canonical=False, **kwargs: Any) -> str:
    """Helper function that wraps :func:`json.dumps`.

    Recursive function that handles main ExtendedJSON types.
    """
    ext_obj = convert_to_extjson(obj, canonical=canonical)
    return json.dumps(ext_obj, *args, **kwargs)


def loads(s: Union[str, bytes, bytearray], *args: Any, **kwargs: Any) -> Any:
    """Helper function that wraps :func:`json.loads`.

    Recursive function that handles main ExtendedJSON types.
    """
    ext_obj = json.loads(s, *args, **kwargs)
    return convert_from_extjson(ext_obj)


def dump_to_json_str(data, **extra_options):
    """
    Dump a data tree to a json representation as string.
    Supports advanced types like bytes, uuids, dates...
    """
    if not IS_MICROPYTHON:
        extra_options.setdefault("sort_keys", True)
    json_str = dumps(data, **extra_options)
    return json_str


def load_from_json_str(data, **extra_options):
    """
    Load a data tree from a json representation as string.
    Supports advanced types like bytes, uuids, dates...

    Raises TypeError on wrongly-typed Extended JSON wrappers, and lets other errors
    of the underlying parsers propagate on malformed data (JSONDecodeError and
    other ValueError subclasses, OverflowError, decimal.InvalidOperation...).
    """
    assert isinstance(data, str), data
    return loads(data, **extra_options)


def dump_to_json_bytes(data, **extra_options):
    """
    Same as `dump_to_json_str`, but returns UTF8-encoded bytes.
    """
    json_str = dump_to_json_str(data, **extra_options)
    return json_str.encode(UTF8_ENCODING)


def load_from_json_bytes(data, **extra_options):
    """
    Same as `load_from_json_str`, but takes UTF8-encoded bytes as input.
    A leading UTF8 byte-order mark (BOM) is ignored.
    """
    if data[: len(UTF8_BOM)] == UTF8_BOM:  # Micropython has no "utf-8-sig" codec
        data = data[len(UTF8_BOM) :]
    json_str = data.decode(UTF8_ENCODING)
    return load_from_json_str(data=json_str, **extra_options)


def dump_to_json_file(filepath, data, **extra_options):
    """
    Same as `dump_to_json_bytes`, but writes data to filesystem (and returns bytes too).
    """
    json_bytes = dump_to_json_bytes(data, **extra_options)
    with open(filepath, "wb") as f:
        f.write(json_bytes)
    return json_bytes


def load_from_json_file(filepath, **extra_options):
    """
    Same as `load_from_json_bytes`, but reads data from filesystem.
    """
    with open(filepath, "rb") as f:
        json_bytes = f.read()
    return load_from_json_bytes(json_bytes, **extra_options)
