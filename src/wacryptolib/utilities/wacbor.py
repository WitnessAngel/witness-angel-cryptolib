# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
WA-CBOR codec: the CBOR (RFC 8949) dialect of wacryptolib documents, bijective with their Extended JSON form.

See docs/specifications/wa_cbor_document_format.md for the normative specification.

This module only depends on the standard library, and avoids constructs foreign to MicroPython,
so that it can later be vendored or moved into the `extjson` package.
"""

import datetime
import math
import re
import struct
import uuid
from decimal import Decimal

# Single-key maps with one of these keys would be parsed as typed values by Extended JSON readers
EXTJSON_KEYWORDS = frozenset(
    ["$binary", "$uuid", "$date", "$numberInt", "$numberLong", "$numberDouble", "$numberDecimal", "$undefined"]
)

MAX_NESTING_DEPTH = 64  # Of arrays and maps, the top-level item having depth 1

SELF_DESCRIBED_CBOR_TAG = 55799
DATETIME_TEXT_TAG = 0
POSITIVE_BIGNUM_TAG = 2
NEGATIVE_BIGNUM_TAG = 3
DECIMAL_FRACTION_TAG = 4
UUID_TAG = 37

_MAJOR_UNSIGNED = 0
_MAJOR_NEGATIVE = 1
_MAJOR_BYTES = 2
_MAJOR_TEXT = 3
_MAJOR_ARRAY = 4
_MAJOR_MAP = 5
_MAJOR_TAG = 6
_MAJOR_SIMPLE = 7

_BREAK_BYTE = 0xFF
_UINT64_LIMIT = 2**64

_NAN_ENCODING = b"\xf9\x7e\x00"
_POSITIVE_INFINITY_ENCODING = b"\xf9\x7c\x00"
_NEGATIVE_INFINITY_ENCODING = b"\xf9\xfc\x00"

# Same text as the RELAXED Extended JSON writer, but with exactly 3 or 0 fraction digits on read, ASCII digits only
_DATETIME_TEXT_REGEX = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,3}))?([Zz]|[+-][0-9]{2}:[0-9]{2})$"
)


class WaCborError(ValueError):
    """Base class of WA-CBOR errors."""


class WaCborEncodingError(WaCborError):
    """A value is outside the WA-CBOR data model, or can't be carried faithfully by both formats."""


class WaCborDecodingError(WaCborError):
    """Some bytes are not a well-formed WA-CBOR document."""


def _describe_value(value):
    representation = repr(value)
    if len(representation) > 100:
        representation = representation[:97] + "..."
    return representation


class _NullSink:
    """Output buffer which discards everything, to check a tree without encoding it."""

    def append(self, value):
        pass

    def extend(self, value):
        pass


def _encode_head(major_type, argument, out):
    initial = major_type << 5
    if argument < 24:
        out.append(initial | argument)
    elif argument < 0x100:
        out.append(initial | 24)
        out.append(argument)
    elif argument < 0x10000:
        out.extend(struct.pack(">BH", initial | 25, argument))
    elif argument < 0x100000000:
        out.extend(struct.pack(">BI", initial | 26, argument))
    else:
        out.extend(struct.pack(">BQ", initial | 27, argument))


def _encode_integer(value, out):
    if value >= 0:
        if value < _UINT64_LIMIT:
            _encode_head(_MAJOR_UNSIGNED, value, out)
            return
        tag, magnitude = POSITIVE_BIGNUM_TAG, value
    else:
        magnitude = -1 - value
        if magnitude < _UINT64_LIMIT:
            _encode_head(_MAJOR_NEGATIVE, magnitude, out)
            return
        tag = NEGATIVE_BIGNUM_TAG
    magnitude_bytes = magnitude.to_bytes((magnitude.bit_length() + 7) // 8, "big")
    _encode_head(_MAJOR_TAG, tag, out)
    _encode_head(_MAJOR_BYTES, len(magnitude_bytes), out)
    out.extend(magnitude_bytes)


def _encode_float(value, out):
    if math.isnan(value):
        out.extend(_NAN_ENCODING)  # Canonical NaN of RFC 8949, whatever the payload
        return
    if math.isinf(value):
        out.extend(_POSITIVE_INFINITY_ENCODING if value > 0 else _NEGATIVE_INFINITY_ENCODING)
        return
    for code, struct_format in ((25, ">e"), (26, ">f")):
        try:
            packed = struct.pack(struct_format, value)
        except OverflowError:
            continue
        if struct.unpack(struct_format, packed)[0] == value:  # Also keeps the sign of zeros
            out.append(0xE0 | code)
            out.extend(packed)
            return
    out.append(0xE0 | 27)
    out.extend(struct.pack(">d", value))


def _encode_text(value, out):
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise WaCborEncodingError("Unsupported text string with lone surrogates: %s" % _describe_value(value)) from exc
    _encode_head(_MAJOR_TEXT, len(encoded), out)
    out.extend(encoded)


def _get_datetime_text(value):
    """Return the RELAXED Extended JSON text of an aware datetime, truncated to milliseconds."""
    timespec = "milliseconds" if value.microsecond != 0 else "seconds"
    text = value.isoformat(sep="T", timespec=timespec)
    if text.endswith("+00:00"):
        text = text[:-6] + "Z"
    return text


def _encode_datetime(value, out):
    utc_offset = value.utcoffset() if value.tzinfo is not None else None
    if utc_offset is None:
        raise WaCborEncodingError("Unsupported naive datetime: %s" % _describe_value(value))
    if utc_offset.microseconds or utc_offset.seconds % 60:
        raise WaCborEncodingError("Unsupported datetime UTC offset with seconds: %s" % _describe_value(value))
    _encode_head(_MAJOR_TAG, DATETIME_TEXT_TAG, out)
    _encode_text(_get_datetime_text(value), out)


def _encode_decimal(value, out):
    sign, digits, exponent = value.as_tuple()
    if not isinstance(exponent, int):  # 'n', 'N' or 'F'
        raise WaCborEncodingError("Unsupported decimal NaN or infinity: %s" % _describe_value(value))
    mantissa = int("".join(str(digit) for digit in digits)) if digits else 0
    if sign:
        if not mantissa:
            raise WaCborEncodingError("Unsupported decimal negative zero: %s" % _describe_value(value))
        mantissa = -mantissa
    if not (-_UINT64_LIMIT <= exponent < _UINT64_LIMIT):
        raise WaCborEncodingError("Unsupported decimal exponent: %s" % _describe_value(value))
    _encode_head(_MAJOR_TAG, DECIMAL_FRACTION_TAG, out)
    _encode_head(_MAJOR_ARRAY, 2, out)
    _encode_integer(exponent, out)
    _encode_integer(mantissa, out)


def _encode_key(key):
    if not isinstance(key, str):
        raise WaCborEncodingError("Unsupported non-text map key: %s" % _describe_value(key))
    encoded_key = bytearray()
    _encode_text(key, encoded_key)
    return bytes(encoded_key)


def _encode_item(value, out, depth):
    # Beware, bool is a subclass of int, and datetime a subclass of date
    if value is None:
        out.append(0xF6)
    elif value is True:
        out.append(0xF5)
    elif value is False:
        out.append(0xF4)
    elif isinstance(value, str):
        _encode_text(value, out)
    elif isinstance(value, bytes):
        _encode_head(_MAJOR_BYTES, len(value), out)
        out.extend(value)
    elif isinstance(value, bool):
        raise AssertionError("Unexpected bool subclass %r" % value)  # Can't happen, bool can't be subclassed
    elif isinstance(value, int):
        _encode_integer(int(value), out)
    elif isinstance(value, float):
        _encode_float(float(value), out)
    elif isinstance(value, dict):
        depth += 1
        if depth > MAX_NESTING_DEPTH:
            raise WaCborEncodingError("Unsupported nesting depth of arrays and maps, above %d" % MAX_NESTING_DEPTH)
        encoded_keys = sorted((_encode_key(key), key) for key in value)  # Bytewise order of encoded keys
        if len(encoded_keys) == 1 and encoded_keys[0][1] in EXTJSON_KEYWORDS:
            raise WaCborEncodingError("Unsupported Extended JSON keyword map: %s" % _describe_value(value))
        _encode_head(_MAJOR_MAP, len(encoded_keys), out)
        for encoded_key, key in encoded_keys:
            out.extend(encoded_key)
            _encode_item(value[key], out, depth)
    elif isinstance(value, (list, tuple)):
        depth += 1
        if depth > MAX_NESTING_DEPTH:
            raise WaCborEncodingError("Unsupported nesting depth of arrays and maps, above %d" % MAX_NESTING_DEPTH)
        _encode_head(_MAJOR_ARRAY, len(value), out)
        for item in value:
            _encode_item(item, out, depth)
    elif isinstance(value, uuid.UUID):
        _encode_head(_MAJOR_TAG, UUID_TAG, out)
        _encode_head(_MAJOR_BYTES, 16, out)
        out.extend(value.bytes)
    elif isinstance(value, datetime.datetime):
        _encode_datetime(value, out)
    elif isinstance(value, Decimal):
        _encode_decimal(value, out)
    else:
        raise WaCborEncodingError(
            "Unsupported value of type %s: %s" % (type(value).__name__, _describe_value(value))
        )


def _check_top_level_item(data):
    if not isinstance(data, (dict, list, tuple)):
        raise WaCborEncodingError("Unsupported top-level value, not a map nor an array: %s" % _describe_value(data))


def check_document_tree(data) -> None:
    """Raise WaCborEncodingError if `data` is not a document of the WA-CBOR data model,
    or holds a value that Extended JSON and WA-CBOR can't both carry faithfully."""
    _check_top_level_item(data)
    _encode_item(data, _NullSink(), depth=0)


def dump_to_cbor_bytes(data) -> bytes:
    """Dump a document tree (map or array at top level) to WA-CBOR bytes, in core deterministic encoding.

    Raises WaCborEncodingError, without any output, on unsupported values."""
    _check_top_level_item(data)
    out = bytearray()
    _encode_item(data, out, depth=0)
    return bytes(out)


class _Decoder:
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("WA-CBOR data must be bytes-like, not %s" % type(data).__name__)
        self._data = memoryview(data).cast("B")  # Slicing it doesn't copy the underlying buffer
        self._length = len(self._data)
        self._position = 0

    def _fail(self, message):
        raise WaCborDecodingError("%s (at byte offset %d)" % (message, self._position))

    def _read(self, count):
        end = self._position + count
        if end > self._length:
            self._fail("Truncated WA-CBOR data")
        chunk = self._data[self._position : end]
        self._position = end
        return chunk

    def _peek_initial_byte(self):
        if self._position >= self._length:
            self._fail("Truncated WA-CBOR data")
        return self._data[self._position]

    def _read_head(self):
        """Return (major_type, additional_info, argument), argument being None for indefinite lengths."""
        initial = self._peek_initial_byte()
        self._position += 1
        major_type, additional_info = initial >> 5, initial & 0x1F
        if additional_info < 24:
            argument = additional_info
        elif additional_info <= 27:
            argument = int.from_bytes(self._read(1 << (additional_info - 24)), "big")
        elif additional_info == 31:
            argument = None
        else:
            self._position -= 1
            self._fail("Reserved additional information %d in initial byte 0x%02x" % (additional_info, initial))
        return major_type, additional_info, argument

    def _peek_head(self):
        position = self._position
        try:
            return self._read_head()
        finally:
            self._position = position

    def _check_count(self, count, item_size):
        if count * item_size > self._length - self._position:
            self._fail("Declared count %d exceeds the remaining data" % count)

    def _read_string_bytes(self, major_type, argument):
        if argument is not None:
            self._check_count(argument, 1)
            return [self._read(argument)]
        chunks = []
        while self._peek_initial_byte() != _BREAK_BYTE:
            chunk_major_type, _info, chunk_length = self._read_head()
            if chunk_major_type != major_type or chunk_length is None:
                self._fail("Invalid chunk in indefinite-length string")
            self._check_count(chunk_length, 1)
            chunks.append(self._read(chunk_length))
        self._position += 1  # Break
        return chunks

    def _decode_text_chunks(self, chunks):
        try:
            return "".join(str(chunk, "utf-8") for chunk in chunks)  # Each chunk must be valid on its own
        except UnicodeDecodeError:
            self._fail("Invalid UTF-8 in text string")

    def _expect_major_type(self, expected_major_type, tag):
        major_type, _info, _argument = self._peek_head()
        if major_type != expected_major_type:
            self._fail("Invalid content of tag %d" % tag)

    def decode_document(self):
        major_type, _info, argument = self._peek_head()
        if major_type == _MAJOR_TAG and argument == SELF_DESCRIBED_CBOR_TAG:
            self._read_head()  # Accepted around the top-level item only
            major_type, _info, argument = self._peek_head()
        if major_type not in (_MAJOR_ARRAY, _MAJOR_MAP):
            self._fail("Top-level item is not a map nor an array")
        document = self._decode_item(depth=0)
        if self._position != self._length:
            self._fail("Unexpected bytes after the top-level item")
        return document

    def _decode_item(self, depth):
        initial = self._peek_initial_byte()
        if initial == _BREAK_BYTE:
            self._fail("Unexpected break code")
        major_type, additional_info, argument = self._read_head()

        if major_type in (_MAJOR_UNSIGNED, _MAJOR_NEGATIVE, _MAJOR_TAG) and argument is None:
            self._position -= 1
            self._fail("Invalid indefinite length for major type %d" % major_type)

        if major_type == _MAJOR_UNSIGNED:
            return argument
        if major_type == _MAJOR_NEGATIVE:
            return -1 - argument
        if major_type == _MAJOR_BYTES:
            return b"".join(self._read_string_bytes(major_type, argument))
        if major_type == _MAJOR_TEXT:
            return self._decode_text_chunks(self._read_string_bytes(major_type, argument))
        if major_type == _MAJOR_ARRAY:
            return self._decode_array(argument, depth=depth + 1)
        if major_type == _MAJOR_MAP:
            return self._decode_map(argument, depth=depth + 1)
        if major_type == _MAJOR_TAG:
            return self._decode_tagged_item(argument, depth=depth)
        return self._decode_simple_value(additional_info, argument)

    def _check_depth(self, depth):
        if depth > MAX_NESTING_DEPTH:
            self._fail("Nesting depth of arrays and maps exceeds %d" % MAX_NESTING_DEPTH)

    def _decode_array(self, count, depth):
        self._check_depth(depth)
        items = []
        if count is None:
            while self._peek_initial_byte() != _BREAK_BYTE:
                items.append(self._decode_item(depth))
            self._position += 1
        else:
            self._check_count(count, 1)
            for _ in range(count):
                items.append(self._decode_item(depth))
        return items

    def _decode_map(self, count, depth):
        self._check_depth(depth)
        result = {}

        def _decode_entry():
            key_position = self._position
            key_major_type, _info, _argument = self._peek_head()
            if key_major_type != _MAJOR_TEXT:
                self._fail("Map key is not a text string")
            key = self._decode_item(depth)
            if key in result:
                self._position = key_position
                self._fail("Duplicate map key %s" % _describe_value(key))
            result[key] = self._decode_item(depth)

        if count is None:
            while self._peek_initial_byte() != _BREAK_BYTE:
                _decode_entry()
            self._position += 1
        else:
            self._check_count(count, 2)
            for _ in range(count):
                _decode_entry()

        if len(result) == 1:
            (key,) = result
            if key in EXTJSON_KEYWORDS:
                self._fail("Extended JSON keyword map %s" % _describe_value(result))
        return result

    def _decode_tagged_item(self, tag, depth):
        if tag == DATETIME_TEXT_TAG:
            self._expect_major_type(_MAJOR_TEXT, tag)
            return self._parse_datetime_text(self._decode_item(depth))
        if tag in (POSITIVE_BIGNUM_TAG, NEGATIVE_BIGNUM_TAG):
            self._expect_major_type(_MAJOR_BYTES, tag)
            magnitude = int.from_bytes(self._decode_item(depth), "big")
            return magnitude if tag == POSITIVE_BIGNUM_TAG else -1 - magnitude
        if tag == DECIMAL_FRACTION_TAG:
            return self._decode_decimal_fraction()
        if tag == UUID_TAG:
            self._expect_major_type(_MAJOR_BYTES, tag)
            uuid_bytes = self._decode_item(depth)
            if len(uuid_bytes) != 16:
                self._fail("Invalid UUID byte string of length %d" % len(uuid_bytes))
            return uuid.UUID(bytes=uuid_bytes)
        self._fail("Unsupported tag %d" % tag)

    def _decode_decimal_fraction(self):
        major_type, _info, count = self._peek_head()
        if major_type != _MAJOR_ARRAY or count not in (2, None):
            self._fail("Invalid content of tag %d" % DECIMAL_FRACTION_TAG)
        self._read_head()

        exponent_major_type, _info, _argument = self._peek_head()
        if exponent_major_type not in (_MAJOR_UNSIGNED, _MAJOR_NEGATIVE):
            self._fail("Invalid decimal fraction exponent")
        exponent = self._decode_item(depth=0)

        mantissa_major_type, _info, mantissa_argument = self._peek_head()
        if not (
            mantissa_major_type in (_MAJOR_UNSIGNED, _MAJOR_NEGATIVE)
            or (mantissa_major_type == _MAJOR_TAG and mantissa_argument in (POSITIVE_BIGNUM_TAG, NEGATIVE_BIGNUM_TAG))
        ):
            self._fail("Invalid decimal fraction mantissa")
        mantissa = self._decode_item(depth=0)

        if count is None:
            if self._peek_initial_byte() != _BREAK_BYTE:
                self._fail("Invalid content of tag %d" % DECIMAL_FRACTION_TAG)
            self._position += 1

        sign = 1 if mantissa < 0 else 0
        digits = tuple(int(digit) for digit in str(abs(mantissa)))
        return Decimal((sign, digits, exponent))

    def _parse_datetime_text(self, text):
        match = _DATETIME_TEXT_REGEX.match(text)
        if not match:
            self._fail("Invalid datetime text %s" % _describe_value(text))
        year, month, day, hour, minute, second, fraction, offset = match.groups()
        microsecond = int(fraction.ljust(3, "0")) * 1000 if fraction else 0
        if offset in ("Z", "z"):
            tzinfo = datetime.timezone.utc
        else:
            offset_hours, offset_minutes = int(offset[1:3]), int(offset[4:6])
            if offset_hours > 23 or offset_minutes > 59:
                self._fail("Invalid datetime UTC offset %s" % _describe_value(text))
            offset_delta = datetime.timedelta(hours=offset_hours, minutes=offset_minutes)
            if not offset_delta:
                tzinfo = datetime.timezone.utc
            else:
                tzinfo = datetime.timezone(-offset_delta if offset[0] == "-" else offset_delta)
        try:
            return datetime.datetime(
                int(year), int(month), int(day), int(hour), int(minute), int(second), microsecond, tzinfo=tzinfo
            )
        except ValueError:  # E.g. leap seconds, or 1st of the 13th month
            self._fail("Invalid datetime text %s" % _describe_value(text))

    def _decode_simple_value(self, additional_info, argument):
        if additional_info == 20:
            return False
        if additional_info == 21:
            return True
        if additional_info == 22:
            return None
        if additional_info in (25, 26, 27):
            byte_count = 1 << (additional_info - 24)
            struct_format = {25: ">e", 26: ">f", 27: ">d"}[additional_info]
            return struct.unpack(struct_format, argument.to_bytes(byte_count, "big"))[0]
        self._fail("Unsupported simple value (additional information %d)" % additional_info)


def load_from_cbor_bytes(data):
    """Load a document tree from WA-CBOR bytes, with strict decoding rules.

    Raises WaCborDecodingError if the data is not a well-formed WA-CBOR document."""
    return _Decoder(data).decode_document()


def dump_to_cbor_file(filepath, data) -> bytes:
    """Same as `dump_to_cbor_bytes`, but writes data to filesystem (and returns bytes too)."""
    cbor_bytes = dump_to_cbor_bytes(data)  # Fully encoded before the file gets created
    with open(filepath, "wb") as f:
        f.write(cbor_bytes)
    return cbor_bytes


def load_from_cbor_file(filepath):
    """Same as `load_from_cbor_bytes`, but reads data from filesystem."""
    with open(filepath, "rb") as f:
        cbor_bytes = f.read()
    return load_from_cbor_bytes(cbor_bytes)
