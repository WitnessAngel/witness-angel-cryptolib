# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import sys
import uuid
from datetime import datetime, timezone, timedelta
from threading import Lock

import pytest
import pytz

from wacryptolib._crypto_backend import get_random_bytes
from wacryptolib.utilities import (
    split_as_chunks,
    recombine_chunks,
    dump_to_json_bytes,
    dump_to_json_str,
    load_from_json_bytes,
    load_from_json_str,
    check_datetime_is_tz_aware,
    dump_to_json_file,
    load_from_json_file,
    generate_uuid0,
    get_utc_now_date,
    get_memory_rss_bytes,
    catch_and_log_exception,
    synchronized,
    pad_bytes_pkcs7,
    unpad_bytes_pkcs7,
    is_file_basename,
)


def test_check_datetime_is_tz_aware():
    with pytest.raises(ValueError):
        check_datetime_is_tz_aware(datetime.now())
    check_datetime_is_tz_aware(get_utc_now_date())


def test_pkcs7_padding():

    assert pad_bytes_pkcs7(b"", 10) == b'\n\n\n\n\n\n\n\n\n\n'
    assert unpad_bytes_pkcs7(b'\n\n\n\n\n\n\n\n\n\n', 10) == b""

    assert pad_bytes_pkcs7(b"abcdefgh", 5) == b'abcdefgh\x02\x02'
    assert unpad_bytes_pkcs7(b'abcdefgh\x02\x02', 10) == b"abcdefgh"

    msg = get_random_bytes(56)
    blk_size = 11
    assert unpad_bytes_pkcs7(pad_bytes_pkcs7(msg, block_size=blk_size), block_size=blk_size) == msg

    with pytest.raises(ValueError):
        unpad_bytes_pkcs7(b'', block_size=5)
    with pytest.raises(ValueError):
        unpad_bytes_pkcs7(b'abc\0', block_size=10)
    with pytest.raises(ValueError):
        unpad_bytes_pkcs7(b'abcdefghijk\x04', block_size=2)
    with pytest.raises(ValueError):
        unpad_bytes_pkcs7(b'abcdefgh\x01\x02', block_size=10)


def test_split_as_chunks_and_recombine():
    bytestring = get_random_bytes(100)

    chunks = split_as_chunks(bytestring, chunk_size=25, must_pad=True)
    assert all(len(x) == 25 for x in chunks)
    result = recombine_chunks(chunks, chunk_size=25, must_unpad=True)
    assert result == bytestring

    chunks = split_as_chunks(bytestring, chunk_size=22, must_pad=True)
    assert all(len(x) == 22 for x in chunks)
    result = recombine_chunks(chunks, chunk_size=22, must_unpad=True)
    assert result == bytestring

    chunks = split_as_chunks(bytestring, chunk_size=25, must_pad=False)
    assert all(len(x) == 25 for x in chunks)
    result = recombine_chunks(chunks, chunk_size=25, must_unpad=False)
    assert result == bytestring

    with pytest.raises(ValueError, match="size multiple of chunk_size"):
        split_as_chunks(bytestring, chunk_size=22, must_pad=False)

    chunks = split_as_chunks(bytestring, chunk_size=22, must_pad=False, accept_incomplete_chunk=True)
    assert not all(len(x) == 22 for x in chunks)
    result = recombine_chunks(chunks, chunk_size=22, must_unpad=False)
    assert result == bytestring


def test_serialization_utilities(tmp_path):
    uid = uuid.UUID("7c0b18f5-f410-4e83-9263-b38c2328e516")
    payload = dict(b=b"xyz", a="hêllo", c=uid)

    serialized_str = dump_to_json_str(payload)
    # Keys are sorted, RELAXED format uses plain UUID representation
    assert (
        serialized_str
        == r'{"a": "h\u00eallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$uuid": "7c0b18f5f4104e839263b38c2328e516"}}'
    )
    deserialized = load_from_json_str(serialized_str)
    assert deserialized == payload

    serialized_str = dump_to_json_str(payload, ensure_ascii=False)  # Json arguments well propagated
    assert (
        serialized_str
        == r'{"a": "hêllo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$uuid": "7c0b18f5f4104e839263b38c2328e516"}}'
    )
    deserialized = load_from_json_str(serialized_str)
    assert deserialized == payload

    serialized_str = dump_to_json_bytes(payload)
    # Keys are sorted, RELAXED format
    assert (
        serialized_str
        == rb'{"a": "h\u00eallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$uuid": "7c0b18f5f4104e839263b38c2328e516"}}'
    )
    deserialized = load_from_json_bytes(serialized_str)
    assert deserialized == payload

    serialized_str = dump_to_json_bytes(payload, ensure_ascii=False)  # Json arguments well propagated
    assert (
        serialized_str
        == b'{"a": "h\xc3\xaallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$uuid": "7c0b18f5f4104e839263b38c2328e516"}}'
    )
    deserialized = load_from_json_bytes(serialized_str)
    assert deserialized == payload

    tmp_filepath = os.path.join(tmp_path, "dummy_temp_file.dat")
    serialized_str = dump_to_json_file(tmp_filepath, data=payload, ensure_ascii=True)  # Json arguments well propagated
    assert (
        serialized_str
        == rb'{"a": "h\u00eallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$uuid": "7c0b18f5f4104e839263b38c2328e516"}}'
    )
    deserialized = load_from_json_file(tmp_filepath)
    assert deserialized == payload

    # Special tests for DATES

    utc_date = pytz.utc.localize(datetime(2022, 10, 10))
    pst_date = utc_date.astimezone(pytz.timezone("America/Los_Angeles"))

    payload1 = {"date": utc_date}
    serialized_str1 = dump_to_json_str(payload1)
    payload2 = {"date": pst_date}
    serialized_str2 = dump_to_json_str(payload2)

    # RELAXED format uses ISO 8601 date strings (milliseconds may or may not be included)
    # Both dates should serialize to the same UTC representation
    assert serialized_str1 in [r'{"date": {"$date": "2022-10-10T00:00:00Z"}}', r'{"date": {"$date": "2022-10-10T00:00:00.000Z"}}']
    # NOTE: PST date is not automatically converted to UTC in RELAXED format - this is intentional
    assert serialized_str1 != serialized_str2

    # We just verify both can be loaded correctly
    deserialized = load_from_json_str(serialized_str1)
    assert deserialized == payload1
    assert deserialized == payload2

    utcoffset = deserialized["date"].utcoffset()
    assert utcoffset == timedelta(0)  # Date is returned as UTC in any case!


def test_generate_uuid0():
    utc = pytz.UTC

    some_date = datetime(year=2000, month=6, day=12, tzinfo=timezone.min)
    some_timestamp = datetime.timestamp(some_date)

    uuid0 = generate_uuid0(some_timestamp)
    assert utc.localize(uuid0.datetime) == some_date
    assert uuid0.datetime_local != some_date.replace(tzinfo=None)  # Local TZ is used here
    assert uuid0.unix_ts == some_timestamp

    uuids = [generate_uuid0().int for _ in range(1000)]
    assert len(set(uuids)) == 1000

    uuids = [generate_uuid0(some_timestamp).int for _ in range(1000)]
    assert len(set(uuids)) == 1000

    uuid_test = generate_uuid0(0)
    assert uuid_test.unix_ts != 0  # Can't generate UUIDs with timestamp=0


def test_get_memory_rss_bytes():
    assert 30 * 1024**2 < get_memory_rss_bytes() < 200 * 1024**2


def test_catch_and_log_exception():
    variable = None

    with catch_and_log_exception("testage1"):
        variable = 12
        raise RuntimeError
        variable = 13

    assert variable == 12

    @catch_and_log_exception("testage2")
    def myfunc(myarg):
        if myarg == 42:
            raise ValueError(myarg)
        return myarg

    result = myfunc(33)
    assert result == 33
    result = myfunc(42)  # Exception raised inside
    assert result is None

    class MyClass:
        _lock = Lock()

        @synchronized
        @catch_and_log_exception("testage3")
        def do_stuffs(self, myarg):
            if myarg == 43:
                raise ValueError(myarg)
            return myarg

    my_instance = MyClass()

    result = my_instance.do_stuffs(32)
    assert result == 32
    result = my_instance.do_stuffs(43)  # Exception raised inside
    assert result is None


# WA-CBOR and document files


import json
import math
import random
import re
import uuid as _uuid_module
from decimal import Decimal
from pathlib import Path

from wacryptolib.utilities import (
    DocumentFormat,
    DocumentFormatError,
    WaCborDecodingError,
    WaCborEncodingError,
    check_document_tree,
    convert_document_bytes,
    convert_document_tree_to_bytes,
    detect_document_format,
    dump_to_cbor_bytes,
    dump_to_cbor_file,
    dump_to_document_bytes,
    dump_to_document_file,
    get_document_format_from_filename,
    get_recognized_extension,
    load_from_cbor_bytes,
    load_from_cbor_file,
    load_from_document_bytes,
    load_from_document_file,
    normalize_recognized_extension,
)

WA_CBOR_SPECIFICATION_PATH = Path(__file__).resolve().parents[1].joinpath(
    "docs", "specifications", "wa_cbor_document_format.md"
)


def assert_same_document_tree(tree1, tree2, path="$"):
    """Strict comparison: same types at every position, same datetime UTC offsets, same decimal digits and
    exponents, same signs of float zeros, and NaN equal to NaN."""
    assert type(tree1) is type(tree2), (path, tree1, tree2)
    if isinstance(tree1, dict):
        assert sorted(tree1) == sorted(tree2), (path, tree1.keys(), tree2.keys())
        for key in tree1:
            assert_same_document_tree(tree1[key], tree2[key], path=path + "." + key)
    elif isinstance(tree1, list):
        assert len(tree1) == len(tree2), (path, tree1, tree2)
        for idx, (item1, item2) in enumerate(zip(tree1, tree2)):
            assert_same_document_tree(item1, item2, path="%s[%d]" % (path, idx))
    elif isinstance(tree1, float):
        if math.isnan(tree1):
            assert math.isnan(tree2), (path, tree1, tree2)
        else:
            assert tree1 == tree2 and math.copysign(1, tree1) == math.copysign(1, tree2), (path, tree1, tree2)
    elif isinstance(tree1, datetime):
        assert tree1 == tree2 and tree1.utcoffset() == tree2.utcoffset(), (path, tree1, tree2)
    elif isinstance(tree1, Decimal):
        assert tree1.as_tuple() == tree2.as_tuple(), (path, tree1, tree2)
    else:
        assert tree1 == tree2, (path, tree1, tree2)


def _extract_wa_cbor_test_vectors(specification_text):
    match = re.search(r"^```json wa-cbor-test-vectors\n(.*?)^```", specification_text, re.MULTILINE | re.DOTALL)
    assert match, "No test vector block found in WA-CBOR specification"
    return json.loads(match.group(1))


def _check_wa_cbor_test_vectors(specification_text):
    import cbor2

    test_vectors = _extract_wa_cbor_test_vectors(specification_text)
    assert len(test_vectors["valid"]) >= 20 and len(test_vectors["invalid"]) >= 20

    for vector in test_vectors["valid"]:
        name = vector["name"]
        cbor_bytes = bytes.fromhex(vector["cbor_hex"])
        expected_tree = load_from_json_str(vector["extjson"])
        decoded_tree = load_from_cbor_bytes(cbor_bytes)
        assert_same_document_tree(decoded_tree, expected_tree, path=name)
        if vector["deterministic"]:
            assert dump_to_cbor_bytes(expected_tree) == cbor_bytes, "Test vector %s is not reproduced" % name
            assert dump_to_json_str(decoded_tree) == vector["extjson"], name
            assert_same_document_tree(cbor2.loads(cbor_bytes), expected_tree, path="cbor2:" + name)  # Oracle
        else:
            assert dump_to_cbor_bytes(expected_tree) != cbor_bytes, name

    for vector in test_vectors["invalid"]:
        name = vector["name"]
        with pytest.raises(WaCborDecodingError) as exc_info:
            load_from_cbor_bytes(bytes.fromhex(vector["cbor_hex"]))
        assert vector["reason"] in str(exc_info.value), (name, str(exc_info.value))


def test_wa_cbor_test_vectors_of_specification():
    specification_text = WA_CBOR_SPECIFICATION_PATH.read_text(encoding="utf8")
    _check_wa_cbor_test_vectors(specification_text)

    # The check fails, naming the vector, as soon as one vector's hex is altered
    vector_line_regex = re.compile(r'("name": "datetime_with_offset", "deterministic": true, "cbor_hex": "[0-9a-f]+)3030"')
    altered_text, substitution_count = vector_line_regex.subn(r'\g<1>3031"', specification_text)
    assert substitution_count == 1
    with pytest.raises(AssertionError, match="datetime_with_offset"):
        _check_wa_cbor_test_vectors(altered_text)


def test_wa_cbor_type_mapping_scenarios():
    # Bytes and UUIDs are native
    uid = _uuid_module.UUID("0123456789abcdef0123456789abcdef")
    cbor_bytes = dump_to_cbor_bytes({"b": b"\x01\x02", "u": uid})
    assert cbor_bytes == bytes.fromhex("a2" "6162" "420102" "6175" "d82550") + uid.bytes
    assert b"$binary" not in cbor_bytes and b"$uuid" not in cbor_bytes

    # Datetime with offset
    some_datetime = datetime(2026, 1, 2, 3, 4, 5, 123000, tzinfo=timezone(timedelta(hours=2)))
    cbor_bytes = dump_to_cbor_bytes([some_datetime])
    assert cbor_bytes == bytes.fromhex("81c0781d") + b"2026-01-02T03:04:05.123+02:00"
    assert_same_document_tree(load_from_cbor_bytes(cbor_bytes), [some_datetime])

    # Decimal keeps its exponent
    cbor_bytes = dump_to_cbor_bytes([Decimal("1.0"), Decimal("1.00")])
    assert cbor_bytes == bytes.fromhex("82" "c482200a" "c482211864")  # [-1, 10] and [-2, 100]
    assert_same_document_tree(load_from_cbor_bytes(cbor_bytes), [Decimal("1.0"), Decimal("1.00")])

    # Big integer
    big_integer = 2**64 + 5
    cbor_bytes = dump_to_cbor_bytes([big_integer])
    assert cbor_bytes == bytes.fromhex("81c249010000000000000005")
    assert load_from_cbor_bytes(cbor_bytes) == [big_integer]

    # Same tree, same bytes
    tree1 = {"zz": 1, "a": [1, 2], "b": {"y": None, "x": True}}
    tree2 = {"b": {"x": True, "y": None}, "a": [1, 2], "zz": 1}
    assert dump_to_cbor_bytes(tree1) == dump_to_cbor_bytes(tree2)

    # Shortest float form
    assert dump_to_cbor_bytes([1.5]) == bytes.fromhex("81f93e00")
    assert load_from_cbor_bytes(bytes.fromhex("81f93e00")) == [1.5]

    # Tuples are written as arrays, and load back as lists
    assert load_from_cbor_bytes(dump_to_cbor_bytes({"t": (1, (2,))})) == {"t": [1, [2]]}

    # Subclasses of supported types are written like their base type
    class MyInt(int):
        pass

    class MyStr(str):
        pass

    assert dump_to_cbor_bytes([MyInt(3), MyStr("a")]) == dump_to_cbor_bytes([3, "a"])


def test_wa_cbor_microseconds_truncated_identically():
    some_datetime = datetime(2026, 1, 2, 3, 4, 5, 123999, tzinfo=timezone.utc)
    json_bytes = dump_to_json_bytes({"d": some_datetime})
    cbor_bytes = dump_to_cbor_bytes({"d": some_datetime})
    assert b'"2026-01-02T03:04:05.123Z"' in json_bytes
    assert b"2026-01-02T03:04:05.123Z" in cbor_bytes
    json_tree = load_from_json_bytes(json_bytes)
    cbor_tree = load_from_cbor_bytes(cbor_bytes)
    assert json_tree["d"].microsecond == 123000
    assert_same_document_tree(json_tree, cbor_tree)


@pytest.mark.parametrize(
    "unsupported_value",
    [
        datetime(2026, 1, 2),  # Naive
        datetime(2026, 1, 2, tzinfo=timezone(timedelta(seconds=30))),
        datetime(2026, 1, 2, tzinfo=timezone(-timedelta(hours=1, seconds=1))),
        Decimal("NaN"),
        Decimal("sNaN"),
        Decimal("Infinity"),
        Decimal("-Infinity"),
        Decimal("-0"),
        Decimal("-0.00"),
        "lone \ud800 surrogate",
        {1: "non-text key"},
        {("tuple", "key"): 1},
        {"$date": "not a date"},
        {"$uuid": "0123"},
        {"$undefined": True},
        {1},
        datetime(2026, 1, 2).date(),
        bytearray(b"abc"),
        memoryview(b"abc"),
        object(),
    ],
)
def test_wa_cbor_unsupported_values_rejected(unsupported_value, tmp_path):
    tree = {"key": [unsupported_value]}

    with pytest.raises(WaCborEncodingError):
        dump_to_cbor_bytes(tree)
    with pytest.raises(WaCborEncodingError):
        check_document_tree(tree)
    for target_format in (DocumentFormat.JSON, DocumentFormat.CBOR):
        with pytest.raises(WaCborEncodingError):
            convert_document_tree_to_bytes(tree, target_format=target_format)

    target_file = tmp_path / "doc.cbor"
    with pytest.raises(WaCborEncodingError):
        dump_to_cbor_file(target_file, tree)
    with pytest.raises(WaCborEncodingError):
        dump_to_document_file(target_file, tree)
    assert not target_file.exists()


def test_wa_cbor_unsupported_value_errors_are_explicit():
    with pytest.raises(WaCborEncodingError, match=r"decimal NaN.*Decimal\('NaN'\)"):
        dump_to_cbor_bytes([Decimal("NaN")])
    with pytest.raises(WaCborEncodingError, match="keyword map"):
        dump_to_cbor_bytes({"x": {"$date": "not a date"}})
    # Maps with several keys, or other "$" keys, are fine
    assert load_from_cbor_bytes(dump_to_cbor_bytes([{"$date": 1, "x": 2}, {"$other": 3}])) == [
        {"$date": 1, "x": 2},
        {"$other": 3},
    ]


def test_wa_cbor_top_level_item_and_nesting_depth():
    for scalar in [None, 1, "a", b"a", 1.5, Decimal("1")]:
        with pytest.raises(WaCborEncodingError, match="top-level"):
            dump_to_cbor_bytes(scalar)
        with pytest.raises(WaCborEncodingError, match="top-level"):
            check_document_tree(scalar)
    with pytest.raises(WaCborDecodingError, match="Top-level item"):
        load_from_cbor_bytes(bytes.fromhex("f6"))

    nested = []
    for _ in range(63):
        nested = [nested]
    assert load_from_cbor_bytes(dump_to_cbor_bytes(nested)) == nested  # Depth 64
    with pytest.raises(WaCborEncodingError, match="nesting depth"):
        dump_to_cbor_bytes([nested])
    with pytest.raises(WaCborEncodingError, match="nesting depth"):
        dump_to_cbor_bytes({"x": nested})

    with pytest.raises(TypeError):
        load_from_cbor_bytes("a0")  # Text is not bytes
    assert load_from_cbor_bytes(bytearray(b"\xa0")) == {}
    assert load_from_cbor_bytes(memoryview(b"\x80")) == []


def test_wa_cbor_strict_decoding_scenarios():
    # Non-deterministic but valid input
    assert load_from_cbor_bytes(bytes.fromhex("bf616201616102ff")) == {"b": 1, "a": 2}

    # Epoch datetime refused, naming the tag
    with pytest.raises(WaCborDecodingError, match="Unsupported tag 1 "):
        load_from_cbor_bytes(bytes.fromhex("a16164c11a5f5e1000"))

    # Duplicate key refused
    with pytest.raises(WaCborDecodingError, match="Duplicate map key 'a'"):
        load_from_cbor_bytes(bytes.fromhex("a2616101616102"))

    # Extended JSON keyword map refused
    with pytest.raises(WaCborDecodingError, match="keyword map"):
        load_from_cbor_bytes(bytes.fromhex("a16178a165247575696464" + "30313233"))

    # Huge declared lengths don't trigger huge allocations
    with pytest.raises(WaCborDecodingError, match="exceeds the remaining data"):
        load_from_cbor_bytes(bytes.fromhex("815bffffffffffffffff"))
    with pytest.raises(WaCborDecodingError, match="exceeds the remaining data"):
        load_from_cbor_bytes(bytes.fromhex("9bffffffffffffffff"))


def _generate_random_text(rnd):
    alphabet = "abcXYZ019 $_-.éà水\U0001f600\n\"\\"
    return "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 8)))


def _generate_random_scalar(rnd, with_sub_second_datetimes):
    kind = rnd.randint(0, 11)
    if kind == 0:
        return rnd.choice([None, True, False])
    if kind == 1:
        return rnd.choice([0, 1, 23, 24, 255, 256, -1, -24, -25, 2**32, 2**64 - 1, -(2**64), 2**64, -(2**64) - 1])
    if kind == 2:
        return rnd.randint(-(2**200), 2**200)
    if kind == 3:
        return rnd.choice(
            [0.0, -0.0, 1.5, -2.25, 65504.0, 1e300, -1e-300, 5e-324, 3.4028234663852886e38, float("nan"),
             float("inf"), float("-inf"), rnd.uniform(-1e6, 1e6)]
        )
    if kind == 4:
        return _generate_random_text(rnd)
    if kind == 5:
        return bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 20)))
    if kind == 6:
        return _uuid_module.UUID(int=rnd.getrandbits(128))
    if kind == 7:
        offset = timedelta(minutes=rnd.randint(-23 * 60 - 59, 23 * 60 + 59))
        microsecond = rnd.choice([0, rnd.randint(1, 999) * 1000]) if with_sub_second_datetimes else 0
        return datetime(
            rnd.randint(1, 9999), rnd.randint(1, 12), rnd.randint(1, 28), rnd.randint(0, 23), rnd.randint(0, 59),
            rnd.randint(0, 59), microsecond, tzinfo=timezone(offset) if offset else timezone.utc,
        )
    if kind == 8:
        digits = tuple(rnd.randint(0, 9) for _ in range(rnd.randint(1, 40)))
        sign = rnd.randint(0, 1) if any(digits) else 0  # No negative zero
        return Decimal((sign, digits, rnd.randint(-30, 30)))
    if kind == 9:
        return rnd.uniform(-1, 1)
    if kind == 10:
        return rnd.randint(-1000, 1000)
    return "$" + _generate_random_text(rnd)


def _generate_random_tree(rnd, depth, with_sub_second_datetimes):
    if depth >= 4 or rnd.random() < 0.3 * depth:
        return _generate_random_scalar(rnd, with_sub_second_datetimes=with_sub_second_datetimes)
    if rnd.random() < 0.5:
        return [
            _generate_random_tree(rnd, depth + 1, with_sub_second_datetimes) for _ in range(rnd.randint(0, 5))
        ]
    tree = {
        _generate_random_text(rnd): _generate_random_tree(rnd, depth + 1, with_sub_second_datetimes)
        for _ in range(rnd.randint(0, 5))
    }
    if len(tree) == 1 and next(iter(tree)).startswith("$"):
        tree["other"] = None  # Not a keyword map
    return tree


def _generate_random_document(rnd, with_sub_second_datetimes=True):
    tree = _generate_random_tree(rnd, depth=0, with_sub_second_datetimes=with_sub_second_datetimes)
    if not isinstance(tree, (dict, list)):
        tree = [tree]
    return tree


def test_wa_cbor_random_trees_against_cbor2_oracle_and_extended_json():
    import cbor2

    rnd = random.Random(1234)

    for idx in range(1200):
        tree = _generate_random_document(rnd, with_sub_second_datetimes=bool(idx % 2))

        cbor_bytes = dump_to_cbor_bytes(tree)
        assert_same_document_tree(load_from_cbor_bytes(cbor_bytes), tree)

        # Our output loads equal in cbor2
        assert_same_document_tree(cbor2.loads(cbor_bytes), tree)

        if idx % 2 == 0:  # cbor2 writes microseconds, which are outside the dialect, so only whole seconds here
            cbor2_bytes = cbor2.dumps(tree, canonical=True)
            assert_same_document_tree(load_from_cbor_bytes(cbor2_bytes), tree)
            assert cbor2_bytes == cbor_bytes  # Same core deterministic encoding

        # Bijection with Extended JSON
        json_bytes = dump_to_json_bytes(tree)
        json_tree = load_from_json_bytes(json_bytes)
        assert_same_document_tree(json_tree, load_from_cbor_bytes(cbor_bytes))
        assert convert_document_bytes(cbor_bytes, target_format=DocumentFormat.JSON) == json_bytes
        assert convert_document_bytes(json_bytes, target_format=DocumentFormat.CBOR) == cbor_bytes
        # Byte-exact round trips from both default writers
        assert convert_document_bytes(
            convert_document_bytes(cbor_bytes, target_format=DocumentFormat.JSON), target_format=DocumentFormat.CBOR
        ) == cbor_bytes
        assert convert_document_bytes(
            convert_document_bytes(json_bytes, target_format=DocumentFormat.CBOR), target_format=DocumentFormat.JSON
        ) == json_bytes


def test_wa_cbor_conversion_of_canonical_extended_json():
    tree = {
        "i": 42,
        "big": 2**40,
        "f": 1.5,
        "b": b"xyz",
        "u": _uuid_module.UUID("7c0b18f5-f410-4e83-9263-b38c2328e516"),
        "d": datetime(2022, 10, 10, 1, 2, 3, 456000, tzinfo=timezone.utc),
    }
    canonical_json_str = dump_to_json_str(tree, canonical=True)
    assert "$numberInt" in canonical_json_str
    cbor_bytes = convert_document_bytes(canonical_json_str.encode("utf8"), target_format=DocumentFormat.CBOR)
    relaxed_json_bytes = convert_document_bytes(cbor_bytes, target_format=DocumentFormat.JSON)
    assert relaxed_json_bytes == dump_to_json_bytes(tree)  # RELAXED form
    assert_same_document_tree(load_from_json_bytes(relaxed_json_bytes), load_from_json_str(canonical_json_str))

    # Conversion refuses values that one of the formats can't carry faithfully
    with pytest.raises(WaCborEncodingError, match="decimal NaN"):
        convert_document_bytes(b'{"x": {"$numberDecimal": "NaN"}}', target_format=DocumentFormat.CBOR)
    with pytest.raises(WaCborEncodingError, match="decimal negative zero"):
        convert_document_bytes(b'{"x": {"$numberDecimal": "-0.00"}}', target_format=DocumentFormat.JSON)
    with pytest.raises(WaCborEncodingError, match="UTC offset with seconds"):
        convert_document_bytes(b'{"x": {"$date": "2020-01-01T00:00:00+00:00:30"}}', target_format=DocumentFormat.CBOR)


def test_recognized_extension_normalization():
    assert get_recognized_extension("Clip.MP4.CRYPT.JSON") == ".crypt.json"
    assert get_recognized_extension("x.Json.CRYPT") == ".crypt"
    assert get_recognized_extension("x.crypt.Cbor") == ".crypt.cbor"
    assert get_recognized_extension("conf.CBOR") == ".cbor"
    assert get_recognized_extension("x.crypt.json~") is None  # Temporary suffix is not skipped here
    assert get_recognized_extension("notes.txt") is None
    assert get_recognized_extension("x.jsonx") is None
    assert get_recognized_extension("") is None

    assert normalize_recognized_extension("Clip.MP4.CRYPT.JSON") == "Clip.MP4.crypt.json"
    assert normalize_recognized_extension("x.Json.CRYPT") == "x.Json.crypt"  # ".json.crypt" is not recognized
    assert normalize_recognized_extension("Report.JSON") == "Report.json"
    assert normalize_recognized_extension("OTHER.CBOR") == "OTHER.cbor"
    assert normalize_recognized_extension("x.CRYPT.CBOR~") == "x.crypt.cbor~"
    assert normalize_recognized_extension("Video.MP4.crypt.json") == "Video.MP4.crypt.json"
    assert normalize_recognized_extension("Notes.TXT") == "Notes.TXT"
    assert normalize_recognized_extension("Notes.TXT~") == "Notes.TXT~"
    assert normalize_recognized_extension("dir/Sub.Dir/Clip.CRYPT") == "dir/Sub.Dir/Clip.crypt"
    assert normalize_recognized_extension("~") == "~"
    assert normalize_recognized_extension("") == ""
    assert normalize_recognized_extension("x.ＪＳＯＮ") == "x.ＪＳＯＮ"  # ASCII only
    assert normalize_recognized_extension(Path("A.JSON")) == "A.json"

    assert get_document_format_from_filename("CONF.JSON") == DocumentFormat.JSON
    assert get_document_format_from_filename("old.CRYPT") == DocumentFormat.JSON
    assert get_document_format_from_filename(Path("some/dir.cbor/x.Crypt.Cbor")) == DocumentFormat.CBOR
    assert get_document_format_from_filename("x.crypt.cbor~") is None
    assert get_document_format_from_filename("01_simple.cryptoconf") is None


def test_document_format_detection():
    json_bytes = dump_to_json_bytes({"a": 1})
    cbor_bytes = dump_to_cbor_bytes({"a": 1})

    assert detect_document_format(json_bytes) == DocumentFormat.JSON
    assert detect_document_format(b"\xef\xbb\xbf \r\n\t[1]") == DocumentFormat.JSON  # BOM and whitespace
    assert detect_document_format(cbor_bytes) == DocumentFormat.CBOR
    assert detect_document_format(b"\x80") == DocumentFormat.CBOR
    assert detect_document_format(b"\xd9\xd9\xf7\xa0") == DocumentFormat.CBOR  # Self-described CBOR prefix
    for undetectable in [b"", b"   ", b"\x01", b"\xc0", b"\xd9\x01\x02", b"abc", b"\xef\xbb\xbf"]:
        with pytest.raises(DocumentFormatError, match="couldn't be detected"):
            detect_document_format(undetectable)

    assert detect_document_format(json_bytes, filename="01_simple.cryptoconf") == DocumentFormat.JSON
    assert detect_document_format(cbor_bytes, filename="x.crypt.cbor~") == DocumentFormat.CBOR
    assert detect_document_format(b"garbage", filename="x.json") == DocumentFormat.JSON  # Parser will complain

    with pytest.raises(DocumentFormatError, match=r"'conf.json' should be Extended JSON .* looks like WA-CBOR"):
        detect_document_format(cbor_bytes, filename="conf.json")
    with pytest.raises(DocumentFormatError, match=r"'old.crypt' should be Extended JSON"):
        detect_document_format(cbor_bytes, filename="old.crypt")
    with pytest.raises(DocumentFormatError, match=r"'conf.CBOR' should be WA-CBOR .* looks like Extended JSON"):
        detect_document_format(json_bytes, filename="conf.CBOR")

    # STDIN-like streams, without names
    assert load_from_document_bytes(cbor_bytes) == {"a": 1}
    assert load_from_document_bytes(json_bytes) == {"a": 1}
    assert load_from_document_bytes(cbor_bytes, format=DocumentFormat.CBOR, filename="x.json") == {"a": 1}
    with pytest.raises(ValueError, match="Unknown document format"):
        load_from_document_bytes(cbor_bytes, format="yaml")


def test_document_file_api(tmp_path):
    cryptoconf = {"payload_cipher_layers": [{"payload_cipher_algo": "AES_CBC", "key_cipher_layers": []}]}

    # Dump a file in the format of its extension
    cbor_file = tmp_path / "conf.cbor"
    written_bytes = dump_to_document_file(cbor_file, cryptoconf)
    assert cbor_file.read_bytes() == written_bytes == dump_to_cbor_bytes(cryptoconf)
    assert load_from_document_file(cbor_file) == cryptoconf
    assert load_from_cbor_file(cbor_file) == cryptoconf

    json_file = tmp_path / "conf.json"
    dump_to_document_file(json_file, cryptoconf)
    assert json_file.read_bytes() == dump_to_json_bytes(cryptoconf)
    assert load_from_document_file(json_file) == cryptoconf

    # Explicit format, consistent with the extension or for names without extension
    dump_to_document_file(tmp_path / "conf2.cbor", cryptoconf, format=DocumentFormat.CBOR)
    dump_to_document_file(tmp_path / "01_simple.cryptoconf", cryptoconf, format=DocumentFormat.CBOR)
    assert load_from_document_file(tmp_path / "01_simple.cryptoconf") == cryptoconf  # Sniffed
    dump_to_document_file(tmp_path / "x.crypt.json", cryptoconf)
    assert (tmp_path / "x.crypt.json").read_bytes() == dump_to_json_bytes(cryptoconf)

    # Extension in another letter case, for reading and writing, at the exact path given
    upper_json_file = tmp_path / "CONF.JSON"
    upper_json_file.write_bytes(dump_to_json_bytes(cryptoconf))
    assert load_from_document_file(upper_json_file) == cryptoconf
    upper_cbor_file = tmp_path / "upper.CBOR"
    dump_to_document_file(upper_cbor_file, cryptoconf)
    assert "upper.CBOR" in os.listdir(tmp_path)
    assert upper_cbor_file.read_bytes() == dump_to_cbor_bytes(cryptoconf)

    # Mislabeled file refused
    mislabeled_file = tmp_path / "mislabeled.json"
    mislabeled_file.write_bytes(dump_to_cbor_bytes(cryptoconf))
    with pytest.raises(DocumentFormatError, match="mislabeled.json.*Extended JSON.*WA-CBOR"):
        load_from_document_file(mislabeled_file)

    # No format for a written file, or contradicting formats
    for filename, format in [("conf.data", None), ("old.crypt", None), ("conf3.cbor", DocumentFormat.JSON),
                             ("conf3.JSON", DocumentFormat.CBOR)]:
        with pytest.raises(DocumentFormatError):
            dump_to_document_file(tmp_path / filename, cryptoconf, format=format)
        assert not (tmp_path / filename).exists()
    with pytest.raises(ValueError, match="Unknown document format"):
        dump_to_document_file(tmp_path / "conf4.json", cryptoconf, format="yaml")
    assert not (tmp_path / "conf4.json").exists()

    assert dump_to_document_bytes(cryptoconf, format=DocumentFormat.JSON) == dump_to_json_bytes(cryptoconf)
    assert dump_to_document_bytes(cryptoconf, format=DocumentFormat.CBOR) == dump_to_cbor_bytes(cryptoconf)


def test_is_file_basename(tmp_path, monkeypatch):
    for name in ["report", "Notes.json", "video.mp4.crypt.json", "temp.crypt~", ".hidden", "a b"]:
        assert is_file_basename(name), name
    for name in ["", ".", "..", "dir/file", os.path.join("dir", "file"), "/file", "file/"]:
        assert not is_file_basename(name), name
    if sys.platform == "win32":
        for name in ["C:", "C:file", r"dir\file"]:
            assert not is_file_basename(name), name

    # Pure string check, whatever the files existing in the current directory
    monkeypatch.chdir(tmp_path)
    (tmp_path / "Notes.JSON").write_bytes(b"")
    (tmp_path / "subdir").mkdir()
    assert is_file_basename("Notes.json")
    assert is_file_basename("subdir")
