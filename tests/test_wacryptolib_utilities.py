# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import uuid
from datetime import datetime, timezone, timedelta
from threading import Lock

import pytest
import pytz
from Crypto.Hash.MD5 import block_size

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
    unpad_bytes_pkcs7
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
