import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytz
from Crypto.Random import get_random_bytes

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
    SUPPORTED_HASH_ALGOS,
    hash_message,
    safe_copy_directory,
)


def test_check_datetime_is_tz_aware():
    with pytest.raises(ValueError):
        check_datetime_is_tz_aware(datetime.now())
    check_datetime_is_tz_aware(datetime.now(tz=timezone.utc))


def test_hash_message():

    bytestring = get_random_bytes(1000)

    assert len(SUPPORTED_HASH_ALGOS) == 4  # For now

    for hash_algo in SUPPORTED_HASH_ALGOS:
        digest1 = hash_message(bytestring, hash_algo=hash_algo)
        assert 32 <= len(digest1) <= 64, len(digest1)
        digest2 = hash_message(bytestring, hash_algo=hash_algo)
        assert digest1 == digest2

    with pytest.raises(ValueError, match="Unsupported"):
        hash_message(bytestring, hash_algo="XYZ")


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
    data = dict(b=b"xyz", a="hêllo", c=uid)

    serialized_str = dump_to_json_str(data)
    # Keys are sorted
    assert (
        serialized_str
        == r'{"a": "h\u00eallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "03"}}}'
    )
    deserialized = load_from_json_str(serialized_str)
    assert deserialized == data

    serialized_str = dump_to_json_str(data, ensure_ascii=False)  # Json arguments well propagated
    assert (
        serialized_str
        == r'{"a": "hêllo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "03"}}}'
    )
    deserialized = load_from_json_str(serialized_str)
    assert deserialized == data

    serialized_str = dump_to_json_bytes(data)
    # Keys are sorted
    assert (
        serialized_str
        == rb'{"a": "h\u00eallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "03"}}}'
    )
    deserialized = load_from_json_bytes(serialized_str)
    assert deserialized == data

    serialized_str = dump_to_json_bytes(data, ensure_ascii=False)  # Json arguments well propagated
    assert (
        serialized_str
        == b'{"a": "h\xc3\xaallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "03"}}}'
    )
    deserialized = load_from_json_bytes(serialized_str)
    assert deserialized == data

    tmp_filepath = os.path.join(tmp_path, "dummy_temp_file.dat")
    serialized_str = dump_to_json_file(tmp_filepath, data=data, ensure_ascii=True)  # Json arguments well propagated
    assert (
        serialized_str
        == b'{"a": "h\u00eallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "03"}}}'
    )
    deserialized = load_from_json_file(tmp_filepath)
    assert deserialized == data


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


def test_safe_copy_directory(tmp_path: Path):

    src = tmp_path / "src"
    src.mkdir()

    existing = tmp_path / "dst"
    existing.mkdir()

    for i in range(10):
        (src / str(i)).touch()

    with pytest.raises(FileExistsError):
        safe_copy_directory(src, existing)  # Target dir must not exists

    safe_copy_directory(src, tmp_path / "__target")
    (tmp_path / "__target" / "whatever").touch()

    safe_copy_directory(src, tmp_path / "target")
    assert not (tmp_path / "__target").exists()
    assert not (tmp_path / "target" / "whatever").touch()  # Temp dir well deleted BEFORE copy operation

    counter = 0

    def broken_copy(*args, **kwargs):
        nonlocal counter
        if counter < 2:
            counter += 1
            return shutil.copy2(*args, **kwargs)
        raise RuntimeError("Dummy breakage of copy operation")

    with pytest.raises(RuntimeError):
        safe_copy_directory(src, tmp_path / "other_target", copy_function=broken_copy)
    assert not (tmp_path / "__other_target").exists()
    assert not (tmp_path / "other_target").exists()  # Good cleanup

    safe_copy_directory(src, tmp_path / "other_target")
    assert not (tmp_path / "__other_target").exists()
    assert (tmp_path / "other_target").exists()
    assert set(i.name for i in (tmp_path / "other_target").iterdir()) == set(str(i) for i in range(10))
