import uuid

import pytest
from Crypto.Random import get_random_bytes

from wacryptolib.utilities import (
    split_as_chunks,
    recombine_chunks,
    dump_to_json_bytes,
    dump_to_json_str,
    load_from_json_bytes,
    load_from_json_str,
)


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

    chunks = split_as_chunks(
        bytestring, chunk_size=22, must_pad=False, accept_incomplete_chunk=True
    )
    assert not all(len(x) == 22 for x in chunks)
    result = recombine_chunks(chunks, chunk_size=22, must_unpad=False)
    assert result == bytestring


def test_serialization_utilities():

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

    serialized_str = dump_to_json_str(
        data, ensure_ascii=False
    )  # Json arguments well propagated
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

    serialized_str = dump_to_json_bytes(
        data, ensure_ascii=False
    )  # Json arguments well propagated
    assert (
        serialized_str
        == b'{"a": "h\xc3\xaallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "03"}}}'
    )
    deserialized = load_from_json_bytes(serialized_str)
    assert deserialized == data
