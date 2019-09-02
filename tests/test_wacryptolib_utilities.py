from datetime import datetime

import pytest

import uuid

from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

import wacryptolib
from wacryptolib.utilities import split_as_chunks


def test_split_as_chunks():

    bytestring = get_random_bytes(100)

    chunks = split_as_chunks(bytestring, chunk_size=25, must_pad=True)
    assert all(len(x) == 25 for x in chunks)
    assert unpad(b"".join(chunks), block_size=25) == bytestring

    chunks = split_as_chunks(bytestring, chunk_size=22, must_pad=True)
    assert all(len(x) == 22 for x in chunks)
    assert unpad(b"".join(chunks), block_size=22) == bytestring

    chunks = split_as_chunks(bytestring, chunk_size=25, must_pad=False)
    assert all(len(x) == 25 for x in chunks)
    assert b"".join(chunks) == bytestring

    with pytest.raises(ValueError, match="size multiple of chunk_size"):
        split_as_chunks(bytestring, chunk_size=22, must_pad=False)

    chunks = split_as_chunks(bytestring, chunk_size=22, must_pad=False, accept_incomplete_chunk=True)
    assert not all(len(x) == 22 for x in chunks)
    assert b"".join(chunks) == bytestring
