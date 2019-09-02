import pytest
from Crypto.Random import get_random_bytes

from wacryptolib.utilities import split_as_chunks, recombine_chunks


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
