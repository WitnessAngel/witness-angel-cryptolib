from typing import List

from Crypto.Util.Padding import pad


def split_as_chunks(
    bytestring: bytes, chunk_size: int, must_pad: bool, accept_incomplete_chunk=False
) -> List[bytes]:
    """Split a `bytestring` into chunks (or blocks) of identical sizes, after padding it.

        :param bytestring: element to be split into chunks
        :param chunk_size: size of a chunk in bytes
        :param must_pad: whether the bytestring must be padded (else, its size must be a multiple of chunk_size)

        :return: list of bytes chunks"""

    assert chunk_size > 0, chunk_size

    if must_pad:
        bytestring = pad(bytestring, block_size=chunk_size)
    if len(bytestring) % chunk_size and not accept_incomplete_chunk:
        raise ValueError(
            "If no padding occurs, bytestring must have a size multiple of chunk_size"
        )

    chunks_count = (len(bytestring) + chunk_size - 1) // chunk_size

    chunks = []

    for i in range(chunks_count):
        chunk = bytestring[i * chunk_size : (i + 1) * chunk_size]
        chunks.append(chunk)
    return chunks
