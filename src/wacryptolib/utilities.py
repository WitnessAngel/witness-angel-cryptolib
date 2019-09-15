from typing import List

from Crypto.Util.Padding import pad, unpad

DEFAULT_ENCODING = "utf8"


def split_as_chunks(
    bytestring: bytes,
    chunk_size: int,
    must_pad: bool,
    accept_incomplete_chunk: bool = False,
) -> List[bytes]:
    """Split a `bytestring` into chunks (or blocks)

        :param bytestring: element to be split into chunks
        :param chunk_size: size of a chunk in bytes
        :param must_pad: whether the bytestring must be padded first or not
        :param accept_incomplete_chunk: do not raise error if a chunk with a length != chunk_size is obtained

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


def recombine_chunks(chunks: List[bytes], chunk_size: int, must_unpad: bool) -> bytes:
    """Recombine chunks which were previously separated.

        :param chunks: sequence of bytestring parts
        :param chunk_size: size of a chunk in bytes (only used for error checking, when unpadding occurs)
        :param must_unpad: whether the bytestring must be unpadded after recombining, or not

        :return: initial bytestring"""
    bytestring = b"".join(chunks)
    if must_unpad:
        bytestring = unpad(bytestring, block_size=chunk_size)
    return bytestring


def dump_to_json_bytes(data, **extra_options):
    """
    Dump a data tree to a json representation in bytes.
    Supports advanced types like bytes, uuids, dates...
    """
    from bson.json_util import dumps, CANONICAL_JSON_OPTIONS

    json_str = dumps(
        data, sort_keys=True, json_options=CANONICAL_JSON_OPTIONS, **extra_options
    )
    return json_str.encode(DEFAULT_ENCODING)


def load_from_json_bytes(data, **extra_options):
    """
    Load a data tree from a json representation in bytes.
    Supports advanced types like bytes, uuids, dates...
    """
    from bson.json_util import loads, CANONICAL_JSON_OPTIONS

    assert isinstance(data, bytes), data
    json_str = data.decode(DEFAULT_ENCODING)
    return loads(json_str, json_options=CANONICAL_JSON_OPTIONS, **extra_options)
