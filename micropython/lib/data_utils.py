# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later


from typing import Sequence


SHAMIR_CHUNK_LENGTH = 16


def do_split_secret_into_shards(secret: bytes, *, shard_count: int, threshold_count: int, shamir_128b_split_func) -> list:
    """Generate a Shamir shared secret of `shard_count` subkeys, with `threshold_count`
    of them required to recompute the initial `bytestring`.

    :param secret: bytestring to separate as shards, whatever its length
    :param shard_count: the number of shards to be created for the secret
    :param threshold_count: the minimal number of shards needed to recombine the key
    :param shamir_128b_split_func: the crypto utility to split a 16-bytes number into shards

    :return: list of full bytestring shards"""

    if not shard_count:
        raise ValueError("Shards count must be strictly positive")

    if threshold_count > shard_count:
        raise ValueError("Threshold count %s can't be higher than shared count %s" % (threshold_count, shard_count))

    all_chunk_shards = []  # List of lists of related 16-bytes shards

    # Split the secret into tuples of 16 bytes exactly (after padding)
    chunks = split_as_chunks(secret, chunk_size=SHAMIR_CHUNK_LENGTH, must_pad=True)

    # Separate each chunk into shard
    for chunk in chunks:
        assert len(chunk) == 16
        shards = shamir_128b_split_func(k=threshold_count, n=shard_count, secret=chunk)
        assert len(shards) == shard_count, shards
        all_chunk_shards.append(shards)
        del shards

    full_shards = []

    for idx in range(shard_count):
        assert all(
            chunk_shard[idx][0] == idx + 1 for chunk_shard in all_chunk_shards
        )  # By construction, shard indices start at 1
        idx_shards = (chunk_shard[idx][1] for chunk_shard in all_chunk_shards)
        complete_shard = recombine_chunks(idx_shards, chunk_size=SHAMIR_CHUNK_LENGTH,
                                             must_unpad=False)
        full_shards.append((idx + 1, complete_shard))

    return full_shards


def do_recombine_secret_from_shards(shards: Sequence, shamir_128b_recombine_func) -> bytes:
    """Reconstruct a secret from list of Shamir `shards`

    :param shards: list of k full-length shards (k being exactly the threshold of this shared secret)
    :param shamir_128b_recombine_func: the crypto utility to recombine shared into a 16-bytes number

    :return: the key reconstructed as bytes"""

    shards_per_secret = []  # List of lists of same-index 16-bytes shards

    if len(set(shard[0] for shard in shards)) != len(shards):
        raise ValueError("Shared secret shards must have unique indices")

    for shard in shards:
        idx, secret = shard
        chunks = split_as_chunks(secret, chunk_size=16, must_pad=False)
        shards_per_secret.append([(idx, chunk) for chunk in chunks])

    if len(set(len(chunks) for chunks in shards_per_secret)) != 1:
        raise ValueError("Shared secret shard chunks must have the same length")

    all_chunk_shards = list(zip(*shards_per_secret))

    chunks = []
    for chunk_shards in all_chunk_shards:
        chunk = shamir_128b_recombine_func(chunk_shards)
        chunks.append(chunk)

    secret = recombine_chunks(chunks, chunk_size=SHAMIR_CHUNK_LENGTH, must_unpad=True)

    return secret


def split_as_chunks(
    bytestring: bytes, *, chunk_size: int, must_pad: bool, accept_incomplete_chunk: bool = False) -> list[bytes]:
    """Split a `bytestring` into chunks (or blocks)

    :param bytestring: element to be split into chunks
    :param chunk_size: size of a chunk in bytes
    :param must_pad: whether the bytestring must be padded first or not
    :param accept_incomplete_chunk: do not raise error if a chunk with a length != chunk_size is obtained

    :return: list of bytes chunks"""

    assert chunk_size > 0, chunk_size

    if must_pad:
        bytestring = pad_bytes_pkcs7(bytestring, block_size=chunk_size)
    if len(bytestring) % chunk_size and not accept_incomplete_chunk:
        raise ValueError("If no padding occurs, bytestring must have a size multiple of chunk_size")

    chunks_count = (len(bytestring) + chunk_size - 1) // chunk_size

    chunks = []

    for i in range(chunks_count):
        chunk = bytestring[i * chunk_size : (i + 1) * chunk_size]
        chunks.append(chunk)
    return chunks


def recombine_chunks(chunks: Sequence[bytes], *, chunk_size: int, must_unpad: bool) -> bytes:
    """Recombine chunks which were previously separated.

    :param chunks: sequence of bytestring parts
    :param chunk_size: size of a chunk in bytes (only used for error checking, when unpadding occurs)
    :param must_unpad: whether the bytestring must be unpadded after recombining, or not

    :return: initial bytestring"""
    bytestring = b"".join(chunks)
    if must_unpad:
        bytestring = unpad_bytes_pkcs7(bytestring, block_size=chunk_size)
    return bytestring


def pad_bytes_pkcs7(data_to_pad, block_size):
    """Apply PKCS7 standard padding.

    Args:
      data_to_pad (byte string):
        The data that needs to be padded.
      block_size (integer):
        The block boundary to use for padding. The output length is guaranteed
        to be a multiple of :data:`block_size`.

    Return:
      byte string : the original data with the appropriate padding added at the end.
    """

    padding_len = block_size - len(data_to_pad) % block_size
    padding = bytes([padding_len]) * padding_len
    return data_to_pad + padding


def unpad_bytes_pkcs7(padded_data, block_size):
    """Remove PKCS7 standard padding.

    Args:
      padded_data (byte string):
        A piece of data with padding that needs to be stripped.
      block_size (integer):
        The block boundary to use for padding. The input length
        must be a multiple of :data:`block_size`.

    Return:
      byte string : data without padding.
    Raises:
      ValueError: if the padding is incorrect.
    """

    pdata_len = len(padded_data)

    if pdata_len == 0:
        raise ValueError("Zero-length input cannot be unpadded")

    if pdata_len % block_size:
        raise ValueError("Input data is not padded")

    padding_len = padded_data[-1]

    if padding_len < 1 or padding_len > min(block_size, pdata_len):
        raise ValueError("Padding is incorrect")

    if padded_data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("PKCS#7 padding is incorrect")

    return padded_data[:-padding_len]


