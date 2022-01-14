import logging
from typing import Sequence

from Crypto.Protocol.SecretSharing import Shamir

from wacryptolib.utilities import split_as_chunks, recombine_chunks

logger = logging.getLogger(__name__)

SHAMIR_CHUNK_LENGTH = 16


def split_secret_into_shards(secret: bytes, *, shard_count: int, threshold_count: int) -> list:
    """Generate a Shamir shared secret of `shard_count` subkeys, with `threshold_count`
        of them required to recompute the initial `bytestring`.

        :param secret: bytestring to separate as shards, whatever its length
        :param shard_count: the number of shards to be created for the secret
        :param threshold_count: the minimal number of shards needed to recombine the key

        :return: list of full bytestring shards"""

    if not shard_count:
        raise ValueError("shards count must be strictly positive")

    if threshold_count > shard_count:
        raise ValueError("Threshold count %s can't be higher than shared count %s" % (threshold_count, shard_count))

    all_chunk_shards = []  # List of lists of related 16-bytes shards

    # Split the secret into tuples of 16 bytes exactly (after padding)
    chunks = split_as_chunks(secret, chunk_size=SHAMIR_CHUNK_LENGTH, must_pad=True)

    # Separate each chunk into shard
    for chunk in chunks:
        shards = _split_128b_bytestring_into_shards(chunk, shard_count, threshold_count)
        all_chunk_shards.append(shards)
        del shards

    full_shards = []

    for idx in range(shard_count):
        assert all(
            chunk_shard[idx][0] == idx + 1 for chunk_shard in all_chunk_shards
        )  # By construction, shard indices start at 1
        idx_shards = (chunk_shard[idx][1] for chunk_shard in all_chunk_shards)
        complete_shard = b"".join(idx_shards)
        full_shards.append((idx + 1, complete_shard))

    return full_shards


def recombine_secret_from_shards(shards: Sequence) -> bytes:
    """Reconstruct a secret from list of Shamir `shards`

    :param shards: list of k full-length shards (k being exactly the threshold of this shared secret)

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
        chunk = _recombine_128b_shards_into_bytestring(chunk_shards)
        chunks.append(chunk)

    secret = recombine_chunks(chunks, chunk_size=SHAMIR_CHUNK_LENGTH, must_unpad=True)

    return secret


def _split_128b_bytestring_into_shards(secret: bytes, shard_count: int, threshold_count: int) -> list:
    """Split a bytestring of exactly 128 bits into shards.

        :param secret: bytestring to split
        :param shard_count: number of shards to create
        :param threshold_count: number of shards needed to reconstitute the secret

        :return: list of tuples (index, shard)"""

    assert len(secret) == 16
    shards = Shamir.split(k=threshold_count, n=shard_count, secret=secret)
    assert len(shards) == shard_count, shards
    return shards


def _recombine_128b_shards_into_bytestring(shards: Sequence[tuple]) -> bytes:
    """Recombine shards of exactly 128 bits into a bytestring.

        :param shards: list of (index, shard) tuples

        :return: list of tuples (index, shard)"""

    secret = Shamir.combine(shards)
    return secret
