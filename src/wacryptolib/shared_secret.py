import logging
from typing import List, Sequence

from Crypto.Protocol.SecretSharing import Shamir

from wacryptolib.utilities import split_as_chunks, recombine_chunks

logger = logging.getLogger(__name__)

SHAMIR_CHUNK_LENGTH = 16


def split_bytestring_as_shamir_shards(secret: bytes, *, shares_count: int, threshold_count: int) -> list:
    """Generate a shared secret of `shares_count` subkeys, with `threshold_count`
        of them required to recompute the initial `bytestring`.

        :param secret: bytestring to separate as shards, whatever its length
        :param shares_count: the number of shards to be created for the secret
        :param threshold_count: the minimal number of shards needed to recombine the key

        :return: list of full bytestring shards"""

    if not shares_count:
        raise ValueError("shards count must be strictly positive")

    if threshold_count > shares_count:
        raise ValueError(
            "Threshold count %s can't be higher than shared count %s" % (threshold_count, shares_count)
        )

    all_chunk_shards = []  # List of lists of related 16-bytes shards

    # Split the secret into tuples of 16 bytes exactly (after padding)
    chunks = split_as_chunks(secret, chunk_size=SHAMIR_CHUNK_LENGTH, must_pad=True)

    # Separate each chunk into shard
    for chunk in chunks:
        shards = _split_128b_bytestring_into_shards(chunk, shares_count, threshold_count)
        all_chunk_shards.append(shards)
        del shards

    full_shards = []

    for idx in range(shares_count):
        assert all(
            chunk_shard[idx][0] == idx + 1 for chunk_shard in all_chunk_shards
        )  # By construction, shard indices start at 1
        idx_shards = (chunk_shard[idx][1] for chunk_shard in all_chunk_shards)
        complete_shard = b"".join(idx_shards)
        full_shards.append((idx + 1, complete_shard))

    return full_shards


def recombine_secret_from_shamir_shards(shards: Sequence) -> bytes:
    """Permits to reconstruct a key which has its secret shared
    into `shares_count` shards thanks to a list of `shards`

    :param shards: list of k full-length shards (k being exactly the threshold of this shared secret)

    :return: the key reconstructed as bytes"""

    shares_per_secret = []  # List of lists of same-index 16-bytes shards

    if len(set(shard[0] for shard in shards)) != len(shards):
        raise ValueError("Shamir shards must have unique indices")

    for shard in shards:
        idx, secret = shard
        chunks = split_as_chunks(secret, chunk_size=16, must_pad=False)
        shares_per_secret.append([(idx, chunk) for chunk in chunks])

    if len(set(len(chunks) for chunks in shares_per_secret)) != 1:
        raise ValueError("Shamir shard chunks must have the same length")

    all_chunk_shards = list(zip(*shares_per_secret))

    chunks = []
    for chunk_shards in all_chunk_shards:
        chunk = _recombine_128b_shards_into_bytestring(chunk_shards)
        chunks.append(chunk)

    secret = recombine_chunks(chunks, chunk_size=SHAMIR_CHUNK_LENGTH, must_unpad=True)

    return secret


def _split_128b_bytestring_into_shards(secret: bytes, shares_count: int, threshold_count: int) -> list:
    """Split a bytestring of exactly 128 bits into shards.

        :param bytestring: bytestring to split
        :param shares_count: number of shards to create
        :param threshold_count: number of shards needed to reconstitute the secret

        :return: list of tuples (index, shard)"""

    assert len(secret) == 16
    shards = Shamir.split(k=threshold_count, n=shares_count, secret=secret)
    assert len(shards) == shares_count, shards
    return shards


def _recombine_128b_shards_into_bytestring(shards: Sequence[tuple]) -> bytes:
    """Recombine shards of exactly 128 bits into a bytestring.

        :param bytestring: bytestring to split
        :param shares_count: number of shards to create
        :param threshold_count: number of shards needed to reconstitute the secret

        :return: list of tuples (index, shard)"""

    secret = Shamir.combine(shards)
    return secret
