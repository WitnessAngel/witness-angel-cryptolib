import logging
from typing import List

from Crypto.Protocol.SecretSharing import Shamir

from wacryptolib.utilities import split_as_chunks, recombine_chunks

logger = logging.getLogger(__name__)

SHAMIR_CHUNK_LENGTH = 16


def split_bytestring_as_shamir_shares(secret: bytes, *, shares_count: int, threshold_count: int) -> list:
    """Generate a shared secret of `shares_count` subkeys, with `threshold_count`
        of them required to recompute the initial `bytestring`.

        :param secret: bytestring to separate as shares, whatever its length
        :param shares_count: the number of shares to be created for the secret
        :param threshold_count: the minimal number of shares needed to recombine the key

        :return: list of full bytestring shares"""

    if not (threshold_count < shares_count):
        raise ValueError(
            "Threshold count %s must be strictly lower than shared count %s" % (threshold_count, shares_count)
        )

    all_chunk_shares = []  # List of lists of related 16-bytes shares

    # Split the secret into tuples of 16 bytes exactly (after padding)
    chunks = split_as_chunks(secret, chunk_size=SHAMIR_CHUNK_LENGTH, must_pad=True)

    # Separate each chunk into share
    for chunk in chunks:
        shares = _split_128b_bytestring_into_shares(chunk, shares_count, threshold_count)
        all_chunk_shares.append(shares)
        del shares

    full_shares = []

    for idx in range(shares_count):
        assert all(
            chunk_share[idx][0] == idx + 1 for chunk_share in all_chunk_shares
        )  # By construction, share indices start at 1
        idx_shares = (chunk_share[idx][1] for chunk_share in all_chunk_shares)
        complete_share = b"".join(idx_shares)
        full_shares.append((idx + 1, complete_share))

    return full_shares


def recombine_secret_from_shamir_shares(shares: list) -> bytes:
    """Permits to reconstruct a key which has its secret shared
    into `shares_count` shares thanks to a list of `shares`

    :param shares: list of k full-length shares (k being exactly the threshold of this shared secret)

    :return: the key reconstructed as bytes"""

    shares_per_secret = []  # List of lists of same-index 16-bytes shares

    if len(set(share[0] for share in shares)) != len(shares):
        raise ValueError("Shamir shares must have unique indices")

    for share in shares:
        idx, secret = share
        chunks = split_as_chunks(secret, chunk_size=16, must_pad=False)
        shares_per_secret.append([(idx, chunk) for chunk in chunks])

    if len(set(len(chunks) for chunks in shares_per_secret)) != 1:
        raise ValueError("Shamir share chunks must have the same length")

    all_chunk_shares = list(zip(*shares_per_secret))

    chunks = []
    for chunk_shares in all_chunk_shares:
        chunk = _recombine_128b_shares_into_bytestring(chunk_shares)
        chunks.append(chunk)

    secret = recombine_chunks(chunks, chunk_size=SHAMIR_CHUNK_LENGTH, must_unpad=True)

    return secret


def _split_128b_bytestring_into_shares(secret: bytes, shares_count: int, threshold_count: int) -> list:
    """Split a bytestring of exactly 128 bits into shares.

        :param bytestring: bytestring to split
        :param shares_count: number of shares to create
        :param threshold_count: number of shares needed to reconstitute the secret

        :return: list of tuples (index, share)"""

    assert len(secret) == 16
    shares = Shamir.split(k=threshold_count, n=shares_count, secret=secret)
    assert len(shares) == shares_count, shares
    return shares


def _recombine_128b_shares_into_bytestring(shares: List[tuple]) -> bytes:
    """Recombine shares of exactly 128 bits into a bytestring.

        :param bytestring: bytestring to split
        :param shares_count: number of shares to create
        :param threshold_count: number of shares needed to reconstitute the secret

        :return: list of tuples (index, share)"""

    secret = Shamir.combine(shares)
    return secret
