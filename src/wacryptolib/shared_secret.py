from typing import List
import itertools

from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Util.Padding import unpad

from wacryptolib.utilities import split_as_padded_chunks


def split_bytestring_as_shamir_shares(
    bytestring: bytes, shares_count: int, threshold_count: int
) -> dict:
    """Generate a shared secret of `shares_count` keys, where `threshold_count`
        of them are required to recompute the initial `bytestring`.

        :param bytestring: bytestring to split, no matter its length
        :param shares_count: the number of shares that there will be in the shared secret
        :param threshold_count: the minimal number of shares needed to recombine the key

        :return: a list of bytes with all shares"""

    # FOR testing: use 'with pytest.raises(ValueError, match="the threshold .* must be strictly...."):'
    assert threshold_count < shares_count, (threshold_count, shares_count)
    all_shares = []

    # Split the private key into N tuples of 16 bytes in order to split each of them into shares
    # and add the value 0 at the end of the last tuple if there is not enough values to have 16 bytes
    chunks = split_as_padded_chunks(bytestring, 16)

    # Split the chunks into share
    for chunk in chunks:
        shares = _split_128b_bytestring_into_shares(chunk, shares_count, threshold_count)
        all_shares.append(shares)

    all_shares = list(itertools.chain(*all_shares))
    return all_shares  # FIXME, this func must return 3 long bytestrings, each with all the shares of index i


def reconstruct_bytestring(shares: List, shares_count: int, bytestring_length: int) -> bytes:
    """Permits to reconstruct a key which has its secret shared
    into `shares_count` shares thanks to a list of `shares`

    :param length: length of the bytestring to reconstruct
    :param shares_count: number of shares
    :param shares: a list of tuple of shares

    :return: the key reconstructed as bytes"""

    shares = split_as_padded_chunks(shares, shares_count)
    combined_shares = _recombine_shares_into_list(shares)
    if bytestring_length % 16 != 0:
        combined_shares[-1] = unpad(combined_shares[-1], 16)
    bytestring_reconstructed = b"".join(combined_shares)
    return bytestring_reconstructed


def _split_128b_bytestring_into_shares(
    bytestring: bytes, shares_count: int, threshold_count: int
) -> List[tuple]:
    """Split a bytestring with a maximum length of 128 bits into `shares_count`
        shares and which can be recombined with a threshold of `threshold_count`

        :param bytestring: bytestring to split
        :param shares_count: number of shares
        :param threshold_count: threshold of shares needed to recombine them

        :return: list with the `shares_count` tuples of shares."""

    shares = Shamir.split(threshold_count, shares_count, secret=bytestring)  # Splitting the key
    assert len(shares) == shares_count, shares
    return shares


def _recombine_shares_into_list(shares: List[bytes]) -> List[bytes]:
    """Recombine shares from a list of bytes corresponding
        to the `shares` of a bytestring. In the `shares` list, it is possible
        to have shares which doesn't come from the same initial message.

        :param shares: list of tuples composed of the share and its corresponding number

        :return: list of bytes with all the shares recombined."""

    combined_shares_list = []
    for slices in range(0, len(shares)):
        combined_share = Shamir.combine(shares[slices])
        combined_shares_list.append(combined_share)
    return combined_shares_list
