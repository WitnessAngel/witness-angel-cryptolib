from typing import List
import itertools

from Crypto.Protocol.SecretSharing import Shamir

from wacryptolib.utilities import split_as_padded_chunks, unpad_last_element


def split_bytestring_into_shares(
    key: bytes, shares_count: int, threshold_count: int
) -> List[tuple]:
    """Split a bytestring corresponding to a `key` into `shares_count` shares and which
        can be recombined with a threshold of `threshold_count`

        :param key: key to split
        :param shares_count: number of shares
        :param threshold_count: threshold of shares needed to recombine them

        :return: list with the `shares_count` tuples of shares."""

    shares = Shamir.split(threshold_count, shares_count, secret=key)  # Spliting the key
    assert len(shares) == shares_count, shares
    return shares


def recombine_shares_into_bytestring(shares: List[bytes]) -> List[bytes]:
    """Recombine a bytestring from a list of bytes corresponding
        to the `shares` of a key. In the `shares` list, it is possible
        to have shares which doesn't come from the same initial message.

        :param shares: list of tuples composed of the share and its corresponding number

        :return: list of bytes with all the shares recombined."""

    combined_shares_list = []
    for slices in range(0, len(shares)):
        combined_share = Shamir.combine(shares[slices])
        combined_shares_list.append(combined_share)
    return combined_shares_list


def generate_shared_secret_key(
    private_key: bytes, public_key: bytes, shares_count: int, threshold_count: int
) -> dict:
    """Generate a shared secret of `shares_count` keys, where `threshold_count`
        of them are required to recompute the private key corresponding to the public key.

        :param public_key: a public key as bytes
        :param private_key: a private key as bytes
        :param shares_count: the number of shares that there will be in the shared secret
        :param threshold_count: the minimal number of shares needed to recombine the key

        :return: "public_key" as bytes, and "shares" as a list of bytes."""

    # FOR testing: use 'with pytest.raises(ValueError, match="the threshold .* must be strictly...."):'
    assert threshold_count < shares_count, (threshold_count, shares_count)
    all_shares = []
    keys_info = {}

    # Split the private key into N tuples of 16 bytes in order to split each of them into shares
    # and add the value 0 at the end of the last tuple if there is not enough values to have 16 bytes
    split_prkey = split_as_padded_chunks(private_key, 16)
    chunks = tuple(split_prkey)

    # Split the chunks into share
    for chunk in chunks:
        chunk = bytes(itertools.chain(chunk))
        shares = split_bytestring_into_shares(chunk, shares_count, threshold_count)
        all_shares.append(shares)

    all_shares = list(itertools.chain(*all_shares))

    keys_info["public_key"] = public_key
    keys_info["shares"] = all_shares
    return keys_info


def reconstruct_shared_secret_key(shares: List, shares_count: int) -> bytes:
    """Permits to reconstruct a key which has its secret shared
    into `shares_count` shares thanks to a list of `shares`

    :param shares_count: the number of shares
    :param shares: a list of tuple of shares

    :return: the key reconstructed as bytes"""

    shares = split_as_padded_chunks(shares, shares_count)
    combined_shares = recombine_shares_into_bytestring(shares)
    unpadded_combined_shares = unpad_last_element(combined_shares)
    key_reconstructed = b"".join(unpadded_combined_shares)
    return key_reconstructed
