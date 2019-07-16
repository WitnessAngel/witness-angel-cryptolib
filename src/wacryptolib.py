import uuid
import itertools

from Crypto.PublicKey import RSA
from Crypto.PublicKey import DSA
from Crypto.PublicKey import ECC

from Crypto.Protocol.SecretSharing import Shamir
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Util.Padding import pad, unpad
from typing import List


def generate_rsa_keypair(uid: uuid.UUID, key_length: int = 2048) -> dict:
    """Generate a RSA (public_key, private_key) pair for a user ID.
    Result has fields "public_key" and "private_key" as bytes."""
    del uid
    if key_length < 1024:
        raise ValueError("The key lenght must be superior to 1024 bits")
    keys = RSA.generate(key_length)  # Generate private key pair
    private_key = keys
    public_key = keys.publickey()  # Generate the corresponding public key

    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def generate_dsa_keypair(uid: uuid.UUID, key_length: int = 2048) -> dict:
    """Generate a DSA (public_key, private_key) pair for a user ID.
    Result has fields "public_key" and "private_key" as bytes.
    DSA keypair is not used for encryption/decryption, it is only
    for signing."""
    del uid
    if key_length != 1024 and key_length != 2048 and key_length != 3072:
        raise ValueError("The key length must 1024, 2048 or 3072")
    keys = DSA.generate(2048)  # Generate private key pair
    private_key = keys
    public_key = keys.publickey()  # Generate the corresponding public key

    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


# Quick-test and forget for now
def generate_ecc_keypair(uid: uuid.UUID) -> dict:
    """Generate an ECC (public_key, private_key) pair for a user ID.
        Result has fields "public_key" and "private_key" as bytes."""
    del uid
    keys = ECC.generate(curve="p256")  # Generate private key pair
    private_key = keys
    public_key = keys.public_key()  # Generate the corresponding public key

    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def split_bytestring_into_shares(key: bytes, shares_count: int, threshold_count: int):
    shares = Shamir.split(threshold_count, shares_count, secret=key)  # Spliting the key
    assert len(shares) == shares_count, shares
    return shares


def recombine_shares_into_bytestring(shares: List[bytes]):
    combined_shares_list = []
    for slices in range(0, len(shares)):
        combined_share = Shamir.combine(shares[slices])
        combined_shares_list.append(combined_share)
    pass
    return combined_shares_list


def unpad_last_element(list: List[bytes]):
    last_element = len(list)-1
    list[last_element] = unpad(list[last_element], 16)
    return list


def generate_shared_secret_key(uid: uuid.UUID, shares_count: int, threshold_count: int) -> dict:
    """Generate a shared secret of `keys_count` keys, where `threshold_count`
        of them are required to recompute the private key corresponding to the public key.
        Result has fields "public_key" as bytes, and "shares" as a list of bytes."""

    # FOR testing: use 'with pytest.raises(ValueError, match="the threshold .* must be strictly...."):'
    assert threshold_count < shares_count, (threshold_count, shares_count)
    all_shares = []
    keys_info = {}
    keypair = generate_rsa_keypair(uid)
    private_key = RsaKey.export_key(keypair["private_key"])
    public_key = keypair["public_key"]

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

    # shares doit devenir une liste de "shares" complète (bytestring), cf ZIP and b"".join()
    keys_info["public_key"] = public_key
    keys_info["shares"] = all_shares
    return keys_info


def split_as_padded_chunks(bytestring, chunk_size):
    """Collect data into fixed-length chunks or blocks and pad the last chunk
    when there isn't enough values initially"""

    chunks = []
    for i in range((len(bytestring) + chunk_size - 1) // chunk_size):
        chunk = [bytestring[i * chunk_size:(i + 1) * chunk_size]]
        if len(chunk[0]) != chunk_size:
            chunks.append(pad(chunk[0], chunk_size))
        else:
            chunks.append(chunk[0])
    return chunks
