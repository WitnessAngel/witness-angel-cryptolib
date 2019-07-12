import uuid
import itertools

from Crypto.PublicKey import RSA
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.PublicKey.RSA import RsaKey


def generate_RSA_keypair(uid: uuid.UUID) -> dict:
    """Generate a (public_key, private_key) pair for a user ID.
    Result has fields "public_key" and "private_key" as bytes."""
    del uid
    keys = RSA.generate(2048)  # Generate private key pair
    private_key = keys
    public_key = keys.publickey()  # Generate the corresponding public key

    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def generate_private_key_shared_secret(uid: uuid.UUID, shares_count: int, threshold_count: int) -> dict:
    """Generate a shared secret of `keys_count` keys, where `threshold_count`
        of them are required to recompute the private key corresponding to the public key.
        Result has fields "public_key" as bytes, and "shares" as a list of bytes."""

    try:
        # FOR testing: use 'with pytest.raises(ValueError, match="the threshold .* must be strictly...."):'
        assert threshold_count < shares_count, (threshold_count, shares_count)
        shares_list = []
        public_key_shares = {}

        keypair = generate_RSA_keypair(uid)
        public_key = RsaKey.export_key(keypair["public_key"])
        private_key = RsaKey.export_key(keypair["private_key"])

        # Split the private key into N tuples of 16 bytes in order to split each of them into shares
        # and add the value 0 at the end of the last tuple if there is not enough values to have 16 bytes
        split_prkey = grouper(private_key, 16, 0)
        chunks = tuple(split_prkey)  ##chunks

        # Split the tuple corresponding to the private key into shares
        for chunk in chunks:
            chunk = bytes(itertools.chain(chunk)) #FIXME
            shares = Shamir.split(threshold_count, shares_count, secret=chunk)  # Spliting the key
            assert len(shares) == shares_count
            shares_list.append(shares)

        # shares doit devenir une liste de "shares" complète (bytestring), cf ZIP and b"".join()

        public_key_shares["public_key"] = public_key
        public_key_shares["shares"] = shares_list
        return public_key_shares

    except AssertionError:
        print("Not enough keys count")
        raise


def grouper(iterable, n, fillvalue=None):
    """Collect data into fixed-length chunks or blocks"""

    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=fillvalue)  # de-lazify all --> tuple of bytes
