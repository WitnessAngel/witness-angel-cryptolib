import uuid

from Crypto.PublicKey import RSA, DSA, ECC


def generate_rsa_keypair(uid: uuid.UUID, key_length: int = 2048) -> dict:
    """Generate a RSA (public_key, private_key) pair for a user ID of a
        length in bits `key_length`.

        :param uid: ID of the user
        :param key_length: Length of the key in bits

        :return: "public_key" and "private_key" as bytes."""

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
        for signing.

        :param uid: ID of the user
        :param key_length: Length of the key in bits. May be 1024, 2048 or 3072

        :return: "public_key" and "private_key" as bytes."""

    del uid
    keys = DSA.generate(key_length)  # Generate private key pair
    private_key = keys
    public_key = keys.publickey()  # Generate the corresponding public key

    keypair = {"public_key": public_key, "private_key": private_key}

    return keypair


def generate_ecc_keypair(uid: uuid.UUID, curve: str) -> dict:
    """Generate an ECC (public_key, private_key) pair for a user ID according
        to a curve `curve` that can be chosen between "p256", "p384" and "p521".

        :param uid: ID of the user
        :param curve: curve chosen among p256, p384 and p521

        :return: "public_key" and "private_key" as bytes."""

    del uid
    keys = ECC.generate(curve=curve)  # Generate private key pair
    private_key = keys
    public_key = keys.public_key()  # Generate the corresponding public key

    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def rsakey_to_bytes(keypair):
    """Permits to export a pair of RsaKey to two bytestrings

    :param keypair: dictionary composed of : {"public_key" = RsaKey, "private_key" = RsaKey}

    :return: public and private keys in bytes"""

    public_key = RSA.RsaKey.export_key(keypair["public_key"])
    private_key = RSA.RsaKey.export_key(keypair["private_key"])
    return public_key, private_key
