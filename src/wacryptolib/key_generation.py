import uuid

from Crypto.PublicKey import RSA, DSA, ECC


def generate_rsa_keypair(uid: uuid.UUID, key_length: int = 2048) -> dict:
    """Generate a RSA (public_key, private_key) pair for a user ID of a
        length in bits `key_length` which must be superior to 1024.

        :param uid: ID of the user
        :param key_length: Length of the key in bits

        :return: "public_key" and "private_key" as RsaKey."""

    del uid
    if key_length < 1024:
        raise ValueError("The key length must be superior to 1024 bits")
    keys = RSA.generate(key_length)  # Generate private key pair
    private_key = keys
    public_key = keys.publickey()  # Generate the corresponding public key

    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def _generate_rsa_key_objects(keypair: bytes):
    """Generate a keypair of RsaKeys objects from a keypair of RSA keys in
    PEM format

    :param keypair: dictionary of public and private RSA keys in bytes
    :return: dict of RSA keypair as RsaKey objects"""

    public_key = RSA.import_key(keypair["public_key"])
    private_key = RSA.import_key(keypair["private_key"])
    rsa_keypair = {"private_key": private_key, "public_key": public_key}
    return rsa_keypair


def _serialize_rsa_key_objects_to_pem(keypair: dict):
    """Generate a keypair of bytes from a keypair as RsaKey objects

    :param keypair: dict of public and private RSA keys as RsaKey objects
    :return: dict of RSA keypair as bytes"""

    public_key = RSA.RsaKey.export_key(keypair["public_key"])
    private_key = RSA.RsaKey.export_key(keypair["private_key"])
    pem_keypair = {"private_key": private_key, "public_key": public_key}
    return pem_keypair


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


def _generate_dsa_key_objects(keypair: bytes):
    """Generate a keypair of DsaKeys objects from a keypair of DSA keys in
    PEM format

    :param keypair: dict of public and private DSA keys in bytes
    :return: dict of DSA keypair as DsaKey objects"""

    public_key = DSA.import_key(keypair["public_key"])
    private_key = DSA.import_key(keypair["private_key"])
    dsa_keypair = {"private_key": private_key, "public_key": public_key}
    return dsa_keypair


def _serialize_dsa_key_objects_to_pem(keypair: dict):
    """Generate a keypair of bytes from a keypair as DsaKey objects

    :param keypair: dict of public and private DSA keys as DsaKey objects
    :return: dict of DSA keypair as bytes"""

    public_key = DSA.DsaKey.export_key(keypair["public_key"])
    private_key = DSA.DsaKey.export_key(keypair["private_key"])
    pem_keypair = {"private_key": private_key, "public_key": public_key}
    return pem_keypair


def generate_ecc_keypair(uid: uuid.UUID, curve: str) -> dict:
    """Generate an ECC (public_key, private_key) pair for a user ID according
        to a curve; see https://tools.ietf.org/html/rfc6637.

        :param uid: ID of the user
        :param curve: curve chosen among p256, p384 and p521

        :return: "public_key" and "private_key" as bytes."""

    del uid
    keys = ECC.generate(curve=curve)  # Generate private key pair
    private_key = keys
    public_key = keys.public_key()  # Generate the corresponding public key

    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def _generate_ecc_key_objects(keypair: bytes):
    """Generate a keypair of EccKeys objects from a keypair of ECC keys in
    PEM format

    :param keypair: dict of public and private ECC keys in bytes
    :return: dict of ECC keypair as EccKey objects"""

    public_key = ECC.import_key(keypair["public_key"])
    private_key = ECC.import_key(keypair["private_key"])
    dsa_keypair = {"private_key": private_key, "public_key": public_key}
    return dsa_keypair


def _serialize_ecc_key_objects_to_pem(keypair: dict):
    """Generate a keypair of bytes from a keypair as EccKey objects

    :return: dict of ECC keypair as bytes
    :param keypair: dict of public and private ECC keys as EccKey objects"""

    public_key = ECC.EccKey.export_key(keypair["public_key"], format="PEM")
    private_key = ECC.EccKey.export_key(keypair["private_key"], format="PEM")
    pem_keypair = {"private_key": private_key, "public_key": public_key}
    return pem_keypair
