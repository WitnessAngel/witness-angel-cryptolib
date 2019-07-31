import uuid

from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Random.random import getrandbits


def generate_public_key(uid: uuid.UUID, key_type: str, key_length=2048, curve="p256"):
    key_generator = dict(
        RSA={"function": generate_rsa_keypair, "parameter": key_length},
        DSA={"function": generate_dsa_keypair, "parameter": key_length},
        ECC={"function": generate_ecc_keypair, "parameter": curve},
    )

    generation_func = key_generator[key_type]["function"]
    parameter = key_generator[key_type]["parameter"]
    keypair = generation_func(uid, parameter)

    return keypair


def generate_rsa_keypair_as_pem(uid: uuid.UUID, key_length: int = 2048):
    """Generate a rsa (public_key, private_key) pair in PEM format

    :param uid: ID of the user
    :param key_length: length of the key in bits, must be superior to 1024.

    :return: dictionary with public and private keys in PEM format"""
    keypair = generate_rsa_keypair(uid=uid, key_length=key_length)
    private_key = _serialize_rsa_key_objects_to_pem(keypair["private_key"])
    public_key = _serialize_rsa_key_objects_to_pem(keypair["public_key"])
    pem_keypair = {"private_key": private_key, "public_key": public_key}
    return pem_keypair


def generate_rsa_keypair(uid: uuid.UUID, key_length: int = 2048) -> dict:
    """Generate a RSA (public_key, private_key) pair for a user ID of a
        length `key_length` in bits which must be superior to 1024.

        :param uid: ID of the user
        :param key_length: Length of the key in bits

        :return: "public_key" and "private_key" as RsaKey."""

    if key_length < 1024:
        raise ValueError("The key length must be superior to 1024 bits")

    randfunc = None
    # if uid:
    #     randfunc = random_function(uid)
    key = RSA.generate(key_length, randfunc=randfunc)  # Generate private key pair
    public_key = key.publickey()  # Generate the corresponding public key

    keypair = {"public_key": public_key, "private_key": key}
    return keypair


def _serialize_rsa_key_objects_to_pem(key: RSA.RsaKey):
    """Generate a keypair of bytes from a keypair as RsaKey objects

    :param key: key to serialize in RSA key
    :return: dict of RSA keypair as bytes"""

    key = RSA.RsaKey.export_key(key, format="PEM")
    return key


def generate_dsa_keypair_as_pem(uid: uuid.UUID, key_length: int = 2048):
    """Generate a DSA (public_key, private_key) pair in PEM format

    :param uid: ID of the user
    :param key_length: length of the key in bits, must be superior to 1024.

    :return: dictionary with public and private keys in PEM format"""

    keypair = generate_dsa_keypair(uid=uid, key_length=key_length)
    private_key = _serialize_dsa_key_objects_to_pem(keypair["private_key"])
    public_key = _serialize_dsa_key_objects_to_pem(keypair["public_key"])
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

    randfunc = None
    # if uid:
    #     randfunc = random_function(uid=uid)
    key = DSA.generate(key_length, randfunc=randfunc)  # Generate private key pair
    public_key = key.publickey()  # Generate the corresponding public key
    keypair = {"public_key": public_key, "private_key": key}

    return keypair


def _serialize_dsa_key_objects_to_pem(key: DSA.DsaKey):
    """Generate a keypair of bytes from a keypair as DsaKey objects

    :param key: key to serialize in DSA key
    :return: dict of DSA keypair as bytes"""

    key = DSA.DsaKey.export_key(key, format="PEM")
    return key


def generate_ecc_keypair_as_pem(uid: uuid.UUID, curve: str = "p256"):
    """Generate an ECC (public_key, private_key) pair in PEM format

    :param curve: curve chosen among p256, p384, p521
    :param uid: ID of the user

    :return: dictionary with public and private ECC keys in PEM format"""

    keypair = generate_ecc_keypair(uid=uid, curve=curve)
    private_key = _serialize_ecc_key_objects_to_pem(keypair["private_key"])
    public_key = _serialize_ecc_key_objects_to_pem(keypair["public_key"])
    pem_keypair = {"private_key": private_key, "public_key": public_key}
    return pem_keypair


def generate_ecc_keypair(uid: uuid.UUID, curve: str = "p256") -> dict:
    """Generate an ECC (public_key, private_key) pair for a user ID according
    to a curve; see https://tools.ietf.org/html/rfc6637.

    :param uid: ID of the user
    :param curve: curve chosen among p256, p384 and p521

    :return: "public_key" and "private_key" as bytes."""

    randfunc = None
    # if uid:
    #     randfunc = random_function(uid=uid)
    key = ECC.generate(curve=curve, randfunc=randfunc)  # Generate private key pair
    public_key = key.public_key()  # Generate the corresponding public key

    keypair = {"public_key": public_key, "private_key": key}
    return keypair


def _serialize_ecc_key_objects_to_pem(key: ECC.EccKey):
    """Generate a keypair of bytes from a keypair as EccKey objects

    :return: dict of ECC keypair as bytes
    :param key: key to serialize in ECC key"""

    key = ECC.EccKey.export_key(key, format="PEM")
    return key


# def _get_randfunc(uid: uuid.UUID):
#     import random
#     import os
#
#     random.SystemRandom(uid.int)
#     randfunc = os.urandom
#     # randfunc = random_instance.getrandbits(128)
#     # print(randfunc)
#     return randfunc

def random_function(uid: uuid.UUID):
    from Crypto.Hash import SHA256
    hash_obj = SHA256.new(uid.bytes)
    hash_obj2 = SHA256.new(hash_obj.digest())
    hash_obj3 = SHA256.new(hash_obj2.digest())
    print(type(hash_obj3))
    return hash_obj3.digest()
