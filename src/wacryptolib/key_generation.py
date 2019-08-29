import random
import uuid

from Crypto.PublicKey import RSA, DSA, ECC


def generate_asymmetric_keypair(
    uid: uuid.UUID, key_type: str, key_length=2048, curve="p256"
):
    """Generate a RSA (public_key, private_key) pair in PEM format.

    :param uid: UUID of the encryption operation
    :param key_length: length of the key in bits, must be superior to 1024.

    :return: dictionary with "private_key" and "public_key" fields in PEM format"""

    asymmetric_key_generators = dict(
        RSA={
            "function": generate_rsa_keypair_as_pem_bytestrings,
            "extra_parameters": dict(key_length=key_length),
        },
        DSA={
            "function": generate_dsa_keypair_as_pem_bytestrings,
            "extra_parameters": dict(key_length=key_length),
        },
        ECC={
            "function": generate_ecc_keypair_as_pem_bytestrings,
            "extra_parameters": dict(curve=curve),
        },
    )

    key_type = key_type.upper()
    if key_type not in asymmetric_key_generators:
        raise ValueError("Unknown asymmetric key type '%s'" % key_type)

    key_generator = asymmetric_key_generators[key_type]

    function = key_generator["function"]
    extra_parameters = key_generator["extra_parameters"]

    keypair = function(uid=uid, **extra_parameters)

    return keypair


def generate_rsa_keypair_as_pem_bytestrings(uid: uuid.UUID, key_length: int) -> dict:
    """Generate a RSA (public_key, private_key) pair in PEM format.

    :param uid: UUID of the encryption operation
    :param key_length: length of the key in bits, must be superior to 1024.

    :return: dictionary with "private_key" and "public_key" fields in PEM format"""
    keypair = _generate_rsa_keypair_as_objects(uid=uid, key_length=key_length)
    private_key = _serialize_key_object_to_pem_bytestring(keypair["private_key"])
    public_key = _serialize_key_object_to_pem_bytestring(keypair["public_key"])
    pem_keypair = {"private_key": private_key, "public_key": public_key}
    return pem_keypair


def _generate_rsa_keypair_as_objects(uid: uuid.UUID, key_length: int) -> dict:

    if key_length < 1024:
        raise ValueError("The RSA key length must be superior or equal to 1024 bits")

    randfunc = _get_pseudorandom_generator(uid=uid)
    private_key = RSA.generate(key_length, randfunc=randfunc)
    public_key = private_key.publickey()
    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def generate_dsa_keypair_as_pem_bytestrings(uid: uuid.UUID, key_length: int):
    """Generate a DSA (public_key, private_key) pair in PEM format.

    DSA keypair is not used for encryption/decryption, only for signing.

    :param uid: UUID of the encryption operation
    :param key_length: length of the key in bits, must be superior to 1024.

    :return: dictionary with "private_key" and "public_key" fields in PEM format"""
    keypair = _generate_dsa_keypair_as_objects(uid=uid, key_length=key_length)
    private_key = _serialize_key_object_to_pem_bytestring(keypair["private_key"])
    public_key = _serialize_key_object_to_pem_bytestring(keypair["public_key"])
    pem_keypair = {"private_key": private_key, "public_key": public_key}
    return pem_keypair


def _generate_dsa_keypair_as_objects(uid: uuid.UUID, key_length: int) -> dict:

    if key_length < 1024:
        raise ValueError("The DSA key length must be superior or equal to 1024 bits")

    randfunc = _get_pseudorandom_generator(uid=uid)
    private_key = DSA.generate(key_length, randfunc=randfunc)
    public_key = private_key.publickey()
    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def generate_ecc_keypair_as_pem_bytestrings(uid: uuid.UUID, curve: str):
    """Generate an ECC (public_key, private_key) pair in PEM format

    :param uid: UUID of the encryption operation
    :param curve: curve chosen among p256, p384, p521 and maybe others.

    :return: dictionary with "private_key" and "public_key" fields in PEM format"""

    keypair = _generate_ecc_keypair_as_objects(uid=uid, curve=curve)
    private_key = _serialize_key_object_to_pem_bytestring(keypair["private_key"])
    public_key = _serialize_key_object_to_pem_bytestring(keypair["public_key"])
    pem_keypair = {"private_key": private_key, "public_key": public_key}
    return pem_keypair


def _generate_ecc_keypair_as_objects(uid: uuid.UUID, curve: str) -> dict:

    if curve not in ECC._curves:
        raise ValueError(
            "Unexisting ECC curve '%s', must be one of '%s'"
            % (curve, sorted(ECC._curves.keys()))
        )

    randfunc = _get_pseudorandom_generator(uid)
    private_key = ECC.generate(curve=curve, randfunc=randfunc)
    public_key = private_key.public_key()
    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def _serialize_key_object_to_pem_bytestring(key):
    """Convert a private or public key to PEM-formatted bytestring."""
    pem = key.export_key(format="PEM")
    return pem


def _get_pseudorandom_generator(uid):
    """Generate a pseudorandom generator from an uid.

    :param uid: uuid to be used as seed
    :return: a callable taking a number of bytes as parameter and outputting this many pseudorandom bytes
    """
    random_instance = random.Random(uid.int)

    def _randfunc(count):
        """Return a bytestring of `count` bytes."""
        random_bytes = bytes(
            list(random_instance.randrange(0, 256) for _ in range(count))
        )
        return random_bytes

    return _randfunc
