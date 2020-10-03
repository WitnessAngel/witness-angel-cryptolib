import logging
from typing import Union

import unicodedata
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Random import get_random_bytes

from wacryptolib.exceptions import KeyLoadingError

logger = logging.getLogger(__name__)


def encode_passphrase(passphrase: str):
    """Strip and NFKC-normalize passphrase, then encode it as utf8 bytes."""
    return unicodedata.normalize("NFKC", passphrase.strip()).encode("utf8")


def generate_symmetric_key(encryption_algo: str) -> bytes:
    """
    Generate the strongest key possible for the wanted symmetric cipher,
    as a bytestring.
    """
    encryption_algo = encryption_algo.upper()
    if encryption_algo not in SUPPORTED_SYMMETRIC_KEY_ALGOS:
        raise ValueError("Unknown symmetric key algorithm '%s'" % encryption_algo)

    return get_random_bytes(32)  # Same (big) length for all currently supported symmetric ciphers


def generate_asymmetric_keypair(
    *, key_type: str, serialize=True, key_length_bits=2048, curve="p521", passphrase: Union[bytes, str] = None
) -> dict:
    """Generate a (public_key, private_key) pair.

    :param key_type: name of the key type
    :param serialize: Indicates if key must be serialized as PEM string
    :param passphrase: Bytestring used for private key export (requires serialize=True)

    Other arguments are used or not depending on the chosen `key_type`.

    :return: dictionary with "private_key" and "public_key" fields as objects or PEM-format strings"""
    assert serialize or passphrase is None

    if isinstance(passphrase, str):
        passphrase = encode_passphrase(passphrase)

    potential_params = dict(key_length_bits=key_length_bits, curve=curve)

    key_type = key_type.upper()
    if key_type not in SUPPORTED_ASYMMETRIC_KEY_TYPES:
        raise ValueError("Unknown asymmetric key type '%s'" % key_type)

    descriptors = ASYMMETRIC_KEY_TYPES_REGISTRY[key_type]

    generation_function = descriptors["generation_function"]
    generation_extra_parameters = descriptors["generation_extra_parameters"]

    keypair = generation_function(**{k: potential_params[k] for k in generation_extra_parameters})

    assert set(keypair.keys()) == set(["private_key", "public_key"])
    if serialize:
        keypair["private_key"] = _serialize_key_object_to_pem_bytestring(
            keypair["private_key"], key_type=key_type, passphrase=passphrase
        )
        keypair["public_key"] = _serialize_key_object_to_pem_bytestring(keypair["public_key"], key_type=key_type)

    return keypair


def load_asymmetric_key_from_pem_bytestring(key_pem: bytes, *, key_type: str, passphrase: Union[bytes, str] = None):
    """Load a key (public or private) from a PEM-formatted bytestring.

    :param key_pem: the key bytrestring
    :param key_type: name of the key format

    :return: key object
    """
    if isinstance(passphrase, str):
        passphrase = encode_passphrase(passphrase)

    key_type = key_type.upper()
    if key_type not in SUPPORTED_ASYMMETRIC_KEY_TYPES:
        raise ValueError("Unknown key type %s" % key_pem)
    key_import_function = ASYMMETRIC_KEY_TYPES_REGISTRY[key_type]["pem_import_function"]
    try:
        return key_import_function(key_pem, passphrase=passphrase)
    except (ValueError, IndexError, TypeError) as exc:
        raise KeyLoadingError(
            "Failed loading %s key from pem bytestring %s passphrase (%s)"
            % (key_type, "with" if passphrase else "without", exc)
        ) from exc


def _generate_rsa_keypair_as_objects(key_length_bits: int) -> dict:
    """Generate a RSA (public_key, private_key) pair.

    :param key_length_bits: length of the key in bits, must be superior to 2048.

    :return: dictionary with "private_key" and "public_key" fields as objects."""

    _check_asymmetric_key_length_bits(key_length_bits)

    private_key = RSA.generate(key_length_bits)
    public_key = private_key.publickey()
    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def _generate_dsa_keypair_as_objects(key_length_bits: int) -> dict:
    """Generate a DSA (public_key, private_key) pair.

    DSA keypair is not used for encryption/decryption, only for signing.

    :param key_length_bits: length of the key in bits, must be superior to 2048.

    :return: dictionary with "private_key" and "public_key" fields as objects."""

    _check_asymmetric_key_length_bits(key_length_bits)

    private_key = DSA.generate(key_length_bits)
    public_key = private_key.publickey()
    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def _generate_ecc_keypair_as_objects(curve: str) -> dict:
    """Generate an ECC (public_key, private_key) pair.

    ECC keypair is not used for encryption/decryption, only for signing.

    :param curve: curve chosen among p256, p384, p521 and maybe others.

    :return: dictionary with "private_key" and "public_key" fields as objects."""

    if curve not in ECC._curves:
        raise ValueError("Unexisting ECC curve '%s', must be one of '%s'" % (curve, sorted(ECC._curves.keys())))

    private_key = ECC.generate(curve=curve)
    public_key = private_key.public_key()
    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def _serialize_key_object_to_pem_bytestring(key, key_type: str, passphrase: bytes = None) -> str:
    """Convert a private or public key to PEM-formatted bytestring.

    If a passphrase is provided, the key (which must be PRIVATE) is encrypted with it.
    The exact encryption of the key depends on its key_type."""
    assert passphrase is None or (isinstance(passphrase, bytes) and passphrase), repr(
        passphrase
    )  # No implicit encoding here
    extra_params = {}
    if passphrase:
        extra_params = dict(passphrase=passphrase)
        extra_params.update(ASYMMETRIC_KEY_TYPES_REGISTRY[key_type]["pem_export_private_key_encryption_kwargs"])
    key_pem = key.export_key(format="PEM", **extra_params)
    if isinstance(key_pem, str):
        key_pem = key_pem.encode("ascii")  # Some types deliver ascii bytestrings, let's normalize
    return key_pem


def _check_asymmetric_key_length_bits(key_length_bits):
    """Asymmetric ciphers usually talk in bits: 1024, 2048, 3072..."""
    if key_length_bits < 2048:
        raise ValueError("The asymmetric key length must be superior or equal to 2048 bits")


def _check_symmetric_key_length_bytes(key_length_bytes):
    """Symmetric ciphers usually talk in bytes: 16, 24, 32..."""
    if key_length_bytes < 32:
        raise ValueError("The symmetric key length must be superior or equal to 32 bits")


ASYMMETRIC_KEY_TYPES_REGISTRY = dict(
    ## KEYS FOR ASYMMETRIC ENCRYPTION ##
    RSA_OAEP={
        "generation_function": _generate_rsa_keypair_as_objects,
        "generation_extra_parameters": ["key_length_bits"],
        "pem_export_private_key_encryption_kwargs": dict(pkcs=8, protection="PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC"),
        "pem_import_function": RSA.import_key,
    },
    ## KEYS FOR SIGNATURE ##
    RSA_PSS={  # Same parameters as RSA_OAEP for now
        "generation_function": _generate_rsa_keypair_as_objects,
        "generation_extra_parameters": ["key_length_bits"],
        "pem_export_private_key_encryption_kwargs": dict(pkcs=8, protection="PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC"),
        "pem_import_function": RSA.import_key,
    },
    DSA_DSS={
        "generation_function": _generate_dsa_keypair_as_objects,
        "generation_extra_parameters": ["key_length_bits"],
        "pem_export_private_key_encryption_kwargs": dict(pkcs8=True, protection="PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC"),
        "pem_import_function": DSA.import_key,
    },
    ECC_DSS={
        "generation_function": _generate_ecc_keypair_as_objects,
        "generation_extra_parameters": ["curve"],
        "pem_export_private_key_encryption_kwargs": dict(use_pkcs8=True, protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"),
        "pem_import_function": ECC.import_key,
    },
)


#: These values can be used as 'key_type' for asymmetric key generation.
SUPPORTED_ASYMMETRIC_KEY_TYPES = sorted(ASYMMETRIC_KEY_TYPES_REGISTRY.keys())

#: These values can be used as 'encryption_algo' for symmetric key generation.
SUPPORTED_SYMMETRIC_KEY_ALGOS = ["AES_CBC", "AES_EAX", "CHACHA20_POLY1305"]
