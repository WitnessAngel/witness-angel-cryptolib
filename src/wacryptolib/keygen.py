import logging
from typing import Optional, AnyStr

import unicodedata

from wacryptolib import _crypto_backend
from wacryptolib.exceptions import KeyLoadingError

logger = logging.getLogger(__name__)


def _encode_passphrase(passphrase: str):
    """Strip and NFKC-normalize passphrase, then encode it as utf8 bytes."""
    return unicodedata.normalize("NFKC", passphrase.strip()).encode("utf8")


def generate_symkey(cipher_algo: str) -> dict:
    """
    Generate the strongest dict of keys/initializers possible for the wanted symmetric cipher,
    as a dict.
    """
    logger.debug("Generating symkey of type %s", cipher_algo)
    cipher_algo = cipher_algo.upper()
    if cipher_algo not in SUPPORTED_SYMMETRIC_KEY_ALGOS:
        raise ValueError("Unknown symmetric key algorithm '%s'" % cipher_algo)

    descriptors = SYMMETRIC_KEY_ALGOS_REGISTRY[cipher_algo]
    generation_function = descriptors["generation_function"]

    key_dict = generation_function()
    return key_dict


def _generate_aes_cbc_key_dict():
    return dict(
        key=_crypto_backend.get_random_bytes(32), iv=_crypto_backend.get_random_bytes(_crypto_backend.AES_BLOCK_SIZE)
    )


def _generate_aes_eax_key_dict():
    return dict(
        key=_crypto_backend.get_random_bytes(32), nonce=_crypto_backend.get_random_bytes(16)
    )  # Recommended length, could be bigger


def _generate_chacha20_poly1305_key_dict():
    return dict(
        key=_crypto_backend.get_random_bytes(32), nonce=_crypto_backend.get_random_bytes(12)
    )  # We could switch to 24-bytes nonce for XChaCha20


def generate_keypair(
    *, key_algo: str, serialize=True, key_length_bits=2048, curve="p521", passphrase: Optional[AnyStr] = None
) -> dict:
    """Generate a (public_key, private_key) pair.

    :param key_algo: name of the key type
    :param serialize: indicates if key must be serialized as PEM string (else it remains a python object)
    :param passphrase: bytestring used for private key export (requires serialize=True)

    Other arguments are used or not depending on the chosen `key_algo`.

    :return: dictionary with "private_key" and "public_key" fields as objects or PEM-format strings
    """
    return _do_generate_keypair(
        key_algo=key_algo, serialize=serialize, key_length_bits=key_length_bits, curve=curve, passphrase=passphrase
    )


# Intermediate function to help monkey-patching in tests
def _do_generate_keypair(key_algo, serialize, key_length_bits, curve, passphrase):
    assert serialize or passphrase is None

    if isinstance(passphrase, str):
        passphrase = _encode_passphrase(passphrase)

    potential_params = dict(key_length_bits=key_length_bits, curve=curve)

    key_algo = key_algo.upper()
    if key_algo not in SUPPORTED_ASYMMETRIC_KEY_ALGOS:
        raise ValueError("Unknown asymmetric key type '%s'" % key_algo)

    descriptors = ASYMMETRIC_KEY_ALGOS_REGISTRY[key_algo]

    generation_function = descriptors["generation_function"]
    generation_extra_parameters = descriptors["generation_extra_parameters"]

    keypair = generation_function(**{k: potential_params[k] for k in generation_extra_parameters})

    assert set(keypair.keys()) == set(["private_key", "public_key"])
    if serialize:
        keypair["private_key"] = _serialize_key_object_to_pem_bytestring(
            keypair["private_key"], key_algo=key_algo, passphrase=passphrase
        )
        keypair["public_key"] = _serialize_key_object_to_pem_bytestring(keypair["public_key"], key_algo=key_algo)

    return keypair


# TODO add debugging parameter keychain_uid!
def load_asymmetric_key_from_pem_bytestring(key_pem: bytes, *, key_algo: str, passphrase: Optional[AnyStr] = None):
    """Load a key (public or private) from a PEM-formatted bytestring.

    :param key_pem: the key bytrestring
    :param key_algo: name of the key format

    :return: key object
    """
    if isinstance(passphrase, str):
        passphrase = _encode_passphrase(passphrase)

    key_algo = key_algo.upper()
    if key_algo not in SUPPORTED_ASYMMETRIC_KEY_ALGOS:
        raise ValueError("Unknown key type %s" % key_pem)
    key_import_function = ASYMMETRIC_KEY_ALGOS_REGISTRY[key_algo]["pem_import_function"]
    try:
        return key_import_function(key_pem, passphrase=passphrase)
    except (ValueError, IndexError, TypeError) as exc:
        raise KeyLoadingError(
            "Failed loading %s key from pem bytestring %s passphrase (%s)"
            % (key_algo, "with" if passphrase else "without", exc)
        ) from exc


def _generate_rsa_keypair_as_objects(key_length_bits: int) -> dict:
    """Generate a RSA (public_key, private_key) pair.

    :param key_length_bits: length of the key in bits, must be superior to 2048.

    :return: dictionary with "private_key" and "public_key" fields as objects."""

    _check_asymmetric_key_length_bits(key_length_bits)
    public_key, private_key = _crypto_backend.generate_rsa_keypair(key_length_bits)
    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def _generate_dsa_keypair_as_objects(key_length_bits: int) -> dict:
    """Generate a DSA (public_key, private_key) pair.

    DSA keypair is not used for encryption/decryption, only for signing.

    :param key_length_bits: length of the key in bits, must be superior to 2048.

    :return: dictionary with "private_key" and "public_key" fields as objects."""

    _check_asymmetric_key_length_bits(key_length_bits)
    public_key, private_key = _crypto_backend.generate_dsa_keypair(key_length_bits)
    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def _generate_ecc_keypair_as_objects(curve: str) -> dict:
    """Generate an ECC (public_key, private_key) pair.

    ECC keypair is not used for encryption/decryption, only for signing.

    :param curve: curve chosen among p256, p384, p521 and maybe others.

    :return: dictionary with "private_key" and "public_key" fields as objects."""

    public_key, private_key = _crypto_backend.generate_ecc_keypair(curve)
    keypair = {"public_key": public_key, "private_key": private_key}
    return keypair


def _serialize_key_object_to_pem_bytestring(key, key_algo: str, passphrase: Optional[AnyStr] = None) -> bytes:
    """Convert a private or public key to PEM-formatted bytestring.

    If a passphrase is provided, the key (which must be PRIVATE) is encrypted with it.
    The exact encryption of the key depends on its key_algo."""
    assert passphrase is None or (isinstance(passphrase, bytes) and passphrase), repr(
        passphrase
    )  # No implicit encoding here
    pem_export_function = ASYMMETRIC_KEY_ALGOS_REGISTRY[key_algo]["pem_export_function"]
    key_pem = pem_export_function(key, passphrase=passphrase)
    if isinstance(key_pem, str):
        key_pem = key_pem.encode("ascii")  # Some APIs deliver ascii bytestrings, let's normalize to bytes...
    return key_pem


def _check_symmetric_key_length_bytes(key_length_bytes):
    """Symmetric ciphers usually talk in bytes: 16, 24, 32..."""
    if key_length_bytes < 32:
        raise ValueError("The symmetric key length must be superior or equal to 32 bits")


def _check_asymmetric_key_length_bits(key_length_bits):
    """Asymmetric ciphers usually talk in bits: 1024, 2048, 3072..."""
    if key_length_bits < 2048:
        raise ValueError("The asymmetric key length must be superior or equal to 2048 bits")


SYMMETRIC_KEY_ALGOS_REGISTRY = dict(
    AES_CBC={"generation_function": _generate_aes_cbc_key_dict},
    AES_EAX={"generation_function": _generate_aes_eax_key_dict},
    CHACHA20_POLY1305={"generation_function": _generate_chacha20_poly1305_key_dict},
)

ASYMMETRIC_KEY_ALGOS_REGISTRY = dict(
    ## KEYS FOR ASYMMETRIC ENCRYPTION ##
    RSA_OAEP={
        "generation_function": _generate_rsa_keypair_as_objects,
        "generation_extra_parameters": ["key_length_bits"],
        "pem_import_function": _crypto_backend.import_rsa_key_from_pem,
        "pem_export_function": _crypto_backend.export_rsa_key_to_pem,
    },
    ## KEYS FOR SIGNATURE ##
    RSA_PSS={  # Same parameters as RSA_OAEP for now
        "generation_function": _generate_rsa_keypair_as_objects,
        "generation_extra_parameters": ["key_length_bits"],
        "pem_import_function": _crypto_backend.import_rsa_key_from_pem,
        "pem_export_function": _crypto_backend.export_rsa_key_to_pem,
    },
    DSA_DSS={
        "generation_function": _generate_dsa_keypair_as_objects,
        "generation_extra_parameters": ["key_length_bits"],
        "pem_import_function": _crypto_backend.import_dsa_key_from_pem,
        "pem_export_function": _crypto_backend.export_dsa_key_to_pem,
    },
    ECC_DSS={
        "generation_function": _generate_ecc_keypair_as_objects,
        "generation_extra_parameters": ["curve"],
        "pem_import_function": _crypto_backend.import_ecc_key_from_pem,
        "pem_export_function": _crypto_backend.export_ecc_key_to_pem,
    },
)


#: These values can be used as 'key_algo' for asymmetric key generation.
SUPPORTED_ASYMMETRIC_KEY_ALGOS = sorted(ASYMMETRIC_KEY_ALGOS_REGISTRY.keys())

#: These values can be used as 'key_algo' for symmetric key generation.
SUPPORTED_SYMMETRIC_KEY_ALGOS = sorted(SYMMETRIC_KEY_ALGOS_REGISTRY.keys())
