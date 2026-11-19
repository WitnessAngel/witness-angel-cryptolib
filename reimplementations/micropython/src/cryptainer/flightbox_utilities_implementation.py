from ._flightbox import FlightBox, FlightboxUtilitiesBase, KEY_CIPHERTEXT_FORMAT_JSON, _copy_data_tree
from .input_validation import (
    InvalidInputError,
    KeyConstraintError,
    MissingPublicKeyError,
    UnsupportedFeatureError,
    validate_flightbox_inputs,
)

import os
import binascii
import logging
from extjson import dump_to_json_bytes
from .pycryptodome_secret_sharing import Shamir as _Shamir
from data_utils import do_split_secret_into_shards, split_as_chunks
from .fallback_adapter import encrypt_via_rsa_oaep, encrypt_via_aes_cbc

import time
import struct
from uuid import UUID



AES_BLOCK_SIZE = 16
AUTHENTICATOR_TRUSTEE = "authenticator"


def _shamir_128b_split_func(*args, **kwargs):
    return _Shamir.split(*args, **kwargs)


def _get_random_bytes(nbytes):
    """Like pycryptodome, we rely on the randomness of the OS!"""
    return os.urandom(nbytes)


def _generate_uuid0() -> UUID:  # Adapted from "uuid0" MIT package
    """Generate a new UUID. If the UNIX timestamp 'ts' is not given, the current time is used"""
    ts = time.time()
    tsi = int(ts * 10000)
    # Pack as an 8-byte uint and drop the first 2 bytes:
    t_bytes = struct.pack('>Q', tsi)[2:]
    r_bytes = os.urandom(10)

    return UUID(bytes=t_bytes + r_bytes)



## GRABBED FROM CIPHER.PY OF WACTYPTOLIB ##

RSA_OAEP_CHUNKS_SIZE = 60  # SAFE mmini-chunk for RSA


def _check_symmetric_key_length_bytes(key_length_bytes):
    """Symmetric ciphers usually talk in bytes: 16, 24, 32..."""
    if key_length_bytes < 32:
        raise ValueError("The symmetric key length must be superior or equal to 32 bytes")


def _encrypt_via_aes_cbc(plaintext: bytes, key_dict: dict) -> dict:
    """Encrypt a bytestring using AES (CBC mode, PKCS#7 padding).

    :param plaintext: the bytes to cipher
    :param key_dict: dict with AES cryptographic main key (32 bytes, for AES-256) and iv

    :return: dict with field "ciphertext" as bytestring"""
    key = key_dict["key"]
    iv = key_dict["iv"]
    _check_symmetric_key_length_bytes(len(key))
    ciphertext = encrypt_via_aes_cbc(plaintext, key, iv)
    return {"ciphertext": ciphertext}


def _check_asymmetric_key_length_bits(key_length_bits):
    """Asymmetric ciphers usually talk in bits: 1024, 2048, 3072..."""
    if key_length_bits < 2048:
        raise ValueError("The asymmetric key length must be superior or equal to 2048 bits")


# Like the default maximum of flightbox device profiles: modular exponentiations get slow on microcontrollers
MAX_RSA_KEY_LENGTH_BITS = 4096


def _check_rsa_public_numbers(n, e):
    """Check an RSA public key like both backends of wacryptolib do on import, else e.g. e=1 would leave OAEP
    "ciphertexts" readable by anyone."""
    if type(n) is not int or type(e) is not int:  # Booleans are no integers here
        raise KeyConstraintError("RSA public key components must be integers")
    if not (1 << 2047) <= n < (1 << MAX_RSA_KEY_LENGTH_BITS):
        raise KeyConstraintError("RSA modulus must have between 2048 and %d bits" % MAX_RSA_KEY_LENGTH_BITS)
    a, b = n, e if e > 0 else 0
    while b:  # Greatest common divisor (not provided by the math module of MicroPython)
        a, b = b, a % b
    if not n & 1 or not 3 <= e < n or a != 1:
        raise KeyConstraintError("Invalid RSA public key components")


_X25519_P = 2**255 - 19

# Canonical u-coordinates of the points of low order (0, 1, the two points of order 8, and p - 1), with which the
# shared secret would not depend on the ephemeral private key
_X25519_LOW_ORDER_PUBLIC_KEYS = (
    bytes(32),
    b"\x01" + bytes(31),
    binascii.unhexlify("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    binascii.unhexlify("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
    binascii.unhexlify("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
)


def _check_x25519_public_key(public_key):
    """Check a raw X25519 public key like hpke_x25519_seal does, but before any random draw."""
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise KeyConstraintError("X25519 public key must be 32 bytes long")
    if int.from_bytes(public_key, "little") >= _X25519_P:  # This includes keys having their most significant bit set
        raise KeyConstraintError("Non-canonical X25519 public key")
    if public_key in _X25519_LOW_ORDER_PUBLIC_KEYS:
        raise KeyConstraintError("Invalid X25519 public key (low order point)")


def _perform_chunked_encryption_via_rsa_oaep(plaintext: bytes, key_dict: dict) -> dict:
    """Encrypt a bytestring with PKCS#1 RSA OAEP (asymmetric algo).

    :param plaintext: the bytes to cipher
    :param key_dict: dict with PUBLIC RSA key object (RSA.RsaKey)

    :return: a dict with field `ciphertext_chunks`, a list of bytestrings having the byte length of the modulus."""
    key = key_dict["key"]
    _key_length_bits = key.size_in_bits() if hasattr(key, "size_in_bits") else key.bit_size
    _check_asymmetric_key_length_bits(_key_length_bits)

    plaintext_chunks = split_as_chunks(plaintext, chunk_size=RSA_OAEP_CHUNKS_SIZE,
                                       must_pad=False, accept_incomplete_chunk=True)

    ciphertext_chunks = encrypt_via_rsa_oaep(plaintext_chunks, public_key=key)
    return dict(ciphertext_chunks=ciphertext_chunks)


class FlightboxUtilitiesImpl(FlightboxUtilitiesBase):
    """
    THIS CLASS IS PRIVATE API

    Contains a set of platform-specific functions to deal with time,
    cryptography, and other primitives required for Flightbox to operate.
    """

    SUPPORTED_SYMMETRIC_CIPHER_ALGOS = ["AES_CBC"]

    SUPPORTED_ASYMMETRIC_CIPHER_ALGOS = ["RSA_OAEP", "ECIES_X25519"]

    def __init__(self, logger: logging.Logger, keystore_data: dict) -> None:
        self.logger = logger
        # Dict of trustee dicts of keychain PEMs, only having public keys
        self._keystore_data = keystore_data

    def raise_validation_error(self, msg: str) -> None:
        raise InvalidInputError(msg)  # A RuntimeError subclass

    def dump_to_json_bytes(self, data):
        return dump_to_json_bytes(data)

    def generate_uuid0(self) -> UUID:
        return _generate_uuid0()

    def split_secret_into_shards(self, secret: bytes, *, shard_count: int, threshold_count: int) -> list:
        return do_split_secret_into_shards(secret, shard_count=shard_count, threshold_count=threshold_count,
                                           shamir_128b_split_func=_shamir_128b_split_func)

    def generate_symkey(self, cipher_algo: str):
        if cipher_algo not in self.SUPPORTED_SYMMETRIC_CIPHER_ALGOS:  # No assertion, these can be stripped (-O)
            raise UnsupportedFeatureError("Unsupported symmetric cipher algo %r" % (cipher_algo,))
        return dict(
            key=_get_random_bytes(32),
            iv=_get_random_bytes(AES_BLOCK_SIZE)
        )

    def get_public_key(self, trustee: dict, key_algo: str, keychain_uid: UUID) -> dict:  # FIXME
        """Return the public key of an authenticator trustee, after checking its sanity.

        Raise UnsupportedFeatureError for another trustee type or an unsupported algo, MissingPublicKeyError if
        the keystore data holds no such key, and KeyConstraintError if that key is invalid."""
        trustee_type = trustee["trustee_type"]
        if trustee_type != AUTHENTICATOR_TRUSTEE:
            raise UnsupportedFeatureError("Unsupported trustee type %r" % (trustee_type,))
        if key_algo not in self.SUPPORTED_ASYMMETRIC_CIPHER_ALGOS:  # No assertion, these can be stripped (-O)
            raise UnsupportedFeatureError("Unsupported asymmetric cipher algo %r" % (key_algo,))

        _keystore_uid = trustee["keystore_uid"]  # ID of authenticator is identical to that of its keystore
        self.logger.debug("Fetching asymmetric public key %s/%s to encrypt symmetric key struct", key_algo, keychain_uid)
        try:
            public_key_parameters = self._keystore_data[_keystore_uid][keychain_uid]
            if key_algo == "ECIES_X25519":
                public_key = public_key_parameters["x25519"]  # Raw 32-bytes public key
            else:
                n, e = public_key_parameters["n"], public_key_parameters["e"]
        except KeyError:
            raise MissingPublicKeyError(
                "No %s public key for keychain %s in keystore %s" % (key_algo, keychain_uid, _keystore_uid)
            )

        if key_algo == "ECIES_X25519":
            _check_x25519_public_key(public_key)
            return public_key

        _check_rsa_public_numbers(n, e)
        import pkcs1
        return pkcs1.keys.RsaPublicKey(n, e)

    def encrypt_bytestring(self, plaintext: bytes, *, cipher_algo: str, key_dict: dict) -> dict:  # FIXME
        if cipher_algo == "RSA_OAEP":
            return _perform_chunked_encryption_via_rsa_oaep(plaintext=plaintext, key_dict=key_dict)
        elif cipher_algo == "ECIES_X25519":
            import hpke_x25519_seal  # Lazy, to spare RAM on RSA-only deployments
            kem_ciphertext, ciphertext = hpke_x25519_seal.seal(key_dict["key"], plaintext)
            return dict(kem_ciphertext=kem_ciphertext, ciphertext=ciphertext)
        elif cipher_algo == "AES_CBC":
            return _encrypt_via_aes_cbc(plaintext=plaintext, key_dict=key_dict)
        else:
            raise UnsupportedFeatureError("Unsupported cipher algo %r" % (cipher_algo,))


class ValidatingFlightBox(FlightBox):
    """
    Flightbox core which first validates all its inputs (see input_validation.py), so that an invalid, unsupported
    or unresolvable input is rejected with a dedicated FlightboxError subclass before any random draw, instead of
    failing half-way or yielding a cryptainer that wacryptolib rejects.

    It must be given a FlightboxUtilitiesImpl, and be preferred to a bare FlightBox.
    """

    def generate_cryptainer_base_and_secrets(
        self, cryptoconf: dict, cryptainer_metadata=None, key_ciphertext_format=KEY_CIPHERTEXT_FORMAT_JSON
    ) -> tuple:
        validate_flightbox_inputs(self._fbu, cryptoconf, cryptainer_metadata, key_ciphertext_format)
        cryptainer_metadata = _copy_data_tree(cryptainer_metadata)  # The cryptainer must not alias caller data
        return FlightBox.generate_cryptainer_base_and_secrets(
            self, cryptoconf, cryptainer_metadata=cryptainer_metadata, key_ciphertext_format=key_ciphertext_format
        )
