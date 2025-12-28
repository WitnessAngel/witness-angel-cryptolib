from flightbox import FlightboxUtilitiesBase

import os
import logging
import uuid
import uuid0
from extjson import dump_to_json_bytes
from PycryptodomeSecretSharing import Shamir as _Shamir
from data_utils import do_split_secret_into_shards, split_as_chunks
from fallback_adapter import encrypt_via_rsa_oaep, encrypt_via_aes_cbc, import_rsa_key_from_pem


AES_BLOCK_SIZE = 16
AUTHENTICATOR_TRUSTEE = "authenticator"


def _shamir_128b_split_func(*args, **kwargs):
    return _Shamir.split(*args, **kwargs)


def _get_random_bytes(nbytes):
    """Like pycryptodome, we rely on the randomness of the OS!"""
    return os.urandom(nbytes)


## GRABBED FROM CIPHER.PY OF WACTYPTOLIB ##

RSA_OAEP_CHUNKS_SIZE = 60  # SAFE mmini-chunk for RSA


def _check_asymmetric_key_length_bits(key_length_bits):
    """Asymmetric ciphers usually talk in bits: 1024, 2048, 3072..."""
    if key_length_bits < 2048:
        raise ValueError("The asymmetric key length must be superior or equal to 2048 bits")


def _perform_chunked_encryption_via_rsa_oaep(plaintext: bytes, key_dict: dict) -> dict:
    """Encrypt a bytestring with PKCS#1 RSA OAEP (asymmetric algo).

    :param plaintext: the bytes to cipher
    :param key_dict: dict with PUBLIC RSA key object (RSA.RsaKey)

    :return: a dict with field `digest_list`, containing bytestring chunks of variable width."""
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

    SUPPORTED_ASYMMETRIC_CIPHER_ALGOS = ["RSA_OAEP"]

    def __init__(self, logger: logging.Logger, keystore_data: dict) -> None:
        self.logger = logger
        # Dict of trustee dicts of keychain PEMs, only having public keys
        self._keystore_data = keystore_data

    def raise_validation_error(self, msg: str) -> None:
        raise RuntimeError(msg)

    def dump_to_json_bytes(self, data):
        return dump_to_json_bytes(data)

    def generate_uuid0(self) -> uuid.UUID:
        return uuid0.generate()

    def split_secret_into_shards(self, secret: bytes, *, shard_count: int, threshold_count: int) -> list:
        return do_split_secret_into_shards(secret, shard_count=shard_count, threshold_count=threshold_count,
                                           shamir_128b_split_func=_shamir_128b_split_func)

    def generate_symkey(self, cipher_algo: str):
        assert cipher_algo == "AES_CBC", cipher_algo
        return dict(
            key=_get_random_bytes(32),
            iv=_get_random_bytes(AES_BLOCK_SIZE)
        )

    def get_public_key(self, trustee: dict, key_algo: str, keychain_uid: uuid.UUID) -> dict:  # FIXME
        trustee_type = trustee["trustee_type"]
        if trustee_type != AUTHENTICATOR_TRUSTEE:
            raise RuntimeError(f"Unsupported trustee type {trustee_type}")

        _keystore_uid = trustee["keystore_uid"]  # ID of authenticator is identical to that of its keystore
        trustee_data = self._keystore_data[_keystore_uid]
        public_key_pem = trustee_data[keychain_uid]
        self.logger.debug("Fetching asymmetric public key %s/%s to encrypt symmetric key struct", key_algo, keychain_uid)
        public_key = import_rsa_key_from_pem(public_key_pem, passphrase=None)
        return public_key

    def encrypt_bytestring(self, plaintext: bytes, *, cipher_algo: str, key_dict: dict) -> dict:  # FIXME
        if cipher_algo == "RSA_OAEP":
            return _perform_chunked_encryption_via_rsa_oaep(plaintext=plaintext, key_dict=key_dict)
        elif cipher_algo == "AES_CBC":
            key = key_dict["key"]
            iv = key_dict["iv"]
            return encrypt_via_aes_cbc(plaintext, key, iv)
        else:
            raise RuntimeError(f"Abnormal cipher algo {cipher_algo}")