from flightbox import FlightboxUtilitiesBase

import os
import logging
import uuid
import uuid0
from extjson import dump_to_json_bytes
from PycryptodomeSecretSharing import Shamir as _Shamir
from data_utils import do_split_secret_into_shards


AES_BLOCK_SIZE = 16


def shamir_128b_split_func(*args, **kwargs):
    return _Shamir.split(*args, **kwargs)


def get_random_bytes(nbytes):
    """Like pycryptodome, we rely on the randomness of the OS!"""
    return os.urandom(nbytes)


class FlightboxUtilitiesImpl(FlightboxUtilitiesBase):
    """
    THIS CLASS IS PRIVATE API

    Contains a set of platform-specific functions to deal with time,
    cryptography, and other primitives required for Flightbox to operate.
    """

    SUPPORTED_SYMMETRIC_CIPHER_ALGOS = ["AES_CBC"]

    SUPPORTED_ASYMMETRIC_CIPHER_ALGOS = ["RSA_OAEP"]

    def __init__(self, logger: logging.Logger, keystore_pool) -> None:
        self.logger = logger
        self._keystore_pool = keystore_pool  # FIXME???

    def raise_validation_error(self, msg: str) -> None:
        raise RuntimeError(msg)

    def dump_to_json_bytes(self, data):
        return dump_to_json_bytes(data)

    def generate_uuid0(self) -> uuid.UUID:
        return uuid0.generate()

    def split_secret_into_shards(self, secret: bytes, *, shard_count: int, threshold_count: int) -> list:
        return do_split_secret_into_shards(secret, shard_count=shard_count, threshold_count=threshold_count,
                                           shamir_128b_split_func=shamir_128b_split_func)

    def generate_symkey(self, cipher_algo: str):
        assert cipher_algo == "AES_CBC", cipher_algo
        return dict(
            key=get_random_bytes(32),
            iv=get_random_bytes(AES_BLOCK_SIZE)
        )

    def get_public_key(self, trustee: dict, key_algo: str, keychain_uid: uuid.UUID) -> dict:  # FIXME
        public_key_pem = self._fetch_asymmetric_key_pem_from_trustee(trustee, key_algo=key_algo, keychain_uid=keychain_uid)
        self.logger.debug("Encrypting symmetric key struct with asymmetric keypair %s/%s", key_algo, keychain_uid)
        public_key = load_asymmetric_key_from_pem_bytestring(key_pem=public_key_pem, key_algo=key_algo)
        return public_key

    def encrypt_bytestring(self, plaintext: bytes, *, cipher_algo: str, key_dict: dict) -> dict:  # FIXME
        return encrypt_bytestring(plaintext=plaintext, cipher_algo=cipher_algo, key_dict=key_dict)
