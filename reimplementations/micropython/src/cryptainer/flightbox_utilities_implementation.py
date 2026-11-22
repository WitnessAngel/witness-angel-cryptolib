from ._flightbox import FlightBox, FlightboxUtilitiesBase, KEY_CIPHERTEXT_FORMAT_JSON
from .text_validation import find_ill_formed_text, get_ill_formed_text_message, is_well_formed_utf8

import os
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

    SUPPORTED_ASYMMETRIC_CIPHER_ALGOS = ["RSA_OAEP", "ECIES_X25519"]

    def __init__(self, logger: logging.Logger, keystore_data: dict) -> None:
        self.logger = logger
        # Dict of trustee dicts of keychain PEMs, only having public keys
        self._keystore_data = keystore_data

    def raise_validation_error(self, msg: str) -> None:
        raise RuntimeError(msg)

    def dump_to_json_bytes(self, data):
        json_bytes = dump_to_json_bytes(data)
        # Last resort for the strings that ValidatingFlightBox would have refused, e.g. with a bare FlightBox: the
        # key struct holding them is then refused before any output, if only after some random draws
        if not is_well_formed_utf8(json_bytes):
            self.raise_validation_error(get_ill_formed_text_message("cryptainer_metadata", " (in a key struct)"))
        return json_bytes

    def generate_uuid0(self) -> UUID:
        return _generate_uuid0()

    def split_secret_into_shards(self, secret: bytes, *, shard_count: int, threshold_count: int) -> list:
        return do_split_secret_into_shards(secret, shard_count=shard_count, threshold_count=threshold_count,
                                           shamir_128b_split_func=_shamir_128b_split_func)

    def generate_symkey(self, cipher_algo: str):
        assert cipher_algo == "AES_CBC", cipher_algo
        return dict(
            key=_get_random_bytes(32),
            iv=_get_random_bytes(AES_BLOCK_SIZE)
        )

    def get_public_key(self, trustee: dict, key_algo: str, keychain_uid: UUID) -> dict:  # FIXME
        trustee_type = trustee["trustee_type"]
        if trustee_type != AUTHENTICATOR_TRUSTEE:
            raise RuntimeError(f"Unsupported trustee type {trustee_type}")

        _keystore_uid = trustee["keystore_uid"]  # ID of authenticator is identical to that of its keystore
        trustee_data = self._keystore_data[_keystore_uid]
        public_key_parameters = trustee_data[keychain_uid]
        self.logger.debug("Fetching asymmetric public key %s/%s to encrypt symmetric key struct", key_algo, keychain_uid)
        ### public_key = import_rsa_key_from_pem(public_key_pem, passphrase=None)

        if key_algo == "ECIES_X25519":
            return public_key_parameters["x25519"]  # Raw 32-bytes public key

        assert key_algo == "RSA_OAEP", key_algo
        import pkcs1
        public_key = pkcs1.keys.RsaPublicKey(public_key_parameters["n"], public_key_parameters['e'])

        return public_key

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
            raise RuntimeError(f"Abnormal cipher algo {cipher_algo}")


class ValidatingFlightBox(FlightBox):
    """
    Flightbox core which first checks, before any random draw, that every text string of its inputs is a sequence
    of Unicode scalar values (see text_validation.py): the keys and values of the cryptainer metadata, and of the
    cryptoconf (algo names, trustee fields like keystore_owner, uids given as text...), at any depth, since all of
    them are copied into the cryptainer. Else MicroPython would write ill-formed UTF-8, which wacryptolib can't load.

    It must be given a FlightboxUtilitiesImpl, and be preferred to a bare FlightBox.
    """

    def generate_cryptainer_base_and_secrets(
        self, cryptoconf: dict, cryptainer_metadata=None, key_ciphertext_format=KEY_CIPHERTEXT_FORMAT_JSON
    ) -> tuple:
        for label, tree in (("cryptoconf", cryptoconf), ("cryptainer_metadata", cryptainer_metadata)):
            location = find_ill_formed_text(tree)
            if location is not None:
                self._fbu.raise_validation_error(get_ill_formed_text_message(label, location))
        return FlightBox.generate_cryptainer_base_and_secrets(
            self, cryptoconf, cryptainer_metadata=cryptainer_metadata, key_ciphertext_format=key_ciphertext_format
        )
