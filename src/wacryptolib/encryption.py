import importlib
import logging
from typing import BinaryIO

import Crypto.Hash.SHA512
from Crypto.Cipher import AES, ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from wacryptolib import utilities
from wacryptolib.exceptions import EncryptionError, DecryptionError, DecryptionIntegrityError
from wacryptolib.key_generation import (
    _check_symmetric_key_length_bytes,
    SUPPORTED_SYMMETRIC_KEY_ALGOS,
    _check_asymmetric_key_length_bits,
)
from wacryptolib.utilities import split_as_chunks

logger = logging.getLogger(__name__)

RSA_OAEP_CHUNKS_SIZE = 60
RSA_OAEP_HASHER = Crypto.Hash.SHA512


def _get_encryption_type_conf(encryption_algo):
    encryption_algo = encryption_algo.upper()
    if encryption_algo not in ENCRYPTION_ALGOS_REGISTRY:
        raise ValueError("Unknown cipher type '%s'" % encryption_algo)

    encryption_type_conf = ENCRYPTION_ALGOS_REGISTRY[encryption_algo]
    return encryption_type_conf


# FIXME make it return BYTESTRING ALWAYS, no need to jsonify them!
# FIXME key_dict name is wrong in the case of RSA_OAEP!!
def encrypt_bytestring(plaintext: bytes, *, encryption_algo: str, key_dict: dict) -> dict:
    """Encrypt a bytestring with the selected algorithm for the given payload,
    using the provided key dict (which must contain keys/initializers of proper types and lengths).

    :return: dictionary with encryption data"""
    assert isinstance(plaintext, bytes), repr(plaintext)
    encryption_type_conf = _get_encryption_type_conf(encryption_algo=encryption_algo)
    encryption_function = encryption_type_conf["encryption_function"]
    #### _check_symmetric_key_length_bytes(len(main_key))
    try:
        cipherdict = encryption_function(key_dict=key_dict, plaintext=plaintext)
    except ValueError as exc:
        raise EncryptionError("Failed %s encryption (%s)" % (encryption_algo, exc)) from exc
    return cipherdict


def decrypt_bytestring(
        cipherdict: dict, *, encryption_algo: str, key_dict: dict, verify: bool=True
) -> bytes:  # Fixme rename encryption_algo to decryption_algo? Or normalize?
    """Decrypt a bytestring with the selected algorithm for the given encrypted data dict,
    using the provided key (which must be of a compatible type and length).

    :param cipherdict: dict with field "ciphertext" as bytestring and (depending
        on the encryption_algo) some other fields like "tag" or "nonce"
        as bytestrings
    :param encryption_algo: one of the supported encryption algorithms
    :param key_dict: dict with secret key fields
    :param verify: whether to check tag/mac values of the ciphertext

    :return: dictionary with encryption data."""
    encryption_type_conf = _get_encryption_type_conf(encryption_algo)
    decryption_function = encryption_type_conf["decryption_function"]
    try:
        plaintext = decryption_function(key_dict=key_dict, cipherdict=cipherdict, verify=verify)
    except ValueError as exc:
        if "MAC check failed" in str(exc):  # Hackish check for pycryptodome
            raise DecryptionIntegrityError("Failed %s decryption authentication (%s)" % (encryption_algo, exc)) from exc
        raise DecryptionError("Failed %s decryption (%s)" % (encryption_algo, exc)) from exc
    return plaintext


def _encrypt_via_aes_cbc(plaintext: bytes, key_dict: dict) -> dict:
    """Encrypt a bytestring using AES (CBC mode).

    :param plaintext: the bytes to cipher
    :param key_dict: dict with AES cryptographic main key and iv.
        Main key must be 16, 24 or 32 bytes long
        (respectively for *AES-128*, *AES-192* or *AES-256*).

    :return: dict with field "ciphertext" as bytestring"""
    main_key = key_dict["key"]
    iv = key_dict["iv"]
    _check_symmetric_key_length_bytes(len(main_key))
    cipher = AES.new(main_key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext, block_size=AES.block_size))
    cipherdict = {"ciphertext": ciphertext}
    return cipherdict


def _decrypt_via_aes_cbc(cipherdict: dict, key_dict: dict, verify: bool=True) -> bytes:
    """Decrypt a bytestring using AES (CBC mode).

    :param cipherdict: dict with field "ciphertext" as bytestring
    :param key_dict: dict with AES cryptographic main key and nonce.
    :param verify: whether to check tag/mac values of the ciphertext
        (not applicable for this cipher)

    :return: the decrypted bytestring"""
    main_key = key_dict["key"]
    iv = key_dict["iv"]
    _check_symmetric_key_length_bytes(len(main_key))
    ciphertext = cipherdict["ciphertext"]
    decipher = AES.new(main_key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(decipher.decrypt(ciphertext), block_size=AES.block_size)
    return plaintext


def _encrypt_via_aes_eax(plaintext: bytes, key_dict: dict) -> dict:
    """Encrypt a bytestring using AES (EAX mode).

    :param plaintext: the bytes to cipher
    :param key_dict: dict with AES cryptographic main key and nonce.
        Main key must be 16, 24 or 32 bytes long
        (respectively for *AES-128*, *AES-192* or *AES-256*).

    :return: dict with fields "ciphertext" and "tag" as bytestrings"""
    main_key = key_dict["key"]
    nonce = key_dict["nonce"]
    _check_symmetric_key_length_bytes(len(main_key))
    cipher = AES.new(main_key, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    cipherdict = {"ciphertext": ciphertext, "tag": tag}
    return cipherdict


def _decrypt_via_aes_eax(cipherdict: dict, key_dict: dict, verify: bool=True) -> bytes:
    """Decrypt a bytestring using AES (EAX mode).

    :param cipherdict: dict with fields "ciphertext", "tag" as bytestrings
    :param key_dict: dict with AES cryptographic main key and nonce.
    :param verify: whether to check tag/mac values of the ciphertext

    :return: the decrypted bytestring"""
    main_key = key_dict["key"]
    nonce = key_dict["nonce"]
    _check_symmetric_key_length_bytes(len(main_key))
    decipher = AES.new(main_key, AES.MODE_EAX, nonce=nonce)
    plaintext = decipher.decrypt(cipherdict["ciphertext"])
    if verify:
        decipher.verify(cipherdict["tag"])
    return plaintext


def _encrypt_via_chacha20_poly1305(plaintext: bytes, key_dict: dict) -> dict:
    """Encrypt a bytestring with the stream cipher ChaCha20.

    Additional cleartext data can be provided so that the
    generated mac tag also verifies its integrity.

    :param plaintext: the bytes to cipher
    :param key_dict: 32 bytes long cryptographic key and nonce
    :param aad: optional "additional authenticated data"

    :return: dict with fields "ciphertext", "tag", and "header" as bytestrings"""
    main_key = key_dict["key"]
    nonce = key_dict["nonce"]
    _check_symmetric_key_length_bytes(len(main_key))
    cipher = ChaCha20_Poly1305.new(key=main_key, nonce=nonce)
    # cipher.update(aad)  UNUSED
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    encryption = {"ciphertext": ciphertext, "tag": tag}
    return encryption


def _decrypt_via_chacha20_poly1305(cipherdict: dict, key_dict: dict, verify: bool=True) -> bytes:
    """Decrypt a bytestring with the stream cipher ChaCha20.

    :param cipherdict: dict with fields "ciphertext", "tag" and "nonce" as bytestrings
    :param key_dict: 32 bytes long cryptographic key and nonce
    :param verify: whether to check tag/mac values of the ciphertext

    :return: the decrypted bytestring"""
    main_key = key_dict["key"]
    nonce = key_dict["nonce"]
    _check_symmetric_key_length_bytes(len(main_key))
    decipher = ChaCha20_Poly1305.new(key=main_key, nonce=nonce)
    # decipher.update(cipherdict["aad"])  UNUSED
    if verify:
        plaintext = decipher.decrypt_and_verify(ciphertext=cipherdict["ciphertext"], received_mac_tag=cipherdict["tag"])
    else:
        plaintext = decipher.decrypt(ciphertext=cipherdict["ciphertext"])
    return plaintext


def _encrypt_via_rsa_oaep(plaintext: bytes, key_dict: dict) -> dict:
    """Encrypt a bytestring with PKCS#1 RSA OAEP (asymmetric algo).

    :param plaintext: the bytes to cipher
    :param key_dict: dict with public RSA key object (RSA.RsaKey)

    :return: a dict with field `digest_list`, containing bytestring chunks of variable width."""
    key = key_dict["key"]
    _check_asymmetric_key_length_bits(key.size_in_bits())

    cipher = PKCS1_OAEP.new(key=key, hashAlgo=RSA_OAEP_HASHER)
    chunks = split_as_chunks(plaintext, chunk_size=RSA_OAEP_CHUNKS_SIZE, must_pad=False, accept_incomplete_chunk=True)

    encrypted_chunks = []
    for chunk in chunks:
        encrypted_chunk = cipher.encrypt(chunk)
        encrypted_chunks.append(encrypted_chunk)
    return dict(digest_list=encrypted_chunks)


def _decrypt_via_rsa_oaep(cipherdict: dict, key_dict: dict, verify: bool=True) -> bytes:
    """Decrypt a bytestring with PKCS#1 RSA OAEP (asymmetric algo).

    :param cipherdict: list of ciphertext chunks
    :param key_dict: dict with public RSA key object (RSA.RsaKey)
    :param verify: whether to check tag/mac values of the ciphertext
        (not applicable for this cipher)

    :return: the decrypted bytestring"""
    key = key_dict["key"]
    _check_asymmetric_key_length_bits(key.size_in_bits())

    decipher = PKCS1_OAEP.new(key, hashAlgo=RSA_OAEP_HASHER)

    encrypted_chunks = cipherdict["digest_list"]

    decrypted_chunks = []
    for encrypted_chunk in encrypted_chunks:
        decrypted_chunk = decipher.decrypt(encrypted_chunk)
        decrypted_chunks.append(decrypted_chunk)
    return b"".join(decrypted_chunks)


class EncryptionStreamBase:
    """General class of Encrytion Stream Node"""
    _is_finished = False

    BLOCK_SIZE = 1
    _remainder = b""  # Used when BLOCK_SIZE != 1

    _cipher = None  # Created by subclasses
    _hashers_dict = None

    def __init__(self, message_digest_algo=()):
        """ for each algo hash, create an instance that we store in a dictionary
            :param hash algo: different hash algorithm
        """
        hashers_dict = {}

        for hash_algo in message_digest_algo:
            module = importlib.import_module("Crypto.Hash.%s" % hash_algo)
            hasher_instance = module.new()
            hashers_dict[hash_algo] = hasher_instance

        self._hashers_dict = hashers_dict

    def _encrypt_aligned_data(self, plaintext):
        ciphertext = self._cipher.encrypt(plaintext)
        assert isinstance(ciphertext, bytes), repr(ciphertext)

        for hash_algo, hasher_instance in self._hashers_dict.items():
            hasher_instance.update(ciphertext)

        return ciphertext

    def encrypt(self, plaintext) -> bytes:
        """ Encrypt a bytestring and Hash a result (ciphertext) with the selected hash algorithm.

            return : a ciphertext
        """
        assert not self._is_finished
        if self.BLOCK_SIZE != 1:
            formatted_plaintext, self._remainder = utilities.split_as_formatted_data(self._remainder, plaintext,
                                                                                     block_size=self.BLOCK_SIZE)
            plaintext = formatted_plaintext
        ciphertext = self._encrypt_aligned_data(plaintext)
        return ciphertext

    def finalize(self) -> bytes:
        """ Finalize by the encryption the remainder?????????

            : block_size : The output length is guaranteed to be a multiple of block_size

            : return : a ciphertext
        """
        assert not self._is_finished
        self._is_finished = True

        ciphertext = b""

        if self.BLOCK_SIZE != 1:
            padded_remainder = pad(self._remainder, block_size=self.BLOCK_SIZE)
            ciphertext = self._encrypt_aligned_data(padded_remainder)
            self._remainder = b""

        return ciphertext

    def get_authentication_data(self) -> dict:
        """ Get metadata
        Digest all hash instance in a dictionnary , and return the hash as bytes.

        DO NOT OVERRIDE

            :return :  a dict with digest of hashers (ex: "SHA512": b"\sdddqsd")
        """
        assert self._is_finished

        return dict(integrity_tags=self._get_integrity_tags(),
                    message_digests=self._get_message_digests())

    def _get_message_digests(self) -> dict:
        hashes = {}
        for hash_algo, hasher_instance in self._hashers_dict.items():
            digest = hasher_instance.digest()
            assert 32 <= len(digest) <= 64, len(digest)
            hashes[hash_algo] = digest
        return hashes

    def _get_integrity_tags(self) -> dict:
        return {}


class AesCbcEncryptionNode(EncryptionStreamBase):
    """Encrypt a bytestring using AES (CBC mode)."""
    BLOCK_SIZE = AES.block_size

    def __init__(self, key_dict: dict, message_digest_algo=()):
        super().__init__(message_digest_algo=message_digest_algo)
        self._key = key_dict["key"]
        self._iv = key_dict["iv"]
        self._cipher = AES.new(self._key, AES.MODE_CBC, self._iv)


class AesEaxEncryptionNode(EncryptionStreamBase):
    """Encrypt a bytestring using AES (EAX mode)."""

    def __init__(self, key_dict: dict, message_digest_algo=()):
        super().__init__(message_digest_algo=message_digest_algo)
        self._key = key_dict["key"]
        self._nonce = key_dict["nonce"]
        self._cipher = AES.new(self._key, AES.MODE_EAX, nonce=self._nonce)

    def _get_integrity_tags(self) -> dict:
        return {"tag": self._cipher.digest()}


class Chacha20Poly1305EncryptionNode(EncryptionStreamBase):
    """Encrypt a bytestring using ChaCha20 with Poly1305 authentication."""

    def __init__(self, key_dict: dict, message_digest_algo=()):
        # TODO init CHACHA instance with this proper
        super().__init__(message_digest_algo=message_digest_algo)

        self._key = key_dict["key"]
        self._nonce = key_dict["nonce"]
        self._cipher = ChaCha20_Poly1305.new(key=self._key, nonce=self._nonce)

    def _get_integrity_tags(self) -> dict:
        return {"tag": self._cipher.digest()}


class StreamManager:
    """"Pipeline to encrypt data through several encryption nodes, down to an outout stream (e.g. file or ByteIO)"""

    def __init__(self, output_stream: BinaryIO, data_encryption_strata_extracts: list):

        self._output_stream = output_stream
        self._cipher_streams = []

        for data_encryption_stratum_extract in data_encryption_strata_extracts:
            data_encryption_algo = data_encryption_stratum_extract["encryption_algo"]  # FIXME RENAME THIS
            symmetric_key_dict = data_encryption_stratum_extract["symmetric_key_dict"]
            message_digest_algos = data_encryption_stratum_extract["message_digest_algos"]

            encryption_algo_conf = _get_encryption_type_conf(encryption_algo=data_encryption_algo)
            encryption_class = encryption_algo_conf["encryption_node_class"]

            if encryption_class is None:
                raise ValueError(
                    "Node class %s is not implemented" % data_encryption_algo)  # FIXME use custom exception class

            self._cipher_streams.append(
                encryption_class(key_dict=symmetric_key_dict, message_digest_algo=message_digest_algos))

    def encrypt_chunk(self, chunk):
        for cipher in self._cipher_streams:
            ciphertext = cipher.encrypt(chunk)
            chunk = ciphertext
        self._output_stream.write(ciphertext)

    def finalize(self):
        current_plaintext = b""

        for cipher in self._cipher_streams:
            ciphertext = b""
            if current_plaintext:
                ciphertext = cipher.encrypt(current_plaintext)
            ciphertext += cipher.finalize()
            current_plaintext = ciphertext
        self._output_stream.write(ciphertext)
        self._output_stream.flush()

    def get_authentication_data(self) -> list:
        authentication_data_list = []
        for cipher in self._cipher_streams:
            authentication_data_list.append(cipher.get_authentication_data())
        return authentication_data_list


ENCRYPTION_ALGOS_REGISTRY = dict(
    ## SYMMETRIC ENCRYPTION ##
    # ALL encryption/decryption routines must handle a "ciphertext" attribute on their cipherdict
    AES_CBC={"encryption_function": _encrypt_via_aes_cbc, "decryption_function": _decrypt_via_aes_cbc,
             "encryption_node_class": AesCbcEncryptionNode, "is_authenticated": False},
    AES_EAX={"encryption_function": _encrypt_via_aes_eax, "decryption_function": _decrypt_via_aes_eax,
             "encryption_node_class": AesEaxEncryptionNode, "is_authenticated": True},
    CHACHA20_POLY1305={
        "encryption_function": _encrypt_via_chacha20_poly1305,
        "decryption_function": _decrypt_via_chacha20_poly1305,
        "encryption_node_class": Chacha20Poly1305EncryptionNode,
        "is_authenticated": True
    },
    ## ASYMMETRIC ENCRYPTION ##
    RSA_OAEP={"encryption_function": _encrypt_via_rsa_oaep, "decryption_function": _decrypt_via_rsa_oaep,
              "encryption_node_class": None, "is_authenticated": False},
)

#: These values can be used as 'encryption_algo'.
SUPPORTED_ENCRYPTION_ALGOS = sorted(ENCRYPTION_ALGOS_REGISTRY.keys())
assert set(SUPPORTED_SYMMETRIC_KEY_ALGOS) <= set(SUPPORTED_ENCRYPTION_ALGOS)

AUTHENTICATED_ENCRYPTION_ALGOS = sorted(k for (k, v) in ENCRYPTION_ALGOS_REGISTRY.items() if v["is_authenticated"])
assert set(AUTHENTICATED_ENCRYPTION_ALGOS) <= set(SUPPORTED_ENCRYPTION_ALGOS)

STREAMABLE_ENCRYPTION_ALGOS = sorted(k for (k, v) in ENCRYPTION_ALGOS_REGISTRY.items() if v["encryption_node_class"])
assert set(STREAMABLE_ENCRYPTION_ALGOS) < set(SUPPORTED_ENCRYPTION_ALGOS)
