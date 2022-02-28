import importlib
import logging
from typing import BinaryIO

import Crypto.Hash.SHA512
from Crypto.Cipher import AES, ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

from wacryptolib import utilities
from wacryptolib.exceptions import EncryptionError, DecryptionError, DecryptionIntegrityError, OperationNotSupported
from wacryptolib.keygen import (
    _check_symmetric_key_length_bytes,
    SUPPORTED_SYMMETRIC_KEY_ALGOS,
    _check_asymmetric_key_length_bits,
)
from wacryptolib.utilities import split_as_chunks

logger = logging.getLogger(__name__)

RSA_OAEP_CHUNKS_SIZE = 60
RSA_OAEP_HASHER = Crypto.Hash.SHA512


def _get_cipher_algo_conf(cipher_algo):
    cipher_algo = cipher_algo.upper()
    if cipher_algo not in CIPHER_ALGOS_REGISTRY:
        raise ValueError("Unknown cipher type '%s'" % cipher_algo)

    cipher_algo_conf = CIPHER_ALGOS_REGISTRY[cipher_algo]
    return cipher_algo_conf


def encrypt_bytestring(plaintext: bytes, *, cipher_algo: str, key_dict: dict) -> dict:
    """Encrypt a bytestring with the selected algorithm for the given payload,
    using the provided key dict (which must contain keys/initializers of proper types and lengths).

    :return: dictionary with encryption data"""
    assert isinstance(plaintext, bytes), repr(plaintext)
    cipher_algo_conf = _get_cipher_algo_conf(cipher_algo=cipher_algo)
    encryption_function = cipher_algo_conf["encryption_function"]
    #### _check_symmetric_key_length_bytes(len(main_key))
    try:
        cipherdict = encryption_function(key_dict=key_dict, plaintext=plaintext)
    except ValueError as exc:
        raise EncryptionError("Failed %s encryption (%s)" % (cipher_algo, exc)) from exc
    return cipherdict


def decrypt_bytestring(
    cipherdict: dict, *, cipher_algo: str, key_dict: dict, verify_integrity_tags: bool = True
) -> bytes:
    """Decrypt a bytestring with the selected algorithm for the given encrypted data dict,
    using the provided key (which must be of a compatible type and length).

    :param cipherdict: dict with field "ciphertext" as bytestring and (depending
        on the cipher_algo) some other fields like "tag" or "nonce"
        as bytestrings
    :param cipher_algo: one of the supported encryption algorithms
    :param key_dict: dict with secret key fields
    :param verify_integrity_tags: whether to check MAC tags of the ciphertext

    :return: dictionary with encryption data."""
    cipher_algo_conf = _get_cipher_algo_conf(cipher_algo)
    decryption_function = cipher_algo_conf["decryption_function"]
    try:
        plaintext = decryption_function(
            key_dict=key_dict, cipherdict=cipherdict, verify_integrity_tags=verify_integrity_tags
        )
    except ValueError as exc:
        if "MAC check failed" in str(exc):  # Hackish check for pycryptodome
            raise DecryptionIntegrityError("Failed %s decryption authentication (%s)" % (cipher_algo, exc)) from exc
        raise DecryptionError("Failed %s decryption (%s)" % (cipher_algo, exc)) from exc
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
    plaintext_padded = pad(plaintext, block_size=AES.block_size)
    ciphertext = cipher.encrypt(plaintext_padded)
    cipherdict = {"ciphertext": ciphertext}
    return cipherdict


def _decrypt_via_aes_cbc(cipherdict: dict, key_dict: dict, verify_integrity_tags: bool = True) -> bytes:
    """Decrypt a bytestring using AES (CBC mode).

    :param cipherdict: dict with field "ciphertext" as bytestring
    :param key_dict: dict with AES cryptographic main key and nonce.
    :param verify_integrity_tags: whether to check MAC tags of the ciphertext
        (not applicable for this cipher)

    :return: the decrypted bytestring"""
    main_key = key_dict["key"]
    iv = key_dict["iv"]
    _check_symmetric_key_length_bytes(len(main_key))
    ciphertext = cipherdict["ciphertext"]
    decipher = AES.new(main_key, AES.MODE_CBC, iv=iv)
    plaintext_padded = decipher.decrypt(ciphertext)
    plaintext = unpad(plaintext_padded, block_size=AES.block_size)
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


def _decrypt_via_aes_eax(cipherdict: dict, key_dict: dict, verify_integrity_tags: bool = True) -> bytes:
    """Decrypt a bytestring using AES (EAX mode).

    :param cipherdict: dict with fields "ciphertext", "tag" as bytestrings
    :param key_dict: dict with AES cryptographic main key and nonce.
    :param verify_integrity_tags: whether to check MAC tags of the ciphertext

    :return: the decrypted bytestring"""
    main_key = key_dict["key"]
    nonce = key_dict["nonce"]
    _check_symmetric_key_length_bytes(len(main_key))
    decipher = AES.new(main_key, AES.MODE_EAX, nonce=nonce)
    plaintext = decipher.decrypt(cipherdict["ciphertext"])
    if verify_integrity_tags:
        decipher.verify(cipherdict["tag"])
    return plaintext


def _encrypt_via_chacha20_poly1305(plaintext: bytes, key_dict: dict) -> dict:
    """Encrypt a bytestring with the stream cipher ChaCha20.

    Additional cleartext data can be provided so that the
    generated mac tag also verifies its integrity.

    :param plaintext: the bytes to cipher
    :param key_dict: 32 bytes long cryptographic key and nonce

    :return: dict with fields "ciphertext", "tag", and "header" as bytestrings"""
    main_key = key_dict["key"]
    nonce = key_dict["nonce"]
    _check_symmetric_key_length_bytes(len(main_key))
    cipher = ChaCha20_Poly1305.new(key=main_key, nonce=nonce)
    # cipher.update(aad)  UNUSED
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    encryption = {"ciphertext": ciphertext, "tag": tag}
    return encryption


def _decrypt_via_chacha20_poly1305(cipherdict: dict, key_dict: dict, verify_integrity_tags: bool = True) -> bytes:
    """Decrypt a bytestring with the stream cipher ChaCha20.

    :param cipherdict: dict with fields "ciphertext", "tag" and "nonce" as bytestrings
    :param key_dict: 32 bytes long cryptographic key and nonce
    :param verify_integrity_tags: whether to check MAC tags of the ciphertext

    :return: the decrypted bytestring"""
    main_key = key_dict["key"]
    nonce = key_dict["nonce"]
    _check_symmetric_key_length_bytes(len(main_key))
    decipher = ChaCha20_Poly1305.new(key=main_key, nonce=nonce)
    # decipher.update(cipherdict["aad"])  UNUSED
    if verify_integrity_tags:
        plaintext = decipher.decrypt_and_verify(ciphertext=cipherdict["ciphertext"], received_mac_tag=cipherdict["tag"])
    else:
        plaintext = decipher.decrypt(ciphertext=cipherdict["ciphertext"])
    return plaintext


def _encrypt_via_rsa_oaep(plaintext: bytes, key_dict: dict) -> dict:
    """Encrypt a bytestring with PKCS#1 RSA OAEP (asymmetric algo).

    :param plaintext: the bytes to cipher
    :param key_dict: dict with PUBLIC RSA key object (RSA.RsaKey)

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


def _decrypt_via_rsa_oaep(cipherdict: dict, key_dict: dict, verify_integrity_tags: bool = True) -> bytes:
    """Decrypt a bytestring with PKCS#1 RSA OAEP (asymmetric algo).

    :param cipherdict: list of ciphertext chunks
    :param key_dict: dict with PRIVATE RSA key object (RSA.RsaKey)
    :param verify_integrity_tags: whether to check MAC tags of the ciphertext
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


class EncryptionNodeBase:
    """General class of Encrytion Stream Node"""

    _is_finished = False

    BLOCK_SIZE = 1
    _remainder = b""  # Used when BLOCK_SIZE != 1

    _cipher = None  # Created by subclasses
    _hashers_dict = None

    def __init__(self, payload_digest_algo=()):
        """Base class for nodes able to encrypt and digest data chunk by chunk.

        :param payload_digest_algo: different hash algorithms to apply on ciphertext
        """
        hashers_dict = {}

        for hash_algo in payload_digest_algo:
            module = importlib.import_module("Crypto.Hash.%s" % hash_algo)
            hasher_instance = module.new()
            hashers_dict[hash_algo] = hasher_instance

        self._hashers_dict = hashers_dict

    def _encrypt_aligned_payload(self, plaintext):
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
            formatted_plaintext, self._remainder = utilities.split_as_formatted_data(
                self._remainder, plaintext, block_size=self.BLOCK_SIZE
            )
            plaintext = formatted_plaintext
        ciphertext = self._encrypt_aligned_payload(plaintext)
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
            ciphertext = self._encrypt_aligned_payload(padded_remainder)
            self._remainder = b""

        return ciphertext

    def get_payload_integrity_tags(self) -> dict:
        assert self._is_finished
        return dict(payload_macs=self._get_payload_macs(), payload_digests=self._get_payload_digests())

    def _get_payload_digests(self) -> dict:
        hashes = {}
        for hash_algo, hasher_instance in self._hashers_dict.items():
            digest = hasher_instance.digest()
            assert 32 <= len(digest) <= 64, len(digest)
            hashes[hash_algo] = digest
        return hashes

    def _get_payload_macs(self) -> dict:
        return {}


class AesCbcEncryptionNode(EncryptionNodeBase):
    """Encrypt a bytestring using AES (CBC mode)."""

    BLOCK_SIZE = AES.block_size

    def __init__(self, key_dict: dict, payload_digest_algo=()):
        super().__init__(payload_digest_algo=payload_digest_algo)
        self._key = key_dict["key"]
        self._iv = key_dict["iv"]
        self._cipher = AES.new(self._key, AES.MODE_CBC, self._iv)


class AesEaxEncryptionNode(EncryptionNodeBase):
    """Encrypt a bytestring using AES (EAX mode)."""

    def __init__(self, key_dict: dict, payload_digest_algo=()):
        super().__init__(payload_digest_algo=payload_digest_algo)
        self._key = key_dict["key"]
        self._nonce = key_dict["nonce"]
        self._cipher = AES.new(self._key, AES.MODE_EAX, nonce=self._nonce)

    def _get_payload_macs(self) -> dict:
        return {"tag": self._cipher.digest()}


class Chacha20Poly1305EncryptionNode(EncryptionNodeBase):
    """Encrypt a bytestring using ChaCha20 with Poly1305 authentication."""

    def __init__(self, key_dict: dict, payload_digest_algo=()):
        super().__init__(payload_digest_algo=payload_digest_algo)

        self._key = key_dict["key"]
        self._nonce = key_dict["nonce"]
        self._cipher = ChaCha20_Poly1305.new(key=self._key, nonce=self._nonce)

    def _get_payload_macs(self) -> dict:
        return {"tag": self._cipher.digest()}


class PayloadEncryptionPipeline:
    """PRIVATE API FOR NOW

    Pipeline to encrypt data through several encryption nodes, and stream it to an output
    binary stream (e.g. file or ByteIO)
    """

    _finalized = False

    def __init__(self, output_stream: BinaryIO, payload_cipher_layer_extracts: list):

        self._output_stream = output_stream
        self._cipher_streams = []

        for payload_cipher_layer_extract in payload_cipher_layer_extracts:
            payload_cipher_algo = payload_cipher_layer_extract["cipher_algo"]
            symkey = payload_cipher_layer_extract["symkey"]
            payload_digest_algos = payload_cipher_layer_extract["payload_digest_algos"]

            cipher_algo_conf = _get_cipher_algo_conf(cipher_algo=payload_cipher_algo)
            encryption_class = cipher_algo_conf["encryption_node_class"]

            if encryption_class is None:
                raise OperationNotSupported(
                    "Node class %s is not implemented" % payload_cipher_algo
                )  # FIXME use custom exception class

            self._cipher_streams.append(encryption_class(key_dict=symkey, payload_digest_algo=payload_digest_algos))

    def encrypt_chunk(self, chunk):
        assert not self._finalized
        for cipher in self._cipher_streams:
            ciphertext = cipher.encrypt(chunk)
            chunk = ciphertext
        self._output_stream.write(ciphertext)

    def finalize(self):
        assert not self._finalized
        current_plaintext = b""
        for cipher in self._cipher_streams:
            ciphertext = b""
            if current_plaintext:
                ciphertext = cipher.encrypt(current_plaintext)
            ciphertext += cipher.finalize()
            current_plaintext = ciphertext
        self._output_stream.write(ciphertext)
        self._output_stream.flush()
        self._finalized = True

    def get_payload_integrity_tags(self) -> list:
        integrity_tags_list = []
        for cipher in self._cipher_streams:
            integrity_tags_list.append(cipher.get_payload_integrity_tags())
        return integrity_tags_list


CIPHER_ALGOS_REGISTRY = dict(
    ## SYMMETRIC ENCRYPTION ##
    # ALL encryption/decryption routines must handle a "ciphertext" attribute on their cipherdict
    AES_CBC={
        "encryption_function": _encrypt_via_aes_cbc,
        "decryption_function": _decrypt_via_aes_cbc,
        "encryption_node_class": AesCbcEncryptionNode,
        "is_authenticated": False,
    },
    AES_EAX={
        "encryption_function": _encrypt_via_aes_eax,
        "decryption_function": _decrypt_via_aes_eax,
        "encryption_node_class": AesEaxEncryptionNode,
        "is_authenticated": True,
    },
    CHACHA20_POLY1305={
        "encryption_function": _encrypt_via_chacha20_poly1305,
        "decryption_function": _decrypt_via_chacha20_poly1305,
        "encryption_node_class": Chacha20Poly1305EncryptionNode,
        "is_authenticated": True,
    },
    ## ASYMMETRIC ENCRYPTION (proper part of the keypair must be provided) ##
    RSA_OAEP={
        "encryption_function": _encrypt_via_rsa_oaep,
        "decryption_function": _decrypt_via_rsa_oaep,
        "encryption_node_class": None,
        "is_authenticated": False,
    },
)

#: These values can be used as 'cipher_algo'.
SUPPORTED_CIPHER_ALGOS = sorted(CIPHER_ALGOS_REGISTRY.keys())
assert set(SUPPORTED_SYMMETRIC_KEY_ALGOS) <= set(SUPPORTED_CIPHER_ALGOS)

AUTHENTICATED_CIPHER_ALGOS = sorted(k for (k, v) in CIPHER_ALGOS_REGISTRY.items() if v["is_authenticated"])
assert set(AUTHENTICATED_CIPHER_ALGOS) <= set(SUPPORTED_CIPHER_ALGOS)

STREAMABLE_CIPHER_ALGOS = sorted(k for (k, v) in CIPHER_ALGOS_REGISTRY.items() if v["encryption_node_class"])
assert set(STREAMABLE_CIPHER_ALGOS) < set(SUPPORTED_CIPHER_ALGOS)
