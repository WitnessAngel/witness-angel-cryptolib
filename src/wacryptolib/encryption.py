import logging

import Crypto.Hash.SHA512
from Crypto.Cipher import AES, ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from wacryptolib.exceptions import EncryptionError, DecryptionError
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


#FIXME make it return BYTESTRING ALWAYS, no need to jsonify them!
#FIXME key_dict name is wrong in the case of RSA_OAEP!!
def encrypt_bytestring(plaintext: bytes, *, encryption_algo: str, key_dict: dict) -> dict:
    """Encrypt a bytestring with the selected algorithm for the given payload,
    using the provided key dict (which must contain keys/initializers of proper types and lengths).

    :return: dictionary with encryption data"""
    assert isinstance(plaintext, bytes), repr(plaintext)
    encryption_type_conf = _get_encryption_type_conf(encryption_algo=encryption_algo)
    encryption_function = encryption_type_conf["encryption_function"]
    try:
        cipherdict = encryption_function(key_dict=key_dict, plaintext=plaintext)
    except ValueError as exc:
        raise EncryptionError("Failed %s encryption (%s)" % (encryption_algo, exc)) from exc
    return cipherdict


def decrypt_bytestring(
    cipherdict: dict, *, encryption_algo: str, key_dict: dict
) -> bytes:  # Fixme rename encryption_algo to decryption_algo? Or normalize?
    """Decrypt a bytestring with the selected algorithm for the given encrypted data dict,
    using the provided key (which must be of a compatible type and length).

    :return: dictionary with encryption data."""
    encryption_type_conf = _get_encryption_type_conf(encryption_algo)
    decryption_function = encryption_type_conf["decryption_function"]
    try:
        plaintext = decryption_function(key_dict=key_dict, cipherdict=cipherdict)
    except ValueError as exc:
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


def _decrypt_via_aes_cbc(cipherdict: dict, key_dict: dict) -> bytes:
    """Decrypt a bytestring using AES (CBC mode).

    :param cipherdict: dict with field "ciphertext" as bytestring
    :param key_dict: dict with AES cryptographic main key and nonce.

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


def _decrypt_via_aes_eax(cipherdict: dict, key_dict: dict) -> bytes:
    """Decrypt a bytestring using AES (EAX mode).

    :param cipherdict: dict with fields "ciphertext", "tag" as bytestrings
    :param key_dict: dict with AES cryptographic main key and nonce.

    :return: the decrypted bytestring"""
    main_key = key_dict["key"]
    nonce = key_dict["nonce"]
    _check_symmetric_key_length_bytes(len(main_key))
    decipher = AES.new(main_key, AES.MODE_EAX, nonce=nonce)
    plaintext = decipher.decrypt(cipherdict["ciphertext"])
    decipher.verify(cipherdict["tag"])
    return plaintext


def _encrypt_via_chacha20_poly1305(plaintext: bytes, key_dict: dict, aad: bytes = b"header") -> dict:
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
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    encryption = {"ciphertext": ciphertext, "tag": tag, "aad": aad}
    return encryption


def _decrypt_via_chacha20_poly1305(cipherdict: dict, key_dict: dict) -> bytes:
    """Decrypt a bytestring with the stream cipher ChaCha20.

    :param cipherdict: dict with fields "ciphertext", "tag", "nonce" and "header" as bytestrings
    :param key_dict: 32 bytes long cryptographic key and nonce

    :return: the decrypted bytestring"""
    main_key = key_dict["key"]
    nonce = key_dict["nonce"]
    _check_symmetric_key_length_bytes(len(main_key))
    decipher = ChaCha20_Poly1305.new(key=main_key, nonce=nonce)
    decipher.update(cipherdict["aad"])
    plaintext = decipher.decrypt_and_verify(ciphertext=cipherdict["ciphertext"], received_mac_tag=cipherdict["tag"])
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


def _decrypt_via_rsa_oaep(cipherdict: dict, key_dict: dict) -> bytes:
    """Decrypt a bytestring with PKCS#1 RSA OAEP (asymmetric algo).

    :param cipherdict: list of ciphertext chunks
    :param key_dict: dict with public RSA key object (RSA.RsaKey)

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


ENCRYPTION_ALGOS_REGISTRY = dict(
    ## SYMMETRIC ENCRYPTION ##
    AES_CBC={"encryption_function": _encrypt_via_aes_cbc, "decryption_function": _decrypt_via_aes_cbc},
    AES_EAX={"encryption_function": _encrypt_via_aes_eax, "decryption_function": _decrypt_via_aes_eax},
    CHACHA20_POLY1305={
        "encryption_function": _encrypt_via_chacha20_poly1305,
        "decryption_function": _decrypt_via_chacha20_poly1305,
    },
    ## ASYMMETRIC ENCRYPTION ##
    RSA_OAEP={"encryption_function": _encrypt_via_rsa_oaep, "decryption_function": _decrypt_via_rsa_oaep},
)

#: These values can be used as 'encryption_algo'.
SUPPORTED_ENCRYPTION_ALGOS = sorted(ENCRYPTION_ALGOS_REGISTRY.keys())
assert set(SUPPORTED_SYMMETRIC_KEY_ALGOS) <= set(SUPPORTED_ENCRYPTION_ALGOS)
