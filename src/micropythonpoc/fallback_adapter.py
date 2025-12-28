# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import hashlib
import rsa
import pkcs1
import pyaes


# HASHER FACTORY #


_DESIRED_HASH_ALGOS =  ["SHA256", "SHA512", "SHA3_256", "SHA3_512"]
IMPLEMENTED_HASH_ALGOS = [_x for _x in _DESIRED_HASH_ALGOS if hasattr(hashlib, _x.lower())]


_HASH_ALGO_TO_OID = {
    # See Pycryptodome sources for OIDs
    "SHA256": "2.16.840.1.101.3.4.2.1",
    "SHA512": "2.16.840.1.101.3.4.2.3",
    "SHA3_256": "2.16.840.1.101.3.4.2.8",
    "SHA3_512": "2.16.840.1.101.3.4.2.10",
}


class HasherCompatibilityLayer():
    def __init__(self, hasher):
        self._hasher = hasher

    def __getattr__(self, attr):
        return getattr(self._hasher, attr)

    @property
    def oid(self):
        return _HASH_ALGO_TO_OID[self._hasher.name.upper()]

    def new(self, *args, **kwargs):
        # HASH instances can't be normally instantiated when C-based...
        return hashlib.new(self._hasher.name.lower())


def get_hasher_instance(hash_algo: str) -> HasherCompatibilityLayer:
    hasher_instance = hashlib.new(hash_algo.lower())
    return HasherCompatibilityLayer(hasher_instance)


class AESModeCBCCompatibilityLayer:
    def __init__(self, key, iv):
        self._cipher = cipher = pyaes.Encrypter(
            pyaes.AESModeOfOperationCBC(key, iv=iv),
            # For compatibility with pycryptodome,
            # we do not want any padding at this level
            padding=pyaes.PADDING_NONE)

    def encrypt(self, plaintext):
        assert len(plaintext) % 16 == 0  # ALREADY PADDED TO BLOCK SIZE
        ciphertext = self._cipher.feed(plaintext)
        _buffer = self._cipher._buffer
        # Normalized buffer (because plaintext was already padded):
        assert len(_buffer) in (0, 16), len(_buffer)
        return ciphertext

    def finalize(self):
        # Returns last bytes (with NO padding)
        return self._cipher.feed(None)


def build_aes_cbc_encrypter(key, iv):
    return AESModeCBCCompatibilityLayer(key, iv=iv)


def encrypt_via_aes_cbc(plaintext, key, iv):
    # Default padding is PKCS7
    cipher = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv=iv))
    ciphertext = cipher.feed(plaintext)
    ciphertext += cipher.feed()
    return ciphertext


def decrypt_via_aes_cbc(ciphertext, key, iv):
    # Default padding is PKCS7
    decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key, iv))
    decrypted = decrypter.feed(ciphertext)
    decrypted += decrypter.feed()
    return decrypted


def _prevent_passphrase_usage_for_rsa_key():
    raise NotImplementedError(
        "RSA key with passphrase is not supported in fallback implementation")


def import_rsa_key_from_pem(key_pem, passphrase=None):
    import rsa  # Not well supported by micropython, due to pyasn1 code

    if passphrase:
        _prevent_passphrase_usage_for_rsa_key()

    # We use python-rsa for parsing, but then pkcs1 package for encryption/decryption
    try:
        _pyrsa_format_public_key = rsa.PublicKey.load_pkcs1_openssl_pem(key_pem)
        _pkcs1_format_public_key = pkcs1.keys.RsaPublicKey(
            _pyrsa_format_public_key.n, _pyrsa_format_public_key.e)
        return _pkcs1_format_public_key
    except ValueError:
        _pyrsa_format_private_key = rsa.PrivateKey.load_pkcs1(key_pem)
        _pkcs1_format_private_key = pkcs1.keys.RsaPrivateKey(
            _pyrsa_format_private_key.n, _pyrsa_format_private_key.d)
        return _pkcs1_format_private_key


''' NOT IMPLEMENTED YET - ABORTED!
def export_rsa_key_to_pem(private_key, passphrase=None):  # FIXME not always private key
    if passphrase:
        _prevent_passphrase_usage_for_rsa_key()
    ...
'''


def encrypt_via_rsa_oaep(plaintext_chunks: list[bytes], public_key) -> list[bytes]:
    """We expect each plaintext chunk to be small enough for the RSA key size"""
    encrypter = lambda chunk: pkcs1.rsaes_oaep.encrypt(public_key, message=chunk, label=b'',
                             hash_class=hashlib.sha512)
                    # TODO: ARGUMENTS mgf=mgf.mgf1, seed=None, rnd=default_crypto_random))
    ciphertext_chunks = [encrypter(chunk) for chunk in plaintext_chunks]
    return ciphertext_chunks


def decrypt_via_rsa_oaep(ciphertext_chunks: list[bytes], private_key) -> list[bytes]:
    decrypter = lambda chunk: pkcs1.rsaes_oaep.decrypt(private_key, message=chunk,
                                         label=b'', hash_class=hashlib.sha512)
                     # TODO: ARGUMENTS mgf=mgf.mgf1, seed=None, rnd=default_crypto_random))
    cleartext_chunks = [decrypter(chunk) for chunk in ciphertext_chunks]
    return cleartext_chunks


def rsa_key_class_fetcher():
    # Tuple usable in isinstance()
    return (pkcs1.keys.RsaPublicKey, pkcs1.keys.RsaPrivateKey)


def generate_rsa_keypair(key_length_bits):
    public_key, private_key = pkcs1.keys.generate_key_pair(
        primality_algorithm="solovay-strassen",  # Or [gmpy-]miller-rabin
        size=key_length_bits, strict_size=True, e=65537)  # Same 'e' as pycryptodome
    return public_key, private_key

