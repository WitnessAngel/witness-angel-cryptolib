# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import logging, os, sys

logger = logging.getLogger(__name__)


def __monkey_patch_pycryptodome_compiled_internals():

    # WE MONKEY PATCH PYCRYPTODOME INTERNALS TO BYPASS SOME ".so" objects #

    class FakePycryptodomeExtensionLib:
        @staticmethod
        def have_aes_ni():
            return False

        @staticmethod
        def have_clmul():
            return False

    def fake_load_pycryptodome_raw_lib(name, cdecl):
        if name in ["Crypto.Math._modexp"]:  # We force automatic fallback for some libs, inside pycryptodome
            raise ImportError("Fake ImportError to force failure on non-vital extension %s" % name)
        return FakePycryptodomeExtensionLib()

    assert not sys.modules.get("Crypto.Util._raw_api")  # Must NOT have been already imported by another submodule
    import Crypto.Util._raw_api

    assert Crypto.Util._raw_api.load_pycryptodome_raw_lib
    Crypto.Util._raw_api.load_pycryptodome_raw_lib = fake_load_pycryptodome_raw_lib

    def patched_strxor(term1, term2, output=None):
        return bytes([_a ^ _b for (_a, _b) in zip(term1, term2)])

    assert not sys.modules.get("Crypto.Util.strxor")
    import Crypto.Util.strxor

    assert Crypto.Util.strxor.strxor
    Crypto.Util.strxor.strxor = patched_strxor

    import hashlib, importlib

    def _generate_patched_hasher(hash_algo):
        hasher_factory = getattr(hashlib, hash_algo.lower())

        class PatchedHasherClass:
            def __init__(self, *args, **kwargs):
                self._hasher = hasher_factory(*args, **kwargs)

            def update(self, msg):
                return self._hasher.update(msg)

            def digest(self):
                return self._hasher.digest()

            def copy(self):
                return self._hasher.copy()

            def new(self, *args, **kwargs):
                return hasher_factory(*args, **kwargs)

            @property
            def digest_size(self):
                return self._hasher.digest_size

            @property
            def block_size(self):
                return self._hasher.block_size

        return PatchedHasherClass

    PATCHABLE_HASH_ALGOS = [
        "SHA1",
        "MD5",
        "SHA512",
        "SHA256",
        "SHA512",
        "SHA3_256",
        "SHA3_512",
    ]  # Must be bigger than SUPPORTED_HASH_ALGOS of wacryptolib

    for patchable_hash_algo in PATCHABLE_HASH_ALGOS:
        patched_hash_class = _generate_patched_hasher(patchable_hash_algo)
        module = importlib.import_module("Crypto.Hash.%s" % patchable_hash_algo)
        class_name = patchable_hash_algo + ("_" if "_" in patchable_hash_algo else "") + "Hash"
        assert hasattr(module, class_name), (module, class_name)
        setattr(module, class_name, patched_hash_class)
        setattr(
            module,
            "new",
            lambda *args, patched_hash_class=patched_hash_class, **kwargs: patched_hash_class(*args, **kwargs),
        )
        if hasattr(module, "_pbkdf2_hmac_assist"):
            del module._pbkdf2_hmac_assist  # Force slow code path, not requiring advanced hasher capabilities

    import Crypto.Cipher.AES
    import pyaes  # BEWARE - MUST BE INSTALLED!

    def patched_aes_new(key, mode, iv, *args, **kwargs):
        assert mode == Crypto.Cipher.AES.MODE_CBC, mode
        cipher = pyaes.AESModeOfOperationCBC(key=key, iv=iv)
        cipher.block_size = Crypto.Cipher.AES.block_size
        original_cipher_encrypt = cipher.encrypt
        original_cipher_decrypt = cipher.decrypt

        def patched_encrypt(plaintext):
            ciphertext = b""
            while plaintext:
                chunk = plaintext[: cipher.block_size]
                plaintext = plaintext[cipher.block_size :]
                ciphertext += original_cipher_encrypt(chunk)
            return ciphertext

        cipher.encrypt = patched_encrypt

        def patched_decrypt(ciphertext):
            plaintext = b""
            while ciphertext:
                chunk = ciphertext[: cipher.block_size]
                ciphertext = ciphertext[cipher.block_size :]
                plaintext += original_cipher_decrypt(chunk)
            return plaintext

        cipher.decrypt = patched_decrypt

        return cipher

    Crypto.Cipher.AES.new = patched_aes_new

    from Crypto.Cipher import PKCS1_OAEP

    def patched_oaep_decode(em, lHash, db):
        # Replace the 2023 C implementation by the old Python one
        from Crypto.Util.strxor import strxor
        from Crypto.Util.py3compat import bord

        y = em[0]
        hLen = len(lHash)
        one_pos = hLen + db[hLen:].find(b"\x01")
        lHash1 = db[:hLen]
        invalid = bord(y) | int(one_pos < hLen)
        hash_compare = strxor(lHash1, lHash)
        for x in hash_compare:
            invalid |= bord(x)
        for x in db[hLen:one_pos]:
            invalid |= bord(x)
        return -1 if invalid else (one_pos + 1)

    PKCS1_OAEP.oaep_decode = patched_oaep_decode


try:
    # Impossible to use pycryptodome package on iOS due to forbidden dlopen()...
    import ios

    _patch_pycryptodome_internals = True
except ImportError:
    _patch_pycryptodome_internals = True if os.getenv("FORCE_WACRYPTOLIB_FALLBACK_BACKEND") else False


if _patch_pycryptodome_internals:
    # BEWARE - to test this fallback mode on a normal PC, erase all .so/.dll files of pycrptodome, and for use_fallback_backend to True #
    logger.info("Full pycryptodome lib not available under this environment, injecting fake C extensions")
    __monkey_patch_pycryptodome_compiled_internals()


# Utilities #


AES_BLOCK_SIZE = 16


def pad_bytes(*args, **kwargs):
    from Crypto.Util.Padding import pad

    return pad(*args, **kwargs)


def unpad_bytes(*args, **kwargs):
    from Crypto.Util.Padding import unpad

    return unpad(*args, **kwargs)


# AES CBC CIPHER #


def build_aes_cbc_encrypter(key, iv):
    from Crypto.Cipher import AES
    # Same construct works for both encryption and decryption, here
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher


def encrypt_via_aes_cbc(plaintext, key, iv):
    cipher = build_aes_cbc_encrypter(key=key, iv=iv)
    plaintext_padded = pad_bytes(plaintext, block_size=AES_BLOCK_SIZE)
    ciphertext = cipher.encrypt(plaintext_padded)
    return ciphertext


def decrypt_via_aes_cbc(ciphertext, key, iv):
    cipher = build_aes_cbc_encrypter(key=key, iv=iv)  # Also for decryption
    plaintext_padded = cipher.decrypt(ciphertext)
    plaintext = unpad_bytes(plaintext_padded, block_size=AES_BLOCK_SIZE)
    return plaintext


# AES EAX CIPHER #


def build_aes_eax_cipher(key, nonce):
    from Crypto.Cipher import AES

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher


def encrypt_via_aes_eax(plaintext, key, nonce):
    cipher = build_aes_eax_cipher(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag


def decrypt_via_aes_eax(ciphertext, tag, key, nonce, verify_integrity_tags):
    cipher = build_aes_eax_cipher(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    if verify_integrity_tags:
        cipher.verify(tag)
    return plaintext


# CHACHA20 POLY1305 CIPHER #


def build_chacha20_poly1305_cipher(key, nonce):
    from Crypto.Cipher import ChaCha20_Poly1305

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    # cipher.update(aad)  NOPE UNUSED
    return cipher


def encrypt_via_chacha20_poly1305(plaintext, key, nonce):
    cipher = build_chacha20_poly1305_cipher(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag


def decrypt_via_chacha20_poly1305(ciphertext, tag, key, nonce, verify_integrity_tags):
    cipher = build_chacha20_poly1305_cipher(key=key, nonce=nonce)
    if verify_integrity_tags:
        plaintext = cipher.decrypt_and_verify(ciphertext=ciphertext, received_mac_tag=tag)
    else:
        plaintext = cipher.decrypt(ciphertext=ciphertext)
    return plaintext


# RSA OAEP CIPHER #


def _build_rsa_oaep_cipher(key):
    # Returned object has encrypt() and decrypt() methods
    import Crypto.Hash.SHA512
    from Crypto.Cipher import PKCS1_OAEP

    return PKCS1_OAEP.new(key=key, hashAlgo=Crypto.Hash.SHA512, label=b"")


def encrypt_via_rsa_oaep(plaintext_chunks: list[bytes], public_key) -> list[bytes]:
    """We expect each plaintext chunk to be small enough for the RSA key size"""
    encrypter = _build_rsa_oaep_cipher(public_key).encrypt
    ciphertext_chunks = [encrypter(chunk) for chunk in plaintext_chunks]
    return ciphertext_chunks


def decrypt_via_rsa_oaep(ciphertext_chunks: list[bytes], private_key) -> list[bytes]:
    decrypter = _build_rsa_oaep_cipher(private_key).decrypt
    cleartext_chunks = [decrypter(chunk) for chunk in ciphertext_chunks]
    return cleartext_chunks


# RSA KEY GENERATION, AND IMPORT/EXPORT #


def rsa_key_class_fetcher():
    from Crypto.PublicKey import RSA

    return RSA.RsaKey


def dsa_key_class_fetcher():
    from Crypto.PublicKey import DSA

    return DSA.DsaKey


def ecc_key_class_fetcher():
    from Crypto.PublicKey import ECC

    return ECC.EccKey


def generate_rsa_keypair(key_length_bits):
    from Crypto.PublicKey import RSA

    private_key = RSA.generate(key_length_bits)
    public_key = private_key.publickey()
    return public_key, private_key


def generate_dsa_keypair(key_length_bits):
    from Crypto.PublicKey import DSA

    private_key = DSA.generate(key_length_bits)
    public_key = private_key.publickey()
    return public_key, private_key


def generate_ecc_keypair(curve):
    from Crypto.PublicKey import ECC

    if curve not in ECC._curves:
        raise ValueError("Unexisting ECC curve '%s', must be one of '%s'" % (curve, sorted(ECC._curves.all_names)))
    private_key = ECC.generate(curve=curve)
    public_key = private_key.public_key()
    return public_key, private_key


def import_rsa_key_from_pem(*args, **kwargs):
    from Crypto.PublicKey import RSA

    return RSA.import_key(*args, **kwargs)


def import_dsa_key_from_pem(*args, **kwargs):
    from Crypto.PublicKey import DSA

    return DSA.import_key(*args, **kwargs)


def import_ecc_key_from_pem(*args, **kwargs):
    from Crypto.PublicKey import ECC

    return ECC.import_key(*args, **kwargs)


def export_rsa_key_to_pem(private_key, passphrase=None):  # FIXME not always private key
    extra_params = (
        dict(passphrase=passphrase, pkcs=8, protection="PBKDF2WithHMAC-SHA1AndAES256-CBC") if passphrase else {}
    )
    return private_key.export_key(format="PEM", **extra_params)


def export_dsa_key_to_pem(private_key, passphrase=None):  # FIXME not always private key
    extra_params = (
        dict(passphrase=passphrase, pkcs8=True, protection="PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC") if passphrase else {}
    )
    return private_key.export_key(format="PEM", **extra_params)


def export_ecc_key_to_pem(private_key, passphrase=None):  # FIXME not always private key
    extra_params = (
        dict(passphrase=passphrase, use_pkcs8=True, protection="PBKDF2WithHMAC-SHA1AndAES128-CBC") if passphrase else {}
    )
    return private_key.export_key(format="PEM", **extra_params)


# MESSAGE SIGNATURES #


def sign_with_pss(message, private_key):
    from Crypto.Signature import pss

    signer = pss.new(private_key)
    signature = signer.sign(message)
    return signature


def verify_with_pss(message, signature, public_key):
    from Crypto.Signature import pss

    verifier = pss.new(public_key)
    verifier.verify(message, signature)  # Raise ValueError if failure


def sign_with_dss(message, private_key):
    from Crypto.Signature import DSS

    signer = DSS.new(private_key, "fips-186-3")
    signature = signer.sign(message)
    return signature


def verify_with_dss(message, signature, public_key):
    from Crypto.Signature import DSS

    verifier = DSS.new(public_key, "fips-186-3")
    verifier.verify(message, signature)  # Raise ValueError if failure
