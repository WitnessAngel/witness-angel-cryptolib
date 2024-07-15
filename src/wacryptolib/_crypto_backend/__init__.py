# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os

import sys

logger = logging.getLogger(__name__)

try:
    # Impossible to use pycryptodome package on iOS due to forbidden dlopen()...
    import ios

    use_fallback_backend = True
except ImportError:
    use_fallback_backend = True if os.getenv("FORCE_WACRYPTOLIB_FALLBACK_BACKEND") else False


if use_fallback_backend:
    # BEWARE - to test this fallback mode on a normal PC, erase all .so/.dll files of pycrptodome, and for use_fallback_backend to True #

    logger.info("Full pycryptodome lib not available under this environment, injecting fake C extensions")

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


from .pycryptodome import (
    encrypt_via_aes_cbc,
    decrypt_via_aes_cbc,
    encrypt_via_aes_eax,
    decrypt_via_aes_eax,
    encrypt_via_chacha20_poly1305,
    decrypt_via_chacha20_poly1305,
    build_rsa_oaep_cipher,
    build_aes_cbc_cipher,
    build_aes_eax_cipher,
    build_chacha20_poly1305_cipher,
    AES_BLOCK_SIZE,
)
from .pycryptodome import (
    generate_rsa_keypair,
    generate_dsa_keypair,
    generate_ecc_keypair,
    import_rsa_key_from_pem,
    import_dsa_key_from_pem,
    import_ecc_key_from_pem,
    export_rsa_key_to_pem,
    export_dsa_key_to_pem,
    export_ecc_key_to_pem,
    rsa_key_class_fetcher,
    dsa_key_class_fetcher,
    ecc_key_class_fetcher,
)
from .pycryptodome import get_random_bytes, pad_bytes, unpad_bytes, get_hasher_instance
from .pycryptodome import shamir_split, shamir_combine
from .pycryptodome import sign_with_pss, verify_with_pss, sign_with_dss, verify_with_dss
