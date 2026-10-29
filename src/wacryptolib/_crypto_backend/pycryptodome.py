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

        def __getattr__(self, name):
            # Algorithms without pure python implementation (ECC, DES3...) end up here
            raise AttributeError("Native function %r of pycryptodome is not available in fallback backend" % name)

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

    PATCHABLE_HASH_ALGOS = {  # With their OIDs, which pycryptodome only exposes on (unusable here) hasher instances
        "SHA1": "1.3.14.3.2.26",
        "MD5": "1.2.840.113549.2.5",
        "SHA256": "2.16.840.1.101.3.4.2.1",
        "SHA512": "2.16.840.1.101.3.4.2.3",
        "SHA3_256": "2.16.840.1.101.3.4.2.8",
        "SHA3_512": "2.16.840.1.101.3.4.2.10",
    }  # Must be bigger than SUPPORTED_HASH_ALGOS of wacryptolib

    for patchable_hash_algo in PATCHABLE_HASH_ALGOS:
        patched_hash_class = _generate_patched_hasher(patchable_hash_algo)
        module = importlib.import_module("Crypto.Hash.%s" % patchable_hash_algo)
        class_name = patchable_hash_algo + ("_" if "_" in patchable_hash_algo else "") + "Hash"
        assert hasattr(module, class_name), (module, class_name)
        patched_hash_class.oid = PATCHABLE_HASH_ALGOS[patchable_hash_algo]  # Needed e.g. by DSS signatures
        setattr(module, class_name, patched_hash_class)
        setattr(
            module,
            "new",
            lambda *args, patched_hash_class=patched_hash_class, **kwargs: patched_hash_class(*args, **kwargs),
        )
        if hasattr(module, "_pbkdf2_hmac_assist"):
            del module._pbkdf2_hmac_assist  # Force slow code path, not requiring advanced hasher capabilities

    import Crypto.Hash.BLAKE2s

    def patched_blake2s_new(data=None, digest_bits=256, key=b""):
        # Used by MAC verify() methods, to compare tags in constant time
        return hashlib.blake2s(data or b"", digest_size=digest_bits // 8, key=key)

    Crypto.Hash.BLAKE2s.new = patched_blake2s_new

    import Crypto.Cipher.AES
    import pyaes  # BEWARE - MUST BE INSTALLED!

    class PyaesCipherAdapter:
        """Pycryptodome-like cipher API, over a pyaes cipher (which handles one block per call, except for CTR)"""

        block_size = Crypto.Cipher.AES.block_size

        def __init__(self, pyaes_cipher, chunk_size):
            self._pyaes_cipher = pyaes_cipher
            self._chunk_size = chunk_size

        def _process(self, method, data, output):
            assert output is None, "Unsupported output parameter"
            data = bytes(data)  # pyaes doesn't support memoryviews
            chunk_size = self._chunk_size or len(data) or 1
            return b"".join(method(data[i : i + chunk_size]) for i in range(0, len(data), chunk_size))

        def encrypt(self, plaintext, output=None):
            return self._process(self._pyaes_cipher.encrypt, plaintext, output)

        def decrypt(self, ciphertext, output=None):
            return self._process(self._pyaes_cipher.decrypt, ciphertext, output)

    original_aes_new = Crypto.Cipher.AES.new

    def patched_aes_new(key, mode, *args, **kwargs):
        AES = Crypto.Cipher.AES
        if mode == AES.MODE_CBC:
            (iv,) = args or (kwargs["iv"],)
            return PyaesCipherAdapter(pyaes.AESModeOfOperationCBC(key, iv=iv), chunk_size=AES.block_size)
        if mode == AES.MODE_ECB:
            return PyaesCipherAdapter(pyaes.AESModeOfOperationECB(key), chunk_size=AES.block_size)
        if mode == AES.MODE_CTR and kwargs.get("nonce") == b"":
            # Full-block counter, as used by EAX mode
            counter = pyaes.Counter(initial_value=kwargs["initial_value"])
            return PyaesCipherAdapter(pyaes.AESModeOfOperationCTR(key, counter=counter), chunk_size=None)
        if mode == AES.MODE_EAX:
            return original_aes_new(key, mode, *args, **kwargs)  # Pure python, relying on modes above
        raise NotImplementedError("AES mode %s is not supported by fallback backend" % mode)

    Crypto.Cipher.AES.new = patched_aes_new

    import Crypto.Cipher.ChaCha20_Poly1305
    from .chacha20_poly1305 import ChaCha20Poly1305Cipher

    Crypto.Cipher.ChaCha20_Poly1305.new = lambda key, nonce: ChaCha20Poly1305Cipher(key, nonce=nonce)

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


def _pad_bytes_pkcs7_internal(*args, **kwargs):
    # Direct pycrotodome version rather than our utilities
    from Crypto.Util.Padding import pad

    return pad(*args, **kwargs)


def _unpad_bytes_pkcs7_internal(*args, **kwargs):
    # Direct pycrotodome version rather than our utilities
    from Crypto.Util.Padding import unpad

    return unpad(*args, **kwargs)


# HASHER FACTORY #

IMPLEMENTED_HASH_ALGOS = ["SHA256", "SHA512", "SHA3_256", "SHA3_512"]


def get_hasher_instance(hash_algo):
    import importlib

    module = importlib.import_module("Crypto.Hash.%s" % hash_algo)
    hasher_instance = module.new()
    return hasher_instance


# AES CBC CIPHER #


def build_aes_cbc_encrypter(key, iv):
    from Crypto.Cipher import AES
    # Same construct works for both encryption and decryption, here
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher


def encrypt_via_aes_cbc(plaintext, key, iv):
    cipher = build_aes_cbc_encrypter(key=key, iv=iv)
    plaintext_padded = _pad_bytes_pkcs7_internal(plaintext, block_size=AES_BLOCK_SIZE)
    ciphertext = cipher.encrypt(plaintext_padded)
    return ciphertext


def decrypt_via_aes_cbc(ciphertext, key, iv):
    cipher = build_aes_cbc_encrypter(key=key, iv=iv)  # Also for decryption
    plaintext_padded = cipher.decrypt(ciphertext)
    plaintext = _unpad_bytes_pkcs7_internal(plaintext_padded, block_size=AES_BLOCK_SIZE)
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
        curve_names = getattr(ECC._curves, "all_names", ECC._curves)  # "all_names" since pycryptodome 3.21
        raise ValueError("Unexisting ECC curve '%s', must be one of '%s'" % (curve, sorted(curve_names)))
    private_key = ECC.generate(curve=curve)
    public_key = private_key.public_key()
    return public_key, private_key


# PBKDF2-HMAC-SHA256 count recommended by OWASP (2023); legacy PEMs stored their own count (default 1000) and stay loadable
PEM_PBKDF2_ITERATIONS = 600000

_OID_PBES2 = "1.2.840.113549.1.5.13"
_OID_PBKDF2 = "1.2.840.113549.1.5.12"
_OID_HMAC_SHA256 = "1.2.840.113549.2.9"
_OID_AES256_CBC = "2.16.840.1.101.3.4.1.42"


def _encrypt_pkcs8_to_pem(clear_pkcs8_der, passphrase):
    """PBES2 (PBKDF2-HMAC-SHA256 + AES256-CBC) encryption, using hashlib since pycryptodome's PBES2 runs PBKDF2 in pure (too slow) python."""
    import hashlib
    from Crypto.IO import PEM
    from Crypto.Random import get_random_bytes
    from Crypto.Util.asn1 import DerSequence, DerObjectId, DerOctetString, DerNull

    salt, iv = get_random_bytes(16), get_random_bytes(AES_BLOCK_SIZE)
    key = hashlib.pbkdf2_hmac("sha256", passphrase, salt, PEM_PBKDF2_ITERATIONS, dklen=32)
    ciphertext = encrypt_via_aes_cbc(clear_pkcs8_der, key=key, iv=iv)
    pbkdf2_params = DerSequence(
        [DerOctetString(salt), PEM_PBKDF2_ITERATIONS, DerSequence([DerObjectId(_OID_HMAC_SHA256), DerNull()])]
    )
    pbes2_params = DerSequence(
        [
            DerSequence([DerObjectId(_OID_PBKDF2), pbkdf2_params]),
            DerSequence([DerObjectId(_OID_AES256_CBC), DerOctetString(iv)]),
        ]
    )
    encrypted_der = DerSequence(
        [DerSequence([DerObjectId(_OID_PBES2), pbes2_params]), DerOctetString(ciphertext)]
    ).encode()
    return PEM.encode(encrypted_der, "ENCRYPTED PRIVATE KEY").encode("ascii")


def _decrypt_pkcs8_from_pem(key_pem, passphrase):
    """Return the clear PKCS8 DER of a PEM made by _encrypt_pkcs8_to_pem(), or None for other formats (left to pycryptodome)."""
    import hashlib
    from Crypto.IO import PEM
    from Crypto.Util.asn1 import DerSequence, DerObjectId, DerOctetString

    def _oid(der):
        return DerObjectId().decode(der).value

    try:
        der, marker, _ = PEM.decode(key_pem.decode("ascii") if isinstance(key_pem, bytes) else key_pem)
        if marker != "ENCRYPTED PRIVATE KEY":
            return None
        algo, ciphertext = DerSequence().decode(der, nr_elements=2)
        pbes2_oid, pbes2_params = DerSequence().decode(algo, nr_elements=2)
        kdf, cipher = DerSequence().decode(pbes2_params, nr_elements=2)
        kdf_oid, kdf_params = DerSequence().decode(kdf, nr_elements=2)
        salt, iteration_count, prf = DerSequence().decode(kdf_params, nr_elements=3)
        prf_oid = DerSequence().decode(prf)[0]
        cipher_oid, iv = DerSequence().decode(cipher, nr_elements=2)
        if (_oid(pbes2_oid), _oid(kdf_oid), _oid(prf_oid), _oid(cipher_oid)) != (
            _OID_PBES2,
            _OID_PBKDF2,
            _OID_HMAC_SHA256,
            _OID_AES256_CBC,
        ):
            return None
        salt, iv, ciphertext = (DerOctetString().decode(x).payload for x in (salt, iv, ciphertext))
    except (ValueError, TypeError):
        return None  # Unexpected structure, e.g. legacy protection or unencrypted key

    key = hashlib.pbkdf2_hmac("sha256", passphrase, salt, iteration_count, dklen=32)
    try:
        return decrypt_via_aes_cbc(ciphertext, key=key, iv=iv)
    except ValueError as exc:  # Bad padding
        raise ValueError("Wrong passphrase or corrupted encrypted private key") from exc


def _import_key_from_pem(key_module, key_pem, passphrase=None):
    if passphrase:
        clear_pkcs8_der = _decrypt_pkcs8_from_pem(key_pem, passphrase)
        if clear_pkcs8_der is not None:
            return key_module.import_key(clear_pkcs8_der)
    return key_module.import_key(key_pem, passphrase=passphrase)


def _export_key_to_pem(key, passphrase, **pkcs8_der_params):
    if not passphrase or not key.has_private():  # Public keys are never encrypted
        return key.export_key(format="PEM")
    return _encrypt_pkcs8_to_pem(key.export_key(format="DER", **pkcs8_der_params), passphrase)


def import_rsa_key_from_pem(key_pem, passphrase=None):
    from Crypto.PublicKey import RSA

    return _import_key_from_pem(RSA, key_pem, passphrase=passphrase)


def import_dsa_key_from_pem(key_pem, passphrase=None):
    from Crypto.PublicKey import DSA

    return _import_key_from_pem(DSA, key_pem, passphrase=passphrase)


def import_ecc_key_from_pem(key_pem, passphrase=None):
    from Crypto.PublicKey import ECC

    return _import_key_from_pem(ECC, key_pem, passphrase=passphrase)


def export_rsa_key_to_pem(private_key, passphrase=None):  # FIXME not always private key
    return _export_key_to_pem(private_key, passphrase, pkcs=8)


def export_dsa_key_to_pem(private_key, passphrase=None):  # FIXME not always private key
    return _export_key_to_pem(private_key, passphrase, pkcs8=True)


def export_ecc_key_to_pem(private_key, passphrase=None):  # FIXME not always private key
    return _export_key_to_pem(private_key, passphrase, use_pkcs8=True)


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
