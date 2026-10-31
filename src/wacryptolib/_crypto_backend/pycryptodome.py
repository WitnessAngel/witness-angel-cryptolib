# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Native crypto backend: a plain wrapper over pycryptodome, which must be importable with its native code.
"""

__all__ = [
    "IMPLEMENTED_HASH_ALGOS",
    "get_hasher_instance",
    "AES_BLOCK_SIZE",
    "build_aes_cbc_encrypter",
    "encrypt_via_aes_cbc",
    "decrypt_via_aes_cbc",
    "build_aes_eax_cipher",
    "encrypt_via_aes_eax",
    "decrypt_via_aes_eax",
    "build_chacha20_poly1305_cipher",
    "encrypt_via_chacha20_poly1305",
    "decrypt_via_chacha20_poly1305",
    "encrypt_via_rsa_oaep",
    "decrypt_via_rsa_oaep",
    "encrypt_via_hpke",
    "decrypt_via_hpke",
    "import_x25519_key_from_pem",
    "generate_rsa_keypair",
    "generate_dsa_keypair",
    "generate_ecc_keypair",
    "import_rsa_key_from_pem",
    "import_dsa_key_from_pem",
    "import_ecc_key_from_pem",
    "export_rsa_key_to_pem",
    "export_dsa_key_to_pem",
    "export_ecc_key_to_pem",
    "rsa_key_class_fetcher",
    "dsa_key_class_fetcher",
    "ecc_key_class_fetcher",
    "sign_with_pss",
    "verify_with_pss",
    "sign_with_dss",
    "verify_with_dss",
]


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


# HPKE (RFC 9180) KEY WRAPPING, BASE MODE, EMPTY INFO AND AAD #


def encrypt_via_hpke(plaintext: bytes, public_key, aead_id) -> tuple[bytes, bytes]:
    """Returns (enc, ciphertext), enc being the KEM encapsulation (ephemeral public key for DHKEM)."""
    from Crypto.Protocol import HPKE

    # A private key would switch pycryptodome to unsealing mode
    sender = HPKE.new(receiver_key=public_key.public_key(), aead_id=HPKE.AEAD(aead_id))
    return sender.enc, sender.seal(plaintext)


def decrypt_via_hpke(enc: bytes, ciphertext: bytes, private_key, aead_id) -> bytes:
    from Crypto.Protocol import HPKE

    return HPKE.new(receiver_key=private_key, enc=enc, aead_id=HPKE.AEAD(aead_id)).unseal(ciphertext)


def import_x25519_key_from_pem(key_pem, passphrase=None):
    key = import_ecc_key_from_pem(key_pem, passphrase=passphrase)
    if key.curve != "Curve25519":
        raise ValueError("Expected an X25519 key, not a %s one" % key.curve)
    return key


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

    curve = curve.upper()
    curve_names = getattr(ECC._curves, "all_names", ECC._curves)  # "all_names" since pycryptodome 3.21
    pycryptodome_curve_names = {name.upper(): name for name in curve_names}  # These are case-sensitive
    if curve not in pycryptodome_curve_names:
        raise ValueError("Unexisting ECC curve '%s', must be one of '%s'" % (curve, sorted(pycryptodome_curve_names)))
    private_key = ECC.generate(curve=pycryptodome_curve_names[curve])
    public_key = private_key.public_key()
    return public_key, private_key


# PBKDF2-HMAC-SHA256 count recommended by OWASP (2023); legacy PEMs stored their own count (default 1000) and stay loadable
PEM_PBKDF2_ITERATIONS = 600000
PEM_PBKDF2_MAX_ITERATIONS = 10_000_000  # Iteration count is read from untrusted PEMs, so it must be bounded (~2s at most)

# Same error for bad padding and invalid decrypted key, so that callers can't be used as CBC padding oracles
_PEM_DECRYPTION_ERROR = "Wrong passphrase or corrupted encrypted private key"

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
        salt, iteration_count, *key_length, prf = DerSequence().decode(kdf_params, nr_elements=(3, 4))
        prf_oid = DerSequence().decode(prf, nr_elements=(1, 2))[0]
        cipher_oid, iv = DerSequence().decode(cipher, nr_elements=2)
        if (_oid(pbes2_oid), _oid(kdf_oid), _oid(prf_oid), _oid(cipher_oid)) != (
            _OID_PBES2,
            _OID_PBKDF2,
            _OID_HMAC_SHA256,
            _OID_AES256_CBC,
        ):
            return None
        salt, iv, ciphertext = (DerOctetString().decode(x).payload for x in (salt, iv, ciphertext))
    except (ValueError, TypeError, IndexError):
        return None  # Unexpected structure, e.g. legacy protection or unencrypted key

    if not isinstance(iteration_count, int) or not 0 < iteration_count <= PEM_PBKDF2_MAX_ITERATIONS:
        raise ValueError("Unsupported PBKDF2 iteration count in encrypted private key")
    if key_length not in ([], [32]) or len(iv) != AES_BLOCK_SIZE or not ciphertext or len(ciphertext) % AES_BLOCK_SIZE:
        raise ValueError("Malformed encrypted private key")

    key = hashlib.pbkdf2_hmac("sha256", passphrase, salt, iteration_count, dklen=32)
    try:
        return decrypt_via_aes_cbc(ciphertext, key=key, iv=iv)
    except ValueError:  # Bad padding
        raise ValueError(_PEM_DECRYPTION_ERROR) from None


def _import_key_from_pem(key_module, key_pem, passphrase=None):
    from Crypto.Util.py3compat import tobytes

    if passphrase:
        passphrase = tobytes(passphrase)  # Like pycryptodome does for str passphrases
        clear_pkcs8_der = _decrypt_pkcs8_from_pem(key_pem, passphrase)
        if clear_pkcs8_der is not None:
            try:
                return key_module.import_key(clear_pkcs8_der)
            except (ValueError, IndexError, TypeError):
                raise ValueError(_PEM_DECRYPTION_ERROR) from None
    return key_module.import_key(key_pem, passphrase=passphrase)


def _export_key_to_pem(key, passphrase, **pkcs8_der_params):
    if not passphrase:
        return key.export_key(format="PEM")
    if not key.has_private():
        raise ValueError("Public keys can't be exported to PEM with a passphrase")
    from Crypto.Util.py3compat import tobytes

    return _encrypt_pkcs8_to_pem(key.export_key(format="DER", **pkcs8_der_params), tobytes(passphrase))


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
