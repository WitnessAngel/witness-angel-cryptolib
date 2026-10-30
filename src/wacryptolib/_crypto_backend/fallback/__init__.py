# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Pure python crypto backend, for platforms where pycryptodome's native code can't load (iOS, micropython...).

Exposes the same names as the pycryptodome backend, built upon the "fallbacks" extra packages (pkcs1, pyaes)
and vendored modules. It must never import pycryptodome. NIST-curve ECC is not supported.

ponytail: python bigints are not constant-time, so private key operations may leak to local timing observers.
"""

import hashlib
import hmac
import math
import os

import pkcs1.exceptions
import pkcs1.keys
import pkcs1.mgf
import pkcs1.rsaes_oaep
import pyaes

from .. import hpke_x25519_seal
from ..vendor import dsa as _dsa
from ..vendor.aes_eax import EaxCipher
from ..vendor.chacha20_poly1305 import ChaCha20Poly1305Cipher
from ..vendor.primes import get_random_prime
from . import pem as _pem
from ...utilities.data_utils import pad_bytes_pkcs7, unpad_bytes_pkcs7

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


def _requires_pycryptodome(operation):
    return NotImplementedError("%s requires pycryptodome, unavailable in the fallback backend" % operation)


def _to_bytes(passphrase):
    return passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase  # Like pycryptodome's tobytes()


# HASHER FACTORY #

IMPLEMENTED_HASH_ALGOS = ["SHA256", "SHA512", "SHA3_256", "SHA3_512"]


def get_hasher_instance(hash_algo):
    return hashlib.new(hash_algo.lower())


# AES CBC CIPHER #

AES_BLOCK_SIZE = 16


class _AesCbcCipher:
    """Pycryptodome-like CBC cipher over pyaes, for block-aligned data (no finalize(), unlike pyaes' Encrypter)."""

    def __init__(self, key, iv):
        self._mode = pyaes.AESModeOfOperationCBC(bytes(key), iv=bytes(iv))

    def _process(self, method, data):
        data = bytes(data)
        if len(data) % AES_BLOCK_SIZE:
            raise ValueError("Data must be padded to 16 byte boundary in CBC mode")
        return b"".join(method(data[i : i + AES_BLOCK_SIZE]) for i in range(0, len(data), AES_BLOCK_SIZE))

    def encrypt(self, plaintext):
        return self._process(self._mode.encrypt, plaintext)

    def decrypt(self, ciphertext):
        return self._process(self._mode.decrypt, ciphertext)


def build_aes_cbc_encrypter(key, iv):
    return _AesCbcCipher(key, iv=iv)


def encrypt_via_aes_cbc(plaintext, key, iv):
    return build_aes_cbc_encrypter(key, iv=iv).encrypt(pad_bytes_pkcs7(plaintext, block_size=AES_BLOCK_SIZE))


def decrypt_via_aes_cbc(ciphertext, key, iv):
    plaintext_padded = build_aes_cbc_encrypter(key, iv=iv).decrypt(ciphertext)
    return unpad_bytes_pkcs7(plaintext_padded, block_size=AES_BLOCK_SIZE)


# AES EAX CIPHER #


def build_aes_eax_cipher(key, nonce):
    block_cipher = pyaes.AES(bytes(key))
    return EaxCipher(lambda block: bytes(block_cipher.encrypt(block)), nonce=bytes(nonce))


def encrypt_via_aes_eax(plaintext, key, nonce):
    return build_aes_eax_cipher(key=key, nonce=nonce).encrypt_and_digest(plaintext)


def decrypt_via_aes_eax(ciphertext, tag, key, nonce, verify_integrity_tags):
    cipher = build_aes_eax_cipher(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    if verify_integrity_tags:
        cipher.verify(tag)
    return plaintext


# CHACHA20 POLY1305 CIPHER #


def build_chacha20_poly1305_cipher(key, nonce):
    return ChaCha20Poly1305Cipher(key, nonce=nonce)


def encrypt_via_chacha20_poly1305(plaintext, key, nonce):
    return build_chacha20_poly1305_cipher(key=key, nonce=nonce).encrypt_and_digest(plaintext)


def decrypt_via_chacha20_poly1305(ciphertext, tag, key, nonce, verify_integrity_tags):
    cipher = build_chacha20_poly1305_cipher(key=key, nonce=nonce)
    if verify_integrity_tags:
        return cipher.decrypt_and_verify(ciphertext, tag)
    return cipher.decrypt(ciphertext)


# RSA OAEP CIPHER, AND RSA PSS SIGNATURES (both with SHA512 and MGF1-SHA512) #

_RSA_PUBLIC_EXPONENT = 65537
_RSA_HASH = hashlib.sha512
_RSA_HASH_LENGTH = 64


def _xor(a, b):
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def _mgf1(seed, length):
    # pkcs1 must be given the hash explicitly, its own callers forget to do so in several places
    return pkcs1.mgf.mgf1(seed, length, hash_class=_RSA_HASH)


def encrypt_via_rsa_oaep(plaintext_chunks: list[bytes], public_key) -> list[bytes]:
    """We expect each plaintext chunk to be small enough for the RSA key size"""
    ciphertext_chunks = []
    for chunk in plaintext_chunks:
        try:
            ciphertext_chunks.append(pkcs1.rsaes_oaep.encrypt(public_key, message=chunk, hash_class=_RSA_HASH))
        except pkcs1.exceptions.PKCS1BaseException as exc:
            raise ValueError("Plaintext is too long for RSA OAEP") from exc
    return ciphertext_chunks


def _decrypt_one_rsa_oaep_chunk(ciphertext, private_key):
    """RFC 8017 section 7.1.2, rather than pkcs1's decrypt() which uses MGF1-SHA1, prints padding bytes,
    and raises distinguishable exceptions (i.e. a padding oracle)."""
    k = private_key.byte_size
    if len(ciphertext) != k or k < 2 * _RSA_HASH_LENGTH + 2:
        raise ValueError("Incorrect decryption.")
    c = int.from_bytes(ciphertext, "big")
    if c >= private_key.n:
        raise ValueError("Incorrect decryption.")
    em = private_key.rsadp(c).to_bytes(k, "big")
    masked_seed, masked_db = em[1 : 1 + _RSA_HASH_LENGTH], em[1 + _RSA_HASH_LENGTH :]
    seed = _xor(masked_seed, _mgf1(masked_db, _RSA_HASH_LENGTH))
    db = _xor(masked_db, _mgf1(seed, k - _RSA_HASH_LENGTH - 1))
    separator_position = db.find(b"\x01", _RSA_HASH_LENGTH)
    valid = (
        em[0] == 0
        and hmac.compare_digest(db[:_RSA_HASH_LENGTH], _RSA_HASH(b"").digest())  # Empty label
        and separator_position >= 0
        and not any(db[_RSA_HASH_LENGTH:separator_position])
    )
    if not valid:
        raise ValueError("Incorrect decryption.")
    return db[separator_position + 1 :]


def decrypt_via_rsa_oaep(ciphertext_chunks: list[bytes], private_key) -> list[bytes]:
    return [_decrypt_one_rsa_oaep_chunk(chunk, private_key) for chunk in ciphertext_chunks]


def _emsa_pss_hash(message_hash, salt):
    return _RSA_HASH(bytes(8) + message_hash + salt).digest()


def sign_with_pss(message, private_key):
    """RFC 8017 section 8.1, with a salt as long as the hash, like pycryptodome's pss.new() default.

    :param message: already-fed SHA512 hasher object"""
    message_hash = message.digest()
    em_bits = private_key.bit_size - 1
    em_length = (em_bits + 7) // 8
    salt = os.urandom(_RSA_HASH_LENGTH)
    h = _emsa_pss_hash(message_hash, salt)
    db = bytes(em_length - 2 * _RSA_HASH_LENGTH - 2) + b"\x01" + salt
    masked_db = bytearray(_xor(db, _mgf1(h, em_length - _RSA_HASH_LENGTH - 1)))
    masked_db[0] &= 0xFF >> (8 * em_length - em_bits)
    em = bytes(masked_db) + h + b"\xbc"
    return private_key.rsasp1(int.from_bytes(em, "big")).to_bytes(private_key.byte_size, "big")


def verify_with_pss(message, signature, public_key):
    """Raise ValueError if the signature is invalid."""
    error = ValueError("Incorrect signature")
    em_bits = public_key.bit_size - 1
    em_length = (em_bits + 7) // 8
    if len(signature) != public_key.byte_size:
        raise error
    s = int.from_bytes(signature, "big")
    if s >= public_key.n:
        raise error
    m = public_key.rsavp1(s)
    if m.bit_length() > em_bits:
        raise error
    em = m.to_bytes(em_length, "big")
    masked_db, h = em[: em_length - _RSA_HASH_LENGTH - 1], em[em_length - _RSA_HASH_LENGTH - 1 : -1]
    unused_bits_mask = 0xFF & ~(0xFF >> (8 * em_length - em_bits))
    if em[-1] != 0xBC or masked_db[0] & unused_bits_mask:
        raise error
    db = bytearray(_xor(masked_db, _mgf1(h, len(masked_db))))
    db[0] &= ~unused_bits_mask & 0xFF
    padding_length = em_length - 2 * _RSA_HASH_LENGTH - 2
    if any(db[:padding_length]) or db[padding_length] != 0x01:
        raise error
    salt = bytes(db[padding_length + 1 :])
    if not hmac.compare_digest(h, _emsa_pss_hash(message.digest(), salt)):
        raise error


def rsa_key_class_fetcher():
    return (pkcs1.keys.RsaPublicKey, pkcs1.keys.MultiPrimeRsaPrivateKey)


def generate_rsa_keypair(key_length_bits):
    # Own prime generation, since pkcs1's generate_key_pair() doesn't check gcd(e, q-1) for the last prime
    e = _RSA_PUBLIC_EXPONENT
    while True:
        p, q = sorted(get_random_prime(key_length_bits // 2, top_bits_mask=0b11) for _ in range(2))
        if p != q and math.gcd(e, (p - 1) * (q - 1)) == 1:
            break
    private_key = pkcs1.keys.MultiPrimeRsaPrivateKey([p, q], e)
    return pkcs1.keys.RsaPublicKey(private_key.n, e), private_key


def _build_rsa_private_key(n, e, d, p, q):
    if p * q != n or e * d % math.lcm(p - 1, q - 1) != 1:
        raise ValueError("Invalid RSA key components")
    return pkcs1.keys.MultiPrimeRsaPrivateKey([p, q], e)


def _encode_rsa_pkcs1_private_key(private_key):
    (p, q), e = private_key.primes, private_key.e
    d = pow(e, -1, math.lcm(p - 1, q - 1))  # Like pycryptodome's RSA.generate()
    components = [0, private_key.n, e, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p)]
    return _pem.encode_sequence(*(_pem.encode_integer(x) for x in components))


def _decode_rsa_pkcs1_private_key(der):
    version, n, e, d, p, q, *_crt_values = (_pem.decode_integer(x) for x in _pem.decode_sequence(der, 9))
    if version != 0:
        raise ValueError("Unsupported RSA private key version")
    return _build_rsa_private_key(n, e, d, p, q)


def _decode_rsa_pkcs1_public_key(der):
    n, e = (_pem.decode_integer(x) for x in _pem.decode_sequence(der, 2))
    if n < 3 or not 3 <= e < n:
        raise ValueError("Invalid RSA public key components")
    return pkcs1.keys.RsaPublicKey(n, e)


_RSA_ALGORITHM_IDENTIFIER = _pem.encode_algorithm_identifier(_pem.OID_RSA, _pem.encode_null())


# DSA KEYS AND SIGNATURES #


def dsa_key_class_fetcher():
    return _dsa.DsaKey


def generate_dsa_keypair(key_length_bits):
    private_key = _dsa.generate_dsa_key(key_length_bits)
    return private_key.public_key(), private_key


def _dsa_algorithm_identifier(key):
    parameters = _pem.encode_sequence(*(_pem.encode_integer(x) for x in (key.p, key.q, key.g)))
    return _pem.encode_algorithm_identifier(_pem.OID_DSA, parameters)


def _decode_dsa_parameters(parameters):
    if parameters is None:
        raise ValueError("Missing DSA domain parameters")
    return [_pem.decode_integer(x) for x in _pem.decode_sequence(parameters, 3)]


def sign_with_dss(message, private_key):
    if not isinstance(private_key, _dsa.DsaKey):
        raise ValueError("Only DSA keys can be used for DSS signatures in the fallback backend")
    return _dsa.sign(private_key, message.digest())


def verify_with_dss(message, signature, public_key):
    if not isinstance(public_key, _dsa.DsaKey):
        raise ValueError("Only DSA keys can be used for DSS signatures in the fallback backend")
    _dsa.verify(public_key, message.digest(), signature)


# X25519 KEYS AND HPKE (RFC 9180) KEY WRAPPING, BASE MODE, EMPTY INFO AND AAD #


class X25519Key:
    """Raw X25519 keys, with the few EccKey attributes that wacryptolib uses."""

    __slots__ = ("public_bytes", "private_bytes")
    curve = "Curve25519"

    def __init__(self, public_bytes, private_bytes=None):
        self.public_bytes, self.private_bytes = public_bytes, private_bytes

    def has_private(self):
        return self.private_bytes is not None

    def public_key(self):
        return X25519Key(self.public_bytes)

    def __eq__(self, other):
        return isinstance(other, X25519Key) and (self.public_bytes, self.private_bytes) == (
            other.public_bytes,
            other.private_bytes,
        )

    def __repr__(self):
        return "<X25519Key%s>" % (" (private)" if self.has_private() else "")


def _build_x25519_private_key(private_bytes):
    if len(private_bytes) != 32:
        raise ValueError("X25519 private key must be 32 bytes long")
    return X25519Key(hpke_x25519_seal.x25519(private_bytes, hpke_x25519_seal._X25519_BASE_POINT), private_bytes)


def ecc_key_class_fetcher():
    return X25519Key


def generate_ecc_keypair(curve):
    if curve.lower() not in ("curve25519", "x25519"):
        raise _requires_pycryptodome("ECC key generation on curve %r" % curve)
    private_key = _build_x25519_private_key(os.urandom(32))
    return private_key.public_key(), private_key


def _check_hpke_aead_id(aead_id):
    if aead_id != hpke_x25519_seal.AEAD_ID:
        raise _requires_pycryptodome("HPKE with AEAD %#06x" % aead_id)


def encrypt_via_hpke(plaintext: bytes, public_key, aead_id) -> tuple[bytes, bytes]:
    """Returns (enc, ciphertext), enc being the KEM encapsulation (ephemeral public key for DHKEM)."""
    _check_hpke_aead_id(aead_id)
    return hpke_x25519_seal.seal(public_key.public_bytes, plaintext)


def decrypt_via_hpke(enc: bytes, ciphertext: bytes, private_key, aead_id) -> bytes:
    _check_hpke_aead_id(aead_id)
    if not private_key.has_private():
        raise ValueError("HPKE decryption requires a private key")
    return hpke_x25519_seal.open(private_key.private_bytes, enc, ciphertext)


# PEM IMPORT/EXPORT #


def _import_key_from_pem(key_pem, passphrase, private_key_decoders, public_key_decoders):
    """Decoders are dicts {marker or OID: callable}, OIDs being used for PKCS#8 and SubjectPublicKeyInfo."""
    der, marker = _pem.decode_pem(key_pem)
    if marker == "ENCRYPTED PRIVATE KEY":
        if not passphrase:
            raise ValueError("Encrypted private key requires a passphrase")
        clear_pkcs8_der = _pem.decrypt_pkcs8(der, _to_bytes(passphrase), decrypt_via_aes_cbc=decrypt_via_aes_cbc)
        try:
            return _decode_pkcs8_private_key(clear_pkcs8_der, private_key_decoders)
        except (ValueError, IndexError, TypeError):
            raise ValueError(_pem.PEM_DECRYPTION_ERROR) from None  # Same error as for a bad padding
    if marker == "PRIVATE KEY":
        return _decode_pkcs8_private_key(der, private_key_decoders)
    if marker == "PUBLIC KEY":
        oid, parameters, public_key_bits = _pem.decode_spki(der)
        return _get_decoder(public_key_decoders, oid)(public_key_bits, parameters)
    if marker in private_key_decoders:
        return private_key_decoders[marker](der, None)
    if marker in public_key_decoders:
        return public_key_decoders[marker](der, None)
    raise ValueError("Unsupported PEM type %r" % marker)


def _decode_pkcs8_private_key(der, private_key_decoders):
    oid, parameters, private_key_octets = _pem.decode_pkcs8(der)
    return _get_decoder(private_key_decoders, oid)(private_key_octets, parameters)


def _get_decoder(decoders, oid):
    if oid == _pem.OID_EC_PUBLIC_KEY:
        raise _requires_pycryptodome("Import of NIST-curve ECC keys")
    if oid not in decoders:
        raise ValueError("Unexpected key algorithm %s" % oid)
    return decoders[oid]


def _export_key_to_pem(key, passphrase, has_private, encode_private_pkcs8, encode_spki, encode_private_pem=None):
    """Same formats as the pycryptodome backend: public keys are never encrypted, and clear private keys
    are PKCS#8 unless `encode_private_pem` is given."""
    if not has_private:
        return _pem.encode_pem(encode_spki(key), "PUBLIC KEY")
    if passphrase:
        return _pem.encrypt_pkcs8_to_pem(
            encode_private_pkcs8(key), _to_bytes(passphrase), encrypt_via_aes_cbc=encrypt_via_aes_cbc,
            random_bytes=os.urandom,
        )
    if encode_private_pem:
        return encode_private_pem(key)
    return _pem.encode_pem(encode_private_pkcs8(key), "PRIVATE KEY")


def import_rsa_key_from_pem(key_pem, passphrase=None):
    private_key_decoders = {
        _pem.OID_RSA: lambda octets, _parameters: _decode_rsa_pkcs1_private_key(octets),
        "RSA PRIVATE KEY": lambda der, _parameters: _decode_rsa_pkcs1_private_key(der),
    }
    public_key_decoders = {
        _pem.OID_RSA: lambda bits, _parameters: _decode_rsa_pkcs1_public_key(bits),
        "RSA PUBLIC KEY": lambda der, _parameters: _decode_rsa_pkcs1_public_key(der),
    }
    return _import_key_from_pem(key_pem, passphrase, private_key_decoders, public_key_decoders)


def export_rsa_key_to_pem(private_key, passphrase=None):
    return _export_key_to_pem(
        private_key,
        passphrase,
        has_private=isinstance(private_key, pkcs1.keys.MultiPrimeRsaPrivateKey),
        encode_private_pkcs8=lambda key: _pem.encode_pkcs8(_RSA_ALGORITHM_IDENTIFIER, _encode_rsa_pkcs1_private_key(key)),
        encode_spki=lambda key: _pem.encode_spki(
            _RSA_ALGORITHM_IDENTIFIER, _pem.encode_sequence(_pem.encode_integer(key.n), _pem.encode_integer(key.e))
        ),
        encode_private_pem=lambda key: _pem.encode_pem(_encode_rsa_pkcs1_private_key(key), "RSA PRIVATE KEY"),
    )


def _decode_dsa_private_key(private_key_octets, parameters):
    p, q, g = _decode_dsa_parameters(parameters)
    x = _pem.decode_integer(private_key_octets)
    key = _dsa.DsaKey(p, q, g, pow(g, x, p), x)
    _dsa.check_dsa_key(key)
    return key


def _decode_dsa_public_key(public_key_bits, parameters):
    p, q, g = _decode_dsa_parameters(parameters)
    key = _dsa.DsaKey(p, q, g, _pem.decode_integer(public_key_bits))
    _dsa.check_dsa_key(key)
    return key


def import_dsa_key_from_pem(key_pem, passphrase=None):
    return _import_key_from_pem(
        key_pem,
        passphrase,
        private_key_decoders={_pem.OID_DSA: _decode_dsa_private_key},
        public_key_decoders={_pem.OID_DSA: _decode_dsa_public_key},
    )


def export_dsa_key_to_pem(private_key, passphrase=None):
    return _export_key_to_pem(
        private_key,
        passphrase,
        has_private=private_key.has_private(),
        encode_private_pkcs8=lambda key: _pem.encode_pkcs8(_dsa_algorithm_identifier(key), _pem.encode_integer(key.x)),
        encode_spki=lambda key: _pem.encode_spki(_dsa_algorithm_identifier(key), _pem.encode_integer(key.y)),
    )


_X25519_ALGORITHM_IDENTIFIER = _pem.encode_algorithm_identifier(_pem.OID_X25519)


def _decode_x25519_private_key(private_key_octets, parameters):
    if parameters is not None:
        raise ValueError("Unexpected parameters for X25519 key")
    return _build_x25519_private_key(_pem.decode_octet_string(private_key_octets))


def _decode_x25519_public_key(public_key_bits, parameters):
    if parameters is not None or len(public_key_bits) != 32:
        raise ValueError("Invalid X25519 public key")
    return X25519Key(public_key_bits)


def import_ecc_key_from_pem(key_pem, passphrase=None):
    return _import_key_from_pem(
        key_pem,
        passphrase,
        private_key_decoders={_pem.OID_X25519: _decode_x25519_private_key},
        public_key_decoders={_pem.OID_X25519: _decode_x25519_public_key},
    )


def import_x25519_key_from_pem(key_pem, passphrase=None):
    return import_ecc_key_from_pem(key_pem, passphrase=passphrase)  # Only X25519 keys are supported here anyway


def export_ecc_key_to_pem(private_key, passphrase=None):
    return _export_key_to_pem(
        private_key,
        passphrase,
        has_private=private_key.has_private(),
        encode_private_pkcs8=lambda key: _pem.encode_pkcs8(
            _X25519_ALGORITHM_IDENTIFIER, _pem.encode_octet_string(key.private_bytes)
        ),
        encode_spki=lambda key: _pem.encode_spki(_X25519_ALGORITHM_IDENTIFIER, key.public_bytes),
    )
