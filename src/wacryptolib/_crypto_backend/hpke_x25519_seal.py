# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Pure python ECIES_X25519: HPKE (RFC 9180) Base mode with DHKEM(X25519, HKDF-SHA256),
HKDF-SHA256 and ChaCha20-Poly1305, empty info and AAD, a single seal() or open() per context.
Byte-compatible with pycryptodome's HPKE, only meant for platforms (micropython, iOS) where pycryptodome is unusable.

ChaCha20-Poly1305 was preferred to AES-256-GCM: it is already implemented in pure python here (GCM would need
a new GHASH), add-rotate-xor is less prone to timing leaks than table-based AES, and RFC 9180 Appendix A.2
provides a test vector for exactly this suite.

Only depends on hashlib, hmac, os and the sibling chacha20_poly1305 module, so that it can be copied as is.
"""

import hashlib
import hmac
import os

if "." in __name__:  # Inside wacryptolib package
    from .vendor.chacha20_poly1305 import ChaCha20Poly1305Cipher
else:  # Copied as a top-level module on micropython, where relative imports fail
    from chacha20_poly1305 import ChaCha20Poly1305Cipher

_P = 2**255 - 19
_A24 = 121665

_KEM_SUITE_ID = b"KEM\x00\x20"
AEAD_ID = 0x0003  # ChaCha20-Poly1305, the only AEAD implemented here
_HPKE_SUITE_ID = b"HPKE\x00\x20\x00\x01" + AEAD_ID.to_bytes(2, "big")
_MODE_BASE = b"\x00"


def x25519(scalar: bytes, u_coordinate: bytes) -> bytes:
    """RFC 7748 Montgomery ladder.

    ponytail: python bigints are not constant-time, so the (ephemeral) scalar may leak to local timing/power
    observers; acceptable for sealing, and for open() only on devices without such observers (fallback backend)."""
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(bytes(k), "little")
    x1 = int.from_bytes(u_coordinate, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = k_t
        a = x2 + z2
        aa = a * a
        b = x2 - z2
        bb = b * b
        e = aa - bb
        c = x3 + z3
        d = x3 - z3
        da = d * a
        cb = c * b
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


_X25519_BASE_POINT = b"\x09" + bytes(31)


def _hmac_sha256(key, data):
    return hmac.new(key, data, digestmod=hashlib.sha256).digest()


def _hkdf_expand(prk, info, length):
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = _hmac_sha256(prk, block + info + bytes([counter]))
        output += block
        counter += 1
    return output[:length]


def _labeled_extract(suite_id, salt, label, ikm):
    return _hmac_sha256(salt, b"HPKE-v1" + suite_id + label + ikm)


def _labeled_expand(suite_id, prk, label, info, length):
    labeled_info = length.to_bytes(2, "big") + b"HPKE-v1" + suite_id + label + info
    return _hkdf_expand(prk, labeled_info, length)


def _compute_key_schedule_context(info):
    psk_id_hash = _labeled_extract(_HPKE_SUITE_ID, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(_HPKE_SUITE_ID, b"", b"info_hash", info)
    return _MODE_BASE + psk_id_hash + info_hash


_EMPTY_INFO_KEY_SCHEDULE_CONTEXT = _compute_key_schedule_context(b"")  # Constant, as psk is always empty too


def _derive_key_schedule(receiver_public_key, ephemeral_private_key, info=b""):
    """Returns (enc, key, base_nonce) of HPKE Base mode with empty psk; info is only non-empty in RFC test vectors."""
    enc = x25519(ephemeral_private_key, _X25519_BASE_POINT)
    dh = x25519(ephemeral_private_key, receiver_public_key)
    key, base_nonce = _derive_key_schedule_from_dh(dh, enc, receiver_public_key, info=info)
    return enc, key, base_nonce


def _derive_key_schedule_from_dh(dh, enc, receiver_public_key, info=b""):
    if dh == bytes(32):
        raise ValueError("Invalid X25519 public key (low order point)")
    eae_prk = _labeled_extract(_KEM_SUITE_ID, b"", b"eae_prk", dh)
    shared_secret = _labeled_expand(_KEM_SUITE_ID, eae_prk, b"shared_secret", enc + receiver_public_key, 32)

    key_schedule_context = _EMPTY_INFO_KEY_SCHEDULE_CONTEXT if not info else _compute_key_schedule_context(info)
    secret = _labeled_extract(_HPKE_SUITE_ID, shared_secret, b"secret", b"")
    key = _labeled_expand(_HPKE_SUITE_ID, secret, b"key", key_schedule_context, 32)
    base_nonce = _labeled_expand(_HPKE_SUITE_ID, secret, b"base_nonce", key_schedule_context, 12)
    return key, base_nonce


def seal(receiver_public_key: bytes, plaintext: bytes, ephemeral_private_key: bytes = None) -> tuple:
    """Encrypt plaintext for the raw 32-bytes X25519 public key.

    :param ephemeral_private_key: only for known-answer tests, else freshly taken from os.urandom()

    :return: tuple (enc, ciphertext), the latter including its 16-bytes MAC tag"""
    if len(receiver_public_key) != 32:
        raise ValueError("X25519 public key must be 32 bytes long")
    # The receiver puts its canonically re-encoded public key in the HPKE context, so other encodings would
    # yield undecryptable ciphertexts
    if receiver_public_key[31] & 0x80 or int.from_bytes(receiver_public_key, "little") >= _P:
        raise ValueError("Non-canonical X25519 public key")
    if ephemeral_private_key is None:
        ephemeral_private_key = os.urandom(32)
    enc, key, base_nonce = _derive_key_schedule(receiver_public_key, ephemeral_private_key)
    # Sequence number 0, so the nonce is base_nonce itself
    ciphertext, tag = ChaCha20Poly1305Cipher(key, base_nonce).encrypt_and_digest(plaintext)
    return enc, ciphertext + tag


def open(receiver_private_key: bytes, enc: bytes, ciphertext: bytes) -> bytes:
    """Decrypt the output of seal() with the raw 32-bytes X25519 private key, raising ValueError on any failure."""
    if len(receiver_private_key) != 32 or len(enc) != 32:
        raise ValueError("X25519 private key and encapsulated key must be 32 bytes long")
    if len(ciphertext) < 16:
        raise ValueError("Ciphertext is too short to contain a MAC tag")
    receiver_public_key = x25519(receiver_private_key, _X25519_BASE_POINT)
    dh = x25519(receiver_private_key, enc)
    key, base_nonce = _derive_key_schedule_from_dh(dh, enc, receiver_public_key)
    return ChaCha20Poly1305Cipher(key, base_nonce).decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
