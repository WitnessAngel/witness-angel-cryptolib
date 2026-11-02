# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Pure python ChaCha20-Poly1305 AEAD (RFC 8439, without associated data), with the same API as
pycryptodome's ChaCha20_Poly1305 ciphers. Slow, only meant for platforms where pycryptodome's C extensions are unusable.
"""

import hmac
import struct

_MASK32 = 0xFFFFFFFF
_POLY1305_PRIME = (1 << 130) - 5
_POLY1305_R_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
_QUARTER_ROUND_INDICES = (
    (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),  # Columns
    (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14),  # Diagonals
)


def _rotate_left(value, shift):
    return ((value << shift) & _MASK32) | (value >> (32 - shift))


def _chacha20_block(key_words, counter, nonce_words):
    # No star-unpacking inside list displays on micropython
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574] + list(key_words) + [counter] + list(nonce_words)
    w = list(state)
    for _ in range(10):  # 20 rounds
        for a, b, c, d in _QUARTER_ROUND_INDICES:
            w[a] = (w[a] + w[b]) & _MASK32
            w[d] = _rotate_left(w[d] ^ w[a], 16)
            w[c] = (w[c] + w[d]) & _MASK32
            w[b] = _rotate_left(w[b] ^ w[c], 12)
            w[a] = (w[a] + w[b]) & _MASK32
            w[d] = _rotate_left(w[d] ^ w[a], 8)
            w[c] = (w[c] + w[d]) & _MASK32
            w[b] = _rotate_left(w[b] ^ w[c], 7)
    return struct.pack("<16I", *((x + y) & _MASK32 for x, y in zip(w, state)))


class _Poly1305ForAead:
    """Poly1305 over the zero-padded ciphertext, as RFC 8439 AEAD requires"""

    def __init__(self, one_time_key):
        self._r = int.from_bytes(one_time_key[:16], "little") & _POLY1305_R_CLAMP
        self._s = int.from_bytes(one_time_key[16:], "little")
        self._accumulator = 0
        self._pending = b""

    def _process_block(self, block):
        self._accumulator = (self._accumulator + int.from_bytes(block + b"\x01", "little")) * self._r % _POLY1305_PRIME

    def update(self, data):
        data = self._pending + data
        full_length = len(data) - len(data) % 16
        for i in range(0, full_length, 16):
            self._process_block(data[i : i + 16])
        self._pending = data[full_length:]

    def finalize(self, ciphertext_length):
        if self._pending:
            self._process_block(self._pending + bytes(16 - len(self._pending)))  # No bytes.ljust() on micropython
        self._process_block(struct.pack("<QQ", 0, ciphertext_length))  # Lengths of associated data and ciphertext
        return ((self._accumulator + self._s) & ((1 << 128) - 1)).to_bytes(16, "little")


class ChaCha20Poly1305Cipher:
    def __init__(self, key, nonce):
        if len(key) != 32 or len(nonce) != 12:
            raise ValueError("ChaCha20-Poly1305 requires a 32-bytes key and a 12-bytes nonce")
        self.nonce = bytes(nonce)
        self._key_words = struct.unpack("<8I", key)
        self._nonce_words = struct.unpack("<3I", nonce)
        self._mac = _Poly1305ForAead(_chacha20_block(self._key_words, 0, self._nonce_words)[:32])
        self._counter = 1  # Block 0 was used for the Poly1305 key
        self._keystream = b""
        self._ciphertext_length = 0
        self._tag = None

    def _xor_with_keystream(self, data):
        missing_length = len(data) - len(self._keystream)
        if missing_length > 0:
            block_count = -(-missing_length // 64)
            if self._counter + block_count - 1 > _MASK32:  # Last block used is counter + block_count - 1
                raise OverflowError("Too much data for a single ChaCha20 nonce")
            self._keystream += b"".join(
                _chacha20_block(self._key_words, self._counter + i, self._nonce_words) for i in range(block_count)
            )
            self._counter += block_count
        keystream, self._keystream = self._keystream[: len(data)], self._keystream[len(data) :]
        return (int.from_bytes(data, "little") ^ int.from_bytes(keystream, "little")).to_bytes(len(data), "little")

    def _authenticate_ciphertext(self, ciphertext):
        if self._tag is not None:
            raise TypeError("Cipher can't be used anymore once its tag was computed")
        self._mac.update(ciphertext)
        self._ciphertext_length += len(ciphertext)

    def encrypt(self, plaintext):
        ciphertext = self._xor_with_keystream(bytes(plaintext))
        self._authenticate_ciphertext(ciphertext)
        return ciphertext

    def decrypt(self, ciphertext):
        ciphertext = bytes(ciphertext)
        self._authenticate_ciphertext(ciphertext)
        return self._xor_with_keystream(ciphertext)

    def digest(self):
        if self._tag is None:
            self._tag = self._mac.finalize(self._ciphertext_length)
        return self._tag

    def verify(self, received_mac_tag):
        if not hmac.compare_digest(self.digest(), bytes(received_mac_tag)):
            raise ValueError("MAC check failed")

    def encrypt_and_digest(self, plaintext):
        return self.encrypt(plaintext), self.digest()

    def decrypt_and_verify(self, ciphertext, received_mac_tag):
        plaintext = self.decrypt(ciphertext)
        self.verify(received_mac_tag)
        return plaintext
