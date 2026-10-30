# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Pure python EAX mode (Bellare, Rogaway, Wagner), over any 128-bits block encryption callable (e.g. pyaes),
with the same streaming API as pycryptodome's EAX ciphers: encrypt(), decrypt(), digest(), verify()...

Supports an optional header (associated data), only used by test vectors.
"""

import hmac

_BLOCK_SIZE = 16


def _xor(a, b):
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def _double(block):
    value = int.from_bytes(block, "big") << 1
    if value >> 128:
        value ^= (1 << 128) | 0x87
    return value.to_bytes(_BLOCK_SIZE, "big")


class _Omac:
    """Streaming OMAC1/CMAC, prefixed by the EAX tweak block [t]_n."""

    def __init__(self, encrypt_block, subkeys, tweak):
        self._encrypt_block = encrypt_block
        self._subkeys = subkeys
        self._state = bytes(_BLOCK_SIZE)
        self._pending = bytes(_BLOCK_SIZE - 1) + bytes([tweak])

    def update(self, data):
        data = self._pending + bytes(data)
        # Always keep a (possibly full) last block pending, since it gets special treatment at the end
        full_length = max(0, (len(data) - 1) // _BLOCK_SIZE * _BLOCK_SIZE)
        for i in range(0, full_length, _BLOCK_SIZE):
            self._state = self._encrypt_block(_xor(self._state, data[i : i + _BLOCK_SIZE]))
        self._pending = data[full_length:]

    def digest(self):
        k1, k2 = self._subkeys
        if len(self._pending) == _BLOCK_SIZE:
            last_block = _xor(self._pending, k1)
        else:
            padded = self._pending + b"\x80" + bytes(_BLOCK_SIZE - 1 - len(self._pending))
            last_block = _xor(padded, k2)
        return self._encrypt_block(_xor(self._state, last_block))


class EaxCipher:
    def __init__(self, encrypt_block, nonce, header=b"", mac_len=16):
        self._encrypt_block = encrypt_block
        k1 = _double(encrypt_block(bytes(_BLOCK_SIZE)))
        subkeys = (k1, _double(k1))

        nonce_mac = _Omac(encrypt_block, subkeys, 0)
        nonce_mac.update(nonce)
        self._nonce_tag = nonce_mac.digest()
        header_mac = _Omac(encrypt_block, subkeys, 1)
        header_mac.update(header)
        self._header_tag = header_mac.digest()
        self._ciphertext_mac = _Omac(encrypt_block, subkeys, 2)

        self._counter = int.from_bytes(self._nonce_tag, "big")
        self._keystream = b""
        self._mac_len = mac_len
        self._tag = None

    def _apply_keystream(self, data):
        while len(self._keystream) < len(data):
            self._keystream += self._encrypt_block(self._counter.to_bytes(_BLOCK_SIZE, "big"))
            self._counter = (self._counter + 1) & ((1 << 128) - 1)
        keystream, self._keystream = self._keystream[: len(data)], self._keystream[len(data) :]
        return _xor(data, keystream)

    def _check_not_finalized(self):
        if self._tag is not None:
            raise TypeError("Cipher can't be used anymore once its tag was computed")

    def encrypt(self, plaintext):
        self._check_not_finalized()
        ciphertext = self._apply_keystream(bytes(plaintext))
        self._ciphertext_mac.update(ciphertext)
        return ciphertext

    def decrypt(self, ciphertext):
        self._check_not_finalized()
        ciphertext = bytes(ciphertext)
        self._ciphertext_mac.update(ciphertext)
        return self._apply_keystream(ciphertext)

    def digest(self):
        if self._tag is None:
            full_tag = _xor(_xor(self._nonce_tag, self._header_tag), self._ciphertext_mac.digest())
            self._tag = full_tag[: self._mac_len]
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
