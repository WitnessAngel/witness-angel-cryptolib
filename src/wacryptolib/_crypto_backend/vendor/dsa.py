# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Pure python classic DSA (FIPS 186-4): key generation, and signatures over a precomputed message digest, encoded
like pycryptodome's DSS "fips-186-3" mode with "binary" encoding (r || s, each as big-endian bytes of q's length).

Signatures are randomized like pycryptodome's, so both are verify-compatible but not byte-identical.

ponytail: domain parameters are random probable primes, not FIPS 186-4 A.1.1.2 seeded ones (pycryptodome doesn't
check seeds either); python bigints are not constant-time, so keep native code for high-exposure signers.
"""

import secrets

from .primes import get_random_prime, is_probable_prime

L_TO_N = {2048: 224, 3072: 256}  # Same (L, N) pairs as pycryptodome's DSA.generate()


class DsaKey:
    __slots__ = ("p", "q", "g", "y", "x")

    def __init__(self, p, q, g, y, x=None):
        self.p, self.q, self.g, self.y, self.x = p, q, g, y, x

    def has_private(self):
        return self.x is not None

    def public_key(self):
        return DsaKey(self.p, self.q, self.g, self.y)

    publickey = public_key  # Pycryptodome-style alias

    def __eq__(self, other):
        return isinstance(other, DsaKey) and all(getattr(self, a) == getattr(other, a) for a in self.__slots__)

    def __repr__(self):
        return "<DsaKey %d bits%s>" % (self.p.bit_length(), " (private)" if self.has_private() else "")


def check_dsa_key(key):
    """Same consistency checks as pycryptodome's DSA.construct(), raising ValueError."""
    p, q, g, y, x = key.p, key.q, key.g, key.y, key.x
    valid = (
        q > 1 and p > q and (p - 1) % q == 0 and 1 < g < p and 1 < y < p
        and pow(g, q, p) == 1 and pow(y, q, p) == 1
        and (x is None or (0 < x < q and pow(g, x, p) == y))
        and is_probable_prime(q) and is_probable_prime(p)
    )
    if not valid:
        raise ValueError("Invalid DSA key components")


def generate_dsa_key(key_length_bits):
    if key_length_bits not in L_TO_N:
        raise ValueError("DSA modulus length must be one of %s" % sorted(L_TO_N))
    n_bits = L_TO_N[key_length_bits]
    q = get_random_prime(n_bits)
    while True:  # Candidates p = 1 mod 2q, of exactly L bits
        candidate = secrets.randbits(key_length_bits) | (1 << (key_length_bits - 1))
        p = candidate - (candidate % (2 * q)) + 1
        if p.bit_length() == key_length_bits and is_probable_prime(p):
            break
    h = 2
    while (g := pow(h, (p - 1) // q, p)) == 1:
        h += 1
    x = 1 + secrets.randbelow(q - 1)
    return DsaKey(p, q, g, pow(g, x, p), x)


def _digest_to_integer(digest, q):
    return int.from_bytes(digest, "big") >> max(0, len(digest) * 8 - q.bit_length())  # Leftmost N bits


def sign(key, digest, k=None):
    """Sign a message digest; `k` must only be given for known-answer tests."""
    if not key.has_private():
        raise TypeError("Private key is needed to sign")
    p, q, g, x = key.p, key.q, key.g, key.x
    z = _digest_to_integer(digest, q)
    while True:
        nonce = k if k is not None else 1 + secrets.randbelow(q - 1)
        r = pow(g, nonce, p) % q
        s = pow(nonce, -1, q) * (z + x * r) % q
        if r and s:
            break
        if k is not None:
            raise ValueError("Unusable nonce k")
    q_length = (q.bit_length() + 7) // 8
    return r.to_bytes(q_length, "big") + s.to_bytes(q_length, "big")


def verify(key, digest, signature):
    """Raise ValueError if the signature is invalid."""
    p, q, g, y = key.p, key.q, key.g, key.y
    q_length = (q.bit_length() + 7) // 8
    if len(signature) != 2 * q_length:
        raise ValueError("The signature is not authentic (length)")
    r, s = int.from_bytes(signature[:q_length], "big"), int.from_bytes(signature[q_length:], "big")
    if not (0 < r < q and 0 < s < q):
        raise ValueError("The signature is not authentic")
    w = pow(s, -1, q)
    v = pow(g, _digest_to_integer(digest, q) * w % q, p) * pow(y, r * w % q, p) % p % q
    if v != r:
        raise ValueError("The signature is not authentic")
