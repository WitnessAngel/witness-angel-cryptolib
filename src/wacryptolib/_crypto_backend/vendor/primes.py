# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Pure python prime generation (Miller-Rabin with random bases), for the fallback RSA and DSA key generators.
"""

import secrets

_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % d for d in range(3, int(p**0.5) + 1, 2))]

MILLER_RABIN_ROUNDS = 40  # Error probability below 2**-80 even for adversarial candidates


def is_probable_prime(n, rounds=MILLER_RABIN_ROUNDS):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if not n & 1:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while not d & 1:
        d >>= 1
        s += 1
    for _ in range(rounds):
        x = pow(2 + secrets.randbelow(n - 3), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def get_random_prime(bits, top_bits_mask=1):
    """Return a random prime of exactly `bits` bits, whose `top_bits_mask` most significant bits are set
    (top_bits_mask=0b11 ensures that the product of two such primes has exactly 2*bits bits)."""
    top_bits = top_bits_mask << (bits - top_bits_mask.bit_length())
    while True:
        candidate = secrets.randbits(bits) | top_bits | 1
        if is_probable_prime(candidate):
            return candidate
