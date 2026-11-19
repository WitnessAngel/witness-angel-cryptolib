// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Constraints on trustee public keys (device profile specification): keys that would give no confidentiality,
//! or that a backend could mishandle, are refused when the profile is loaded. Every violation is
//! `ErrorKind::KeyConstraintViolation`. Public keys are public: nothing here is constant-time.

use alloc::vec::Vec;

use crate::crypto_backend::{ML_KEM_768_PUBLIC_KEY_SIZE, X25519_KEY_SIZE};
use crate::error::{Error, ErrorKind, Result};

const MINIMUM_RSA_MODULUS_BITS: usize = 2048;
const ML_KEM_MODULUS: u16 = 3329;
/// 3 polynomials of 256 12-bit coefficients; the 32-byte rho follows
const ML_KEM_768_ENCODED_POLYNOMIALS_SIZE: usize = 1152;

fn violation<T>() -> Result<T> {
    Err(Error::new(ErrorKind::KeyConstraintViolation))
}

/// Little-endian 32-bit limbs of a big-endian byte string, `limb_count` of them.
fn load_limbs(big_endian: &[u8], limb_count: usize) -> Result<Vec<u32>> {
    let mut limbs = Vec::new();
    limbs
        .try_reserve_exact(limb_count)
        .map_err(|_| Error::new(ErrorKind::OutOfMemory))?;
    limbs.resize(limb_count, 0u32);
    for (byte_position, byte) in big_endian.iter().rev().enumerate() {
        limbs[byte_position / 4] |= u32::from(*byte) << (8 * (byte_position % 4));
    }
    Ok(limbs)
}

fn subtract_limbs(a: &mut [u32], b: &[u32]) {
    // a -= b, with a >= b
    let mut borrow = false;
    for (a_limb, b_limb) in a.iter_mut().zip(b.iter()) {
        let (difference, first_borrow) = a_limb.overflowing_sub(*b_limb);
        let (difference, second_borrow) = difference.overflowing_sub(u32::from(borrow));
        *a_limb = difference;
        borrow = first_borrow || second_borrow;
    }
}

fn remove_factors_of_two(limbs: &mut [u32]) {
    // limbs must be nonzero
    while limbs[0] & 1 == 0 {
        for index in 0..limbs.len() - 1 {
            limbs[index] = (limbs[index] >> 1) | (limbs[index + 1] << 31);
        }
        let last = limbs.len() - 1;
        limbs[last] >>= 1;
    }
}

/// Whether gcd(n, e) = 1, for an odd n and a nonzero e not longer than n (binary GCD).
fn rsa_values_are_coprime(modulus: &[u8], public_exponent: &[u8]) -> Result<bool> {
    let limb_count = modulus.len().div_ceil(4);
    let mut odd_value = load_limbs(modulus, limb_count)?;
    let mut other_value = load_limbs(public_exponent, limb_count)?;
    // n is odd, so factors of two of e are not common: gcd(n, e) = gcd(n, e / 2^k)
    remove_factors_of_two(&mut other_value);
    loop {
        // Most significant limb first
        match odd_value.iter().rev().cmp(other_value.iter().rev()) {
            core::cmp::Ordering::Equal => break,
            core::cmp::Ordering::Greater => core::mem::swap(&mut odd_value, &mut other_value),
            core::cmp::Ordering::Less => {}
        }
        subtract_limbs(&mut other_value, &odd_value); // Both odd: the difference is even and nonzero
        remove_factors_of_two(&mut other_value);
    }
    Ok(odd_value[0] == 1 && odd_value[1..].iter().all(|limb| *limb == 0))
}

/// RSA: big-endian modulus and exponent without leading zero byte, a modulus of 2048 to `maximum_modulus_bits`
/// bits, both odd, 3 <= e < n, and gcd(n, e) = 1.
pub(crate) fn check_rsa_public_key(modulus: &[u8], public_exponent: &[u8], maximum_modulus_bits: usize) -> Result<()> {
    let (Some(&modulus_first), Some(&modulus_last)) = (modulus.first(), modulus.last()) else {
        return violation();
    };
    let (Some(&exponent_first), Some(&exponent_last)) = (public_exponent.first(), public_exponent.last()) else {
        return violation();
    };
    if modulus_first == 0 || exponent_first == 0 {
        return violation(); // Leading zero bytes
    }
    if modulus.len() > maximum_modulus_bits / 8 {
        return violation();
    }
    let modulus_bits = (modulus.len() - 1) * 8 + (8 - modulus_first.leading_zeros() as usize);
    if !(MINIMUM_RSA_MODULUS_BITS..=maximum_modulus_bits).contains(&modulus_bits) {
        return violation();
    }
    if modulus_last & 1 == 0 || exponent_last & 1 == 0 {
        return violation(); // Even modulus or exponent
    }
    if public_exponent.len() == 1 && exponent_first < 3 {
        return violation();
    }
    // e < n: without leading zeros, a shorter string is a smaller number
    if public_exponent.len() > modulus.len() || (public_exponent.len() == modulus.len() && public_exponent >= modulus) {
        return violation();
    }
    if !rsa_values_are_coprime(modulus, public_exponent)? {
        return violation();
    }
    Ok(())
}

/// X25519: a canonical u-coordinate (32 bytes, below p = 2^255 - 19) that is not a low-order point.
pub(crate) fn check_x25519_public_key(public_key: &[u8]) -> Result<()> {
    // Little-endian u-coordinates of RFC 7748 (section 5 and the Curve25519 low-order points)
    const LOW_ORDER_POINTS: [[u8; X25519_KEY_SIZE]; 5] = [
        [0; X25519_KEY_SIZE],
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09,
            0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
        ],
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44,
            0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
        ],
        // p - 1
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ],
    ];
    let Ok(public_key) = <&[u8; X25519_KEY_SIZE]>::try_from(public_key) else {
        return violation();
    };
    if public_key[X25519_KEY_SIZE - 1] & 0x80 != 0 {
        return violation();
    }
    // u >= p = 2^255 - 19, i.e. 0x7fff...ffed: top byte 0x7f, the 30 middle bytes 0xff, the low byte >= 0xed
    if public_key[X25519_KEY_SIZE - 1] == 0x7f
        && public_key[1..X25519_KEY_SIZE - 1].iter().all(|byte| *byte == 0xff)
        && public_key[0] >= 0xed
    {
        return violation();
    }
    if LOW_ORDER_POINTS.contains(public_key) {
        return violation();
    }
    Ok(())
}

/// ML-KEM-768: 1184 bytes whose polynomial coefficients are all reduced (the modulus check of FIPS 203,
/// section 7.2).
pub(crate) fn check_ml_kem_768_public_key(public_key: &[u8]) -> Result<()> {
    if public_key.len() != ML_KEM_768_PUBLIC_KEY_SIZE {
        return violation();
    }
    // ByteDecode_12: every 3 bytes hold 2 little-endian 12-bit coefficients
    for triple in public_key[..ML_KEM_768_ENCODED_POLYNOMIALS_SIZE].chunks_exact(3) {
        let first = u16::from(triple[0]) | (u16::from(triple[1] & 0x0f) << 8);
        let second = (u16::from(triple[1]) >> 4) | (u16::from(triple[2]) << 4);
        if first >= ML_KEM_MODULUS || second >= ML_KEM_MODULUS {
            return violation();
        }
    }
    Ok(())
}
