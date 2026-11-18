/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_public_key_constraints.h"

#include <string.h>

#include "backends/wa_crypto_backend.h"

#define WA_ML_KEM_MODULUS 3329u
#define WA_ML_KEM_768_ENCODED_POLYNOMIALS_SIZE 1152u /* 3 polynomials of 256 12-bit coefficients, then 32-byte rho */

static size_t wa_get_bit_length_of_byte(uint8_t byte)
{
    size_t bit_length = 0;
    while (byte != 0) {
        ++bit_length;
        byte = (uint8_t)(byte >> 1);
    }
    return bit_length;
}

/* GREATEST COMMON DIVISOR, for gcd(n, e) = 1 */

/* Little-endian 32-bit limbs, enough for any modulus or exponent accepted (e < n) */
#define WA_RSA_LIMB_COUNT ((WA_MAX_RSA_MODULUS_BITS + 31u) / 32u)

static void wa_load_limbs(uint32_t limbs[WA_RSA_LIMB_COUNT], const uint8_t *big_endian, size_t length)
{
    size_t index;
    memset(limbs, 0, WA_RSA_LIMB_COUNT * sizeof(uint32_t));
    for (index = 0; index < length; ++index) {
        size_t bit_position = 8u * (length - 1u - index);
        limbs[bit_position / 32u] |= (uint32_t)big_endian[index] << (bit_position % 32u);
    }
}

static int wa_compare_limbs(const uint32_t *a, const uint32_t *b)
{
    size_t index = WA_RSA_LIMB_COUNT;
    while (index-- > 0) {
        if (a[index] != b[index]) {
            return a[index] < b[index] ? -1 : 1;
        }
    }
    return 0;
}

static void wa_subtract_limbs(uint32_t *a, const uint32_t *b) /* a -= b, with a >= b */
{
    uint64_t borrow = 0;
    size_t index;
    for (index = 0; index < WA_RSA_LIMB_COUNT; ++index) {
        uint64_t difference = (uint64_t)a[index] - b[index] - borrow;
        a[index] = (uint32_t)difference;
        borrow = (difference >> 32) & 1u;
    }
}

static void wa_remove_factors_of_two(uint32_t *limbs) /* limbs must be nonzero */
{
    while ((limbs[0] & 1u) == 0) {
        size_t index;
        for (index = 0; index + 1u < WA_RSA_LIMB_COUNT; ++index) {
            limbs[index] = (limbs[index] >> 1) | (limbs[index + 1u] << 31);
        }
        limbs[WA_RSA_LIMB_COUNT - 1u] >>= 1;
    }
}

/* Whether gcd(n, e) = 1, for an odd n and a nonzero e (binary GCD; both values are public) */
static int wa_rsa_values_are_coprime(const uint8_t *modulus, size_t modulus_length, const uint8_t *public_exponent,
                                     size_t public_exponent_length)
{
    uint32_t first_limbs[WA_RSA_LIMB_COUNT];
    uint32_t second_limbs[WA_RSA_LIMB_COUNT];
    uint32_t *odd_value = first_limbs;
    uint32_t *other_value = second_limbs;
    size_t index;
    wa_load_limbs(odd_value, modulus, modulus_length);
    wa_load_limbs(other_value, public_exponent, public_exponent_length);
    /* n is odd, so factors of two of e are not common: gcd(n, e) = gcd(n, e / 2^k) */
    wa_remove_factors_of_two(other_value);
    for (;;) {
        int comparison = wa_compare_limbs(odd_value, other_value);
        if (comparison == 0) {
            break;
        }
        if (comparison > 0) {
            uint32_t *swapped = odd_value;
            odd_value = other_value;
            other_value = swapped;
        }
        wa_subtract_limbs(other_value, odd_value); /* Both odd: the difference is even and nonzero */
        wa_remove_factors_of_two(other_value);
    }
    if (odd_value[0] != 1u) {
        return 0;
    }
    for (index = 1; index < WA_RSA_LIMB_COUNT; ++index) {
        if (odd_value[index] != 0) {
            return 0;
        }
    }
    return 1;
}

wa_status_t wa_public_key_check_rsa(const uint8_t *modulus, size_t modulus_length, const uint8_t *public_exponent,
                                    size_t public_exponent_length)
{
    size_t modulus_bits;
    if (modulus_length == 0 || modulus[0] == 0 || public_exponent_length == 0 || public_exponent[0] == 0) {
        return WA_STATUS_KEY_CONSTRAINT_VIOLATION; /* Empty, or with leading zero bytes */
    }
    if (modulus_length > WA_MAX_RSA_MODULUS_BITS / 8u) {
        return WA_STATUS_KEY_CONSTRAINT_VIOLATION;
    }
    modulus_bits = (modulus_length - 1u) * 8u + wa_get_bit_length_of_byte(modulus[0]);
    if (modulus_bits < WA_MIN_RSA_MODULUS_BITS || modulus_bits > WA_MAX_RSA_MODULUS_BITS) {
        return WA_STATUS_KEY_CONSTRAINT_VIOLATION;
    }
    if ((modulus[modulus_length - 1u] & 1u) == 0 || (public_exponent[public_exponent_length - 1u] & 1u) == 0) {
        return WA_STATUS_KEY_CONSTRAINT_VIOLATION; /* Even modulus or exponent */
    }
    if (public_exponent_length == 1 && public_exponent[0] < 3u) {
        return WA_STATUS_KEY_CONSTRAINT_VIOLATION;
    }
    /* e < n: without leading zeros, a shorter string is a smaller number */
    if (public_exponent_length > modulus_length ||
        (public_exponent_length == modulus_length && memcmp(public_exponent, modulus, modulus_length) >= 0)) {
        return WA_STATUS_KEY_CONSTRAINT_VIOLATION;
    }
    if (!wa_rsa_values_are_coprime(modulus, modulus_length, public_exponent, public_exponent_length)) {
        return WA_STATUS_KEY_CONSTRAINT_VIOLATION; /* gcd(n, e) != 1 */
    }
    return WA_STATUS_OK;
}

wa_status_t wa_public_key_check_x25519(const uint8_t *public_key, size_t public_key_length)
{
    /* Little-endian u-coordinates of RFC 7748 (section 5 and the Curve25519 low-order points) */
    static const uint8_t low_order_points[][WA_X25519_KEY_SIZE] = {
        {0},
        {1},
        {0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
         0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
        {0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
         0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
        /* p - 1 */
        {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}};
    size_t index;
    int all_middle_bytes_are_ff = 1;
    if (public_key_length != WA_X25519_KEY_SIZE || (public_key[WA_X25519_KEY_SIZE - 1u] & 0x80u) != 0) {
        return WA_STATUS_KEY_CONSTRAINT_VIOLATION;
    }
    /* u >= p = 2^255 - 19, i.e. 0x7fff...ffed: top byte 0x7f, the 30 middle bytes 0xff, the low byte >= 0xed */
    for (index = 1; index < WA_X25519_KEY_SIZE - 1u; ++index) {
        if (public_key[index] != 0xffu) {
            all_middle_bytes_are_ff = 0;
        }
    }
    if (public_key[WA_X25519_KEY_SIZE - 1u] == 0x7fu && all_middle_bytes_are_ff && public_key[0] >= 0xedu) {
        return WA_STATUS_KEY_CONSTRAINT_VIOLATION;
    }
    for (index = 0; index < sizeof(low_order_points) / sizeof(low_order_points[0]); ++index) {
        if (memcmp(public_key, low_order_points[index], WA_X25519_KEY_SIZE) == 0) {
            return WA_STATUS_KEY_CONSTRAINT_VIOLATION;
        }
    }
    return WA_STATUS_OK;
}

wa_status_t wa_public_key_check_ml_kem_768(const uint8_t *public_key, size_t public_key_length)
{
    size_t offset;
    if (public_key_length != WA_ML_KEM_768_PUBLIC_KEY_SIZE) {
        return WA_STATUS_KEY_CONSTRAINT_VIOLATION;
    }
    /* ByteDecode_12: every 3 bytes hold 2 little-endian 12-bit coefficients */
    for (offset = 0; offset < WA_ML_KEM_768_ENCODED_POLYNOMIALS_SIZE; offset += 3u) {
        unsigned int first = (unsigned int)public_key[offset] | ((unsigned int)(public_key[offset + 1u] & 0x0fu) << 8);
        unsigned int second = ((unsigned int)public_key[offset + 1u] >> 4) | ((unsigned int)public_key[offset + 2u] << 4);
        if (first >= WA_ML_KEM_MODULUS || second >= WA_ML_KEM_MODULUS) {
            return WA_STATUS_KEY_CONSTRAINT_VIOLATION;
        }
    }
    return WA_STATUS_OK;
}
