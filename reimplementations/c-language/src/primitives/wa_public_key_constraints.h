/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Public key constraints of the device profile specification, section 5 (encryptor specification, section 11.2,
 * tightened so that every backend accepts exactly the same keys). Each check returns WA_STATUS_OK, or
 * WA_STATUS_KEY_CONSTRAINT_VIOLATION. Keys are public: the checks need not run in constant time. */

#ifndef WA_PUBLIC_KEY_CONSTRAINTS_H
#define WA_PUBLIC_KEY_CONSTRAINTS_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_flightbox_config.h"
#include "wa_flightbox/wa_status_codes.h"

#define WA_MIN_RSA_MODULUS_BITS 2048u

/* RSA: big-endian modulus and public exponent without leading zero bytes; modulus of 2048 to
 * WA_MAX_RSA_MODULUS_BITS bits, odd; 3 <= e < n, e odd; gcd(n, e) = 1 (binary GCD, with two buffers of
 * WA_MAX_RSA_MODULUS_BITS bits on the stack). */
wa_status_t wa_public_key_check_rsa(const uint8_t *modulus, size_t modulus_length, const uint8_t *public_exponent,
                                    size_t public_exponent_length);

/* X25519: 32 bytes, canonical (bit 255 clear, u < 2^255 - 19), and none of the low-order points 0, 1, the two
 * points of order 8 and p - 1. */
wa_status_t wa_public_key_check_x25519(const uint8_t *public_key, size_t public_key_length);

/* ML-KEM-768: 1184 bytes, whose 768 decoded 12-bit coefficients are all below 3329 (FIPS 203, section 7.2). */
wa_status_t wa_public_key_check_ml_kem_768(const uint8_t *public_key, size_t public_key_length);

#endif /* WA_PUBLIC_KEY_CONSTRAINTS_H */
