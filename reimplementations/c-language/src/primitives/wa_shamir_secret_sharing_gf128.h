/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Shamir secret sharing over GF(2^128) (encryptor specification, section 3.7), as wacryptolib's
 * split_secret_into_shards(): PKCS#7 pre-padding, then pycryptodome's Shamir.split on each 16-byte chunk, with
 * fresh random coefficients per chunk. */

#ifndef WA_SHAMIR_SECRET_SHARING_GF128_H
#define WA_SHAMIR_SECRET_SHARING_GF128_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_status_codes.h"

#define WA_GF128_ELEMENT_SIZE 16u

/* Maximum number of shards of a shared secret (encryptor specification, section 3.7): a format limit, readers
 * rejecting shard indices above it, hence not configurable. Cryptoconf validation enforces it (section 5.2). */
#define WA_MAX_SHARED_SECRET_SHARD_COUNT 30u

/* Product in GF(2^128): 16-byte big-endian elements (bit j of the integer is the coefficient of x^j), reduction
 * polynomial x^128 + x^7 + x^2 + x + 1, in time independent of the values. `product` may alias an operand. */
void wa_gf128_multiply(const uint8_t a[WA_GF128_ELEMENT_SIZE], const uint8_t b[WA_GF128_ELEMENT_SIZE],
                       uint8_t product[WA_GF128_ELEMENT_SIZE]);

/* Split `secret` into `shard_count` shards, any `threshold_count` of which recombine it
 * (1 <= k <= n <= WA_MAX_SHARED_SECRET_SHARD_COUNT, else WA_STATUS_INVALID_ARGUMENT). Shard i
 * (1-based) is the `*shard_length_out` bytes at `*shards_out + (i - 1) * *shard_length_out`, in one block of
 * n * shard_length bytes allocated with the platform hooks, to release with wa_release_secret_memory().
 * For each chunk, the k - 1 coefficients are drawn from the random hook one by one, 16 bytes each, highest degree
 * first (pycryptodome's order). */
wa_status_t wa_shamir_split_secret_into_shards(const wa_platform_hooks_t *platform_hooks, const uint8_t *secret,
                                               size_t secret_length, size_t shard_count, size_t threshold_count,
                                               uint8_t **shards_out, size_t *shard_length_out);

#endif /* WA_SHAMIR_SECRET_SHARING_GF128_H */
