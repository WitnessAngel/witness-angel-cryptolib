/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* HKDF-SHA256 (RFC 5869) over the backend's HMAC-SHA256, inputs given as parts (no concatenation buffers): the KDF
 * of both HPKE suites (encryptor specification, section 3.5). */

#ifndef WA_HKDF_SHA256_H
#define WA_HKDF_SHA256_H

#include <stddef.h>
#include <stdint.h>

#include "backends/wa_crypto_backend.h"
#include "wa_flightbox/wa_status_codes.h"

#define WA_HKDF_SHA256_PRK_SIZE WA_SHA256_DIGEST_SIZE
#define WA_HKDF_SHA256_MAXIMUM_OKM_LENGTH (255u * WA_SHA256_DIGEST_SIZE)
/* Most parts accepted for the input keying material or the info */
#define WA_HKDF_SHA256_MAXIMUM_PART_COUNT 6u

/* PRK = HMAC-SHA256(salt, IKM); an empty salt stands for 32 zero bytes. */
wa_status_t wa_hkdf_sha256_extract(const uint8_t *salt, size_t salt_length, const wa_byte_span_t *ikm_parts,
                                   size_t ikm_part_count, uint8_t prk[WA_HKDF_SHA256_PRK_SIZE]);

/* OKM = first `okm_length` bytes of T(1) || T(2) || ..., T(i) = HMAC-SHA256(PRK, T(i - 1) || info || i), with
 * 1 <= okm_length <= 255 * 32. */
wa_status_t wa_hkdf_sha256_expand(const uint8_t prk[WA_HKDF_SHA256_PRK_SIZE], const wa_byte_span_t *info_parts,
                                  size_t info_part_count, uint8_t *okm, size_t okm_length);

#endif /* WA_HKDF_SHA256_H */
