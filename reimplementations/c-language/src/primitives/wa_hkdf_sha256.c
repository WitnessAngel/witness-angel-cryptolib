/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_hkdf_sha256.h"

#include <string.h>

#include "primitives/wa_secure_memory_wipe.h"

wa_status_t wa_hkdf_sha256_extract(const uint8_t *salt, size_t salt_length, const wa_byte_span_t *ikm_parts,
                                   size_t ikm_part_count, uint8_t prk[WA_HKDF_SHA256_PRK_SIZE])
{
    static const uint8_t zero_salt[WA_SHA256_DIGEST_SIZE] = {0};
    if (salt_length == 0) {
        salt = zero_salt;
        salt_length = sizeof(zero_salt);
    }
    return wa_crypto_backend_compute_hmac_sha256(salt, salt_length, ikm_parts, ikm_part_count, prk);
}

wa_status_t wa_hkdf_sha256_expand(const uint8_t prk[WA_HKDF_SHA256_PRK_SIZE], const wa_byte_span_t *info_parts,
                                  size_t info_part_count, uint8_t *okm, size_t okm_length)
{
    wa_byte_span_t parts[WA_HKDF_SHA256_MAXIMUM_PART_COUNT + 2u];
    uint8_t block[WA_SHA256_DIGEST_SIZE];
    uint8_t counter = 0;
    size_t offset = 0;
    size_t index;
    wa_status_t status = WA_STATUS_OK;
    if (okm_length == 0 || okm_length > WA_HKDF_SHA256_MAXIMUM_OKM_LENGTH ||
        info_part_count > WA_HKDF_SHA256_MAXIMUM_PART_COUNT) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    /* parts: T(i - 1) (empty at first), the info parts, then the counter byte */
    parts[0].bytes = block;
    parts[0].length = 0;
    for (index = 0; index < info_part_count; ++index) {
        parts[1 + index] = info_parts[index];
    }
    parts[1 + info_part_count].bytes = &counter;
    parts[1 + info_part_count].length = 1;
    while (offset < okm_length) {
        size_t step = okm_length - offset < sizeof(block) ? okm_length - offset : sizeof(block);
        ++counter;
        status = wa_crypto_backend_compute_hmac_sha256(prk, WA_HKDF_SHA256_PRK_SIZE, parts, info_part_count + 2u,
                                                       block);
        if (status != WA_STATUS_OK) {
            wa_secure_memory_wipe(okm, okm_length);
            break;
        }
        memcpy(okm + offset, block, step);
        parts[0].length = sizeof(block);
        offset += step;
    }
    wa_secure_memory_wipe(block, sizeof(block));
    return status;
}
