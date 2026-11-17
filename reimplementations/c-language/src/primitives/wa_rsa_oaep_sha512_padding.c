/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_rsa_oaep_sha512_padding.h"

#include <string.h>

#include "primitives/wa_secure_memory_wipe.h"

/* XOR MGF1-SHA-512(mgf_seed) into `target` (RFC 8017, appendix B.2.1) */
static wa_status_t wa_xor_mgf1_sha512_mask(const uint8_t *mgf_seed, size_t mgf_seed_length, uint8_t *target,
                                           size_t target_length)
{
    uint8_t digest[WA_SHA512_DIGEST_SIZE];
    uint8_t counter_bytes[4];
    wa_byte_span_t parts[2];
    uint32_t counter = 0;
    size_t offset = 0;
    wa_status_t status = WA_STATUS_OK;
    parts[0].bytes = mgf_seed;
    parts[0].length = mgf_seed_length;
    parts[1].bytes = counter_bytes;
    parts[1].length = sizeof(counter_bytes);
    while (offset < target_length) {
        size_t step = target_length - offset < sizeof(digest) ? target_length - offset : sizeof(digest);
        size_t index;
        counter_bytes[0] = (uint8_t)(counter >> 24);
        counter_bytes[1] = (uint8_t)(counter >> 16);
        counter_bytes[2] = (uint8_t)(counter >> 8);
        counter_bytes[3] = (uint8_t)counter;
        status = wa_crypto_backend_compute_sha512(parts, 2, digest);
        if (status != WA_STATUS_OK) {
            break;
        }
        for (index = 0; index < step; ++index) {
            target[offset + index] ^= digest[index];
        }
        offset += step;
        ++counter;
    }
    wa_secure_memory_wipe(digest, sizeof(digest));
    return status;
}

wa_status_t wa_rsa_oaep_sha512_encode_padding(const uint8_t *message, size_t message_length,
                                              const uint8_t seed[WA_RSA_OAEP_SEED_SIZE], uint8_t *encoded_message,
                                              size_t modulus_length)
{
    /* EM = 0x00 || maskedSeed (hLen) || maskedDB (k - hLen - 1), DB = lHash || PS || 0x01 || M */
    uint8_t *masked_seed = encoded_message + 1;
    uint8_t *masked_db = encoded_message + 1 + WA_SHA512_DIGEST_SIZE;
    size_t db_length;
    wa_status_t status;
    if (modulus_length < WA_RSA_OAEP_SHA512_OVERHEAD ||
        message_length > modulus_length - WA_RSA_OAEP_SHA512_OVERHEAD) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    db_length = modulus_length - WA_SHA512_DIGEST_SIZE - 1u;
    encoded_message[0] = 0x00;
    /* lHash: the empty label's digest */
    status = wa_crypto_backend_compute_sha512(NULL, 0, masked_db);
    if (status == WA_STATUS_OK) {
        size_t padding_string_length = db_length - WA_SHA512_DIGEST_SIZE - 1u - message_length;
        memset(masked_db + WA_SHA512_DIGEST_SIZE, 0, padding_string_length);
        masked_db[WA_SHA512_DIGEST_SIZE + padding_string_length] = 0x01;
        if (message_length > 0) {
            memcpy(masked_db + WA_SHA512_DIGEST_SIZE + padding_string_length + 1u, message, message_length);
        }
        memcpy(masked_seed, seed, WA_RSA_OAEP_SEED_SIZE);
        /* maskedDB = DB xor MGF1(seed); maskedSeed = seed xor MGF1(maskedDB) */
        status = wa_xor_mgf1_sha512_mask(seed, WA_RSA_OAEP_SEED_SIZE, masked_db, db_length);
    }
    if (status == WA_STATUS_OK) {
        status = wa_xor_mgf1_sha512_mask(masked_db, db_length, masked_seed, WA_RSA_OAEP_SEED_SIZE);
    }
    if (status != WA_STATUS_OK) {
        wa_secure_memory_wipe(encoded_message, modulus_length);
    }
    return status;
}
