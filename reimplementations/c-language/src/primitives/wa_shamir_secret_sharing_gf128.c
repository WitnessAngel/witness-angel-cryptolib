/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_shamir_secret_sharing_gf128.h"

#include <string.h>

#include "core/wa_platform_hooks_calls.h"
#include "primitives/wa_aes_cbc_pkcs7_padding.h"
#include "primitives/wa_secure_memory_wipe.h"

static uint64_t wa_load_big_endian_64(const uint8_t *bytes)
{
    uint64_t value = 0;
    size_t index;
    for (index = 0; index < 8; ++index) {
        value = (value << 8) | bytes[index];
    }
    return value;
}

static void wa_store_big_endian_64(uint64_t value, uint8_t *bytes)
{
    size_t index;
    for (index = 0; index < 8; ++index) {
        bytes[index] = (uint8_t)(value >> (56u - 8u * index));
    }
}

void wa_gf128_multiply(const uint8_t a[WA_GF128_ELEMENT_SIZE], const uint8_t b[WA_GF128_ELEMENT_SIZE],
                       uint8_t product[WA_GF128_ELEMENT_SIZE])
{
    uint64_t a_high = wa_load_big_endian_64(a);
    uint64_t a_low = wa_load_big_endian_64(a + 8);
    uint64_t b_high = wa_load_big_endian_64(b);
    uint64_t b_low = wa_load_big_endian_64(b + 8);
    uint64_t result_high = 0;
    uint64_t result_low = 0;
    int bit_index;
    /* Horner over the bits of b, from x^127 down to x^0: result = result * x + bit * a */
    for (bit_index = 127; bit_index >= 0; --bit_index) {
        uint64_t overflow_mask = 0u - (result_high >> 63);
        uint64_t bit = bit_index >= 64 ? (b_high >> (bit_index - 64)) & 1u : (b_low >> bit_index) & 1u;
        uint64_t bit_mask = 0u - bit;
        result_high = (result_high << 1) | (result_low >> 63);
        result_low = (result_low << 1) ^ (0x87u & overflow_mask);
        result_high ^= a_high & bit_mask;
        result_low ^= a_low & bit_mask;
    }
    wa_store_big_endian_64(result_high, product);
    wa_store_big_endian_64(result_low, product + 8);
}

wa_status_t wa_shamir_split_secret_into_shards(const wa_platform_hooks_t *platform_hooks, const uint8_t *secret,
                                               size_t secret_length, size_t shard_count, size_t threshold_count,
                                               uint8_t **shards_out, size_t *shard_length_out)
{
    uint8_t chunk[WA_GF128_ELEMENT_SIZE];
    uint8_t coefficient[WA_GF128_ELEMENT_SIZE];
    uint8_t index_element[WA_GF128_ELEMENT_SIZE];
    uint8_t *shards;
    size_t padded_length;
    size_t total_length;
    size_t chunk_offset;
    size_t shard_index;
    size_t coefficient_index;
    wa_status_t status = WA_STATUS_OK;
    *shards_out = NULL;
    *shard_length_out = 0;
    if (threshold_count < 1 || threshold_count > shard_count ||
        secret_length > (size_t)-1 - WA_PKCS7_BLOCK_SIZE) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    padded_length = secret_length + wa_pkcs7_get_padding_length(secret_length);
    if (wa_size_multiplication_overflows(shard_count, padded_length, &total_length)) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    shards = (uint8_t *)wa_allocate_memory(platform_hooks, total_length);
    if (shards == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    /* Shares accumulate in place, by Horner's rule: share_i = share_i * i + coefficient, with share_i = 0 at first */
    memset(shards, 0, total_length);
    memset(index_element, 0, sizeof(index_element));
    for (chunk_offset = 0; chunk_offset < padded_length && status == WA_STATUS_OK;
         chunk_offset += WA_GF128_ELEMENT_SIZE) {
        /* The chunk, the last one completed by its PKCS#7 padding */
        size_t data_length = secret_length - chunk_offset < WA_GF128_ELEMENT_SIZE ? secret_length - chunk_offset
                                                                                  : WA_GF128_ELEMENT_SIZE;
        if (chunk_offset >= secret_length) {
            data_length = 0;
        }
        memcpy(chunk, secret + chunk_offset, data_length);
        if (data_length < WA_GF128_ELEMENT_SIZE) {
            wa_pkcs7_pad_final_block(chunk, data_length);
        }
        /* Random coefficients from the highest degree down, then the chunk itself as constant term */
        for (coefficient_index = 0; coefficient_index < threshold_count && status == WA_STATUS_OK; ++coefficient_index) {
            if (coefficient_index + 1 < threshold_count) {
                status = wa_fill_random_bytes(platform_hooks, coefficient, sizeof(coefficient));
            } else {
                memcpy(coefficient, chunk, sizeof(coefficient));
            }
            for (shard_index = 0; shard_index < shard_count && status == WA_STATUS_OK; ++shard_index) {
                uint8_t *share = shards + shard_index * padded_length + chunk_offset;
                size_t byte_index;
                size_t index_value = shard_index + 1;
                for (byte_index = 0; byte_index < WA_GF128_ELEMENT_SIZE; ++byte_index) {
                    index_element[WA_GF128_ELEMENT_SIZE - 1 - byte_index] =
                        (uint8_t)(byte_index < sizeof(size_t) ? index_value >> (8u * byte_index) : 0u);
                }
                wa_gf128_multiply(share, index_element, share);
                for (byte_index = 0; byte_index < WA_GF128_ELEMENT_SIZE; ++byte_index) {
                    share[byte_index] ^= coefficient[byte_index];
                }
            }
        }
    }
    wa_secure_memory_wipe(chunk, sizeof(chunk));
    wa_secure_memory_wipe(coefficient, sizeof(coefficient));
    if (status != WA_STATUS_OK) {
        wa_release_secret_memory(platform_hooks, shards, total_length);
        return status;
    }
    *shards_out = shards;
    *shard_length_out = padded_length;
    return WA_STATUS_OK;
}
