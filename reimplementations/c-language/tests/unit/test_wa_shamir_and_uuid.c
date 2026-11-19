/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Unit tests of UUID0 generation (task 5.1) and of Shamir secret sharing over GF(2^128) (task 5.6): shards against
 * wacryptolib's split_secret_into_shards() with replayed coefficients, and recombination by Lagrange interpolation
 * from every subset of threshold size, for several secret lengths. */

#include <stdlib.h>
#include <string.h>

#include "primitives/wa_shamir_secret_sharing_gf128.h"
#include "primitives/wa_uuid0_generation.h"
#include "wa_minimal_test_harness.h"
#include "wa_primitive_vectors.h"
#include "wa_test_support.h"

static uint8_t *decode(const char *hex, size_t *length_out)
{
    uint8_t *bytes = wa_test_decode_hex(hex, length_out);
    if (bytes == NULL) {
        abort();
    }
    return bytes;
}

/* UUID0 */

static int wa_failing_clock(void *clock_context, uint64_t *unix_time_out)
{
    (void)clock_context;
    *unix_time_out = 0x1122334455667788u;
    return -1;
}

static void test_uuid0_with_fixed_clock(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(77);
    wa_test_random_generator_t twin_generator;
    uint8_t expected_random_part[WA_UUID0_RANDOM_PART_SIZE];
    uint8_t uuid[WA_UUID_SIZE];
    static const uint8_t expected_prefix[WA_UUID0_TIME_PREFIX_SIZE] = {0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    platform->clock.is_available = 1;
    platform->clock.unix_time_in_ten_thousandths_of_second = 0x0123456789abcdefu; /* The 2 high bytes are dropped */
    platform->clock.increment_per_call = 0;
    wa_test_random_generator_initialize(&twin_generator, 77);
    WA_REQUIRE(wa_test_fill_random(&twin_generator, expected_random_part, sizeof(expected_random_part)) == 0);
    WA_REQUIRE_STATUS(wa_uuid0_generate(&platform->hooks, uuid), WA_STATUS_OK);
    WA_CHECK_BYTES(uuid, WA_UUID0_TIME_PREFIX_SIZE, expected_prefix, sizeof(expected_prefix));
    WA_CHECK_BYTES(uuid + WA_UUID0_TIME_PREFIX_SIZE, WA_UUID0_RANDOM_PART_SIZE, expected_random_part,
                   sizeof(expected_random_part));
    WA_CHECK_SIZE(platform->random_generator.call_count, 1);
    wa_test_platform_destroy(platform);
}

static void test_uuid0_with_real_time_value(void)
{
    /* 2026-01-01 00:00:00 UTC = 1767225600 s, i.e. 17672256000000 in 1/10000 s = 0x00001012a48a9000 */
    wa_test_platform_t *platform = wa_test_platform_create(78);
    uint8_t uuid[WA_UUID_SIZE];
    static const uint8_t expected_prefix[WA_UUID0_TIME_PREFIX_SIZE] = {0x10, 0x12, 0xa4, 0x8a, 0x90, 0x00};
    platform->clock.is_available = 1;
    platform->clock.unix_time_in_ten_thousandths_of_second = 17672256000000u;
    platform->clock.increment_per_call = 0;
    WA_REQUIRE_STATUS(wa_uuid0_generate(&platform->hooks, uuid), WA_STATUS_OK);
    WA_CHECK_BYTES(uuid, WA_UUID0_TIME_PREFIX_SIZE, expected_prefix, sizeof(expected_prefix));
    wa_test_platform_destroy(platform);
}

static void test_uuid0_without_clock(void)
{
    static const uint8_t zero_prefix[WA_UUID0_TIME_PREFIX_SIZE] = {0};
    wa_test_platform_t *platform = wa_test_platform_create(79);
    uint8_t uuid[WA_UUID_SIZE];
    uint8_t other_uuid[WA_UUID_SIZE];
    /* No clock hook at all */
    platform->hooks.get_unix_time_in_ten_thousandths_of_second = NULL;
    WA_REQUIRE_STATUS(wa_uuid0_generate(&platform->hooks, uuid), WA_STATUS_OK);
    WA_CHECK_BYTES(uuid, WA_UUID0_TIME_PREFIX_SIZE, zero_prefix, sizeof(zero_prefix));
    /* A clock hook reporting no clock, even after writing a value */
    platform->hooks.get_unix_time_in_ten_thousandths_of_second = wa_failing_clock;
    WA_REQUIRE_STATUS(wa_uuid0_generate(&platform->hooks, other_uuid), WA_STATUS_OK);
    WA_CHECK_BYTES(other_uuid, WA_UUID0_TIME_PREFIX_SIZE, zero_prefix, sizeof(zero_prefix));
    /* The random parts still differ */
    WA_CHECK(memcmp(uuid + WA_UUID0_TIME_PREFIX_SIZE, other_uuid + WA_UUID0_TIME_PREFIX_SIZE,
                    WA_UUID0_RANDOM_PART_SIZE) != 0);
    /* An unavailable test clock behaves the same */
    platform->hooks.get_unix_time_in_ten_thousandths_of_second = wa_test_get_unix_time;
    platform->clock.is_available = 0;
    WA_REQUIRE_STATUS(wa_uuid0_generate(&platform->hooks, uuid), WA_STATUS_OK);
    WA_CHECK_BYTES(uuid, WA_UUID0_TIME_PREFIX_SIZE, zero_prefix, sizeof(zero_prefix));
    wa_test_platform_destroy(platform);
}

static void test_uuid0_random_failure(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(80);
    uint8_t uuid[WA_UUID_SIZE];
    platform->random_generator.fail_at_call_index = 0;
    WA_CHECK_STATUS(wa_uuid0_generate(&platform->hooks, uuid), WA_STATUS_RANDOMNESS_FAILURE);
    wa_test_platform_destroy(platform);
}

/* GF(2^128) */

static void gf128_from_small_integer(uint64_t value, uint8_t element[WA_GF128_ELEMENT_SIZE])
{
    size_t index;
    memset(element, 0, WA_GF128_ELEMENT_SIZE);
    for (index = 0; index < 8; ++index) {
        element[WA_GF128_ELEMENT_SIZE - 1 - index] = (uint8_t)(value >> (8u * index));
    }
}

/* a^(2^128 - 2) = a^-1 for a != 0, by square-and-multiply (2^128 - 2 has every bit set except bit 0) */
static void gf128_invert(const uint8_t a[WA_GF128_ELEMENT_SIZE], uint8_t inverse[WA_GF128_ELEMENT_SIZE])
{
    uint8_t result[WA_GF128_ELEMENT_SIZE];
    uint8_t power[WA_GF128_ELEMENT_SIZE];
    int bit_index;
    gf128_from_small_integer(1, result);
    memcpy(power, a, WA_GF128_ELEMENT_SIZE);
    for (bit_index = 0; bit_index < 128; ++bit_index) {
        if (bit_index != 0) {
            wa_gf128_multiply(result, power, result);
        }
        wa_gf128_multiply(power, power, power);
    }
    memcpy(inverse, result, WA_GF128_ELEMENT_SIZE);
}

static void test_gf128_multiplication(void)
{
    uint8_t a[WA_GF128_ELEMENT_SIZE];
    uint8_t b[WA_GF128_ELEMENT_SIZE];
    uint8_t product[WA_GF128_ELEMENT_SIZE];
    uint8_t expected[WA_GF128_ELEMENT_SIZE];
    uint8_t inverse[WA_GF128_ELEMENT_SIZE];
    size_t index;
    /* Carry-less small products: 3 * 3 = 5, 7 * 6 = 0x12 */
    gf128_from_small_integer(3, a);
    wa_gf128_multiply(a, a, product);
    gf128_from_small_integer(5, expected);
    WA_CHECK_BYTES(product, 16, expected, 16);
    gf128_from_small_integer(7, a);
    gf128_from_small_integer(6, b);
    wa_gf128_multiply(a, b, product);
    gf128_from_small_integer(0x12, expected);
    WA_CHECK_BYTES(product, 16, expected, 16);
    /* Reduction: x^127 * x = x^128 = x^7 + x^2 + x + 1 */
    memset(a, 0, 16);
    a[0] = 0x80;
    gf128_from_small_integer(2, b);
    wa_gf128_multiply(a, b, product);
    gf128_from_small_integer(0x87, expected);
    WA_CHECK_BYTES(product, 16, expected, 16);
    /* Commutativity, and inverses of arbitrary elements */
    for (index = 0; index < 16; ++index) {
        a[index] = (uint8_t)(0x5a + 13 * index);
        b[index] = (uint8_t)(0xc3 ^ (7 * index));
    }
    wa_gf128_multiply(a, b, product);
    wa_gf128_multiply(b, a, expected);
    WA_CHECK_BYTES(product, 16, expected, 16);
    gf128_invert(a, inverse);
    wa_gf128_multiply(a, inverse, product);
    gf128_from_small_integer(1, expected);
    WA_CHECK_BYTES(product, 16, expected, 16);
}

/* SHAMIR */

/* Recombine chunk by chunk, from the shards of the given 1-based indices, by Lagrange interpolation at x = 0 */
static void recombine(const uint8_t *shards, size_t shard_length, const size_t *indices, size_t index_count,
                      uint8_t *secret_out)
{
    size_t chunk_offset;
    for (chunk_offset = 0; chunk_offset < shard_length; chunk_offset += WA_GF128_ELEMENT_SIZE) {
        uint8_t sum[WA_GF128_ELEMENT_SIZE] = {0};
        size_t i;
        for (i = 0; i < index_count; ++i) {
            uint8_t term[WA_GF128_ELEMENT_SIZE];
            size_t j;
            size_t byte_index;
            memcpy(term, shards + (indices[i] - 1) * shard_length + chunk_offset, WA_GF128_ELEMENT_SIZE);
            for (j = 0; j < index_count; ++j) {
                uint8_t x_j[WA_GF128_ELEMENT_SIZE];
                uint8_t difference[WA_GF128_ELEMENT_SIZE];
                if (j == i) {
                    continue;
                }
                /* term *= x_j / (x_j - x_i), subtraction being XOR */
                gf128_from_small_integer(indices[j], x_j);
                gf128_from_small_integer(indices[j] ^ indices[i], difference);
                gf128_invert(difference, difference);
                wa_gf128_multiply(term, x_j, term);
                wa_gf128_multiply(term, difference, term);
            }
            for (byte_index = 0; byte_index < WA_GF128_ELEMENT_SIZE; ++byte_index) {
                sum[byte_index] ^= term[byte_index];
            }
        }
        memcpy(secret_out + chunk_offset, sum, WA_GF128_ELEMENT_SIZE);
    }
}

static void test_shamir_against_wacryptolib(void)
{
    size_t secret_length;
    size_t coefficients_length;
    uint8_t *secret = decode(WA_SHAMIR_SECRET_HEX, &secret_length);
    uint8_t *coefficients = decode(WA_SHAMIR_COEFFICIENTS_HEX, &coefficients_length);
    wa_test_platform_t *platform = wa_test_platform_create(81);
    wa_test_replayed_random_t replayed_random;
    uint8_t *shards = NULL;
    size_t shard_length = 0;
    size_t index;
    wa_test_replayed_random_initialize(&replayed_random, coefficients, coefficients_length);
    platform->hooks.fill_random = wa_test_fill_replayed_random;
    platform->hooks.random_context = &replayed_random;
    WA_REQUIRE_STATUS(wa_shamir_split_secret_into_shards(&platform->hooks, secret, secret_length,
                                                         WA_SHAMIR_SHARD_COUNT, WA_SHAMIR_THRESHOLD_COUNT, &shards,
                                                         &shard_length),
                      WA_STATUS_OK);
    WA_CHECK_SIZE(shard_length, 32);
    WA_CHECK_SIZE(replayed_random.offset, coefficients_length);
    WA_CHECK_SIZE(replayed_random.call_count, 2 * (WA_SHAMIR_THRESHOLD_COUNT - 1));
    for (index = 0; index < WA_SHAMIR_SHARD_COUNT; ++index) {
        WA_CHECK_HEX(shards + index * shard_length, shard_length, wa_shamir_shards_hex[index]);
    }
    platform->hooks.release(platform->hooks.allocator_context, shards, WA_SHAMIR_SHARD_COUNT * shard_length);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
    free(secret);
    free(coefficients);
}

static void test_shamir_recombination(void)
{
    static const size_t secret_lengths[] = {0, 1, 15, 16, 17, 32, 100};
    static const size_t parameters[][2] = {{1, 1}, {1, 3}, {2, 2}, {2, 5}, {3, 5}, {5, 5}, {4, 7}};
    size_t length_index;
    for (length_index = 0; length_index < sizeof(secret_lengths) / sizeof(secret_lengths[0]); ++length_index) {
        size_t parameter_index;
        for (parameter_index = 0; parameter_index < sizeof(parameters) / sizeof(parameters[0]); ++parameter_index) {
            size_t threshold_count = parameters[parameter_index][0];
            size_t shard_count = parameters[parameter_index][1];
            size_t secret_length = secret_lengths[length_index];
            wa_test_platform_t *platform = wa_test_platform_create(100 + 10 * length_index + parameter_index);
            uint8_t secret[100];
            uint8_t recombined[112];
            uint8_t *shards = NULL;
            size_t shard_length = 0;
            size_t subset_mask;
            size_t index;
            for (index = 0; index < secret_length; ++index) {
                secret[index] = (uint8_t)(index * 31 + secret_length);
            }
            /* An empty secret may be given as NULL */
            WA_REQUIRE_STATUS(wa_shamir_split_secret_into_shards(&platform->hooks, secret_length == 0 ? NULL : secret,
                                                                 secret_length, shard_count, threshold_count, &shards,
                                                                 &shard_length),
                              WA_STATUS_OK);
            WA_CHECK_SIZE(shard_length, (secret_length / 16 + 1) * 16);
            WA_CHECK_SIZE(platform->random_generator.call_count, (shard_length / 16) * (threshold_count - 1));
            /* Every subset of exactly threshold_count shards gives back the PKCS#7-padded secret */
            for (subset_mask = 1; subset_mask < ((size_t)1 << shard_count); ++subset_mask) {
                size_t indices[8];
                size_t index_count = 0;
                size_t padding_length = shard_length - secret_length;
                size_t byte_index;
                for (index = 0; index < shard_count; ++index) {
                    if (subset_mask & ((size_t)1 << index)) {
                        indices[index_count++] = index + 1;
                    }
                }
                if (index_count != threshold_count) {
                    continue;
                }
                recombine(shards, shard_length, indices, index_count, recombined);
                WA_CHECK_BYTES(recombined, secret_length, secret, secret_length);
                for (byte_index = secret_length; byte_index < shard_length; ++byte_index) {
                    WA_CHECK(recombined[byte_index] == padding_length);
                }
            }
            /* With fewer shards, the interpolation gives something else (whp) */
            if (threshold_count >= 2 && secret_length > 0) {
                size_t indices[8];
                for (index = 0; index + 1 < threshold_count; ++index) {
                    indices[index] = index + 1;
                }
                recombine(shards, shard_length, indices, threshold_count - 1, recombined);
                WA_CHECK(memcmp(recombined, secret, secret_length) != 0);
            }
            platform->hooks.release(platform->hooks.allocator_context, shards, shard_count * shard_length);
            WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
            wa_test_platform_destroy(platform);
        }
    }
}

static void test_shamir_errors(void)
{
    static const uint8_t secret[20] = {1, 2, 3};
    wa_test_platform_t *platform = wa_test_platform_create(90);
    uint8_t *shards = (uint8_t *)1;
    size_t shard_length = 99;
    size_t attempt_index;
    WA_CHECK_STATUS(wa_shamir_split_secret_into_shards(&platform->hooks, secret, 20, 3, 0, &shards, &shard_length),
                    WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK(shards == NULL && shard_length == 0);
    WA_CHECK_STATUS(wa_shamir_split_secret_into_shards(&platform->hooks, secret, 20, 3, 4, &shards, &shard_length),
                    WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(
        wa_shamir_split_secret_into_shards(&platform->hooks, secret, 20, (size_t)-1 / 16, 2, &shards, &shard_length),
        WA_STATUS_INVALID_ARGUMENT);
    /* Allocation failure */
    platform->allocator.fail_at_attempt_index = platform->allocator.attempted_allocation_count;
    WA_CHECK_STATUS(wa_shamir_split_secret_into_shards(&platform->hooks, secret, 20, 3, 2, &shards, &shard_length),
                    WA_STATUS_OUT_OF_MEMORY);
    WA_CHECK(shards == NULL);
    platform->allocator.fail_at_attempt_index = WA_TEST_NO_FAILURE;
    /* Random failure at each draw: the partial shards are wiped and released */
    for (attempt_index = 0; attempt_index < 4; ++attempt_index) {
        platform->random_generator.call_count = 0;
        platform->random_generator.fail_at_call_index = attempt_index;
        WA_CHECK_STATUS(wa_shamir_split_secret_into_shards(&platform->hooks, secret, 20, 3, 3, &shards, &shard_length),
                        WA_STATUS_RANDOMNESS_FAILURE);
        WA_CHECK(shards == NULL);
    }
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

int main(void)
{
    WA_RUN_TEST(test_uuid0_with_fixed_clock);
    WA_RUN_TEST(test_uuid0_with_real_time_value);
    WA_RUN_TEST(test_uuid0_without_clock);
    WA_RUN_TEST(test_uuid0_random_failure);
    WA_RUN_TEST(test_gf128_multiplication);
    WA_RUN_TEST(test_shamir_against_wacryptolib);
    WA_RUN_TEST(test_shamir_recombination);
    WA_RUN_TEST(test_shamir_errors);
    return wa_test_finish();
}
