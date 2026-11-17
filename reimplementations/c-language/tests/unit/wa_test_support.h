/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Test support: platform hooks for unit tests, the test driver and the robustness tests.
 *
 * - A test allocator, counting live blocks and bytes and their peak, failing a chosen allocation (fault injection),
 *   checking the size given at release, and checking that released blocks contain none of the registered secret
 *   patterns (by default, the first 16 bytes of every random output of 32 bytes or more: symkeys, X25519 ephemeral
 *   scalars, ML-KEM coins and OAEP seeds, wherever they are copied, e.g. into key structs). Shorter outputs are IVs,
 *   nonces and UUID bits, which are public and written raw into WA-CBOR documents.
 * - A deterministic random hook (splitmix64 stream from a seed), able to fail at a chosen call.
 * - A fixed clock hook.
 * - A memory sink, able to fail after a byte budget. */

#ifndef WA_TEST_SUPPORT_H
#define WA_TEST_SUPPORT_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_platform_hooks.h"

#define WA_TEST_SECRET_PATTERN_LENGTH 16u
#define WA_TEST_MINIMUM_SECRET_RANDOM_OUTPUT_LENGTH 32u
#define WA_TEST_MAXIMUM_SECRET_PATTERNS 4096u
#define WA_TEST_NO_FAILURE ((size_t)-1)

/* TEST ALLOCATOR */

typedef struct wa_test_allocator {
    size_t allocation_count;      /* Successful allocations */
    size_t release_count;
    size_t live_block_count;
    size_t live_bytes;
    size_t peak_live_bytes;
    size_t attempted_allocation_count; /* Including the failed ones */
    size_t fail_at_attempt_index; /* 0-based index of the attempt to fail, or WA_TEST_NO_FAILURE */
    int failure_was_injected;
    size_t size_mismatch_count;   /* Releases with a size different from the allocated one */
    size_t foreign_release_count; /* Releases of blocks this allocator didn't return */

    int check_secret_patterns;
    size_t secret_pattern_count;
    uint8_t secret_patterns[WA_TEST_MAXIMUM_SECRET_PATTERNS][WA_TEST_SECRET_PATTERN_LENGTH];
    /* Patterns indexed by their first two bytes (chained through pattern_next_index; -1 ends a chain) */
    int32_t pattern_bucket_heads[65536];
    int32_t pattern_next_index[WA_TEST_MAXIMUM_SECRET_PATTERNS];
    size_t unwiped_secret_release_count; /* Released blocks still containing a registered secret pattern */
} wa_test_allocator_t;

void wa_test_allocator_initialize(wa_test_allocator_t *allocator);
void wa_test_allocator_register_secret_pattern(wa_test_allocator_t *allocator, const uint8_t *bytes, size_t length);
/* Whether everything allocated was released, with the right sizes: 1 if so */
int wa_test_allocator_is_clean(const wa_test_allocator_t *allocator);

/* DETERMINISTIC RANDOM HOOK */

typedef struct wa_test_random_generator {
    uint64_t state;
    size_t call_count;
    size_t fail_at_call_index; /* 0-based, or WA_TEST_NO_FAILURE */
    int failure_was_injected;
    size_t produced_byte_count;
    wa_test_allocator_t *allocator_registering_secrets_or_null;
} wa_test_random_generator_t;

void wa_test_random_generator_initialize(wa_test_random_generator_t *generator, uint64_t seed);

/* REPLAYED RANDOM HOOK: returns given bytes in order, and fails once they are exhausted */

typedef struct wa_test_replayed_random {
    const uint8_t *bytes;
    size_t length;
    size_t offset;
    size_t call_count;
} wa_test_replayed_random_t;

void wa_test_replayed_random_initialize(wa_test_replayed_random_t *replayed_random, const uint8_t *bytes,
                                        size_t length);
int wa_test_fill_replayed_random(void *random_context, uint8_t *buffer, size_t length);

/* FIXED CLOCK HOOK */

typedef struct wa_test_clock {
    int is_available;
    uint64_t unix_time_in_ten_thousandths_of_second;
    uint64_t increment_per_call;
} wa_test_clock_t;

/* HOOKS ASSEMBLY: allocator, generator and clock may each be NULL (stdlib allocation, failing random, no clock) */

typedef struct wa_test_platform {
    wa_test_allocator_t allocator;
    wa_test_random_generator_t random_generator;
    wa_test_clock_t clock;
    wa_platform_hooks_t hooks;
} wa_test_platform_t;

/* Allocated with malloc() (the allocator struct is large); random generator seeded with `seed`, secret patterns
 * registered, clock fixed at 2026-01-01 00:00:00 UTC, advancing by 1 per call. */
wa_test_platform_t *wa_test_platform_create(uint64_t seed);
void wa_test_platform_destroy(wa_test_platform_t *platform_or_null);

void *wa_test_allocate(void *allocator_context, size_t size);
void wa_test_release(void *allocator_context, void *pointer, size_t size);
int wa_test_fill_random(void *random_context, uint8_t *buffer, size_t length);
int wa_test_get_unix_time(void *clock_context, uint64_t *unix_time_out);

/* MEMORY SINK */

typedef struct wa_test_memory_sink {
    uint8_t *bytes;
    size_t length;
    size_t capacity;
    size_t write_call_count;
    size_t fail_after_byte_count; /* A write going beyond this budget fails, or WA_TEST_NO_FAILURE */
    wa_status_t failure_status;
    wa_output_sink_t sink;
} wa_test_memory_sink_t;

void wa_test_memory_sink_initialize(wa_test_memory_sink_t *memory_sink);
void wa_test_memory_sink_release(wa_test_memory_sink_t *memory_sink);

/* HEX HELPERS (lowercase or uppercase input, whitespace ignored) */

/* Decode into a malloc()'d buffer (at least 1 byte, so never NULL on success); returns NULL on invalid hex */
uint8_t *wa_test_decode_hex(const char *hex, size_t *length_out);
/* Encode into a malloc()'d NUL-terminated lowercase string */
char *wa_test_encode_hex(const uint8_t *bytes, size_t length);

#endif /* WA_TEST_SUPPORT_H */
