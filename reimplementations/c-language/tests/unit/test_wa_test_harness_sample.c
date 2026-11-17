/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Sample test of the harness and of the test support hooks. */

#include <stdlib.h>
#include <string.h>

#include "wa_minimal_test_harness.h"
#include "wa_test_support.h"

static void test_checks_pass(void)
{
    static const uint8_t bytes[3] = {0x00, 0xab, 0xff};
    WA_CHECK(1 + 1 == 2);
    WA_CHECK_SIZE(sizeof(bytes), 3);
    WA_CHECK_STATUS(WA_STATUS_OK, WA_STATUS_OK);
    WA_CHECK_HEX(bytes, sizeof(bytes), "00ABff");
    WA_CHECK_TEXT("abc", 3, "abc");
}

static void test_allocator_counts_and_faults(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(1);
    void *first;
    void *second;
    first = platform->hooks.allocate(platform->hooks.allocator_context, 100);
    second = platform->hooks.allocate(platform->hooks.allocator_context, 50);
    WA_REQUIRE(first != NULL && second != NULL);
    WA_CHECK_SIZE(platform->allocator.live_bytes, 150);
    platform->hooks.release(platform->hooks.allocator_context, first, 100);
    WA_CHECK_SIZE(platform->allocator.peak_live_bytes, 150);
    WA_CHECK_SIZE(platform->allocator.live_bytes, 50);
    platform->hooks.release(platform->hooks.allocator_context, second, 49); /* Wrong size: recorded */
    WA_CHECK_SIZE(platform->allocator.size_mismatch_count, 1);
    WA_CHECK(!wa_test_allocator_is_clean(&platform->allocator));

    platform->allocator.size_mismatch_count = 0;
    platform->allocator.fail_at_attempt_index = platform->allocator.attempted_allocation_count;
    WA_CHECK(platform->hooks.allocate(platform->hooks.allocator_context, 10) == NULL);
    WA_CHECK(platform->allocator.failure_was_injected);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_secret_patterns_detected(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(2);
    uint8_t secret[32];
    uint8_t *block;
    WA_REQUIRE(platform->hooks.fill_random(platform->hooks.random_context, secret, sizeof(secret)) == 0);

    block = (uint8_t *)platform->hooks.allocate(platform->hooks.allocator_context, 64);
    WA_REQUIRE(block != NULL);
    memcpy(block + 7, secret, sizeof(secret));
    platform->hooks.release(platform->hooks.allocator_context, block, 64);
    WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 1);

    block = (uint8_t *)platform->hooks.allocate(platform->hooks.allocator_context, 64);
    WA_REQUIRE(block != NULL);
    memset(block, 0, 64);
    platform->hooks.release(platform->hooks.allocator_context, block, 64);
    WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 1);
    wa_test_platform_destroy(platform);
}

static void test_random_generator_is_deterministic(void)
{
    wa_test_random_generator_t first;
    wa_test_random_generator_t second;
    uint8_t first_bytes[21];
    uint8_t second_bytes[21];
    wa_test_random_generator_initialize(&first, 42);
    wa_test_random_generator_initialize(&second, 42);
    WA_CHECK(wa_test_fill_random(&first, first_bytes, sizeof(first_bytes)) == 0);
    WA_CHECK(wa_test_fill_random(&second, second_bytes, sizeof(second_bytes)) == 0);
    WA_CHECK_BYTES(first_bytes, sizeof(first_bytes), second_bytes, sizeof(second_bytes));
    second.fail_at_call_index = second.call_count;
    WA_CHECK(wa_test_fill_random(&second, second_bytes, sizeof(second_bytes)) != 0);
    WA_CHECK(second.failure_was_injected);
}

static void test_memory_sink_failure_budget(void)
{
    wa_test_memory_sink_t memory_sink;
    static const uint8_t bytes[4] = {1, 2, 3, 4};
    wa_test_memory_sink_initialize(&memory_sink);
    memory_sink.fail_after_byte_count = 6;
    WA_CHECK_STATUS(memory_sink.sink.write(memory_sink.sink.sink_context, bytes, 4), WA_STATUS_OK);
    WA_CHECK_STATUS(memory_sink.sink.write(memory_sink.sink.sink_context, bytes, 4), WA_STATUS_SINK_WRITE_FAILURE);
    WA_CHECK_HEX(memory_sink.bytes, memory_sink.length, "01020304");
    wa_test_memory_sink_release(&memory_sink);
}

int main(void)
{
    WA_RUN_TEST(test_checks_pass);
    WA_RUN_TEST(test_allocator_counts_and_faults);
    WA_RUN_TEST(test_secret_patterns_detected);
    WA_RUN_TEST(test_random_generator_is_deterministic);
    WA_RUN_TEST(test_memory_sink_failure_budget);
    return wa_test_finish();
}
