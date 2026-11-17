/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Unit tests of wa_secure_memory_wipe.c and wa_growable_byte_buffer.c (task 3.1). */

#include <string.h>

#include "encoding/wa_growable_byte_buffer.h"
#include "primitives/wa_secure_memory_wipe.h"
#include "wa_minimal_test_harness.h"
#include "wa_test_support.h"

static const uint8_t secret_pattern[16] = {0x5e, 0xc7, 0x37, 0x01, 0x02, 0x03, 0x04, 0x05,
                                           0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d};

static void test_secure_memory_wipe(void)
{
    uint8_t buffer[37];
    memset(buffer, 0xff, sizeof(buffer));
    wa_secure_memory_wipe(buffer, sizeof(buffer));
    WA_CHECK(wa_constant_time_is_all_zero(buffer, sizeof(buffer)));
    buffer[36] = 1;
    WA_CHECK(!wa_constant_time_is_all_zero(buffer, sizeof(buffer)));
    WA_CHECK(wa_constant_time_is_all_zero(buffer, 0));
    wa_secure_memory_wipe(NULL, 0); /* No-op */
}

/* Fills a buffer with the secret pattern, then grows it over several reallocations and releases it: returns the
 * number of released blocks that still contained the pattern. */
static size_t count_unwiped_blocks_after_growth(int is_secret, size_t *allocation_count_out)
{
    wa_test_platform_t *platform = wa_test_platform_create(7);
    wa_growable_byte_buffer_t buffer;
    uint8_t filler[100];
    size_t unwiped_count;
    size_t round;
    wa_test_allocator_register_secret_pattern(&platform->allocator, secret_pattern, sizeof(secret_pattern));
    memset(filler, 0x11, sizeof(filler));
    wa_growable_byte_buffer_initialize(&buffer, &platform->hooks, is_secret);
    WA_CHECK_STATUS(wa_growable_byte_buffer_append(&buffer, secret_pattern, sizeof(secret_pattern)), WA_STATUS_OK);
    for (round = 0; round < 20; round++) { /* 2016 bytes: grows 64 -> 128 -> ... -> 2048 */
        WA_CHECK_STATUS(wa_growable_byte_buffer_append(&buffer, filler, sizeof(filler)), WA_STATUS_OK);
    }
    WA_CHECK_SIZE(buffer.length, 16 + 20 * 100);
    WA_CHECK(memcmp(buffer.data, secret_pattern, sizeof(secret_pattern)) == 0);
    WA_CHECK(buffer.capacity >= buffer.length);
    wa_growable_byte_buffer_release(&buffer);
    WA_CHECK(buffer.data == NULL && buffer.length == 0 && buffer.capacity == 0);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    unwiped_count = platform->allocator.unwiped_secret_release_count;
    *allocation_count_out = platform->allocator.allocation_count;
    wa_test_platform_destroy(platform);
    return unwiped_count;
}

static void test_secret_buffer_blocks_zeroed_on_growth_and_release(void)
{
    size_t allocation_count = 0;
    WA_CHECK_SIZE(count_unwiped_blocks_after_growth(1, &allocation_count), 0);
    WA_CHECK(allocation_count >= 5); /* Several growths happened */
}

static void test_public_buffer_blocks_not_wiped(void)
{
    /* Control: the same scenario on a non-secret buffer leaves the pattern in every released block */
    size_t allocation_count = 0;
    size_t unwiped_count = count_unwiped_blocks_after_growth(0, &allocation_count);
    WA_CHECK_SIZE(unwiped_count, allocation_count);
}

static void test_clear_keeps_capacity_and_wipes_secret_content(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(8);
    wa_growable_byte_buffer_t buffer;
    size_t capacity;
    wa_growable_byte_buffer_initialize(&buffer, &platform->hooks, 1);
    WA_REQUIRE_STATUS(wa_growable_byte_buffer_append(&buffer, secret_pattern, sizeof(secret_pattern)), WA_STATUS_OK);
    capacity = buffer.capacity;
    wa_growable_byte_buffer_clear(&buffer);
    WA_CHECK_SIZE(buffer.length, 0);
    WA_CHECK_SIZE(buffer.capacity, capacity);
    WA_CHECK(wa_constant_time_is_all_zero(buffer.data, sizeof(secret_pattern)));
    wa_growable_byte_buffer_release(&buffer);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_out_of_memory_keeps_content(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(9);
    wa_growable_byte_buffer_t buffer;
    uint8_t filler[100];
    memset(filler, 0x22, sizeof(filler));
    wa_growable_byte_buffer_initialize(&buffer, &platform->hooks, 1);
    WA_REQUIRE_STATUS(wa_growable_byte_buffer_append(&buffer, secret_pattern, sizeof(secret_pattern)), WA_STATUS_OK);
    platform->allocator.fail_at_attempt_index = platform->allocator.attempted_allocation_count;
    WA_CHECK_STATUS(wa_growable_byte_buffer_append(&buffer, filler, sizeof(filler)), WA_STATUS_OUT_OF_MEMORY);
    WA_CHECK_SIZE(buffer.length, sizeof(secret_pattern));
    WA_CHECK(memcmp(buffer.data, secret_pattern, sizeof(secret_pattern)) == 0);
    wa_growable_byte_buffer_release(&buffer);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
    wa_test_platform_destroy(platform);
}

static void test_sink_appends(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(10);
    wa_growable_byte_buffer_t buffer;
    wa_output_sink_t sink;
    wa_growable_byte_buffer_initialize(&buffer, &platform->hooks, 0);
    sink = wa_growable_byte_buffer_get_sink(&buffer);
    WA_CHECK_STATUS(sink.write(sink.sink_context, (const uint8_t *)"abc", 3), WA_STATUS_OK);
    WA_CHECK_STATUS(sink.write(sink.sink_context, (const uint8_t *)"", 0), WA_STATUS_OK);
    WA_CHECK_STATUS(sink.write(sink.sink_context, (const uint8_t *)"de", 2), WA_STATUS_OK);
    WA_CHECK_TEXT(buffer.data, buffer.length, "abcde");
    wa_growable_byte_buffer_release(&buffer);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

int main(void)
{
    WA_RUN_TEST(test_secure_memory_wipe);
    WA_RUN_TEST(test_secret_buffer_blocks_zeroed_on_growth_and_release);
    WA_RUN_TEST(test_public_buffer_blocks_not_wiped);
    WA_RUN_TEST(test_clear_keeps_capacity_and_wipes_secret_content);
    WA_RUN_TEST(test_out_of_memory_keeps_content);
    WA_RUN_TEST(test_sink_appends);
    return wa_test_finish();
}
