/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Host platform hooks (task 8.1): the random hook fills buffers with distinct bytes, of any length, and fails
 * cleanly (and the library with WA_STATUS_RANDOMNESS_FAILURE) when its source is unavailable, simulated on POSIX with
 * a missing device path; the clock gives a plausible current time; allocation works. */

#include <stdlib.h>
#include <string.h>

#include "wa_flightbox/wa_flightbox.h"
#include "wa_host_platform_hooks.h"
#include "wa_minimal_test_harness.h"
#include "wa_test_device_profile_samples.h"
#include "wa_test_support.h"

#define WA_BUFFER_LENGTH 64u

static void test_random_buffers_are_distinct(void)
{
    wa_platform_hooks_t hooks;
    uint8_t first[WA_BUFFER_LENGTH];
    uint8_t second[WA_BUFFER_LENGTH];
    uint8_t zeros[WA_BUFFER_LENGTH];
    uint8_t *large_buffer;
    size_t large_length = 3u * 1024u * 1024u + 7u; /* Beyond one getrandom() call on old kernels */
    size_t index;
    size_t zero_count = 0;
    wa_host_platform_hooks_initialize(&hooks, NULL);
    memset(first, 0, sizeof(first));
    memset(second, 0, sizeof(second));
    memset(zeros, 0, sizeof(zeros));
    WA_CHECK(hooks.fill_random(hooks.random_context, first, sizeof(first)) == 0);
    WA_CHECK(hooks.fill_random(hooks.random_context, second, sizeof(second)) == 0);
    WA_CHECK(memcmp(first, second, sizeof(first)) != 0);
    WA_CHECK(memcmp(first, zeros, sizeof(first)) != 0);
    WA_CHECK(hooks.fill_random(hooks.random_context, first, 0) == 0);

    large_buffer = (uint8_t *)calloc(1, large_length);
    WA_REQUIRE(large_buffer != NULL);
    WA_CHECK(hooks.fill_random(hooks.random_context, large_buffer, large_length) == 0);
    for (index = 0; index < large_length; ++index) {
        zero_count += large_buffer[index] == 0;
    }
    /* About large_length / 256 zero bytes: far from a partly unfilled buffer */
    WA_CHECK(zero_count < large_length / 128u);
    WA_CHECK(large_buffer[large_length - 1u] != 0 || large_buffer[large_length - 2u] != 0 ||
             large_buffer[large_length - 3u] != 0);
    free(large_buffer);
}

static void test_unavailable_random_source(void)
{
#if defined(_WIN32)
    /* BCryptGenRandom has no source to remove: nothing to simulate */
#else
    wa_host_random_source_t missing_source = {"/nonexistent/wa_flightbox_random_device"};
    wa_host_random_source_t short_source = {"/dev/null"}; /* Reads return end-of-file at once */
    wa_platform_hooks_t hooks;
    wa_device_profile_t *device_profile = NULL;
    wa_cryptainer_encryptor_t *encryptor = NULL;
    wa_cryptainer_encryptor_options_t options;
    wa_test_memory_sink_t payload_sink;
    uint8_t buffer[WA_BUFFER_LENGTH];
    wa_status_t status;

    wa_host_platform_hooks_initialize(&hooks, &missing_source);
    WA_CHECK(hooks.fill_random(hooks.random_context, buffer, sizeof(buffer)) != 0);
    wa_host_platform_hooks_initialize(&hooks, &short_source);
    WA_CHECK(hooks.fill_random(hooks.random_context, buffer, sizeof(buffer)) != 0);

    /* The library reports it, with no instance */
    wa_host_platform_hooks_initialize(&hooks, &missing_source);
    status = wa_test_load_device_profile_sample("nested_all_layer_kinds", &hooks, &device_profile);
    WA_REQUIRE_STATUS(status, WA_STATUS_OK);
    wa_test_memory_sink_initialize(&payload_sink);
    memset(&options, 0, sizeof(options));
    options.platform_hooks = &hooks;
    options.ciphertext_location = WA_CIPHERTEXT_LOCATION_OFFLOADED;
    options.payload_ciphertext_sink = &payload_sink.sink;
    status = wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor);
    WA_CHECK_STATUS(status, WA_STATUS_RANDOMNESS_FAILURE);
    WA_CHECK(encryptor == NULL);
    WA_CHECK_SIZE(payload_sink.write_call_count, 0u);
    wa_test_memory_sink_release(&payload_sink);
    wa_device_profile_destroy(device_profile);
#endif
}

static void test_clock_and_allocation(void)
{
    wa_platform_hooks_t hooks;
    uint64_t first_time = 0;
    uint64_t second_time = 0;
    void *block;
    wa_host_platform_hooks_initialize(&hooks, NULL);
    WA_CHECK(hooks.get_unix_time_in_ten_thousandths_of_second(hooks.clock_context, &first_time) == 0);
    WA_CHECK(hooks.get_unix_time_in_ten_thousandths_of_second(hooks.clock_context, &second_time) == 0);
    /* After 2025-01-01 and before 2100-01-01, never going backwards between two close calls */
    WA_CHECK(first_time > UINT64_C(17356896000000));
    WA_CHECK(first_time < UINT64_C(41023296000000));
    WA_CHECK(second_time >= first_time);
    block = hooks.allocate(hooks.allocator_context, 100);
    WA_REQUIRE(block != NULL);
    memset(block, 0xA5, 100);
    hooks.release(hooks.allocator_context, block, 100);
}

int main(void)
{
    WA_RUN_TEST(test_random_buffers_are_distinct);
    WA_RUN_TEST(test_unavailable_random_source);
    WA_RUN_TEST(test_clock_and_allocation);
    return wa_test_finish();
}
