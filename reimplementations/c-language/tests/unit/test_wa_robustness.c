/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Robustness (task 7.5), in each enabled document format, over the whole workflow (profile load, creation with
 * metadata, chunks, finalization, cryptainer writing), with the nested profile using every layer kind:
 * - out-of-memory sweep: each allocation attempt fails in turn, giving WA_STATUS_OUT_OF_MEMORY, no instance, and no
 *   leak, until the workflow succeeds;
 * - random-hook failure: each random call fails in turn, giving WA_STATUS_RANDOMNESS_FAILURE at creation, with
 *   nothing written to the sinks;
 * - secrets: no released block holds a registered secret pattern (the first 16 bytes of every random output of 32
 *   bytes or more: symkeys, Shamir coefficients, X25519 scalars, ML-KEM coins, OAEP seeds), in any of these runs. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_flightbox/wa_flightbox.h"
#include "wa_minimal_test_harness.h"
#include "wa_test_device_profile_samples.h"
#include "wa_test_support.h"

static const wa_document_format_t enabled_formats[] = {
#if WA_DOCUMENT_FORMAT_JSON_ENABLED
    WA_DOCUMENT_FORMAT_JSON,
#endif
#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
    WA_DOCUMENT_FORMAT_CBOR,
#endif
};
#define WA_ENABLED_FORMAT_COUNT (sizeof(enabled_formats) / sizeof(enabled_formats[0]))

#define WA_PAYLOAD_LENGTH 10000u
#define WA_MAXIMUM_SWEEP_STEPS 100000u

static const char *const sample_names[] = {"nested_all_layer_kinds", "minimal_rsa_authenticator"};

typedef struct workflow_outcome {
    wa_status_t status;
    int profile_was_returned_on_failure;
    int encryptor_was_returned_on_failure;
} workflow_outcome_t;

/* {"device_id": "fb-07", "sequence": 42}, built before the sweeps start */
static wa_value_t *build_metadata(const wa_platform_hooks_t *platform_hooks)
{
    wa_value_t *metadata = NULL;
    wa_value_t *device_id = NULL;
    wa_value_t *sequence = NULL;
    if (wa_value_create_map(platform_hooks, &metadata) != WA_STATUS_OK) {
        return NULL;
    }
    if (wa_value_create_text(platform_hooks, "fb-07", 5, &device_id) != WA_STATUS_OK ||
        wa_value_map_add(metadata, "device_id", 9, device_id) != WA_STATUS_OK ||
        wa_value_create_integer(platform_hooks, 42, &sequence) != WA_STATUS_OK ||
        wa_value_map_add(metadata, "sequence", 8, sequence) != WA_STATUS_OK) {
        wa_value_destroy(metadata);
        return NULL;
    }
    return metadata;
}

/* The whole workflow, with every step's failure reported */
static workflow_outcome_t run_workflow(wa_test_platform_t *platform, const uint8_t *profile_cbor,
                                       size_t profile_cbor_length, const wa_value_t *metadata,
                                       wa_document_format_t format, wa_ciphertext_location_t location,
                                       const uint8_t *payload, wa_test_memory_sink_t *cryptainer_sink,
                                       wa_test_memory_sink_t *payload_sink)
{
    workflow_outcome_t outcome;
    wa_device_profile_t *device_profile = (wa_device_profile_t *)&outcome; /* Must be reset to NULL on failure */
    wa_cryptainer_encryptor_t *encryptor = (wa_cryptainer_encryptor_t *)&outcome;
    wa_cryptainer_encryptor_options_t options;
    size_t offset = 0;
    memset(&outcome, 0, sizeof(outcome));
    outcome.status = wa_device_profile_load_from_cbor(profile_cbor, profile_cbor_length, &platform->hooks,
                                                      &device_profile, NULL, 0);
    if (outcome.status != WA_STATUS_OK) {
        outcome.profile_was_returned_on_failure = device_profile != NULL;
        return outcome;
    }
    options.platform_hooks = &platform->hooks;
    options.document_format = format;
    options.ciphertext_location = location;
    options.payload_ciphertext_sink = location == WA_CIPHERTEXT_LOCATION_OFFLOADED ? &payload_sink->sink : NULL;
    outcome.status = wa_cryptainer_encryptor_create(device_profile, metadata, &options, &encryptor);
    if (outcome.status != WA_STATUS_OK) {
        outcome.encryptor_was_returned_on_failure = encryptor != NULL;
        encryptor = NULL;
    }
    while (outcome.status == WA_STATUS_OK && offset < WA_PAYLOAD_LENGTH) {
        size_t length = WA_PAYLOAD_LENGTH - offset < 3000u ? WA_PAYLOAD_LENGTH - offset : 3000u;
        outcome.status = wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, payload + offset, length);
        offset += length;
    }
    if (outcome.status == WA_STATUS_OK) {
        outcome.status = wa_cryptainer_encryptor_finalize(encryptor);
    }
    if (outcome.status == WA_STATUS_OK) {
        outcome.status = wa_cryptainer_encryptor_write_cryptainer(encryptor, &cryptainer_sink->sink);
    }
    wa_cryptainer_encryptor_destroy(encryptor);
    wa_device_profile_destroy(device_profile);
    return outcome;
}

static void test_out_of_memory_sweep(void)
{
    size_t sample_index;
    size_t format_index;
    uint8_t *payload = (uint8_t *)malloc(WA_PAYLOAD_LENGTH);
    size_t index;
    WA_REQUIRE(payload != NULL);
    for (index = 0; index < WA_PAYLOAD_LENGTH; ++index) {
        payload[index] = (uint8_t)index;
    }
    for (sample_index = 0; sample_index < sizeof(sample_names) / sizeof(sample_names[0]); ++sample_index) {
        size_t profile_cbor_length = 0;
        uint8_t *profile_cbor = wa_test_get_device_profile_sample_cbor(sample_names[sample_index], &profile_cbor_length);
        WA_REQUIRE(profile_cbor != NULL);
        for (format_index = 0; format_index < WA_ENABLED_FORMAT_COUNT; ++format_index) {
            wa_ciphertext_location_t location;
            for (location = WA_CIPHERTEXT_LOCATION_INLINE; location <= WA_CIPHERTEXT_LOCATION_OFFLOADED;
                 location = (wa_ciphertext_location_t)(location + 1)) {
                wa_test_platform_t *platform = wa_test_platform_create(90u);
                wa_value_t *metadata;
                size_t failure_index;
                size_t failure_count = 0;
                int has_succeeded = 0;
                WA_REQUIRE(platform != NULL);
                metadata = build_metadata(&platform->hooks);
                WA_REQUIRE(metadata != NULL);
                for (failure_index = 0; failure_index < WA_MAXIMUM_SWEEP_STEPS && !has_succeeded; ++failure_index) {
                    wa_test_memory_sink_t cryptainer_sink;
                    wa_test_memory_sink_t payload_sink;
                    workflow_outcome_t outcome;
                    size_t live_blocks_before = platform->allocator.live_block_count;
                    wa_test_memory_sink_initialize(&cryptainer_sink);
                    wa_test_memory_sink_initialize(&payload_sink);
                    platform->allocator.failure_was_injected = 0;
                    platform->allocator.fail_at_attempt_index =
                        platform->allocator.attempted_allocation_count + failure_index;
                    outcome = run_workflow(platform, profile_cbor, profile_cbor_length, metadata,
                                           enabled_formats[format_index], location, payload, &cryptainer_sink,
                                           &payload_sink);
                    if (!platform->allocator.failure_was_injected) {
                        WA_CHECK_STATUS(outcome.status, WA_STATUS_OK);
                        WA_CHECK(cryptainer_sink.length > 0);
                        has_succeeded = 1;
                    } else {
                        ++failure_count;
                        if (!wa_test_check_condition(outcome.status == WA_STATUS_OUT_OF_MEMORY, __FILE__, __LINE__,
                                                     "out of memory reported")) {
                            printf("    %s, format %d, location %d, allocation %u: status %d\n",
                                   sample_names[sample_index], (int)enabled_formats[format_index], (int)location,
                                   (unsigned)failure_index, (int)outcome.status);
                        }
                    }
                    WA_CHECK(!outcome.profile_was_returned_on_failure && !outcome.encryptor_was_returned_on_failure);
                    WA_CHECK_SIZE(platform->allocator.live_block_count, live_blocks_before); /* No leak */
                    wa_test_memory_sink_release(&cryptainer_sink);
                    wa_test_memory_sink_release(&payload_sink);
                }
                WA_CHECK(has_succeeded);
                printf("  %s, format %d, location %d: %u allocation failures checked\n", sample_names[sample_index],
                       (int)enabled_formats[format_index], (int)location, (unsigned)failure_count);
                platform->allocator.fail_at_attempt_index = WA_TEST_NO_FAILURE;
                wa_value_destroy(metadata);
                WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
                WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
                wa_test_platform_destroy(platform);
            }
        }
        free(profile_cbor);
    }
    free(payload);
}

static void test_random_failure_writes_nothing(void)
{
    size_t sample_index;
    size_t format_index;
    uint8_t payload[WA_PAYLOAD_LENGTH];
    memset(payload, 0x5A, sizeof(payload));
    for (sample_index = 0; sample_index < sizeof(sample_names) / sizeof(sample_names[0]); ++sample_index) {
        size_t profile_cbor_length = 0;
        uint8_t *profile_cbor = wa_test_get_device_profile_sample_cbor(sample_names[sample_index], &profile_cbor_length);
        WA_REQUIRE(profile_cbor != NULL);
        for (format_index = 0; format_index < WA_ENABLED_FORMAT_COUNT; ++format_index) {
            wa_test_platform_t *platform = wa_test_platform_create(91u);
            wa_value_t *metadata;
            size_t failure_index;
            size_t failure_count = 0;
            int has_succeeded = 0;
            WA_REQUIRE(platform != NULL);
            metadata = build_metadata(&platform->hooks);
            WA_REQUIRE(metadata != NULL);
            for (failure_index = 0; failure_index < WA_MAXIMUM_SWEEP_STEPS && !has_succeeded; ++failure_index) {
                wa_test_memory_sink_t cryptainer_sink;
                wa_test_memory_sink_t payload_sink;
                workflow_outcome_t outcome;
                wa_test_memory_sink_initialize(&cryptainer_sink);
                wa_test_memory_sink_initialize(&payload_sink);
                platform->random_generator.failure_was_injected = 0;
                platform->random_generator.fail_at_call_index = platform->random_generator.call_count + failure_index;
                outcome = run_workflow(platform, profile_cbor, profile_cbor_length, metadata,
                                       enabled_formats[format_index], WA_CIPHERTEXT_LOCATION_OFFLOADED, payload,
                                       &cryptainer_sink, &payload_sink);
                if (!platform->random_generator.failure_was_injected) {
                    WA_CHECK_STATUS(outcome.status, WA_STATUS_OK);
                    has_succeeded = 1;
                } else {
                    ++failure_count;
                    WA_CHECK_STATUS(outcome.status, WA_STATUS_RANDOMNESS_FAILURE);
                    WA_CHECK(!outcome.encryptor_was_returned_on_failure);
                    /* Every random draw happens at creation, before anything is written */
                    WA_CHECK(cryptainer_sink.write_call_count == 0 && payload_sink.write_call_count == 0);
                }
                wa_test_memory_sink_release(&cryptainer_sink);
                wa_test_memory_sink_release(&payload_sink);
            }
            WA_CHECK(has_succeeded);
            WA_CHECK(failure_count > 0);
            printf("  %s, format %d: %u random call failures checked\n", sample_names[sample_index],
                   (int)enabled_formats[format_index], (unsigned)failure_count);
            platform->random_generator.fail_at_call_index = WA_TEST_NO_FAILURE;
            wa_value_destroy(metadata);
            WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
            WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
            wa_test_platform_destroy(platform);
        }
        free(profile_cbor);
    }
}

/* The secret check itself detects an unwiped block holding a registered pattern */
static void test_secret_check_detects_unwiped_blocks(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(92u);
    uint8_t random_bytes[32];
    uint8_t *block;
    WA_REQUIRE(platform != NULL);
    WA_REQUIRE(platform->hooks.fill_random(platform->hooks.random_context, random_bytes, sizeof(random_bytes)) == 0);
    block = (uint8_t *)platform->hooks.allocate(platform->hooks.allocator_context, 100);
    WA_REQUIRE(block != NULL);
    memset(block, 0, 100);
    memcpy(block + 41, random_bytes, WA_TEST_SECRET_PATTERN_LENGTH);
    platform->hooks.release(platform->hooks.allocator_context, block, 100);
    WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 1);
    wa_test_platform_destroy(platform);
}

int main(void)
{
    WA_RUN_TEST(test_secret_check_detects_unwiped_blocks);
    WA_RUN_TEST(test_random_failure_writes_nothing);
    WA_RUN_TEST(test_out_of_memory_sweep);
    return wa_test_finish();
}
