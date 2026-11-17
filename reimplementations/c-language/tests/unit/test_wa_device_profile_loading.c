/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Device profile loading (task 6.2): every sample of wa_device_profile_samples.h (one or more per scenario of the
 * flightbox-device-profile spec, from the export script and the test helpers) loads with the expected status, error
 * location and number of key entries; arguments; key lookups; out-of-memory sweep. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/wa_error_location_path.h"
#include "encoding/wa_device_profile_decoding.h"
#include "encoding/wa_value_tree_internal.h"
#include "wa_device_profile_samples.h"
#include "wa_flightbox/wa_device_profile.h"
#include "wa_minimal_test_harness.h"
#include "wa_test_support.h"

#define WA_SAMPLE_COUNT (sizeof(wa_device_profile_samples) / sizeof(wa_device_profile_samples[0]))

/* The CBOR bytes of a sample, in a malloc()'d buffer (never NULL on success) */
static uint8_t *decode_sample(const wa_device_profile_sample_t *sample, size_t *length_out)
{
    size_t total_length = 1;
    size_t line_index;
    char *hex;
    uint8_t *bytes;
    for (line_index = 0; sample->cbor_hex_lines[line_index] != NULL; ++line_index) {
        total_length += strlen(sample->cbor_hex_lines[line_index]);
    }
    hex = (char *)malloc(total_length);
    if (hex == NULL) {
        return NULL;
    }
    hex[0] = '\0';
    for (line_index = 0; sample->cbor_hex_lines[line_index] != NULL; ++line_index) {
        strcat(hex, sample->cbor_hex_lines[line_index]);
    }
    bytes = wa_test_decode_hex(hex, length_out);
    free(hex);
    return bytes;
}

static const wa_device_profile_sample_t *find_sample(const char *name)
{
    size_t sample_index;
    for (sample_index = 0; sample_index < WA_SAMPLE_COUNT; ++sample_index) {
        if (strcmp(wa_device_profile_samples[sample_index].name, name) == 0) {
            return &wa_device_profile_samples[sample_index];
        }
    }
    fprintf(stderr, "no sample named %s\n", name);
    return NULL;
}

/* Count the asymmetric layers under a map's key_cipher_layers, checking that each resolves to a key of its
 * algorithm; -1 on a lookup failure */
static int count_resolved_layers(const wa_device_profile_t *device_profile, const wa_value_t *map)
{
    const wa_value_t *key_cipher_layers = wa_value_find_map_value(map, "key_cipher_layers");
    int layer_count = 0;
    size_t layer_index;
    for (layer_index = 0; layer_index < wa_value_get_item_count(key_cipher_layers); ++layer_index) {
        const wa_value_t *layer = wa_value_get_array_item(key_cipher_layers, layer_index);
        const wa_value_t *shards = wa_value_find_map_value(layer, "key_shared_secret_shards");
        int sub_count = 0;
        if (shards != NULL) {
            size_t shard_index;
            for (shard_index = 0; shard_index < wa_value_get_item_count(shards); ++shard_index) {
                int shard_count = count_resolved_layers(device_profile, wa_value_get_array_item(shards, shard_index));
                if (shard_count < 0) {
                    return -1;
                }
                sub_count += shard_count;
            }
        } else if (wa_value_find_map_value(layer, "key_cipher_layers") != NULL) {
            sub_count = count_resolved_layers(device_profile, layer);
        } else {
            const wa_asymmetric_public_key_t *public_key = NULL;
            const char *algo_name = NULL;
            size_t algo_name_length = 0;
            wa_asymmetric_cipher_algo_t cipher_algo;
            if (wa_device_profile_find_layer_public_key(device_profile, layer, &public_key) != WA_STATUS_OK ||
                wa_value_get_text(wa_value_find_map_value(layer, "key_cipher_algo"), &algo_name, &algo_name_length) !=
                    0 ||
                !wa_asymmetric_cipher_algo_from_name(algo_name, algo_name_length, &cipher_algo) ||
                public_key->cipher_algo != cipher_algo) {
                return -1;
            }
            sub_count = 1;
        }
        if (sub_count < 0) {
            return -1;
        }
        layer_count += sub_count;
    }
    return layer_count;
}

static int count_resolved_payload_layers(const wa_device_profile_t *device_profile)
{
    const wa_value_t *payload_cipher_layers =
        wa_value_find_map_value(device_profile->cryptoconf, "payload_cipher_layers");
    int layer_count = 0;
    size_t layer_index;
    for (layer_index = 0; layer_index < wa_value_get_item_count(payload_cipher_layers); ++layer_index) {
        int sub_count =
            count_resolved_layers(device_profile, wa_value_get_array_item(payload_cipher_layers, layer_index));
        if (sub_count < 0) {
            return -1;
        }
        layer_count += sub_count;
    }
    return layer_count;
}

static void test_samples(void)
{
    size_t sample_index;
    size_t valid_count = 0;
    wa_test_platform_t *platform = wa_test_platform_create(1);
    WA_REQUIRE(platform != NULL);
    for (sample_index = 0; sample_index < WA_SAMPLE_COUNT; ++sample_index) {
        const wa_device_profile_sample_t *sample = &wa_device_profile_samples[sample_index];
        size_t cbor_length = 0;
        uint8_t *cbor = decode_sample(sample, &cbor_length);
        wa_device_profile_t *device_profile = (wa_device_profile_t *)&cbor_length; /* Must be reset to NULL */
        char location[WA_ERROR_LOCATION_PATH_CAPACITY];
        wa_status_t status;
        int status_is_expected;
        int location_is_expected;
        WA_REQUIRE(cbor != NULL);
        memset(location, 'x', sizeof(location));
        status = wa_device_profile_load_from_cbor(cbor, cbor_length, &platform->hooks, &device_profile, location,
                                                  sizeof(location));
        status_is_expected = status == sample->expected_status ||
                             (sample->alternative_status != WA_STATUS_OK && status == sample->alternative_status);
        location_is_expected = sample->expected_location == NULL || strcmp(location, sample->expected_location) == 0;
        if (!status_is_expected || !location_is_expected) {
            fprintf(stderr, "sample %s: status %d at '%s', expected %d at '%s'\n", sample->name, (int)status,
                    location, (int)sample->expected_status,
                    sample->expected_location == NULL ? "(any)" : sample->expected_location);
        }
        WA_CHECK(status_is_expected);
        WA_CHECK(location_is_expected);
        if (status == WA_STATUS_OK) {
            ++valid_count;
            WA_CHECK(device_profile != NULL);
            WA_CHECK(strcmp(location, "") == 0);
            if (device_profile != NULL) {
                WA_CHECK_SIZE(device_profile->key_entry_count, sample->expected_key_entry_count);
                WA_CHECK(count_resolved_payload_layers(device_profile) > 0);
            }
        } else {
            WA_CHECK(device_profile == NULL);
        }
        wa_device_profile_destroy(device_profile);
        free(cbor);
        if (!wa_test_allocator_is_clean(&platform->allocator)) {
            fprintf(stderr, "sample %s: allocator not clean\n", sample->name);
            WA_CHECK(0);
        }
    }
    WA_CHECK(valid_count >= 17);
    wa_test_platform_destroy(platform);
}

/* The entry of an authenticator whose keystore_owner differs from the cryptoconf's is selected */
static void test_lookup_ignores_keystore_owner(void)
{
    const wa_device_profile_sample_t *sample = find_sample("keystore_owner_differs");
    const wa_value_t *layer;
    const wa_asymmetric_public_key_t *public_key = NULL;
    wa_device_profile_t *device_profile = NULL;
    size_t cbor_length = 0;
    uint8_t *cbor;
    wa_test_platform_t *platform = wa_test_platform_create(2);
    WA_REQUIRE(platform != NULL && sample != NULL);
    cbor = decode_sample(sample, &cbor_length);
    WA_REQUIRE(cbor != NULL);
    WA_REQUIRE_STATUS(
        wa_device_profile_load_from_cbor(cbor, cbor_length, &platform->hooks, &device_profile, NULL, 0),
        WA_STATUS_OK);
    layer = wa_value_get_array_item(
        wa_value_find_map_value(
            wa_value_get_array_item(wa_value_find_map_value(device_profile->cryptoconf, "payload_cipher_layers"), 0),
            "key_cipher_layers"),
        0);
    WA_CHECK(wa_value_is_text_equal_to(
        wa_value_find_map_value(wa_value_find_map_value(layer, "key_cipher_trustee"), "keystore_owner"), "Alice"));
    WA_CHECK(wa_value_is_text_equal_to(
        wa_value_find_map_value(device_profile->key_entries[0].trustee, "keystore_owner"), "Bob"));
    WA_CHECK_STATUS(wa_device_profile_find_layer_public_key(device_profile, layer, &public_key), WA_STATUS_OK);
    WA_CHECK(public_key == &device_profile->key_entries[0].public_key);
    WA_CHECK(public_key->cipher_algo == WA_ASYMMETRIC_CIPHER_RSA_OAEP);
    WA_CHECK_SIZE(public_key->modulus_length, 256);
    wa_device_profile_destroy(device_profile);
    free(cbor);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_load_arguments(void)
{
    const wa_device_profile_sample_t *sample = find_sample("minimal_rsa_authenticator");
    const wa_device_profile_sample_t *invalid_sample = find_sample("x25519_low_order_0");
    wa_device_profile_t *device_profile = NULL;
    wa_platform_hooks_t hooks_without_random;
    char location[8];
    size_t cbor_length = 0;
    size_t invalid_cbor_length = 0;
    uint8_t *cbor;
    uint8_t *invalid_cbor;
    wa_test_platform_t *platform = wa_test_platform_create(3);
    WA_REQUIRE(platform != NULL && sample != NULL && invalid_sample != NULL);
    cbor = decode_sample(sample, &cbor_length);
    invalid_cbor = decode_sample(invalid_sample, &invalid_cbor_length);
    WA_REQUIRE(cbor != NULL && invalid_cbor != NULL);

    WA_CHECK_STATUS(wa_device_profile_load_from_cbor(cbor, cbor_length, &platform->hooks, NULL, location,
                                                     sizeof(location)),
                    WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK(strcmp(location, "") == 0);
    WA_CHECK_STATUS(wa_device_profile_load_from_cbor(cbor, cbor_length, NULL, &device_profile, NULL, 0),
                    WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK(device_profile == NULL);
    hooks_without_random = platform->hooks;
    hooks_without_random.fill_random = NULL;
    WA_CHECK_STATUS(wa_device_profile_load_from_cbor(cbor, cbor_length, &hooks_without_random, &device_profile, NULL,
                                                     0),
                    WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(wa_device_profile_load_from_cbor(NULL, 3, &platform->hooks, &device_profile, NULL, 0),
                    WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(wa_device_profile_load_from_cbor(NULL, 0, &platform->hooks, &device_profile, NULL, 0),
                    WA_STATUS_DECODING_ERROR);
    WA_CHECK(device_profile == NULL);

    /* Location truncated to the buffer, and untouched with a zero size */
    WA_CHECK_STATUS(wa_device_profile_load_from_cbor(invalid_cbor, invalid_cbor_length, &platform->hooks,
                                                     &device_profile, location, sizeof(location)),
                    WA_STATUS_KEY_CONSTRAINT_VIOLATION);
    WA_CHECK(strcmp(location, "trustee") == 0);
    location[0] = 'x';
    WA_CHECK_STATUS(wa_device_profile_load_from_cbor(invalid_cbor, invalid_cbor_length, &platform->hooks,
                                                     &device_profile, location, 0),
                    WA_STATUS_KEY_CONSTRAINT_VIOLATION);
    WA_CHECK(location[0] == 'x');

    /* One profile, any number of lookups; destroy(NULL) is a no-op */
    WA_REQUIRE_STATUS(wa_device_profile_load_from_cbor(cbor, cbor_length, &platform->hooks, &device_profile,
                                                       location, sizeof(location)),
                      WA_STATUS_OK);
    WA_CHECK(strcmp(location, "") == 0);
    WA_CHECK(count_resolved_payload_layers(device_profile) == 1);
    WA_CHECK(count_resolved_payload_layers(device_profile) == 1);
    wa_device_profile_destroy(device_profile);
    wa_device_profile_destroy(NULL);
    free(cbor);
    free(invalid_cbor);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

/* Failing each allocation in turn: out of memory, no profile, nothing leaked; then success */
static void test_out_of_memory_sweep(void)
{
    static const char *const sample_names[] = {"nested_all_layer_kinds", "corpus_2026_cbor_key_ciphertexts_05",
                                               "missing_public_key_in_shard"};
    size_t name_index;
    for (name_index = 0; name_index < sizeof(sample_names) / sizeof(sample_names[0]); ++name_index) {
        const wa_device_profile_sample_t *sample = find_sample(sample_names[name_index]);
        size_t cbor_length = 0;
        uint8_t *cbor;
        size_t fail_index;
        wa_test_platform_t *platform = wa_test_platform_create(4);
        WA_REQUIRE(platform != NULL && sample != NULL);
        cbor = decode_sample(sample, &cbor_length);
        WA_REQUIRE(cbor != NULL);
        for (fail_index = 0;; ++fail_index) {
            wa_device_profile_t *device_profile = NULL;
            wa_status_t status;
            platform->allocator.fail_at_attempt_index = platform->allocator.attempted_allocation_count + fail_index;
            platform->allocator.failure_was_injected = 0;
            status = wa_device_profile_load_from_cbor(cbor, cbor_length, &platform->hooks, &device_profile, NULL, 0);
            wa_device_profile_destroy(device_profile);
            WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
            if (!platform->allocator.failure_was_injected) {
                WA_CHECK_STATUS(status, sample->expected_status);
                break;
            }
            WA_CHECK_STATUS(status, WA_STATUS_OUT_OF_MEMORY);
            WA_CHECK(device_profile == NULL);
        }
        WA_CHECK(fail_index > 10);
        free(cbor);
        wa_test_platform_destroy(platform);
    }
}

int main(void)
{
    WA_RUN_TEST(test_samples);
    WA_RUN_TEST(test_lookup_ignores_keystore_owner);
    WA_RUN_TEST(test_load_arguments);
    WA_RUN_TEST(test_out_of_memory_sweep);
    return wa_test_finish();
}
