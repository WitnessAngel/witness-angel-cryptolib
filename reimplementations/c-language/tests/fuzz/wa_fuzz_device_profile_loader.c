/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* libFuzzer target of the device profile loader (wa_device_profile_load_from_cbor).
 *
 * Every accepted profile is then used: a small payload is encrypted into a cryptainer, in every enabled format,
 * inline and offloaded, with a seeded random source. Besides memory errors (ASan/UBSan), it aborts when:
 * - loading returns a profile and an error together, or neither, or an error without a NUL-terminated location;
 * - an accepted profile cannot be used for encryption;
 * - a block leaks, or a random secret is released unwiped. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_flightbox/wa_flightbox.h"

#include "wa_test_support.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void wa_fuzz_fail(const char *reason)
{
    fprintf(stderr, "wa_fuzz_device_profile_loader: %s\n", reason);
    abort();
}

static void wa_fuzz_check_platform(wa_test_platform_t *platform)
{
    if (!wa_test_allocator_is_clean(&platform->allocator)) {
        wa_fuzz_fail("leaked or mismatched blocks");
    }
    if (platform->allocator.unwiped_secret_release_count != 0) {
        wa_fuzz_fail("a secret was released unwiped");
    }
}

static void wa_fuzz_encrypt_with_profile(const wa_device_profile_t *device_profile, wa_test_platform_t *platform,
                                         wa_document_format_t document_format, int is_offloaded)
{
    static const uint8_t payload[] = "fuzzed device profile payload";
    wa_cryptainer_encryptor_options_t options;
    wa_test_memory_sink_t payload_sink;
    wa_test_memory_sink_t cryptainer_sink;
    wa_status_t status;
    wa_test_memory_sink_initialize(&payload_sink);
    wa_test_memory_sink_initialize(&cryptainer_sink);
    options.platform_hooks = &platform->hooks;
    options.document_format = document_format;
    options.ciphertext_location = is_offloaded ? WA_CIPHERTEXT_LOCATION_OFFLOADED : WA_CIPHERTEXT_LOCATION_INLINE;
    options.payload_ciphertext_sink = is_offloaded ? &payload_sink.sink : NULL;
    status = wa_cryptainer_encrypt_payload_in_one_call(device_profile, NULL, &options, payload, sizeof(payload) - 1u,
                                                       &cryptainer_sink.sink);
    if (status != WA_STATUS_OK || cryptainer_sink.length == 0 || (is_offloaded && payload_sink.length == 0)) {
        fprintf(stderr, "status %s\n", wa_status_get_description(status));
        wa_fuzz_fail("an accepted profile cannot be used for encryption");
    }
    wa_test_memory_sink_release(&payload_sink);
    wa_test_memory_sink_release(&cryptainer_sink);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const wa_document_format_t document_formats[] = {
#if WA_DOCUMENT_FORMAT_JSON_ENABLED
        WA_DOCUMENT_FORMAT_JSON,
#endif
#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
        WA_DOCUMENT_FORMAT_CBOR,
#endif
    };
    wa_test_platform_t *platform = wa_test_platform_create(1u);
    wa_device_profile_t *device_profile = NULL;
    char error_location[256];
    wa_status_t status;
    size_t format_index;
    if (platform == NULL) {
        wa_fuzz_fail("cannot create the test platform");
    }
    memset(error_location, 'x', sizeof(error_location));
    status = wa_device_profile_load_from_cbor(data, size, &platform->hooks, &device_profile, error_location,
                                              sizeof(error_location));
    if ((status == WA_STATUS_OK) != (device_profile != NULL)) {
        wa_fuzz_fail("a profile is returned if and only if loading succeeds");
    }
    if (memchr(error_location, '\0', sizeof(error_location)) == NULL) {
        wa_fuzz_fail("the error location is not NUL-terminated");
    }
    if (status == WA_STATUS_OK) {
        if (error_location[0] != '\0') {
            wa_fuzz_fail("an error location is reported for an accepted profile");
        }
        for (format_index = 0; format_index < sizeof(document_formats) / sizeof(document_formats[0]); ++format_index) {
            wa_fuzz_encrypt_with_profile(device_profile, platform, document_formats[format_index], 0);
            wa_fuzz_encrypt_with_profile(device_profile, platform, document_formats[format_index], 1);
        }
        wa_device_profile_destroy(device_profile);
    }
    wa_fuzz_check_platform(platform);
    wa_test_platform_destroy(platform);
    return 0;
}
