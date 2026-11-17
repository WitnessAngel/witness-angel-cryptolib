/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* The minimal example of README.md (extracted by CMake) compiles, and encrypts a recording into an offloaded
 * cryptainer named after the build's default format. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_flightbox/wa_flightbox.h"
#include "wa_minimal_test_harness.h"
#include "wa_test_device_profile_samples.h"
#include "wa_test_support.h"

int example_encrypt_recording(const wa_platform_hooks_t *hooks, const uint8_t *profile_cbor, size_t profile_length,
                              const char *basename, FILE *recording);

#include "wa_readme_minimal_example.c"

#define WA_RECORDING_LENGTH 5000u

static long wa_get_file_size(const char *path)
{
    long size = -1;
    FILE *file = fopen(path, "rb");
    if (file != NULL) {
        if (fseek(file, 0, SEEK_END) == 0) {
            size = ftell(file);
        }
        fclose(file);
    }
    return size;
}

static void test_readme_example_encrypts_a_recording(void)
{
    static const char basename[] = "wa_readme_example_recording.bin";
    const char *suffix = wa_document_format_get_cryptainer_suffix(WA_DOCUMENT_FORMAT_BUILD_DEFAULT);
    char cryptainer_path[128];
    char payload_path[160];
    wa_test_platform_t *platform = wa_test_platform_create(11);
    size_t profile_length = 0;
    uint8_t *profile = wa_test_get_device_profile_sample_cbor("corpus_2026_cbor_key_ciphertexts_05", &profile_length);
    FILE *recording = fopen(basename, "w+b");
    size_t index;
    WA_REQUIRE(platform != NULL && profile != NULL && recording != NULL && suffix != NULL);
    for (index = 0; index < WA_RECORDING_LENGTH; ++index) {
        WA_REQUIRE(fputc((int)(index % 251u), recording) != EOF);
    }
    rewind(recording);
    snprintf(cryptainer_path, sizeof(cryptainer_path), "%s%s", basename, suffix);
    snprintf(payload_path, sizeof(payload_path), "%s.payload", cryptainer_path);

    WA_CHECK(example_encrypt_recording(&platform->hooks, profile, profile_length, basename, recording) == 0);
    WA_CHECK(wa_get_file_size(cryptainer_path) > 0);
    /* At most one padding block, whatever the payload cipher */
    WA_CHECK(wa_get_file_size(payload_path) >= (long)WA_RECORDING_LENGTH);
    WA_CHECK(wa_get_file_size(payload_path) <= (long)WA_RECORDING_LENGTH + 16);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));

    fclose(recording);
    remove(basename);
    remove(cryptainer_path);
    remove(payload_path);
    free(profile);
    wa_test_platform_destroy(platform);
}

static void test_readme_example_reports_an_invalid_profile(void)
{
    static const uint8_t not_a_profile[] = {0x01};
    wa_test_platform_t *platform = wa_test_platform_create(12);
    FILE *recording = fopen("wa_readme_example_unused.bin", "w+b");
    WA_REQUIRE(platform != NULL && recording != NULL);
    WA_CHECK(example_encrypt_recording(&platform->hooks, not_a_profile, sizeof(not_a_profile),
                                       "wa_readme_example_unused.bin", recording) == -1);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    fclose(recording);
    remove("wa_readme_example_unused.bin");
    wa_test_platform_destroy(platform);
}

int main(void)
{
    WA_RUN_TEST(test_readme_example_encrypts_a_recording);
    WA_RUN_TEST(test_readme_example_reports_an_invalid_profile);
    return wa_test_finish();
}
