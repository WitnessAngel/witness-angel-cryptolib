/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wa_test_device_profile_samples.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_device_profile_samples.h"
#include "wa_test_support.h"

#define WA_SAMPLE_COUNT (sizeof(wa_device_profile_samples) / sizeof(wa_device_profile_samples[0]))

uint8_t *wa_test_get_device_profile_sample_cbor(const char *name, size_t *length_out)
{
    size_t sample_index;
    for (sample_index = 0; sample_index < WA_SAMPLE_COUNT; ++sample_index) {
        const wa_device_profile_sample_t *sample = &wa_device_profile_samples[sample_index];
        size_t total_length = 1;
        size_t line_index;
        char *hex;
        uint8_t *bytes;
        if (strcmp(sample->name, name) != 0) {
            continue;
        }
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
    fprintf(stderr, "no device profile sample named %s\n", name);
    return NULL;
}

wa_status_t wa_test_load_device_profile_sample(const char *name, const wa_platform_hooks_t *platform_hooks,
                                               wa_device_profile_t **device_profile_out)
{
    size_t cbor_length = 0;
    uint8_t *cbor = wa_test_get_device_profile_sample_cbor(name, &cbor_length);
    wa_status_t status;
    *device_profile_out = NULL;
    if (cbor == NULL) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    status = wa_device_profile_load_from_cbor(cbor, cbor_length, platform_hooks, device_profile_out, NULL, 0);
    free(cbor);
    return status;
}
