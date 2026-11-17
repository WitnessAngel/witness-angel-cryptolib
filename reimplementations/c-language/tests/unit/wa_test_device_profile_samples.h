/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Access to the generated device profile samples (wa_device_profile_samples.h) from several tests. */

#ifndef WA_TEST_DEVICE_PROFILE_SAMPLES_H
#define WA_TEST_DEVICE_PROFILE_SAMPLES_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_device_profile.h"
#include "wa_flightbox/wa_platform_hooks.h"

/* The CBOR bytes of a named sample, in a malloc()'d buffer, or NULL (unknown name, printed to stderr) */
uint8_t *wa_test_get_device_profile_sample_cbor(const char *name, size_t *length_out);

/* Load a named sample with the given hooks */
wa_status_t wa_test_load_device_profile_sample(const char *name, const wa_platform_hooks_t *platform_hooks,
                                               wa_device_profile_t **device_profile_out);

#endif /* WA_TEST_DEVICE_PROFILE_SAMPLES_H */
