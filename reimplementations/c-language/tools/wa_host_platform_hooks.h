/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Platform hooks for host tools (Linux, macOS, Windows): operating system randomness (getrandom() on Linux, falling
 * back to /dev/urandom on old kernels; /dev/urandom on other POSIX systems; BCryptGenRandom on Windows), the system
 * clock in 1/10000 s, and stdlib allocation. Devices provide their own hooks: see the README. */

#ifndef WA_HOST_PLATFORM_HOOKS_H
#define WA_HOST_PLATFORM_HOOKS_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_platform_hooks.h"

typedef struct wa_host_random_source {
    /* POSIX only, for tests: read this file instead of the system source (a missing file simulates an unavailable
     * source). NULL in normal use. */
    const char *device_path_or_null;
} wa_host_random_source_t;

/* Fill `hooks` with the host hooks; `random_source_or_null` (NULL for the system source) must outlive them. */
void wa_host_platform_hooks_initialize(wa_platform_hooks_t *hooks, wa_host_random_source_t *random_source_or_null);

int wa_host_fill_random(void *random_context, uint8_t *buffer, size_t length);
int wa_host_get_unix_time_in_ten_thousandths_of_second(void *clock_context, uint64_t *unix_time_out);
void *wa_host_allocate(void *allocator_context, size_t size);
void wa_host_release(void *allocator_context, void *pointer, size_t size);

#endif /* WA_HOST_PLATFORM_HOOKS_H */
