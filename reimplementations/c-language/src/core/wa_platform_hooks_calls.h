/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Internal helpers around the platform hooks: allocation with sizes, wiping release, randomness. */

#ifndef WA_PLATFORM_HOOKS_CALLS_H
#define WA_PLATFORM_HOOKS_CALLS_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_status_codes.h"

#define WA_RETURN_IF_ERROR(expression)                     \
    do {                                                   \
        wa_status_t wa_returned_status_ = (expression);    \
        if (wa_returned_status_ != WA_STATUS_OK) {         \
            return wa_returned_status_;                    \
        }                                                  \
    } while (0)

/* 1 if the mandatory hooks (allocate, release, fill_random) are present, else 0. */
int wa_platform_hooks_are_usable(const wa_platform_hooks_t *platform_hooks);

/* Allocate `size` bytes (size > 0, else NULL is returned). */
void *wa_allocate_memory(const wa_platform_hooks_t *platform_hooks, size_t size);

/* Release a block (NULL is a no-op), without wiping it. */
void wa_release_memory(const wa_platform_hooks_t *platform_hooks, void *pointer_or_null, size_t size);

/* Wipe, then release a block that held secrets (NULL is a no-op). */
void wa_release_secret_memory(const wa_platform_hooks_t *platform_hooks, void *pointer_or_null, size_t size);

/* Fill a buffer from the random hook: WA_STATUS_RANDOMNESS_FAILURE if the hook fails. */
wa_status_t wa_fill_random_bytes(const wa_platform_hooks_t *platform_hooks, uint8_t *buffer, size_t length);

/* 1 if a * b overflows size_t, else 0 (and stores the product). */
int wa_size_multiplication_overflows(size_t a, size_t b, size_t *product_out);

#endif /* WA_PLATFORM_HOOKS_CALLS_H */
