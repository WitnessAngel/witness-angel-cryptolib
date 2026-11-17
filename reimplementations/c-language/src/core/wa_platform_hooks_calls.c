/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/wa_platform_hooks_calls.h"

#include "primitives/wa_secure_memory_wipe.h"

int wa_platform_hooks_are_usable(const wa_platform_hooks_t *platform_hooks)
{
    return platform_hooks != NULL && platform_hooks->allocate != NULL && platform_hooks->release != NULL &&
           platform_hooks->fill_random != NULL;
}

void *wa_allocate_memory(const wa_platform_hooks_t *platform_hooks, size_t size)
{
    if (size == 0) {
        return NULL;
    }
    return platform_hooks->allocate(platform_hooks->allocator_context, size);
}

void wa_release_memory(const wa_platform_hooks_t *platform_hooks, void *pointer_or_null, size_t size)
{
    if (pointer_or_null != NULL) {
        platform_hooks->release(platform_hooks->allocator_context, pointer_or_null, size);
    }
}

void wa_release_secret_memory(const wa_platform_hooks_t *platform_hooks, void *pointer_or_null, size_t size)
{
    if (pointer_or_null != NULL) {
        wa_secure_memory_wipe(pointer_or_null, size);
        platform_hooks->release(platform_hooks->allocator_context, pointer_or_null, size);
    }
}

wa_status_t wa_fill_random_bytes(const wa_platform_hooks_t *platform_hooks, uint8_t *buffer, size_t length)
{
    if (length == 0) {
        return WA_STATUS_OK;
    }
    if (platform_hooks->fill_random(platform_hooks->random_context, buffer, length) != 0) {
        wa_secure_memory_wipe(buffer, length); /* Never keep partial output of a failed source */
        return WA_STATUS_RANDOMNESS_FAILURE;
    }
    return WA_STATUS_OK;
}

int wa_size_multiplication_overflows(size_t a, size_t b, size_t *product_out)
{
    if (a != 0 && b > (size_t)-1 / a) {
        return 1;
    }
    *product_out = a * b;
    return 0;
}
