/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Platform hooks: the only way the library reaches memory, randomness, time and outputs.
 *
 * The library performs no operating-system call and has no global state: hooks are given per instance, and the
 * hooks structure must outlive every object created with it (device profiles, value trees, encryptors). */

#ifndef WA_PLATFORM_HOOKS_H
#define WA_PLATFORM_HOOKS_H

#include <stddef.h>
#include <stdint.h>

#include "wa_status_codes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wa_platform_hooks {
    /* Return a block of at least `size` bytes (size > 0), suitably aligned for any type, or NULL. */
    void *(*allocate)(void *allocator_context, size_t size);
    /* Release a block returned by `allocate`, with the size it was requested with. The library has already wiped
     * the blocks that held secrets. */
    void (*release)(void *allocator_context, void *pointer, size_t size);
    void *allocator_context;

    /* Fill `buffer` with `length` bytes from a CRYPTOGRAPHICALLY SECURE random generator, and return 0; return any
     * other value on failure, which aborts the current operation (there is no fallback source).
     * Every secret comes from this hook: symmetric keys, IVs and nonces, Shamir coefficients, HPKE ephemeral keys,
     * ML-KEM encapsulation randomness, RSA-OAEP seeds and UUID random bits. */
    int (*fill_random)(void *random_context, uint8_t *buffer, size_t length);
    void *random_context;

    /* Optional (may be NULL): store the current Unix time in units of 1/10000 second and return 0, or return any
     * other value when no clock is available. Without a clock, UUID0 time prefixes are zero. */
    int (*get_unix_time_in_ten_thousandths_of_second)(void *clock_context, uint64_t *unix_time_out);
    void *clock_context;
} wa_platform_hooks_t;

/* Destination of produced bytes (cryptainer documents, offloaded payload ciphertexts): a file, flash, a socket or
 * a buffer, as the caller decides. `write` returns WA_STATUS_OK, or any other status on failure. */
typedef struct wa_output_sink {
    wa_status_t (*write)(void *sink_context, const uint8_t *bytes, size_t length);
    void *sink_context;
} wa_output_sink_t;

#ifdef __cplusplus
}
#endif

#endif /* WA_PLATFORM_HOOKS_H */
