/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Byte buffer growing through the allocator hook (no reallocation hook): allocate, copy, wipe the old block when
 * the buffer is secret, release. A secret buffer is also wiped when released. */

#ifndef WA_GROWABLE_BYTE_BUFFER_H
#define WA_GROWABLE_BYTE_BUFFER_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_status_codes.h"
#include "wa_flightbox/wa_value_tree.h"

typedef struct wa_growable_byte_buffer {
    const wa_platform_hooks_t *platform_hooks;
    uint8_t *data;    /* NULL while capacity is 0 */
    size_t length;
    size_t capacity;  /* size of the allocated block */
    int is_secret;
} wa_growable_byte_buffer_t;

void wa_growable_byte_buffer_initialize(wa_growable_byte_buffer_t *buffer, const wa_platform_hooks_t *platform_hooks,
                                        int is_secret);

/* Ensure room for at least `minimum_capacity` bytes in total. */
wa_status_t wa_growable_byte_buffer_reserve(wa_growable_byte_buffer_t *buffer, size_t minimum_capacity);

wa_status_t wa_growable_byte_buffer_append(wa_growable_byte_buffer_t *buffer, const uint8_t *bytes, size_t length);

/* Forget the content (wiped if secret), keeping the block. */
void wa_growable_byte_buffer_clear(wa_growable_byte_buffer_t *buffer);

/* Release the block (wiped if secret); the buffer is then empty and reusable. */
void wa_growable_byte_buffer_release(wa_growable_byte_buffer_t *buffer);

/* Create a bytes node taking over the content of the buffer, which is left empty. On failure, the buffer is
 * released (wiped if secret). */
wa_status_t wa_growable_byte_buffer_move_into_bytes_value(wa_growable_byte_buffer_t *buffer, wa_value_t **value_out);

/* Output sink appending to a buffer, whose context is the buffer. */
wa_output_sink_t wa_growable_byte_buffer_get_sink(wa_growable_byte_buffer_t *buffer);

#endif /* WA_GROWABLE_BYTE_BUFFER_H */
