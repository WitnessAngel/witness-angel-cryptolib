/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Location of the faulty item of a device profile, as a path such as
 * "cryptoconf.payload_cipher_layers[0].key_cipher_layers[1]" (design D10). Validators push a component when they
 * enter a map value or an array item, and pop it when they leave it successfully: on error they return at once, so
 * the path then names the faulty item. Paths longer than the fixed capacity are truncated, while pushes and pops
 * keep working on their logical length. */

#ifndef WA_ERROR_LOCATION_PATH_H
#define WA_ERROR_LOCATION_PATH_H

#include <stddef.h>

#define WA_ERROR_LOCATION_PATH_CAPACITY 256u

typedef struct wa_error_location_path {
    char text[WA_ERROR_LOCATION_PATH_CAPACITY]; /* NUL-terminated, possibly truncated */
    size_t logical_length;                      /* Length the path would have without truncation */
} wa_error_location_path_t;

void wa_error_location_path_initialize(wa_error_location_path_t *path);

/* Append ".key" ("key" at the start of the path) and return the previous logical length, to give to pop(). */
size_t wa_error_location_path_push_key(wa_error_location_path_t *path, const char *key, size_t key_length);

/* Append "[index]" and return the previous logical length. */
size_t wa_error_location_path_push_index(wa_error_location_path_t *path, size_t index);

void wa_error_location_path_pop(wa_error_location_path_t *path, size_t previous_logical_length);

/* Copy the path, NUL-terminated and truncated to the buffer size, into a caller buffer (NULL or size 0: no-op). */
void wa_error_location_path_copy_to_buffer(const wa_error_location_path_t *path, char *buffer_or_null,
                                           size_t buffer_size);

#endif /* WA_ERROR_LOCATION_PATH_H */
