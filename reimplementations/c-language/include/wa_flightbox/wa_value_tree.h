/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Value trees: the data model of cryptoconfs, cryptainers and cryptainer metadata.
 *
 * Node types are those of the device profile sub-profile of WA-CBOR: null, booleans, signed 64-bit integers, UTF-8
 * text, bytes, UUIDs, arrays and maps with text keys, kept sorted by key (bytewise UTF-8, which is the order of
 * wa_value_get_map_entry()). Writers order map keys as their format requires.
 *
 * Every node is allocated through the platform hooks given at creation, which must outlive it. Container functions
 * taking a child node take its ownership on success only; on failure, the caller still owns (and must destroy) it. */

#ifndef WA_VALUE_TREE_H
#define WA_VALUE_TREE_H

#include <stddef.h>
#include <stdint.h>

#include "wa_platform_hooks.h"
#include "wa_status_codes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wa_value wa_value_t;

typedef enum wa_value_type {
    WA_VALUE_TYPE_INVALID = 0, /* only returned by wa_value_get_type(NULL) */
    WA_VALUE_TYPE_NULL = 1,
    WA_VALUE_TYPE_BOOLEAN,
    WA_VALUE_TYPE_INTEGER,
    WA_VALUE_TYPE_TEXT,
    WA_VALUE_TYPE_BYTES,
    WA_VALUE_TYPE_UUID,
    WA_VALUE_TYPE_ARRAY,
    WA_VALUE_TYPE_MAP
} wa_value_type_t;

#define WA_UUID_SIZE 16

/* Builders. Text must be valid UTF-8 without encoded surrogates (WA_STATUS_INVALID_ARGUMENT otherwise), and may
 * contain NUL characters since its length is explicit. */
wa_status_t wa_value_create_null(const wa_platform_hooks_t *platform_hooks, wa_value_t **value_out);
wa_status_t wa_value_create_boolean(const wa_platform_hooks_t *platform_hooks, int boolean, wa_value_t **value_out);
wa_status_t wa_value_create_integer(const wa_platform_hooks_t *platform_hooks, int64_t integer,
                                    wa_value_t **value_out);
wa_status_t wa_value_create_text(const wa_platform_hooks_t *platform_hooks, const char *text, size_t text_length,
                                 wa_value_t **value_out);
wa_status_t wa_value_create_bytes(const wa_platform_hooks_t *platform_hooks, const uint8_t *bytes,
                                  size_t bytes_length, wa_value_t **value_out);
wa_status_t wa_value_create_uuid(const wa_platform_hooks_t *platform_hooks, const uint8_t uuid[WA_UUID_SIZE],
                                 wa_value_t **value_out);
wa_status_t wa_value_create_array(const wa_platform_hooks_t *platform_hooks, wa_value_t **value_out);
wa_status_t wa_value_create_map(const wa_platform_hooks_t *platform_hooks, wa_value_t **value_out);

/* Append `item` to `array`, taking its ownership on success. `item` must be a root node (not already in a
 * container) and must not be `array` nor one of its ancestors: WA_STATUS_INVALID_ARGUMENT otherwise. */
wa_status_t wa_value_array_append(wa_value_t *array, wa_value_t *item);

/* Add the entry `key` -> `value` to `map`, taking ownership of `value` on success. A key already present gives
 * WA_STATUS_INVALID_ARGUMENT, as does a `value` that wa_value_array_append() would refuse. */
wa_status_t wa_value_map_add(wa_value_t *map, const char *key, size_t key_length, wa_value_t *value);

/* Release a tree recursively, wiping the content of bytes and text nodes. NULL is a no-op. */
void wa_value_destroy(wa_value_t *value_or_null);

/* Accessors (no allocation). Getters return 0 on success, -1 when the node has another type or an index is out of
 * range. Returned pointers are borrowed from the tree. */
wa_value_type_t wa_value_get_type(const wa_value_t *value); /* WA_VALUE_TYPE_INVALID for NULL */
int wa_value_get_boolean(const wa_value_t *value, int *boolean_out);
int wa_value_get_integer(const wa_value_t *value, int64_t *integer_out);
int wa_value_get_text(const wa_value_t *value, const char **text_out, size_t *text_length_out);
int wa_value_get_bytes(const wa_value_t *value, const uint8_t **bytes_out, size_t *bytes_length_out);
int wa_value_get_uuid(const wa_value_t *value, const uint8_t **uuid_out);
size_t wa_value_get_item_count(const wa_value_t *value);  /* array items or map entries, 0 for other types */
const wa_value_t *wa_value_get_array_item(const wa_value_t *array, size_t index);
int wa_value_get_map_entry(const wa_value_t *map, size_t index, const char **key_out, size_t *key_length_out,
                           const wa_value_t **value_out);
const wa_value_t *wa_value_find_map_value(const wa_value_t *map, const char *key);  /* NUL-terminated key */

/* Decode a WA-CBOR document within the device profile sub-profile (e.g. cryptainer metadata) into a new tree.
 * Returns WA_STATUS_DECODING_ERROR for bytes that are not WA-CBOR, WA_STATUS_UNSUPPORTED_TYPE for valid WA-CBOR
 * items outside the sub-profile (floats, datetimes, bignums, decimals, indefinite lengths, tag 55799, integers
 * outside int64), and WA_STATUS_NESTING_TOO_DEEP beyond WA_MAX_CBOR_NESTING_DEPTH. `*value_out` is NULL on
 * failure. */
wa_status_t wa_value_tree_decode_from_cbor(const uint8_t *cbor, size_t cbor_length,
                                           const wa_platform_hooks_t *platform_hooks, wa_value_t **value_out);

#ifdef __cplusplus
}
#endif

#endif /* WA_VALUE_TREE_H */
