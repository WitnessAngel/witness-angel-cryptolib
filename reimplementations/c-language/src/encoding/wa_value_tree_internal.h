/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Internal view of the value tree (design D7).
 *
 * Owned nodes are allocated through the platform hooks they keep a pointer to (the hooks must outlive the tree).
 * Borrowed nodes are built on the stack by the core, around data it owns, to serialize intermediate structures
 * (symkeys, key structs, cipherdicts, shard tuples) without allocation: they are never destroyed. */

#ifndef WA_VALUE_TREE_INTERNAL_H
#define WA_VALUE_TREE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_value_tree.h"

typedef struct wa_value_map_entry {
    char *key;  /* UTF-8, not NUL-terminated in general */
    size_t key_length;
    wa_value_t *value;
} wa_value_map_entry_t;

struct wa_value {
    wa_value_type_t type;
    int is_borrowed;
    const wa_platform_hooks_t *platform_hooks;  /* NULL for borrowed nodes */
    union {
        int boolean;
        int64_t integer;
        struct {
            uint8_t *data;  /* text (UTF-8) or bytes; NULL when empty */
            size_t length;
        } string;
        uint8_t uuid[WA_UUID_SIZE];
        struct {
            wa_value_t **items;
            size_t count;
            size_t capacity;
        } array;
        struct {
            wa_value_map_entry_t *entries;  /* in insertion order */
            size_t count;
            size_t capacity;
        } map;
    } content;
};

/* Borrowed nodes, referencing caller-owned data (cast to non-const, but never modified nor released). */
void wa_value_initialize_borrowed_null(wa_value_t *node);
void wa_value_initialize_borrowed_integer(wa_value_t *node, int64_t integer);
void wa_value_initialize_borrowed_text(wa_value_t *node, const char *nul_terminated_text);
void wa_value_initialize_borrowed_bytes(wa_value_t *node, const uint8_t *bytes, size_t length);
void wa_value_initialize_borrowed_array(wa_value_t *node, wa_value_t **items, size_t count);
void wa_value_initialize_borrowed_map(wa_value_t *node, wa_value_map_entry_t *entries, size_t count);
void wa_value_initialize_borrowed_map_entry(wa_value_map_entry_t *entry, const char *nul_terminated_key,
                                            const wa_value_t *value);

/* Recursive copy, each node getting its own copy (no aliasing), allocated with `platform_hooks`. */
wa_status_t wa_value_deep_copy(const wa_value_t *source, const wa_platform_hooks_t *platform_hooks,
                               wa_value_t **copy_out);

/* Create a bytes node taking over the content of a buffer block (`data` of `allocation_size` bytes, the first
 * `length` meaningful). On success the node owns the block; on failure the block is left to the caller. */
wa_status_t wa_value_create_bytes_from_allocated_block(const wa_platform_hooks_t *platform_hooks, uint8_t *data,
                                                       size_t length, size_t allocation_size,
                                                       wa_value_t **value_out);

/* Like wa_value_map_add() with a NUL-terminated key; on failure, `value` is destroyed. */
wa_status_t wa_value_map_add_consuming(wa_value_t *map, const char *key, wa_value_t *value);

/* Remove an entry and return its value (ownership to the caller), or NULL when absent. */
wa_value_t *wa_value_map_take_value(wa_value_t *map, const char *key);

wa_value_t *wa_value_find_map_value_for_update(wa_value_t *map, const char *key);

/* 1 if `value` is a text node equal to the NUL-terminated `text`, else 0. */
int wa_value_is_text_equal_to(const wa_value_t *value_or_null, const char *text);

/* 1 if two keys are equal. */
int wa_value_keys_are_equal(const char *key_a, size_t length_a, const char *key_b, size_t length_b);

#endif /* WA_VALUE_TREE_INTERNAL_H */
