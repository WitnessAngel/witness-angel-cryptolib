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
    wa_value_t *parent;  /* owned container holding this node, NULL for a root (always NULL for borrowed nodes) */
    union {
        int boolean;
        int64_t integer;
        struct {
            uint8_t *data;  /* text (UTF-8) or bytes; NULL when empty */
            size_t length;
            size_t allocation_size;  /* size of the block at data (>= length), released as a whole */
            int is_secret;           /* the block is wiped on release (all text and bytes but ciphertexts) */
        } string;
        uint8_t uuid[WA_UUID_SIZE];
        struct {
            wa_value_t **items;
            size_t count;
            size_t capacity;
        } array;
        struct {
            wa_value_map_entry_t *entries;  /* sorted by key, bytewise (see wa_value_compare_keys()) */
            size_t count;
            size_t capacity;
        } map;
    } content;
};

/* Borrowed nodes, referencing caller-owned data (cast to non-const, but never modified nor released). The entries
 * of a borrowed map must be sorted by key like those of owned maps. */
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

/* Unused tail, as a fraction of the content length, up to which a block is taken over rather than copied */
#define WA_VALUE_MAXIMUM_TAKEN_OVER_SLACK_DIVISOR 8u

/* Create a bytes node from the content of a buffer block (`data` of `allocation_size` bytes, the first `length`
 * meaningful): the node takes the block over, without copying it, if its unused tail is at most 1/8 of `length`,
 * and else gets an exact copy, the block being released. On success the node owns the content, and wipes it on
 * release only if `is_secret` (ciphertexts are public: wiping a large one would only cost time), as is a released
 * block; on failure the block is left to the caller. */
wa_status_t wa_value_create_bytes_from_allocated_block(const wa_platform_hooks_t *platform_hooks, uint8_t *data,
                                                       size_t length, size_t allocation_size, int is_secret,
                                                       wa_value_t **value_out);

/* Like wa_value_create_text(), for a text already known to be valid UTF-8 (not checked again). */
wa_status_t wa_value_create_text_with_valid_utf8(const wa_platform_hooks_t *platform_hooks, const char *text,
                                                 size_t text_length, wa_value_t **value_out);

/* Like wa_value_map_add(), for a key already known to be valid UTF-8 (not checked again). */
wa_status_t wa_value_map_add_with_valid_key(wa_value_t *map, const char *key, size_t key_length, wa_value_t *value);

/* 1 if `map` has the entry `key`, else 0 (binary search). */
int wa_value_map_has_key(const wa_value_t *map, const char *key, size_t key_length);

/* Like wa_value_map_add() with a NUL-terminated key; on failure, `value` is destroyed. */
wa_status_t wa_value_map_add_consuming(wa_value_t *map, const char *key, wa_value_t *value);

/* Remove an entry and return its value (ownership to the caller, as a root), or NULL when absent. */
wa_value_t *wa_value_map_take_value(wa_value_t *map, const char *key);

wa_value_t *wa_value_find_map_value_for_update(wa_value_t *map, const char *key);

/* 1 if `value` is a text node equal to the NUL-terminated `text`, else 0. */
int wa_value_is_text_equal_to(const wa_value_t *value_or_null, const char *text);

/* 1 if two keys are equal. */
int wa_value_keys_are_equal(const char *key_a, size_t length_a, const char *key_b, size_t length_b);

/* Bytewise order of keys (a prefix first), which is the code point order of UTF-8 texts: < 0, 0 or > 0. */
int wa_value_compare_keys(const char *key_a, size_t length_a, const char *key_b, size_t length_b);

#endif /* WA_VALUE_TREE_INTERNAL_H */
