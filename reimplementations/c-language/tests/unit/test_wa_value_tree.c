/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Unit tests of wa_value_tree.c and wa_document_tree_constraints.c (task 3.2). */

#include <stdio.h>
#include <string.h>

#include "encoding/wa_document_tree_constraints.h"
#include "encoding/wa_value_tree_internal.h"
#include "wa_flightbox/wa_flightbox_config.h"
#include "wa_minimal_test_harness.h"
#include "wa_test_support.h"

static const uint8_t sample_uuid[WA_UUID_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                                  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

static void test_builders_and_accessors(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(1);
    const wa_platform_hooks_t *hooks = &platform->hooks;
    wa_value_t *map = NULL;
    wa_value_t *array = NULL;
    wa_value_t *item = NULL;
    const wa_value_t *found;
    const char *text;
    size_t length;
    const uint8_t *bytes;
    int64_t integer;
    int boolean;
    const char *key;
    const wa_value_t *entry_value;

    WA_REQUIRE_STATUS(wa_value_create_map(hooks, &map), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_text(hooks, "zz", 2, &item), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_map_add(map, "z", 1, item), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_integer(hooks, INT64_MIN, &item), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_map_add(map, "a", 1, item), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_bytes(hooks, (const uint8_t *)"\x00\x01", 2, &item), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_map_add(map, "b\0c", 3, item), WA_STATUS_OK); /* Key with a NUL character */
    WA_REQUIRE_STATUS(wa_value_create_array(hooks, &array), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_boolean(hooks, 1, &item), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_array_append(array, item), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_null(hooks, &item), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_array_append(array, item), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_uuid(hooks, sample_uuid, &item), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_array_append(array, item), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_map_add(map, "list", 4, array), WA_STATUS_OK);

    /* Entries are sorted by key, bytewise: "a", "b\0c", "list", "z" */
    WA_CHECK_SIZE(wa_value_get_item_count(map), 4);
    WA_CHECK(wa_value_get_map_entry(map, 0, &key, &length, &entry_value) == 0);
    WA_CHECK_TEXT(key, length, "a");
    WA_CHECK(wa_value_get_map_entry(map, 1, &key, &length, &entry_value) == 0);
    WA_CHECK(length == 3 && memcmp(key, "b\0c", 3) == 0);
    WA_CHECK(wa_value_get_map_entry(map, 3, &key, &length, &entry_value) == 0);
    WA_CHECK_TEXT(key, length, "z");
    WA_CHECK(wa_value_get_map_entry(map, 4, &key, &length, &entry_value) == -1);

    found = wa_value_find_map_value(map, "z");
    WA_CHECK(found != NULL && wa_value_get_text(found, &text, &length) == 0);
    WA_CHECK_TEXT(text, length, "zz");
    WA_CHECK(wa_value_get_bytes(found, &bytes, &length) == -1); /* Wrong type */
    found = wa_value_find_map_value(map, "a");
    WA_CHECK(found != NULL && wa_value_get_integer(found, &integer) == 0 && integer == INT64_MIN);
    WA_CHECK(wa_value_find_map_value(map, "missing") == NULL);
    found = wa_value_find_map_value(map, "list");
    WA_CHECK(found != NULL && wa_value_get_type(found) == WA_VALUE_TYPE_ARRAY);
    WA_CHECK(wa_value_get_boolean(wa_value_get_array_item(found, 0), &boolean) == 0 && boolean == 1);
    WA_CHECK(wa_value_get_type(wa_value_get_array_item(found, 1)) == WA_VALUE_TYPE_NULL);
    WA_CHECK(wa_value_get_uuid(wa_value_get_array_item(found, 2), &bytes) == 0 &&
             memcmp(bytes, sample_uuid, WA_UUID_SIZE) == 0);
    WA_CHECK(wa_value_get_array_item(found, 3) == NULL);

    /* Duplicate keys are refused, and the rejected value stays owned by the caller */
    WA_REQUIRE_STATUS(wa_value_create_null(hooks, &item), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_value_map_add(map, "a", 1, item), WA_STATUS_INVALID_ARGUMENT);
    wa_value_destroy(item);

    wa_value_destroy(map);
    wa_value_destroy(NULL);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_invalid_utf8_rejected(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(2);
    wa_value_t *value = NULL;
    wa_value_t *map = NULL;
    WA_CHECK_STATUS(wa_value_create_text(&platform->hooks, "\xc3", 1, &value), WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK(value == NULL);
    WA_CHECK_STATUS(wa_value_create_text(&platform->hooks, "\xed\xa0\x80", 3, &value), /* Encoded surrogate */
                    WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(wa_value_create_text(&platform->hooks, "\xc0\xaf", 2, &value), /* Overlong */
                    WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(wa_value_create_text(&platform->hooks, "Caf\xc3\xa9 \xe2\x98\x95 \xf0\x9f\x98\x80", 14, &value),
                    WA_STATUS_OK);
    wa_value_destroy(value);
    WA_REQUIRE_STATUS(wa_value_create_map(&platform->hooks, &map), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_null(&platform->hooks, &value), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_value_map_add(map, "\xff", 1, value), WA_STATUS_INVALID_ARGUMENT);
    wa_value_destroy(value);
    wa_value_destroy(map);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_destroy_wipes_strings(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(3);
    static const uint8_t secret[16] = {0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    wa_value_t *map = NULL;
    wa_value_t *bytes = NULL;
    wa_test_allocator_register_secret_pattern(&platform->allocator, secret, sizeof(secret));
    WA_REQUIRE_STATUS(wa_value_create_map(&platform->hooks, &map), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_bytes(&platform->hooks, secret, sizeof(secret), &bytes), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_map_add(map, "key_bytes", 9, bytes), WA_STATUS_OK);
    wa_value_destroy(map);
    WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_shared_subtree_deep_copy_has_no_aliasing(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(4);
    /* Borrowed source tree where the same subtree {"data": b"\x01\x02"} appears twice: {"first": S, "second": S} */
    static const uint8_t data[2] = {1, 2};
    wa_value_t shared_bytes;
    wa_value_map_entry_t shared_entries[1];
    wa_value_t shared_map;
    wa_value_map_entry_t root_entries[2];
    wa_value_t root;
    wa_value_t *copy = NULL;
    wa_value_t *first_copy;
    wa_value_t *first_bytes_copy;
    const wa_value_t *second_bytes_copy;
    const uint8_t *bytes;
    size_t length;

    wa_value_initialize_borrowed_bytes(&shared_bytes, data, sizeof(data));
    wa_value_initialize_borrowed_map_entry(&shared_entries[0], "data", &shared_bytes);
    wa_value_initialize_borrowed_map(&shared_map, shared_entries, 1);
    wa_value_initialize_borrowed_map_entry(&root_entries[0], "first", &shared_map);
    wa_value_initialize_borrowed_map_entry(&root_entries[1], "second", &shared_map);
    wa_value_initialize_borrowed_map(&root, root_entries, 2);

    WA_REQUIRE_STATUS(wa_value_deep_copy(&root, &platform->hooks, &copy), WA_STATUS_OK);
    first_copy = wa_value_find_map_value_for_update(copy, "first");
    WA_REQUIRE(first_copy != NULL && first_copy != wa_value_find_map_value_for_update(copy, "second"));
    first_bytes_copy = wa_value_find_map_value_for_update(first_copy, "data");
    WA_REQUIRE(first_bytes_copy != NULL && first_bytes_copy->content.string.data != data);
    first_bytes_copy->content.string.data[0] = 0x99; /* Modify one copy */

    second_bytes_copy = wa_value_find_map_value(wa_value_find_map_value(copy, "second"), "data");
    WA_REQUIRE(second_bytes_copy != NULL && wa_value_get_bytes(second_bytes_copy, &bytes, &length) == 0);
    WA_CHECK_HEX(bytes, length, "0102"); /* The other copy is unchanged */
    WA_CHECK_HEX(data, sizeof(data), "0102"); /* And so is the source */

    wa_value_destroy(copy);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_take_value_and_consuming_add(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(5);
    wa_value_t *map = NULL;
    wa_value_t *value = NULL;
    wa_value_t *taken;
    WA_REQUIRE_STATUS(wa_value_create_map(&platform->hooks, &map), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_integer(&platform->hooks, 1, &value), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_map_add_consuming(map, "one", value), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_integer(&platform->hooks, 2, &value), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_map_add_consuming(map, "two", value), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_integer(&platform->hooks, 3, &value), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_value_map_add_consuming(map, "one", value), WA_STATUS_INVALID_ARGUMENT); /* Destroyed */
    taken = wa_value_map_take_value(map, "one");
    WA_CHECK(taken != NULL && wa_value_get_item_count(map) == 1);
    WA_CHECK(wa_value_map_take_value(map, "one") == NULL);
    WA_CHECK(wa_value_is_text_equal_to(NULL, "x") == 0);
    wa_value_destroy(taken);
    wa_value_destroy(map);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

/* Builds [[[...]]] with `depth` nested arrays */
static wa_value_t *build_nested_arrays(const wa_platform_hooks_t *hooks, size_t depth)
{
    wa_value_t *root = NULL;
    size_t level;
    for (level = 0; level < depth; level++) {
        wa_value_t *array = NULL;
        if (wa_value_create_array(hooks, &array) != WA_STATUS_OK) {
            wa_value_destroy(root);
            return NULL;
        }
        if (root != NULL && wa_value_array_append(array, root) != WA_STATUS_OK) {
            wa_value_destroy(array);
            wa_value_destroy(root);
            return NULL;
        }
        root = array;
    }
    return root;
}

static void test_depth_constraint(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(6);
    wa_value_t *tree = build_nested_arrays(&platform->hooks, WA_MAX_CBOR_NESTING_DEPTH);
    wa_value_t *scalar = NULL;
    WA_REQUIRE(tree != NULL);
    WA_CHECK_STATUS(wa_document_tree_check_constraints(tree, WA_MAX_CBOR_NESTING_DEPTH), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_document_tree_check_constraints(tree, WA_MAX_CBOR_NESTING_DEPTH - 1),
                    WA_STATUS_NESTING_TOO_DEEP);
    wa_value_destroy(tree);
    tree = build_nested_arrays(&platform->hooks, WA_MAX_CBOR_NESTING_DEPTH + 1);
    WA_REQUIRE(tree != NULL);
    WA_CHECK_STATUS(wa_document_tree_check_constraints(tree, WA_MAX_CBOR_NESTING_DEPTH), WA_STATUS_NESTING_TOO_DEEP);
    wa_value_destroy(tree);
    WA_REQUIRE_STATUS(wa_value_create_integer(&platform->hooks, 5, &scalar), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_document_tree_check_constraints(scalar, 0), WA_STATUS_OK); /* Scalars have no depth */
    wa_value_destroy(scalar);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static wa_status_t check_single_entry_map(const wa_platform_hooks_t *hooks, const char *key, int nested)
{
    wa_value_t *map = NULL;
    wa_value_t *value = NULL;
    wa_status_t status;
    if (wa_value_create_map(hooks, &map) != WA_STATUS_OK || wa_value_create_integer(hooks, 1, &value) != WA_STATUS_OK ||
        wa_value_map_add(map, key, strlen(key), value) != WA_STATUS_OK) {
        return WA_STATUS_INTERNAL_ERROR;
    }
    if (nested) {
        wa_value_t *outer = NULL;
        wa_value_t *other = NULL;
        if (wa_value_create_map(hooks, &outer) != WA_STATUS_OK ||
            wa_value_map_add_consuming(outer, "metadata", map) != WA_STATUS_OK ||
            wa_value_create_null(hooks, &other) != WA_STATUS_OK ||
            wa_value_map_add_consuming(outer, "other", other) != WA_STATUS_OK) {
            return WA_STATUS_INTERNAL_ERROR;
        }
        map = outer;
    }
    status = wa_document_tree_check_constraints(map, WA_MAX_CBOR_NESTING_DEPTH);
    wa_value_destroy(map);
    return status;
}

static void test_keyword_map_constraint(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(7);
    static const char *const keywords[] = {"$binary",      "$uuid",          "$date",     "$numberInt", "$numberLong",
                                           "$numberDouble", "$numberDecimal", "$undefined"};
    size_t index;
    for (index = 0; index < sizeof(keywords) / sizeof(keywords[0]); index++) {
        WA_CHECK(wa_document_tree_is_extended_json_keyword(keywords[index], strlen(keywords[index])));
        WA_CHECK_STATUS(check_single_entry_map(&platform->hooks, keywords[index], 0), WA_STATUS_INVALID_PROFILE);
        WA_CHECK_STATUS(check_single_entry_map(&platform->hooks, keywords[index], 1), WA_STATUS_INVALID_PROFILE);
    }
    WA_CHECK(!wa_document_tree_is_extended_json_keyword("$oid", 4));
    WA_CHECK(!wa_document_tree_is_extended_json_keyword("binary", 6));
    WA_CHECK_STATUS(check_single_entry_map(&platform->hooks, "$oid", 0), WA_STATUS_OK);
    WA_CHECK_STATUS(check_single_entry_map(&platform->hooks, "$Binary", 0), WA_STATUS_OK);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_keyword_key_among_others_accepted(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(8);
    wa_value_t *map = NULL;
    wa_value_t *value = NULL;
    WA_REQUIRE_STATUS(wa_value_create_map(&platform->hooks, &map), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_integer(&platform->hooks, 1, &value), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_map_add_consuming(map, "$binary", value), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_integer(&platform->hooks, 2, &value), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_map_add_consuming(map, "other", value), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_document_tree_check_constraints(map, WA_MAX_CBOR_NESTING_DEPTH), WA_STATUS_OK);
    wa_value_destroy(map);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_out_of_memory_in_builders(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(9);
    wa_value_t *value = NULL;
    platform->allocator.fail_at_attempt_index = platform->allocator.attempted_allocation_count;
    WA_CHECK_STATUS(wa_value_create_text(&platform->hooks, "abc", 3, &value), WA_STATUS_OUT_OF_MEMORY);
    WA_CHECK(value == NULL);
    platform->allocator.fail_at_attempt_index = platform->allocator.attempted_allocation_count + 1;
    WA_CHECK_STATUS(wa_value_create_text(&platform->hooks, "abc", 3, &value), WA_STATUS_OUT_OF_MEMORY);
    WA_CHECK(value == NULL);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_shared_and_cyclic_children_rejected(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(10);
    const wa_platform_hooks_t *hooks = &platform->hooks;
    wa_value_t *root = NULL;
    wa_value_t *child = NULL;
    wa_value_t *grandchild = NULL;
    wa_value_t *other_map = NULL;
    wa_value_t *taken;
    wa_value_t borrowed_null;
    WA_REQUIRE_STATUS(wa_value_create_map(hooks, &root), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_array(hooks, &child), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_map(hooks, &grandchild), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_map(hooks, &other_map), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_map_add(root, "child", 5, child), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_array_append(child, grandchild), WA_STATUS_OK);

    /* A node already held by a container (a double release otherwise) */
    WA_CHECK_STATUS(wa_value_array_append(child, grandchild), WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(wa_value_map_add(other_map, "again", 5, child), WA_STATUS_INVALID_ARGUMENT);
    /* The container itself, or one of its ancestors (a cycle otherwise) */
    WA_CHECK_STATUS(wa_value_array_append(child, child), WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(wa_value_map_add(grandchild, "root", 4, root), WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(wa_value_map_add(grandchild, "self", 4, grandchild), WA_STATUS_INVALID_ARGUMENT);
    /* Borrowed nodes are never owned by a container */
    wa_value_initialize_borrowed_null(&borrowed_null);
    WA_CHECK_STATUS(wa_value_map_add(other_map, "borrowed", 8, &borrowed_null), WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_SIZE(wa_value_get_item_count(child), 1);
    WA_CHECK_SIZE(wa_value_get_item_count(grandchild), 0);
    WA_CHECK_SIZE(wa_value_get_item_count(other_map), 0);

    /* A taken value is a root again, which can be added elsewhere */
    taken = wa_value_map_take_value(root, "child");
    WA_REQUIRE(taken == child);
    WA_CHECK_STATUS(wa_value_map_add(other_map, "moved", 5, taken), WA_STATUS_OK);

    wa_value_destroy(root);
    wa_value_destroy(other_map);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_null_node_accessors(void)
{
    const char *text = NULL;
    size_t length = 0;
    WA_CHECK(wa_value_get_type(NULL) == WA_VALUE_TYPE_INVALID);
    WA_CHECK(wa_value_get_text(NULL, &text, &length) == -1);
    WA_CHECK_SIZE(wa_value_get_item_count(NULL), 0);
    WA_CHECK(wa_value_find_map_value(NULL, "key") == NULL);
}

static void test_allocated_block_taken_over_or_copied(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(11);
    static const uint8_t secret[16] = {0xca, 0xfe, 0xba, 0xbe, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    wa_value_t *value = NULL;
    const uint8_t *bytes;
    size_t length;
    size_t allocation_count;
    size_t index;
    uint8_t *block;
    size_t expected_unwiped_count = 0;
    /* 100 bytes used out of 112 (unused tail within 1/8): taken over; out of 113 or 4096: copied */
    static const size_t allocation_sizes[] = {112, 113, 4096};
    wa_test_allocator_register_secret_pattern(&platform->allocator, secret, sizeof(secret));
    for (index = 0; index < 6u; ++index) {
        int is_secret = index % 2u == 0;
        size_t allocation_size = allocation_sizes[index / 2u];
        int is_taken_over = allocation_size == 112;
        block = (uint8_t *)platform->hooks.allocate(platform->hooks.allocator_context, allocation_size);
        WA_REQUIRE(block != NULL);
        memset(block, 0x5a, allocation_size);
        memcpy(block, secret, sizeof(secret));
        allocation_count = platform->allocator.allocation_count;
        WA_REQUIRE_STATUS(wa_value_create_bytes_from_allocated_block(&platform->hooks, block, 100, allocation_size,
                                                                     is_secret, &value),
                          WA_STATUS_OK);
        /* The node, plus the exact block of a copy (the original block being released at once) */
        WA_CHECK_SIZE(platform->allocator.allocation_count, allocation_count + (is_taken_over ? 1u : 2u));
        WA_REQUIRE(wa_value_get_bytes(value, &bytes, &length) == 0);
        WA_CHECK(length == 100 && memcmp(bytes, secret, sizeof(secret)) == 0);
        WA_CHECK((bytes == block) == is_taken_over);
        wa_value_destroy(value);
        /* Secret content is wiped on release, public content (ciphertexts) is not: an unwiped release per public
         * block, plus one for the content copy */
        if (!is_secret) {
            expected_unwiped_count += is_taken_over ? 1u : 2u;
        }
        WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, expected_unwiped_count);
    }
    /* Empty content: an empty node, the block being released */
    block = (uint8_t *)platform->hooks.allocate(platform->hooks.allocator_context, 16);
    WA_REQUIRE(block != NULL);
    WA_REQUIRE_STATUS(wa_value_create_bytes_from_allocated_block(&platform->hooks, block, 0, 16, 1, &value),
                      WA_STATUS_OK);
    WA_REQUIRE(wa_value_get_bytes(value, &bytes, &length) == 0);
    WA_CHECK(length == 0);
    wa_value_destroy(value);
    WA_CHECK_STATUS(wa_value_create_bytes_from_allocated_block(&platform->hooks, NULL, 0, 0, 1, &value),
                    WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_many_keys_sorted(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(12);
    wa_value_t *map = NULL;
    wa_value_t *value = NULL;
    const wa_value_t *found;
    const char *key;
    const char *previous_key = NULL;
    size_t key_length;
    size_t previous_key_length = 0;
    size_t index;
    char key_text[8];
    int64_t integer;
    WA_REQUIRE_STATUS(wa_value_create_map(&platform->hooks, &map), WA_STATUS_OK);
    /* Keys inserted in a scrambled order, of lengths 1 to 3 */
    for (index = 0; index < 200u; ++index) {
        size_t scrambled = (index * 7919u) % 200u;
        size_t text_length = (size_t)sprintf(key_text, "%u", (unsigned)scrambled);
        WA_REQUIRE_STATUS(wa_value_create_integer(&platform->hooks, (int64_t)scrambled, &value), WA_STATUS_OK);
        WA_REQUIRE_STATUS(wa_value_map_add(map, key_text, text_length, value), WA_STATUS_OK);
    }
    for (index = 0; index < 200u; ++index) {
        WA_REQUIRE(wa_value_get_map_entry(map, index, &key, &key_length, &found) == 0);
        if (previous_key != NULL) {
            WA_CHECK(wa_value_compare_keys(previous_key, previous_key_length, key, key_length) < 0);
        }
        previous_key = key;
        previous_key_length = key_length;
    }
    found = wa_value_find_map_value(map, "137");
    WA_CHECK(found != NULL && wa_value_get_integer(found, &integer) == 0 && integer == 137);
    WA_CHECK(wa_value_find_map_value(map, "200") == NULL);
    WA_CHECK(wa_value_map_has_key(map, "0", 1) && !wa_value_map_has_key(map, "", 0));
    wa_value_destroy(wa_value_map_take_value(map, "99"));
    WA_CHECK(wa_value_find_map_value(map, "99") == NULL && wa_value_find_map_value(map, "98") != NULL);
    WA_CHECK_SIZE(wa_value_get_item_count(map), 199);
    wa_value_destroy(map);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

/* Finding C-7: entries appended in any order, then sorted once */
static void test_unsorted_append_then_sort(void)
{
    static const char *const key_sets[][6] = {
        {NULL},                          /* Empty map */
        {"a", NULL},                     /* One entry */
        {"a", "b", "c", NULL},           /* Sorted already */
        {"c", "b", "a", NULL},           /* Descending */
        {"b", "", "ab", "a", "c", NULL}, /* Any order, with a prefix and the empty key */
        {"b", "a", "b", NULL},           /* Duplicates */
        {"a", "a", NULL},
        {"c", "a", "b", "", "a", NULL},
        {"", "b", "", NULL},
    };
    static const int expected_results[] = {1, 1, 1, 1, 1, 0, 0, 0, 0};
    size_t set_index;
    for (set_index = 0; set_index < sizeof(key_sets) / sizeof(key_sets[0]); ++set_index) {
        wa_test_platform_t *platform = wa_test_platform_create(13);
        wa_value_t *map = NULL;
        wa_value_t *value = NULL;
        size_t count = 0;
        size_t index;
        WA_REQUIRE_STATUS(wa_value_create_map(&platform->hooks, &map), WA_STATUS_OK);
        for (index = 0; key_sets[set_index][index] != NULL; ++index) {
            const char *key = key_sets[set_index][index];
            WA_REQUIRE_STATUS(wa_value_create_integer(&platform->hooks, (int64_t)index, &value), WA_STATUS_OK);
            WA_REQUIRE_STATUS(wa_value_map_append_unsorted_with_valid_key(map, key, strlen(key), value), WA_STATUS_OK);
            /* A node is adopted once, here too */
            WA_CHECK_STATUS(wa_value_map_append_unsorted_with_valid_key(map, "other", 5, value),
                            WA_STATUS_INVALID_ARGUMENT);
            count++;
        }
        WA_CHECK(wa_value_map_sort_entries(map) == expected_results[set_index]);
        WA_CHECK_SIZE(wa_value_get_item_count(map), count);
        for (index = 0; index < count; ++index) {
            const wa_value_map_entry_t *entry = &map->content.map.entries[index];
            int64_t original_index = -1;
            /* Sorted, each value still under its key */
            WA_REQUIRE(wa_value_get_integer(entry->value, &original_index) == 0);
            WA_CHECK(wa_value_keys_are_equal(entry->key, entry->key_length, key_sets[set_index][original_index],
                                             strlen(key_sets[set_index][original_index])));
            if (index > 0) {
                int comparison =
                    wa_value_compare_keys(entry[-1].key, entry[-1].key_length, entry->key, entry->key_length);
                WA_CHECK(expected_results[set_index] ? comparison < 0 : comparison <= 0);
            }
            WA_CHECK(wa_value_map_has_key(map, entry->key, entry->key_length));
        }
        WA_CHECK(wa_value_map_sort_entries(map) == expected_results[set_index]); /* Idempotent */
        wa_value_destroy(map);
        WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
        wa_test_platform_destroy(platform);
    }
    WA_CHECK(wa_value_map_sort_entries(NULL) == 0);
}

int main(void)
{
    WA_RUN_TEST(test_builders_and_accessors);
    WA_RUN_TEST(test_shared_and_cyclic_children_rejected);
    WA_RUN_TEST(test_null_node_accessors);
    WA_RUN_TEST(test_allocated_block_taken_over_or_copied);
    WA_RUN_TEST(test_many_keys_sorted);
    WA_RUN_TEST(test_unsorted_append_then_sort);
    WA_RUN_TEST(test_invalid_utf8_rejected);
    WA_RUN_TEST(test_destroy_wipes_strings);
    WA_RUN_TEST(test_shared_subtree_deep_copy_has_no_aliasing);
    WA_RUN_TEST(test_take_value_and_consuming_add);
    WA_RUN_TEST(test_depth_constraint);
    WA_RUN_TEST(test_keyword_map_constraint);
    WA_RUN_TEST(test_keyword_key_among_others_accepted);
    WA_RUN_TEST(test_out_of_memory_in_builders);
    return wa_test_finish();
}
