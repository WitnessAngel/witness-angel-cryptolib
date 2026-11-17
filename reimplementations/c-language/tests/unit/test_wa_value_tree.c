/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Unit tests of wa_value_tree.c and wa_document_tree_constraints.c (task 3.2). */

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

    /* Insertion order is kept */
    WA_CHECK_SIZE(wa_value_get_item_count(map), 4);
    WA_CHECK(wa_value_get_map_entry(map, 0, &key, &length, &entry_value) == 0);
    WA_CHECK_TEXT(key, length, "z");
    WA_CHECK(wa_value_get_map_entry(map, 2, &key, &length, &entry_value) == 0);
    WA_CHECK(length == 3 && memcmp(key, "b\0c", 3) == 0);
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

int main(void)
{
    WA_RUN_TEST(test_builders_and_accessors);
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
