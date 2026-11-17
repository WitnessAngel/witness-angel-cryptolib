/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Unit tests of wa_wacbor_subprofile_decoder.c and wa_value_tree_decode_from_cbor() (task 3.7): accepted,
 * unsupported and invalid classes of design D8, and every test vector of section 10 of the WA-CBOR specification. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encoding/wa_value_tree_internal.h"
#include "wa_flightbox/wa_flightbox_config.h"
#include "wa_minimal_test_harness.h"
#include "wa_test_support.h"
#include "wa_wacbor_specification_vectors.h"

/* Decodes hex CBOR and returns the status; the tree is returned through tree_out_or_null, or destroyed */
static wa_status_t decode_hex(wa_test_platform_t *platform, const char *cbor_hex, wa_value_t **tree_out_or_null)
{
    size_t cbor_length = 0;
    uint8_t *cbor = wa_test_decode_hex(cbor_hex, &cbor_length);
    wa_value_t *tree = (wa_value_t *)&cbor_length; /* Must be reset to NULL on failure */
    wa_status_t status;
    if (cbor == NULL) {
        return WA_STATUS_INTERNAL_ERROR;
    }
    status = wa_value_tree_decode_from_cbor(cbor, cbor_length, &platform->hooks, &tree);
    free(cbor);
    if (status != WA_STATUS_OK) {
        WA_CHECK(tree == NULL);
        tree = NULL;
    }
    if (tree_out_or_null != NULL) {
        *tree_out_or_null = tree;
    } else {
        wa_value_destroy(tree);
    }
    return status;
}

static void check_decoding(const char *cbor_hex, wa_status_t expected_status)
{
    wa_test_platform_t *platform = wa_test_platform_create(1);
    wa_status_t status = decode_hex(platform, cbor_hex, NULL);
    if (status != expected_status) {
        printf("    input %s\n", cbor_hex);
    }
    WA_CHECK_STATUS(status, expected_status);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_specification_vectors(void)
{
    size_t index;
    for (index = 0; index < sizeof(wa_wacbor_specification_vectors) / sizeof(wa_wacbor_specification_vectors[0]);
         index++) {
        const wa_wacbor_specification_vector_t *vector = &wa_wacbor_specification_vectors[index];
        wa_test_platform_t *platform = wa_test_platform_create(2);
        wa_status_t status = decode_hex(platform, vector->cbor_hex, NULL);
        int is_expected = 0;
        switch (vector->expectation) {
        case WA_EXPECT_ACCEPTED:
            is_expected = status == WA_STATUS_OK;
            break;
        case WA_EXPECT_UNSUPPORTED:
            is_expected = status == WA_STATUS_UNSUPPORTED_TYPE;
            break;
        case WA_EXPECT_DECODING_ERROR:
            is_expected = status == WA_STATUS_DECODING_ERROR;
            break;
        case WA_EXPECT_UNSUPPORTED_OR_DECODING_ERROR:
            is_expected = status == WA_STATUS_UNSUPPORTED_TYPE || status == WA_STATUS_DECODING_ERROR;
            break;
        case WA_EXPECT_NESTING_TOO_DEEP:
            is_expected = status == WA_STATUS_NESTING_TOO_DEEP;
            break;
        }
        if (!is_expected) {
            printf("    vector %s: status %d (%s)\n", vector->name, (int)status, wa_status_get_description(status));
        }
        WA_CHECK(is_expected);
        WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
        wa_test_platform_destroy(platform);
    }
}

static void test_accepted_types(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(3);
    wa_value_t *tree = NULL;
    const wa_value_t *value;
    const char *text;
    const uint8_t *bytes;
    size_t length;
    int64_t integer;
    int boolean;
    const char *key;

    /* {"b": 1, "a": [h'ff', "é", -2^63, 2^63-1, true, false, null, 37(h'00..0f')], "": {}} with unsorted keys */
    WA_REQUIRE_STATUS(decode_hex(platform,
                                 "a3" "6162" "01" "6161" "88" "41ff" "62c3a9" "3b7fffffffffffffff"
                                 "1b7fffffffffffffff" "f5" "f4" "f6" "d82550000102030405060708090a0b0c0d0e0f"
                                 "60" "a0",
                                 &tree),
                      WA_STATUS_OK);
    WA_CHECK(wa_value_get_type(tree) == WA_VALUE_TYPE_MAP && wa_value_get_item_count(tree) == 3);
    WA_CHECK(wa_value_get_map_entry(tree, 0, &key, &length, &value) == 0); /* Insertion order kept */
    WA_CHECK_TEXT(key, length, "b");
    value = wa_value_find_map_value(tree, "a");
    WA_REQUIRE(value != NULL && wa_value_get_item_count(value) == 8);
    WA_CHECK(wa_value_get_bytes(wa_value_get_array_item(value, 0), &bytes, &length) == 0);
    WA_CHECK_HEX(bytes, length, "ff");
    WA_CHECK(wa_value_get_text(wa_value_get_array_item(value, 1), &text, &length) == 0);
    WA_CHECK_TEXT(text, length, "\xc3\xa9");
    WA_CHECK(wa_value_get_integer(wa_value_get_array_item(value, 2), &integer) == 0 && integer == INT64_MIN);
    WA_CHECK(wa_value_get_integer(wa_value_get_array_item(value, 3), &integer) == 0 && integer == INT64_MAX);
    WA_CHECK(wa_value_get_boolean(wa_value_get_array_item(value, 4), &boolean) == 0 && boolean == 1);
    WA_CHECK(wa_value_get_boolean(wa_value_get_array_item(value, 5), &boolean) == 0 && boolean == 0);
    WA_CHECK(wa_value_get_type(wa_value_get_array_item(value, 6)) == WA_VALUE_TYPE_NULL);
    WA_CHECK(wa_value_get_uuid(wa_value_get_array_item(value, 7), &bytes) == 0);
    WA_CHECK_HEX(bytes, WA_UUID_SIZE, "000102030405060708090a0b0c0d0e0f");
    value = wa_value_find_map_value(tree, "");
    WA_CHECK(value != NULL && wa_value_get_type(value) == WA_VALUE_TYPE_MAP && wa_value_get_item_count(value) == 0);
    wa_value_destroy(tree);

    /* Non-shortest heads: integer, text length, bytes length, array and map counts, tag number */
    WA_REQUIRE_STATUS(decode_hex(platform,
                                 "b90002" "7900016b" "1b0000000000000001" "78016c" "9a00000001" "5b000000000000000201"
                                 "02",
                                 &tree),
                      WA_STATUS_OK);
    WA_CHECK(wa_value_get_integer(wa_value_find_map_value(tree, "k"), &integer) == 0 && integer == 1);
    value = wa_value_find_map_value(tree, "l");
    WA_REQUIRE(value != NULL && wa_value_get_item_count(value) == 1);
    WA_CHECK(wa_value_get_bytes(wa_value_get_array_item(value, 0), &bytes, &length) == 0);
    WA_CHECK_HEX(bytes, length, "0102");
    wa_value_destroy(tree);
    check_decoding("81d9002550000102030405060708090a0b0c0d0e0f", WA_STATUS_OK); /* Tag 37 in a 2-byte head */
    check_decoding("80", WA_STATUS_OK);                                         /* Top-level array */
    check_decoding("8163f09f98", WA_STATUS_DECODING_ERROR);                     /* Truncated 4-byte UTF-8 */

    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_unsupported_classes(void)
{
    check_decoding("81f93c00", WA_STATUS_UNSUPPORTED_TYPE);                   /* Half float */
    check_decoding("81fa3f800000", WA_STATUS_UNSUPPORTED_TYPE);               /* Single float */
    check_decoding("81fb3ff0000000000000", WA_STATUS_UNSUPPORTED_TYPE);       /* Double float */
    check_decoding("81c074323032362d30312d30325430333a30343a30355a", WA_STATUS_UNSUPPORTED_TYPE); /* Tag 0 */
    check_decoding("81c249010000000000000000", WA_STATUS_UNSUPPORTED_TYPE);   /* Tag 2 */
    check_decoding("81c349010000000000000000", WA_STATUS_UNSUPPORTED_TYPE);   /* Tag 3 */
    check_decoding("81c482200a", WA_STATUS_UNSUPPORTED_TYPE);                 /* Tag 4 */
    check_decoding("9fff", WA_STATUS_UNSUPPORTED_TYPE);                       /* Indefinite array */
    check_decoding("bfff", WA_STATUS_UNSUPPORTED_TYPE);                       /* Indefinite map */
    check_decoding("815f41014102ff", WA_STATUS_UNSUPPORTED_TYPE);             /* Indefinite bytes */
    check_decoding("817f6161ff", WA_STATUS_UNSUPPORTED_TYPE);                 /* Indefinite text */
    check_decoding("d9d9f7a0", WA_STATUS_UNSUPPORTED_TYPE);                   /* Tag 55799, top level */
    check_decoding("811b8000000000000000", WA_STATUS_UNSUPPORTED_TYPE);       /* 2^63 */
    check_decoding("813b8000000000000000", WA_STATUS_UNSUPPORTED_TYPE);       /* -2^63-1 */
    check_decoding("811bffffffffffffffff", WA_STATUS_UNSUPPORTED_TYPE);       /* 2^64-1 */
}

static void test_invalid_classes(void)
{
    char too_deep[2 * (WA_MAX_CBOR_NESTING_DEPTH + 1) + 1];
    char deepest[2 * WA_MAX_CBOR_NESTING_DEPTH + 1];
    size_t index;

    check_decoding("81c101", WA_STATUS_DECODING_ERROR);                       /* Tag 1 */
    check_decoding("81d9010280", WA_STATUS_DECODING_ERROR);                   /* Tag 258 */
    check_decoding("81d9d9f701", WA_STATUS_DECODING_ERROR);                   /* Tag 55799, nested */
    check_decoding("a10102", WA_STATUS_DECODING_ERROR);                       /* Integer key */
    check_decoding("a1410102", WA_STATUS_DECODING_ERROR);                     /* Bytes key */
    check_decoding("a2616101616102", WA_STATUS_DECODING_ERROR);               /* Duplicate key */
    check_decoding("a2780161016161" "02", WA_STATUS_DECODING_ERROR);          /* Duplicate, non-shortest */
    check_decoding("81a16524757569646430313233", WA_STATUS_DECODING_ERROR);   /* {"$uuid": "0123"} */
    check_decoding("a16a246e756d626572496e7401", WA_STATUS_DECODING_ERROR);   /* {"$numberInt": 1}, top */
    check_decoding("81d8254f000000000000000000000000000000", WA_STATUS_DECODING_ERROR); /* 15-byte UUID */
    check_decoding("81d8256430313233", WA_STATUS_DECODING_ERROR);             /* UUID over text */
    check_decoding("81f7", WA_STATUS_DECODING_ERROR);                         /* undefined */
    check_decoding("81f0", WA_STATUS_DECODING_ERROR);                         /* Simple value 16 */
    check_decoding("81f820", WA_STATUS_DECODING_ERROR);                       /* Simple value 32 */
    check_decoding("811c", WA_STATUS_DECODING_ERROR);                         /* Reserved AI 28 */
    check_decoding("811f", WA_STATUS_DECODING_ERROR);                         /* Indefinite integer */
    check_decoding("81ff", WA_STATUS_DECODING_ERROR);                         /* Stray break */
    check_decoding("8201", WA_STATUS_DECODING_ERROR);                         /* Truncated array */
    check_decoding("815affffffff00", WA_STATUS_DECODING_ERROR);               /* Oversize bytes length */
    check_decoding("819bffffffffffffffff", WA_STATUS_DECODING_ERROR);         /* Oversize array count */
    check_decoding("81bb7fffffffffffffff", WA_STATUS_DECODING_ERROR);         /* Oversize map count */
    check_decoding("8162c328", WA_STATUS_DECODING_ERROR);                     /* Invalid UTF-8 */
    check_decoding("8163eda080", WA_STATUS_DECODING_ERROR);                   /* Encoded surrogate */
    check_decoding("a1" "62c328" "01", WA_STATUS_DECODING_ERROR);             /* Invalid UTF-8 key */
    check_decoding("a000", WA_STATUS_DECODING_ERROR);                         /* Trailing bytes */
    check_decoding("01", WA_STATUS_DECODING_ERROR);                           /* Scalar top level */
    check_decoding("6161", WA_STATUS_DECODING_ERROR);                         /* Text top level */
    check_decoding("", WA_STATUS_DECODING_ERROR);                             /* Empty */
    check_decoding("81", WA_STATUS_DECODING_ERROR);                           /* Truncated item */
    check_decoding("811b00000000", WA_STATUS_DECODING_ERROR);                 /* Truncated head */

    for (index = 0; index < WA_MAX_CBOR_NESTING_DEPTH; index++) {
        memcpy(too_deep + 2 * index, "81", 2);
        memcpy(deepest + 2 * index, index + 1 == WA_MAX_CBOR_NESTING_DEPTH ? "80" : "81", 2);
    }
    memcpy(too_deep + 2 * WA_MAX_CBOR_NESTING_DEPTH, "80", 2);
    too_deep[sizeof(too_deep) - 1] = '\0';
    deepest[sizeof(deepest) - 1] = '\0';
    check_decoding(deepest, WA_STATUS_OK);
    check_decoding(too_deep, WA_STATUS_NESTING_TOO_DEEP);
}

static void test_out_of_memory_sweep(void)
{
    static const char *const document_hex =
        "a3" "6162" "01" "6161" "84" "41ff" "62c3a9" "a1617882f6f5" "d82550000102030405060708090a0b0c0d0e0f" "60" "a0";
    size_t failing_index;
    for (failing_index = 0;; failing_index++) {
        wa_test_platform_t *platform = wa_test_platform_create(4);
        wa_status_t status;
        int failure_was_injected;
        platform->allocator.fail_at_attempt_index = failing_index;
        status = decode_hex(platform, document_hex, NULL);
        failure_was_injected = platform->allocator.failure_was_injected;
        WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
        wa_test_platform_destroy(platform);
        if (!failure_was_injected) {
            WA_CHECK_STATUS(status, WA_STATUS_OK);
            break;
        }
        WA_CHECK_STATUS(status, WA_STATUS_OUT_OF_MEMORY);
    }
    WA_CHECK(failing_index > 10);
}

static void test_invalid_arguments(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(5);
    wa_value_t *tree = NULL;
    static const uint8_t empty_map[1] = {0xa0};
    WA_CHECK(wa_value_tree_decode_from_cbor(NULL, 1, &platform->hooks, &tree) != WA_STATUS_OK);
    WA_CHECK(tree == NULL);
    WA_CHECK(wa_value_tree_decode_from_cbor(empty_map, 1, NULL, &tree) != WA_STATUS_OK);
    WA_CHECK(tree == NULL);
    WA_CHECK(wa_value_tree_decode_from_cbor(empty_map, 1, &platform->hooks, NULL) != WA_STATUS_OK);
    wa_test_platform_destroy(platform);
}

int main(void)
{
    WA_RUN_TEST(test_specification_vectors);
    WA_RUN_TEST(test_accepted_types);
    WA_RUN_TEST(test_unsupported_classes);
    WA_RUN_TEST(test_invalid_classes);
    WA_RUN_TEST(test_out_of_memory_sweep);
    WA_RUN_TEST(test_invalid_arguments);
    return wa_test_finish();
}
