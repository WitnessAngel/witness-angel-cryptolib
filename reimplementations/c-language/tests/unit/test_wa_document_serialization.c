/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Unit tests of wa_document_serialization.c (task 3.6), run in each build: both formats, CBOR only, JSON only. */

#include <string.h>

#include "encoding/wa_document_serialization.h"
#include "encoding/wa_value_tree_internal.h"
#include "wa_minimal_test_harness.h"
#include "wa_test_support.h"

/* {"b": b"\x01", "a": 1} */
static wa_value_t *build_sample_tree(const wa_platform_hooks_t *hooks)
{
    wa_value_t *map = NULL;
    wa_value_t *value = NULL;
    if (wa_value_create_map(hooks, &map) != WA_STATUS_OK ||
        wa_value_create_bytes(hooks, (const uint8_t *)"\x01", 1, &value) != WA_STATUS_OK ||
        wa_value_map_add_consuming(map, "b", value) != WA_STATUS_OK ||
        wa_value_create_integer(hooks, 1, &value) != WA_STATUS_OK ||
        wa_value_map_add_consuming(map, "a", value) != WA_STATUS_OK) {
        wa_value_destroy(map);
        return NULL;
    }
    return map;
}

#define WA_SAMPLE_EXTENDED_JSON "{\"a\": 1, \"b\": {\"$binary\": {\"base64\": \"AQ==\", \"subType\": \"00\"}}}"
#define WA_SAMPLE_WACBOR_HEX "a2616101616241" "01"

static void test_format_resolution(void)
{
    wa_document_format_t resolved = WA_DOCUMENT_FORMAT_BUILD_DEFAULT;
    WA_CHECK_STATUS(wa_document_format_resolve(WA_DOCUMENT_FORMAT_BUILD_DEFAULT, &resolved), WA_STATUS_OK);
#if WA_DOCUMENT_FORMAT_JSON_ENABLED
    WA_CHECK(resolved == WA_DOCUMENT_FORMAT_JSON); /* Extended JSON by default when enabled */
    WA_CHECK_STATUS(wa_document_format_resolve(WA_DOCUMENT_FORMAT_JSON, &resolved), WA_STATUS_OK);
    WA_CHECK(resolved == WA_DOCUMENT_FORMAT_JSON);
    WA_CHECK(wa_document_format_is_enabled(WA_DOCUMENT_FORMAT_JSON));
    WA_CHECK(strcmp(wa_document_format_get_cryptainer_suffix(WA_DOCUMENT_FORMAT_JSON), ".crypt.json") == 0);
#else
    WA_CHECK(resolved == WA_DOCUMENT_FORMAT_CBOR);
    WA_CHECK_STATUS(wa_document_format_resolve(WA_DOCUMENT_FORMAT_JSON, &resolved), WA_STATUS_UNSUPPORTED_FEATURE);
    WA_CHECK(!wa_document_format_is_enabled(WA_DOCUMENT_FORMAT_JSON));
    WA_CHECK(wa_document_format_get_cryptainer_suffix(WA_DOCUMENT_FORMAT_JSON) == NULL);
#endif
#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
    WA_CHECK_STATUS(wa_document_format_resolve(WA_DOCUMENT_FORMAT_CBOR, &resolved), WA_STATUS_OK);
    WA_CHECK(resolved == WA_DOCUMENT_FORMAT_CBOR);
    WA_CHECK(wa_document_format_is_enabled(WA_DOCUMENT_FORMAT_CBOR));
    WA_CHECK(strcmp(wa_document_format_get_cryptainer_suffix(WA_DOCUMENT_FORMAT_CBOR), ".crypt.cbor") == 0);
#else
    WA_CHECK_STATUS(wa_document_format_resolve(WA_DOCUMENT_FORMAT_CBOR, &resolved), WA_STATUS_UNSUPPORTED_FEATURE);
    WA_CHECK(!wa_document_format_is_enabled(WA_DOCUMENT_FORMAT_CBOR));
    WA_CHECK(wa_document_format_get_cryptainer_suffix(WA_DOCUMENT_FORMAT_CBOR) == NULL);
#endif
    WA_CHECK_STATUS(wa_document_format_resolve((wa_document_format_t)77, &resolved), WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK(!wa_document_format_is_enabled((wa_document_format_t)77));
    WA_CHECK(wa_document_format_is_enabled(WA_DOCUMENT_FORMAT_BUILD_DEFAULT)); /* Resolved first */
    WA_CHECK(wa_document_format_get_cryptainer_suffix((wa_document_format_t)77) == NULL);
    WA_CHECK(wa_document_format_get_cryptainer_suffix(WA_DOCUMENT_FORMAT_BUILD_DEFAULT) != NULL);
}

static void check_serialization(wa_document_format_t format, const wa_value_t *tree, const char *expected_json,
                                const char *expected_cbor_hex)
{
    wa_test_platform_t *platform = wa_test_platform_create(2);
    wa_growable_byte_buffer_t buffer;
    wa_test_memory_sink_t memory_sink;
    wa_growable_byte_buffer_initialize(&buffer, &platform->hooks, 0);
    wa_test_memory_sink_initialize(&memory_sink);
    WA_CHECK_STATUS(wa_document_serialize_to_buffer(tree, format, &buffer), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_document_serialize_to_sink(tree, format, &memory_sink.sink), WA_STATUS_OK);
    if (format == WA_DOCUMENT_FORMAT_JSON) {
        WA_CHECK_TEXT(buffer.data, buffer.length, expected_json);
    } else {
        WA_CHECK_HEX(buffer.data, buffer.length, expected_cbor_hex);
    }
    WA_CHECK_BYTES(memory_sink.bytes, memory_sink.length, buffer.data, buffer.length);
    wa_growable_byte_buffer_release(&buffer);
    wa_test_memory_sink_release(&memory_sink);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_serialization_dispatch(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(1);
    wa_value_t *tree = build_sample_tree(&platform->hooks);
    wa_test_memory_sink_t memory_sink;
    WA_REQUIRE(tree != NULL);
#if WA_DOCUMENT_FORMAT_JSON_ENABLED
    check_serialization(WA_DOCUMENT_FORMAT_JSON, tree, WA_SAMPLE_EXTENDED_JSON, NULL);
#endif
#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
    check_serialization(WA_DOCUMENT_FORMAT_CBOR, tree, NULL, WA_SAMPLE_WACBOR_HEX);
#endif
    /* Unresolved or disabled formats are refused, and nothing is written */
    wa_test_memory_sink_initialize(&memory_sink);
    WA_CHECK(wa_document_serialize_to_sink(tree, WA_DOCUMENT_FORMAT_BUILD_DEFAULT, &memory_sink.sink) !=
             WA_STATUS_OK);
#if !WA_DOCUMENT_FORMAT_JSON_ENABLED
    WA_CHECK_STATUS(wa_document_serialize_to_sink(tree, WA_DOCUMENT_FORMAT_JSON, &memory_sink.sink),
                    WA_STATUS_UNSUPPORTED_FEATURE);
#endif
#if !WA_DOCUMENT_FORMAT_CBOR_ENABLED
    WA_CHECK_STATUS(wa_document_serialize_to_sink(tree, WA_DOCUMENT_FORMAT_CBOR, &memory_sink.sink),
                    WA_STATUS_UNSUPPORTED_FEATURE);
#endif
    WA_CHECK_SIZE(memory_sink.length, 0);
    wa_test_memory_sink_release(&memory_sink);
    wa_value_destroy(tree);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

int main(void)
{
    WA_RUN_TEST(test_format_resolution);
    WA_RUN_TEST(test_serialization_dispatch);
    return wa_test_finish();
}
