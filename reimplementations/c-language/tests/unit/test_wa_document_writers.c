/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Unit tests of the base64 encoder (task 3.3), the Extended JSON writer (task 3.4) and the WA-CBOR deterministic
 * writer (task 3.5). Expected outputs come from wacryptolib (wa_writer_expected_outputs.h) and from section 10 of
 * the WA-CBOR specification (wa_wacbor_specification_vectors.h); see the generators next to this file. */

#include <stdlib.h>
#include <string.h>

#include "encoding/wa_buffered_sink_writer.h"
#include "encoding/wa_value_tree_internal.h"
#include "wa_flightbox/wa_flightbox_config.h"
#include "wa_minimal_test_harness.h"
#include "wa_test_support.h"
#include "wa_wacbor_specification_vectors.h"
#include "wa_writer_expected_outputs.h"

#if WA_DOCUMENT_FORMAT_JSON_ENABLED
#include "encoding/wa_base64_encoder.h"
#include "encoding/wa_extended_json_writer.h"
#endif
#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
#include "encoding/wa_wacbor_deterministic_writer.h"
#endif

/* Decodes a hex CBOR document into a tree (NULL on failure, reported as a check failure) */
static wa_value_t *decode_hex_document(const wa_platform_hooks_t *hooks, const char *cbor_hex)
{
    size_t cbor_length = 0;
    uint8_t *cbor = wa_test_decode_hex(cbor_hex, &cbor_length);
    wa_value_t *tree = NULL;
    WA_CHECK(cbor != NULL);
    if (cbor != NULL) {
        WA_CHECK_STATUS(wa_value_tree_decode_from_cbor(cbor, cbor_length, hooks, &tree), WA_STATUS_OK);
    }
    free(cbor);
    return tree;
}

#if WA_DOCUMENT_FORMAT_JSON_ENABLED

static void encode_base64_in_chunks(const uint8_t *bytes, size_t length, size_t chunk_size,
                                    wa_test_memory_sink_t *memory_sink)
{
    wa_buffered_sink_writer_t writer;
    wa_base64_encoder_t encoder;
    size_t offset = 0;
    wa_buffered_sink_writer_initialize(&writer, &memory_sink->sink);
    wa_base64_encoder_initialize(&encoder, &writer);
    while (offset < length) {
        size_t piece = length - offset < chunk_size ? length - offset : chunk_size;
        wa_base64_encoder_update(&encoder, bytes + offset, piece);
        offset += piece;
    }
    wa_base64_encoder_finish(&encoder);
    WA_CHECK_STATUS(wa_buffered_sink_writer_finish(&writer), WA_STATUS_OK);
}

static void test_base64_rfc4648_vectors(void)
{
    static const char *const inputs[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
    static const char *const outputs[] = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};
    size_t index;
    for (index = 0; index < sizeof(inputs) / sizeof(inputs[0]); index++) {
        wa_test_memory_sink_t memory_sink;
        wa_test_memory_sink_initialize(&memory_sink);
        encode_base64_in_chunks((const uint8_t *)inputs[index], strlen(inputs[index]), 100, &memory_sink);
        WA_CHECK_TEXT(memory_sink.bytes, memory_sink.length, outputs[index]);
        wa_test_memory_sink_release(&memory_sink);
    }
}

static void test_base64_chunked_streaming_equivalence(void)
{
    uint8_t bytes[1000];
    wa_test_memory_sink_t reference;
    size_t index;
    size_t chunk_size;
    for (index = 0; index < sizeof(bytes); index++) {
        bytes[index] = (uint8_t)(index * 7 + 3);
    }
    wa_test_memory_sink_initialize(&reference);
    encode_base64_in_chunks(bytes, sizeof(bytes), sizeof(bytes), &reference);
    WA_CHECK_SIZE(reference.length, 4 * ((sizeof(bytes) + 2) / 3));
    for (chunk_size = 1; chunk_size <= 7; chunk_size++) {
        wa_test_memory_sink_t chunked;
        wa_test_memory_sink_initialize(&chunked);
        encode_base64_in_chunks(bytes, sizeof(bytes), chunk_size, &chunked);
        WA_CHECK_BYTES(chunked.bytes, chunked.length, reference.bytes, reference.length);
        wa_test_memory_sink_release(&chunked);
    }
    wa_test_memory_sink_release(&reference);
}

static void check_extended_json_output(const wa_value_t *tree, const char *expected_json)
{
    wa_test_memory_sink_t memory_sink;
    wa_test_memory_sink_initialize(&memory_sink);
    WA_CHECK_STATUS(wa_extended_json_writer_write_document(tree, &memory_sink.sink), WA_STATUS_OK);
    WA_CHECK_TEXT(memory_sink.bytes, memory_sink.length, expected_json);
    wa_test_memory_sink_release(&memory_sink);
}

#endif /* WA_DOCUMENT_FORMAT_JSON_ENABLED */

#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
static void check_wacbor_output(const wa_value_t *tree, const char *expected_hex)
{
    wa_test_memory_sink_t memory_sink;
    wa_test_memory_sink_initialize(&memory_sink);
    WA_CHECK_STATUS(wa_wacbor_deterministic_writer_write_document(tree, &memory_sink.sink), WA_STATUS_OK);
    WA_CHECK_HEX(memory_sink.bytes, memory_sink.length, expected_hex);
    wa_test_memory_sink_release(&memory_sink);
}
#endif

static void test_wacryptolib_samples(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(1);
    size_t index;
    for (index = 0; index < sizeof(wa_writer_expected_outputs) / sizeof(wa_writer_expected_outputs[0]); index++) {
        const wa_writer_expected_output_t *sample = &wa_writer_expected_outputs[index];
        wa_value_t *tree = decode_hex_document(&platform->hooks, sample->unsorted_input_cbor_hex);
        if (tree == NULL) {
            continue;
        }
#if WA_DOCUMENT_FORMAT_JSON_ENABLED
        check_extended_json_output(tree, sample->expected_extended_json);
#endif
#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
        check_wacbor_output(tree, sample->expected_wacbor_hex);
#endif
        wa_value_destroy(tree);
    }
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_manually_built_non_ascii_text(void)
{
    /* Built without the decoder: {"text": "Café ☕", "smile": "😀"} */
    wa_test_platform_t *platform = wa_test_platform_create(2);
    wa_value_t *map = NULL;
    wa_value_t *text = NULL;
    WA_REQUIRE_STATUS(wa_value_create_map(&platform->hooks, &map), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_text(&platform->hooks, "Caf\xc3\xa9 \xe2\x98\x95", 9, &text), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_map_add_consuming(map, "text", text), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_text(&platform->hooks, "\xf0\x9f\x98\x80", 4, &text), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_map_add_consuming(map, "smile", text), WA_STATUS_OK);
#if WA_DOCUMENT_FORMAT_JSON_ENABLED
    check_extended_json_output(map, "{\"smile\": \"\\ud83d\\ude00\", \"text\": \"Caf\\u00e9 \\u2615\"}");
#endif
#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
    /* Keys by length first: "text" (4) before "smile" (5) */
    check_wacbor_output(map, "a2" "6474657874" "69436166c3a920e29895" "65736d696c65" "64f09f9880");
#endif
    wa_value_destroy(map);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_specification_vectors_rewritten(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(3);
    size_t index;
    size_t checked_count = 0;
    for (index = 0; index < sizeof(wa_wacbor_specification_vectors) / sizeof(wa_wacbor_specification_vectors[0]);
         index++) {
        const wa_wacbor_specification_vector_t *vector = &wa_wacbor_specification_vectors[index];
        wa_value_t *tree;
        if (vector->expectation != WA_EXPECT_ACCEPTED) {
            continue;
        }
        tree = decode_hex_document(&platform->hooks, vector->cbor_hex);
        if (tree == NULL) {
            continue;
        }
#if WA_DOCUMENT_FORMAT_JSON_ENABLED
        check_extended_json_output(tree, vector->extjson);
#endif
#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
        if (vector->is_deterministic) {
            check_wacbor_output(tree, vector->cbor_hex);
        }
#endif
        checked_count++;
        wa_value_destroy(tree);
    }
    WA_CHECK(checked_count >= 9);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

/* A large document reaches the sink in several writes, and a failing sink fails the writers */
static void test_streaming_and_sink_failures(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(4);
    wa_value_t *map = NULL;
    wa_value_t *bytes = NULL;
    uint8_t payload[5000];
    wa_test_memory_sink_t memory_sink;
    memset(payload, 0x42, sizeof(payload));
    WA_REQUIRE_STATUS(wa_value_create_map(&platform->hooks, &map), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_bytes(&platform->hooks, payload, sizeof(payload), &bytes), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_map_add_consuming(map, "ciphertext", bytes), WA_STATUS_OK);

#if WA_DOCUMENT_FORMAT_JSON_ENABLED
    wa_test_memory_sink_initialize(&memory_sink);
    WA_CHECK_STATUS(wa_extended_json_writer_write_document(map, &memory_sink.sink), WA_STATUS_OK);
    WA_CHECK(memory_sink.write_call_count > 1);
    WA_CHECK(memory_sink.length > 4 * sizeof(payload) / 3);
    wa_test_memory_sink_release(&memory_sink);
    wa_test_memory_sink_initialize(&memory_sink);
    memory_sink.fail_after_byte_count = 1000;
    WA_CHECK_STATUS(wa_extended_json_writer_write_document(map, &memory_sink.sink), WA_STATUS_SINK_WRITE_FAILURE);
    wa_test_memory_sink_release(&memory_sink);
    wa_test_memory_sink_initialize(&memory_sink);
    memory_sink.fail_after_byte_count = 0;
    memory_sink.failure_status = WA_STATUS_OUT_OF_MEMORY; /* Kept as is */
    WA_CHECK_STATUS(wa_extended_json_writer_write_document(map, &memory_sink.sink), WA_STATUS_OUT_OF_MEMORY);
    wa_test_memory_sink_release(&memory_sink);
#endif
#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
    wa_test_memory_sink_initialize(&memory_sink);
    WA_CHECK_STATUS(wa_wacbor_deterministic_writer_write_document(map, &memory_sink.sink), WA_STATUS_OK);
    WA_CHECK_SIZE(memory_sink.length, 1 + 11 + 3 + sizeof(payload));
    wa_test_memory_sink_release(&memory_sink);
    wa_test_memory_sink_initialize(&memory_sink);
    memory_sink.fail_after_byte_count = 10;
    WA_CHECK_STATUS(wa_wacbor_deterministic_writer_write_document(map, &memory_sink.sink),
                    WA_STATUS_SINK_WRITE_FAILURE);
    wa_test_memory_sink_release(&memory_sink);
#endif
    wa_value_destroy(map);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

int main(void)
{
#if WA_DOCUMENT_FORMAT_JSON_ENABLED
    WA_RUN_TEST(test_base64_rfc4648_vectors);
    WA_RUN_TEST(test_base64_chunked_streaming_equivalence);
#endif
    WA_RUN_TEST(test_wacryptolib_samples);
    WA_RUN_TEST(test_manually_built_non_ascii_text);
    WA_RUN_TEST(test_specification_vectors_rewritten);
    WA_RUN_TEST(test_streaming_and_sink_failures);
    return wa_test_finish();
}
