/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Checks follow the order of wacryptolib's WA-CBOR decoder (src/wacryptolib/utilities/wacbor.py, _Decoder), so that
 * every input accepted here loads there to the same tree. */

#include "encoding/wa_wacbor_subprofile_decoder.h"

#include <string.h>

#include "core/wa_platform_hooks_calls.h"
#include "encoding/wa_document_tree_constraints.h"
#include "encoding/wa_utf8_validation.h"
#include "encoding/wa_value_tree_internal.h"
#include "wa_flightbox/wa_flightbox_config.h"

#define WA_CBOR_MAJOR_UNSIGNED 0u
#define WA_CBOR_MAJOR_NEGATIVE 1u
#define WA_CBOR_MAJOR_BYTES 2u
#define WA_CBOR_MAJOR_TEXT 3u
#define WA_CBOR_MAJOR_ARRAY 4u
#define WA_CBOR_MAJOR_MAP 5u
#define WA_CBOR_MAJOR_TAG 6u
#define WA_CBOR_MAJOR_SIMPLE 7u
#define WA_CBOR_BREAK_BYTE 0xFFu
#define WA_CBOR_INDEFINITE_LENGTH 31u

#define WA_CBOR_DATETIME_TEXT_TAG 0u
#define WA_CBOR_POSITIVE_BIGNUM_TAG 2u
#define WA_CBOR_NEGATIVE_BIGNUM_TAG 3u
#define WA_CBOR_DECIMAL_FRACTION_TAG 4u
#define WA_CBOR_UUID_TAG 37u
#define WA_CBOR_SELF_DESCRIBED_TAG 55799u

#define WA_INT64_MAXIMUM_AS_UINT64 0x7FFFFFFFFFFFFFFFull

typedef struct wa_cbor_decoder {
    const uint8_t *data;
    size_t length;
    size_t position;
    const wa_platform_hooks_t *platform_hooks;
} wa_cbor_decoder_t;

typedef struct wa_cbor_head {
    unsigned int major_type;
    unsigned int additional_information;
    uint64_t argument;  /* meaningless for indefinite lengths */
} wa_cbor_head_t;

static size_t wa_cbor_get_remaining_length(const wa_cbor_decoder_t *decoder)
{
    return decoder->length - decoder->position;
}

static wa_status_t wa_cbor_read_head(wa_cbor_decoder_t *decoder, wa_cbor_head_t *head)
{
    uint8_t initial;
    size_t argument_size;
    size_t index;
    if (decoder->position >= decoder->length) {
        return WA_STATUS_DECODING_ERROR; /* Truncated */
    }
    initial = decoder->data[decoder->position++];
    head->major_type = initial >> 5;
    head->additional_information = initial & 0x1Fu;
    head->argument = 0;
    if (head->additional_information < 24u) {
        head->argument = head->additional_information;
    } else if (head->additional_information <= 27u) {
        argument_size = (size_t)1 << (head->additional_information - 24u);
        if (wa_cbor_get_remaining_length(decoder) < argument_size) {
            return WA_STATUS_DECODING_ERROR;
        }
        for (index = 0; index < argument_size; index++) {
            head->argument = (head->argument << 8) | decoder->data[decoder->position++];
        }
    } else if (head->additional_information != WA_CBOR_INDEFINITE_LENGTH) {
        return WA_STATUS_DECODING_ERROR; /* Reserved additional information 28..30 */
    }
    return WA_STATUS_OK;
}

static wa_status_t wa_cbor_peek_head(const wa_cbor_decoder_t *decoder, wa_cbor_head_t *head)
{
    wa_cbor_decoder_t probe = *decoder;
    return wa_cbor_read_head(&probe, head);
}

/* Definite-length byte or text string content, bounds-checked */
static wa_status_t wa_cbor_read_string_content(wa_cbor_decoder_t *decoder, const wa_cbor_head_t *head,
                                               const uint8_t **content_out, size_t *content_length_out)
{
    if (head->additional_information == WA_CBOR_INDEFINITE_LENGTH) {
        return WA_STATUS_UNSUPPORTED_TYPE;
    }
    if (head->argument > (uint64_t)wa_cbor_get_remaining_length(decoder)) {
        return WA_STATUS_DECODING_ERROR;
    }
    *content_out = decoder->data + decoder->position;
    *content_length_out = (size_t)head->argument;
    decoder->position += (size_t)head->argument;
    if (head->major_type == WA_CBOR_MAJOR_TEXT && !wa_utf8_is_valid(*content_out, *content_length_out)) {
        return WA_STATUS_DECODING_ERROR;
    }
    return WA_STATUS_OK;
}

static wa_status_t wa_cbor_decode_item(wa_cbor_decoder_t *decoder, size_t depth, wa_value_t **value_out);

static wa_status_t wa_cbor_decode_array(wa_cbor_decoder_t *decoder, const wa_cbor_head_t *head, size_t depth,
                                        wa_value_t **value_out)
{
    wa_value_t *array = NULL;
    uint64_t index;
    if (head->additional_information == WA_CBOR_INDEFINITE_LENGTH) {
        return WA_STATUS_UNSUPPORTED_TYPE;
    }
    if (depth > WA_MAX_CBOR_NESTING_DEPTH) {
        return WA_STATUS_NESTING_TOO_DEEP;
    }
    if (head->argument > (uint64_t)wa_cbor_get_remaining_length(decoder)) {
        return WA_STATUS_DECODING_ERROR; /* Each item takes at least one byte */
    }
    WA_RETURN_IF_ERROR(wa_value_create_array(decoder->platform_hooks, &array));
    for (index = 0; index < head->argument; index++) {
        wa_value_t *item = NULL;
        wa_status_t status = wa_cbor_decode_item(decoder, depth, &item);
        if (status == WA_STATUS_OK) {
            status = wa_value_array_append(array, item);
            if (status != WA_STATUS_OK) {
                wa_value_destroy(item);
                status = WA_STATUS_OUT_OF_MEMORY;
            }
        }
        if (status != WA_STATUS_OK) {
            wa_value_destroy(array);
            return status;
        }
    }
    *value_out = array;
    return WA_STATUS_OK;
}

static wa_status_t wa_cbor_decode_map_entry(wa_cbor_decoder_t *decoder, wa_value_t *map, size_t depth)
{
    wa_cbor_head_t key_head;
    const uint8_t *key;
    size_t key_length;
    wa_value_t *value = NULL;
    wa_status_t status;

    WA_RETURN_IF_ERROR(wa_cbor_peek_head(decoder, &key_head));
    if (key_head.major_type != WA_CBOR_MAJOR_TEXT) {
        return WA_STATUS_DECODING_ERROR; /* Map key is not a text string */
    }
    WA_RETURN_IF_ERROR(wa_cbor_read_head(decoder, &key_head));
    WA_RETURN_IF_ERROR(wa_cbor_read_string_content(decoder, &key_head, &key, &key_length));
    if (wa_value_map_has_key(map, (const char *)key, key_length)) {
        return WA_STATUS_DECODING_ERROR; /* Duplicate map key */
    }
    WA_RETURN_IF_ERROR(wa_cbor_decode_item(decoder, depth, &value));
    /* The key is valid UTF-8 (read_string_content checked it) and new */
    status = wa_value_map_add_with_valid_key(map, (const char *)key, key_length, value);
    if (status != WA_STATUS_OK) {
        wa_value_destroy(value);
        return WA_STATUS_OUT_OF_MEMORY; /* Keys were checked already, only allocation can fail */
    }
    return WA_STATUS_OK;
}

static wa_status_t wa_cbor_decode_map(wa_cbor_decoder_t *decoder, const wa_cbor_head_t *head, size_t depth,
                                      wa_value_t **value_out)
{
    wa_value_t *map = NULL;
    uint64_t index;
    if (head->additional_information == WA_CBOR_INDEFINITE_LENGTH) {
        return WA_STATUS_UNSUPPORTED_TYPE;
    }
    if (depth > WA_MAX_CBOR_NESTING_DEPTH) {
        return WA_STATUS_NESTING_TOO_DEEP;
    }
    if (head->argument > (uint64_t)(wa_cbor_get_remaining_length(decoder) / 2u)) {
        return WA_STATUS_DECODING_ERROR; /* Each entry takes at least two bytes */
    }
    WA_RETURN_IF_ERROR(wa_value_create_map(decoder->platform_hooks, &map));
    for (index = 0; index < head->argument; index++) {
        wa_status_t status = wa_cbor_decode_map_entry(decoder, map, depth);
        if (status != WA_STATUS_OK) {
            wa_value_destroy(map);
            return status;
        }
    }
    if (map->content.map.count == 1 &&
        wa_document_tree_is_extended_json_keyword(map->content.map.entries[0].key,
                                                  map->content.map.entries[0].key_length)) {
        wa_value_destroy(map);
        return WA_STATUS_DECODING_ERROR; /* Extended JSON keyword map */
    }
    *value_out = map;
    return WA_STATUS_OK;
}

static wa_status_t wa_cbor_decode_tagged_item(wa_cbor_decoder_t *decoder, const wa_cbor_head_t *head,
                                              wa_value_t **value_out)
{
    wa_cbor_head_t content_head;
    const uint8_t *content;
    size_t content_length;

    switch (head->argument) {
    case WA_CBOR_DATETIME_TEXT_TAG:
    case WA_CBOR_POSITIVE_BIGNUM_TAG:
    case WA_CBOR_NEGATIVE_BIGNUM_TAG:
    case WA_CBOR_DECIMAL_FRACTION_TAG:
        return WA_STATUS_UNSUPPORTED_TYPE; /* Valid WA-CBOR tags, outside the sub-profile */
    case WA_CBOR_UUID_TAG:
        WA_RETURN_IF_ERROR(wa_cbor_peek_head(decoder, &content_head));
        if (content_head.major_type != WA_CBOR_MAJOR_BYTES) {
            return WA_STATUS_DECODING_ERROR;
        }
        WA_RETURN_IF_ERROR(wa_cbor_read_head(decoder, &content_head));
        WA_RETURN_IF_ERROR(wa_cbor_read_string_content(decoder, &content_head, &content, &content_length));
        if (content_length != WA_UUID_SIZE) {
            return WA_STATUS_DECODING_ERROR;
        }
        return wa_value_create_uuid(decoder->platform_hooks, content, value_out);
    default:
        return WA_STATUS_DECODING_ERROR; /* Any other tag, 55799 included when not around the top-level item */
    }
}

static wa_status_t wa_cbor_decode_simple_value(const wa_cbor_decoder_t *decoder, const wa_cbor_head_t *head,
                                               wa_value_t **value_out)
{
    switch (head->additional_information) {
    case 20u:
        return wa_value_create_boolean(decoder->platform_hooks, 0, value_out);
    case 21u:
        return wa_value_create_boolean(decoder->platform_hooks, 1, value_out);
    case 22u:
        return wa_value_create_null(decoder->platform_hooks, value_out);
    case 25u:
    case 26u:
    case 27u:
        return WA_STATUS_UNSUPPORTED_TYPE; /* Floats */
    default:
        return WA_STATUS_DECODING_ERROR; /* Other simple values */
    }
}

static wa_status_t wa_cbor_decode_item(wa_cbor_decoder_t *decoder, size_t depth, wa_value_t **value_out)
{
    wa_cbor_head_t head;
    const uint8_t *content;
    size_t content_length;

    *value_out = NULL;
    if (decoder->position >= decoder->length) {
        return WA_STATUS_DECODING_ERROR; /* Truncated */
    }
    if (decoder->data[decoder->position] == WA_CBOR_BREAK_BYTE) {
        return WA_STATUS_DECODING_ERROR; /* Unexpected break code */
    }
    WA_RETURN_IF_ERROR(wa_cbor_read_head(decoder, &head));
    if ((head.major_type == WA_CBOR_MAJOR_UNSIGNED || head.major_type == WA_CBOR_MAJOR_NEGATIVE ||
         head.major_type == WA_CBOR_MAJOR_TAG) &&
        head.additional_information == WA_CBOR_INDEFINITE_LENGTH) {
        return WA_STATUS_DECODING_ERROR;
    }

    switch (head.major_type) {
    case WA_CBOR_MAJOR_UNSIGNED:
        if (head.argument > WA_INT64_MAXIMUM_AS_UINT64) {
            return WA_STATUS_UNSUPPORTED_TYPE;
        }
        return wa_value_create_integer(decoder->platform_hooks, (int64_t)head.argument, value_out);
    case WA_CBOR_MAJOR_NEGATIVE:
        if (head.argument > WA_INT64_MAXIMUM_AS_UINT64) {
            return WA_STATUS_UNSUPPORTED_TYPE;
        }
        return wa_value_create_integer(decoder->platform_hooks, -1 - (int64_t)head.argument, value_out);
    case WA_CBOR_MAJOR_BYTES:
        WA_RETURN_IF_ERROR(wa_cbor_read_string_content(decoder, &head, &content, &content_length));
        return wa_value_create_bytes(decoder->platform_hooks, content, content_length, value_out);
    case WA_CBOR_MAJOR_TEXT:
        WA_RETURN_IF_ERROR(wa_cbor_read_string_content(decoder, &head, &content, &content_length));
        /* Valid UTF-8, checked by read_string_content */
        return wa_value_create_text_with_valid_utf8(decoder->platform_hooks, (const char *)content, content_length,
                                                    value_out);
    case WA_CBOR_MAJOR_ARRAY:
        return wa_cbor_decode_array(decoder, &head, depth + 1, value_out);
    case WA_CBOR_MAJOR_MAP:
        return wa_cbor_decode_map(decoder, &head, depth + 1, value_out);
    case WA_CBOR_MAJOR_TAG:
        return wa_cbor_decode_tagged_item(decoder, &head, value_out);
    default:
        return wa_cbor_decode_simple_value(decoder, &head, value_out);
    }
}

wa_status_t wa_wacbor_subprofile_decode_document(const uint8_t *cbor, size_t cbor_length,
                                                 const wa_platform_hooks_t *platform_hooks, wa_value_t **value_out)
{
    wa_cbor_decoder_t decoder;
    wa_cbor_head_t head;
    wa_value_t *document = NULL;

    if (value_out == NULL) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    *value_out = NULL;
    if ((cbor == NULL && cbor_length != 0) || !wa_platform_hooks_are_usable(platform_hooks)) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    decoder.data = cbor;
    decoder.length = cbor_length;
    decoder.position = 0;
    decoder.platform_hooks = platform_hooks;

    WA_RETURN_IF_ERROR(wa_cbor_peek_head(&decoder, &head));
    if (head.major_type == WA_CBOR_MAJOR_TAG && head.additional_information != WA_CBOR_INDEFINITE_LENGTH &&
        head.argument == WA_CBOR_SELF_DESCRIBED_TAG) {
        return WA_STATUS_UNSUPPORTED_TYPE; /* Valid around the top-level item, outside the sub-profile */
    }
    if (head.major_type != WA_CBOR_MAJOR_ARRAY && head.major_type != WA_CBOR_MAJOR_MAP) {
        return WA_STATUS_DECODING_ERROR; /* Top-level item is not a map nor an array */
    }
    WA_RETURN_IF_ERROR(wa_cbor_decode_item(&decoder, 0, &document));
    if (decoder.position != decoder.length) {
        wa_value_destroy(document);
        return WA_STATUS_DECODING_ERROR; /* Bytes after the top-level item */
    }
    *value_out = document;
    return WA_STATUS_OK;
}

wa_status_t wa_value_tree_decode_from_cbor(const uint8_t *cbor, size_t cbor_length,
                                           const wa_platform_hooks_t *platform_hooks, wa_value_t **value_out)
{
    return wa_wacbor_subprofile_decode_document(cbor, cbor_length, platform_hooks, value_out);
}
