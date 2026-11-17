/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wa_test_document_reader.h"

#include <stdlib.h>
#include <string.h>

#define WA_TEST_JSON_MAXIMUM_DEPTH 128

typedef struct wa_test_json_parser {
    const wa_platform_hooks_t *platform_hooks;
    const uint8_t *json;
    size_t length;
    size_t offset;
} wa_test_json_parser_t;

static wa_status_t wa_test_parse_json_value(wa_test_json_parser_t *parser, size_t depth, wa_value_t **value_out);

static void wa_test_skip_json_whitespace(wa_test_json_parser_t *parser)
{
    while (parser->offset < parser->length &&
           (parser->json[parser->offset] == ' ' || parser->json[parser->offset] == '\n' ||
            parser->json[parser->offset] == '\r' || parser->json[parser->offset] == '\t')) {
        ++parser->offset;
    }
}

static int wa_test_consume_json_literal(wa_test_json_parser_t *parser, const char *literal)
{
    size_t literal_length = strlen(literal);
    if (parser->length - parser->offset < literal_length ||
        memcmp(parser->json + parser->offset, literal, literal_length) != 0) {
        return 0;
    }
    parser->offset += literal_length;
    return 1;
}

static int wa_test_get_hex_digit_value(uint8_t character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return -1;
}

static int wa_test_parse_four_hex_digits(wa_test_json_parser_t *parser, uint32_t *code_unit_out)
{
    size_t index;
    *code_unit_out = 0;
    if (parser->length - parser->offset < 4) {
        return 0;
    }
    for (index = 0; index < 4; ++index) {
        int digit = wa_test_get_hex_digit_value(parser->json[parser->offset + index]);
        if (digit < 0) {
            return 0;
        }
        *code_unit_out = (*code_unit_out << 4) | (uint32_t)digit;
    }
    parser->offset += 4;
    return 1;
}

static size_t wa_test_encode_utf8(uint32_t code_point, char *output)
{
    if (code_point < 0x80u) {
        output[0] = (char)code_point;
        return 1;
    }
    if (code_point < 0x800u) {
        output[0] = (char)(0xC0u | (code_point >> 6));
        output[1] = (char)(0x80u | (code_point & 0x3Fu));
        return 2;
    }
    if (code_point < 0x10000u) {
        output[0] = (char)(0xE0u | (code_point >> 12));
        output[1] = (char)(0x80u | ((code_point >> 6) & 0x3Fu));
        output[2] = (char)(0x80u | (code_point & 0x3Fu));
        return 3;
    }
    output[0] = (char)(0xF0u | (code_point >> 18));
    output[1] = (char)(0x80u | ((code_point >> 12) & 0x3Fu));
    output[2] = (char)(0x80u | ((code_point >> 6) & 0x3Fu));
    output[3] = (char)(0x80u | (code_point & 0x3Fu));
    return 4;
}

/* A JSON string into a malloc()'d UTF-8 buffer (escapes resolved) */
static wa_status_t wa_test_parse_json_string(wa_test_json_parser_t *parser, char **text_out, size_t *length_out)
{
    char *text;
    size_t text_length = 0;
    *text_out = NULL;
    if (parser->offset >= parser->length || parser->json[parser->offset] != '"') {
        return WA_STATUS_DECODING_ERROR;
    }
    ++parser->offset;
    text = (char *)malloc(parser->length - parser->offset + 1u); /* Escapes never expand */
    if (text == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    while (parser->offset < parser->length && parser->json[parser->offset] != '"') {
        uint8_t character = parser->json[parser->offset++];
        uint32_t code_point;
        if (character < 0x20u) {
            free(text);
            return WA_STATUS_DECODING_ERROR;
        }
        if (character != '\\') {
            text[text_length++] = (char)character;
            continue;
        }
        if (parser->offset >= parser->length) {
            break;
        }
        character = parser->json[parser->offset++];
        switch (character) {
        case '"': text[text_length++] = '"'; continue;
        case '\\': text[text_length++] = '\\'; continue;
        case '/': text[text_length++] = '/'; continue;
        case 'b': text[text_length++] = '\b'; continue;
        case 'f': text[text_length++] = '\f'; continue;
        case 'n': text[text_length++] = '\n'; continue;
        case 'r': text[text_length++] = '\r'; continue;
        case 't': text[text_length++] = '\t'; continue;
        case 'u': break;
        default: free(text); return WA_STATUS_DECODING_ERROR;
        }
        if (!wa_test_parse_four_hex_digits(parser, &code_point)) {
            free(text);
            return WA_STATUS_DECODING_ERROR;
        }
        if (code_point >= 0xD800u && code_point <= 0xDBFFu) {
            uint32_t low_surrogate;
            if (!wa_test_consume_json_literal(parser, "\\u") || !wa_test_parse_four_hex_digits(parser, &low_surrogate) ||
                low_surrogate < 0xDC00u || low_surrogate > 0xDFFFu) {
                free(text);
                return WA_STATUS_DECODING_ERROR;
            }
            code_point = 0x10000u + ((code_point - 0xD800u) << 10) + (low_surrogate - 0xDC00u);
        } else if (code_point >= 0xDC00u && code_point <= 0xDFFFu) {
            free(text);
            return WA_STATUS_DECODING_ERROR;
        }
        text_length += wa_test_encode_utf8(code_point, text + text_length);
    }
    if (parser->offset >= parser->length) {
        free(text);
        return WA_STATUS_DECODING_ERROR;
    }
    ++parser->offset; /* Closing quote */
    text[text_length] = '\0';
    *text_out = text;
    *length_out = text_length;
    return WA_STATUS_OK;
}

static int wa_test_get_base64_digit_value(char character)
{
    if (character >= 'A' && character <= 'Z') {
        return character - 'A';
    }
    if (character >= 'a' && character <= 'z') {
        return character - 'a' + 26;
    }
    if (character >= '0' && character <= '9') {
        return character - '0' + 52;
    }
    if (character == '+') {
        return 62;
    }
    if (character == '/') {
        return 63;
    }
    return -1;
}

/* Strict standard base64, padded */
static wa_status_t wa_test_decode_base64(const wa_platform_hooks_t *platform_hooks, const char *text, size_t length,
                                         wa_value_t **value_out)
{
    uint8_t *bytes;
    size_t byte_count = 0;
    size_t index;
    wa_status_t status;
    if (length % 4u != 0) {
        return WA_STATUS_DECODING_ERROR;
    }
    bytes = (uint8_t *)malloc(length / 4u * 3u + 1u);
    if (bytes == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    for (index = 0; index < length; index += 4) {
        int digits[4];
        size_t digit_index;
        size_t padding_count = 0;
        for (digit_index = 0; digit_index < 4; ++digit_index) {
            char character = text[index + digit_index];
            if (character == '=' && index + 4 == length && digit_index >= 2) {
                digits[digit_index] = 0;
                ++padding_count;
                continue;
            }
            digits[digit_index] = padding_count > 0 ? -1 : wa_test_get_base64_digit_value(character);
            if (digits[digit_index] < 0) {
                free(bytes);
                return WA_STATUS_DECODING_ERROR;
            }
        }
        bytes[byte_count++] = (uint8_t)((digits[0] << 2) | (digits[1] >> 4));
        if (padding_count < 2) {
            bytes[byte_count++] = (uint8_t)(((digits[1] & 0x0F) << 4) | (digits[2] >> 2));
        }
        if (padding_count < 1) {
            bytes[byte_count++] = (uint8_t)(((digits[2] & 0x03) << 6) | digits[3]);
        }
    }
    status = wa_value_create_bytes(platform_hooks, bytes, byte_count, value_out);
    free(bytes);
    return status;
}

/* {"$binary": {"base64": ..., "subType": "00"}} or {"$uuid": <32 lowercase hex>}, once parsed as plain maps */
static wa_status_t wa_test_convert_keyword_map(const wa_platform_hooks_t *platform_hooks, const wa_value_t *map,
                                               wa_value_t **value_out)
{
    const char *key;
    size_t key_length;
    const wa_value_t *inner;
    const char *text;
    size_t text_length;
    *value_out = NULL;
    if (wa_value_get_item_count(map) != 1 || wa_value_get_map_entry(map, 0, &key, &key_length, &inner) != 0) {
        return WA_STATUS_OK; /* Not a keyword map */
    }
    if (key_length == 7 && memcmp(key, "$binary", 7) == 0) {
        const wa_value_t *sub_type = wa_value_find_map_value(inner, "subType");
        if (wa_value_get_item_count(inner) != 2 || wa_value_get_text(sub_type, &text, &text_length) != 0 ||
            text_length != 2 || memcmp(text, "00", 2) != 0 ||
            wa_value_get_text(wa_value_find_map_value(inner, "base64"), &text, &text_length) != 0) {
            return WA_STATUS_DECODING_ERROR;
        }
        return wa_test_decode_base64(platform_hooks, text, text_length, value_out);
    }
    if (key_length == 5 && memcmp(key, "$uuid", 5) == 0) {
        uint8_t uuid[WA_UUID_SIZE];
        size_t index;
        if (wa_value_get_text(inner, &text, &text_length) != 0 || text_length != 2u * WA_UUID_SIZE) {
            return WA_STATUS_DECODING_ERROR;
        }
        for (index = 0; index < WA_UUID_SIZE; ++index) {
            int high = wa_test_get_hex_digit_value((uint8_t)text[2 * index]);
            int low = wa_test_get_hex_digit_value((uint8_t)text[2 * index + 1]);
            if (high < 0 || low < 0 || (text[2 * index] >= 'A' && text[2 * index] <= 'F') ||
                (text[2 * index + 1] >= 'A' && text[2 * index + 1] <= 'F')) {
                return WA_STATUS_DECODING_ERROR;
            }
            uuid[index] = (uint8_t)((high << 4) | low);
        }
        return wa_value_create_uuid(platform_hooks, uuid, value_out);
    }
    if (key_length > 0 && key[0] == '$') {
        return WA_STATUS_DECODING_ERROR; /* Other keywords are never written */
    }
    return WA_STATUS_OK;
}

static wa_status_t wa_test_parse_json_object(wa_test_json_parser_t *parser, size_t depth, wa_value_t **value_out)
{
    wa_value_t *map = NULL;
    wa_value_t *converted = NULL;
    wa_status_t status = wa_value_create_map(parser->platform_hooks, &map);
    int is_first = 1;
    ++parser->offset; /* '{' */
    while (status == WA_STATUS_OK) {
        char *key = NULL;
        size_t key_length = 0;
        wa_value_t *item = NULL;
        wa_test_skip_json_whitespace(parser);
        if (is_first && wa_test_consume_json_literal(parser, "}")) {
            break;
        }
        status = wa_test_parse_json_string(parser, &key, &key_length);
        if (status != WA_STATUS_OK) {
            break;
        }
        wa_test_skip_json_whitespace(parser);
        status = wa_test_consume_json_literal(parser, ":") ? wa_test_parse_json_value(parser, depth + 1, &item)
                                                          : WA_STATUS_DECODING_ERROR;
        if (status == WA_STATUS_OK) {
            status = wa_value_map_add(map, key, key_length, item);
            if (status != WA_STATUS_OK) {
                wa_value_destroy(item);
                status = WA_STATUS_DECODING_ERROR; /* Duplicate key */
            }
        }
        free(key);
        if (status != WA_STATUS_OK) {
            break;
        }
        is_first = 0;
        wa_test_skip_json_whitespace(parser);
        if (wa_test_consume_json_literal(parser, "}")) {
            break;
        }
        if (!wa_test_consume_json_literal(parser, ",")) {
            status = WA_STATUS_DECODING_ERROR;
        }
    }
    if (status == WA_STATUS_OK) {
        status = wa_test_convert_keyword_map(parser->platform_hooks, map, &converted);
    }
    if (status != WA_STATUS_OK || converted != NULL) {
        wa_value_destroy(map);
        map = converted;
    }
    *value_out = map;
    return status;
}

static wa_status_t wa_test_parse_json_array(wa_test_json_parser_t *parser, size_t depth, wa_value_t **value_out)
{
    wa_value_t *array = NULL;
    wa_status_t status = wa_value_create_array(parser->platform_hooks, &array);
    int is_first = 1;
    ++parser->offset; /* '[' */
    while (status == WA_STATUS_OK) {
        wa_value_t *item = NULL;
        wa_test_skip_json_whitespace(parser);
        if (is_first && wa_test_consume_json_literal(parser, "]")) {
            break;
        }
        status = wa_test_parse_json_value(parser, depth + 1, &item);
        if (status == WA_STATUS_OK) {
            status = wa_value_array_append(array, item);
            if (status != WA_STATUS_OK) {
                wa_value_destroy(item);
            }
        }
        if (status != WA_STATUS_OK) {
            break;
        }
        is_first = 0;
        wa_test_skip_json_whitespace(parser);
        if (wa_test_consume_json_literal(parser, "]")) {
            break;
        }
        if (!wa_test_consume_json_literal(parser, ",")) {
            status = WA_STATUS_DECODING_ERROR;
        }
    }
    if (status != WA_STATUS_OK) {
        wa_value_destroy(array);
        array = NULL;
    }
    *value_out = array;
    return status;
}

static wa_status_t wa_test_parse_json_integer(wa_test_json_parser_t *parser, wa_value_t **value_out)
{
    int is_negative = wa_test_consume_json_literal(parser, "-");
    uint64_t magnitude = 0;
    size_t digit_count = 0;
    while (parser->offset < parser->length && parser->json[parser->offset] >= '0' &&
           parser->json[parser->offset] <= '9') {
        uint64_t digit = (uint64_t)(parser->json[parser->offset] - '0');
        if (digit_count == 1 && magnitude == 0) {
            return WA_STATUS_DECODING_ERROR; /* Leading zero */
        }
        if (magnitude > (UINT64_MAX - digit) / 10u) {
            return WA_STATUS_DECODING_ERROR;
        }
        magnitude = magnitude * 10u + digit;
        ++digit_count;
        ++parser->offset;
    }
    if (digit_count == 0 || (parser->offset < parser->length &&
                             (parser->json[parser->offset] == '.' || parser->json[parser->offset] == 'e' ||
                              parser->json[parser->offset] == 'E'))) {
        return WA_STATUS_DECODING_ERROR; /* Floats are never written */
    }
    if (is_negative ? magnitude > (uint64_t)INT64_MAX + 1u : magnitude > (uint64_t)INT64_MAX) {
        return WA_STATUS_DECODING_ERROR;
    }
    if (is_negative) {
        return wa_value_create_integer(parser->platform_hooks,
                                       magnitude == (uint64_t)INT64_MAX + 1u ? INT64_MIN : -(int64_t)magnitude,
                                       value_out);
    }
    return wa_value_create_integer(parser->platform_hooks, (int64_t)magnitude, value_out);
}

static wa_status_t wa_test_parse_json_value(wa_test_json_parser_t *parser, size_t depth, wa_value_t **value_out)
{
    uint8_t character;
    *value_out = NULL;
    if (depth > WA_TEST_JSON_MAXIMUM_DEPTH) {
        return WA_STATUS_NESTING_TOO_DEEP;
    }
    wa_test_skip_json_whitespace(parser);
    if (parser->offset >= parser->length) {
        return WA_STATUS_DECODING_ERROR;
    }
    character = parser->json[parser->offset];
    if (character == '{') {
        return wa_test_parse_json_object(parser, depth, value_out);
    }
    if (character == '[') {
        return wa_test_parse_json_array(parser, depth, value_out);
    }
    if (character == '"') {
        char *text = NULL;
        size_t text_length = 0;
        wa_status_t status = wa_test_parse_json_string(parser, &text, &text_length);
        if (status == WA_STATUS_OK) {
            status = wa_value_create_text(parser->platform_hooks, text, text_length, value_out);
            free(text);
        }
        return status;
    }
    if (wa_test_consume_json_literal(parser, "null")) {
        return wa_value_create_null(parser->platform_hooks, value_out);
    }
    if (wa_test_consume_json_literal(parser, "true")) {
        return wa_value_create_boolean(parser->platform_hooks, 1, value_out);
    }
    if (wa_test_consume_json_literal(parser, "false")) {
        return wa_value_create_boolean(parser->platform_hooks, 0, value_out);
    }
    return wa_test_parse_json_integer(parser, value_out);
}

wa_status_t wa_test_parse_extended_json(const wa_platform_hooks_t *platform_hooks, const uint8_t *json,
                                        size_t json_length, wa_value_t **tree_out)
{
    wa_test_json_parser_t parser;
    wa_status_t status;
    parser.platform_hooks = platform_hooks;
    parser.json = json;
    parser.length = json_length;
    parser.offset = 0;
    status = wa_test_parse_json_value(&parser, 0, tree_out);
    wa_test_skip_json_whitespace(&parser);
    if (status == WA_STATUS_OK && parser.offset != parser.length) {
        status = WA_STATUS_DECODING_ERROR; /* Trailing data */
    }
    if (status != WA_STATUS_OK) {
        wa_value_destroy(*tree_out);
        *tree_out = NULL;
    }
    return status;
}

wa_status_t wa_test_read_document(const wa_platform_hooks_t *platform_hooks, wa_document_format_t format,
                                  const uint8_t *document, size_t document_length, wa_value_t **tree_out)
{
    *tree_out = NULL;
    if (format == WA_DOCUMENT_FORMAT_JSON) {
        return wa_test_parse_extended_json(platform_hooks, document, document_length, tree_out);
    }
    if (format == WA_DOCUMENT_FORMAT_CBOR) {
        return wa_value_tree_decode_from_cbor(document, document_length, platform_hooks, tree_out);
    }
    return WA_STATUS_INVALID_ARGUMENT;
}
