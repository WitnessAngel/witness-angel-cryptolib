/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wa_test_value_notation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/wa_platform_hooks_calls.h"
#include "wa_test_support.h"

typedef struct wa_notation_parser {
    const wa_platform_hooks_t *platform_hooks;
    const char *notation;
    size_t position;
} wa_notation_parser_t;

static wa_status_t wa_notation_error(const wa_notation_parser_t *parser, const char *message)
{
    fprintf(stderr, "notation error at offset %lu (%s): %s\n", (unsigned long)parser->position, message,
            parser->notation);
    return WA_STATUS_INVALID_ARGUMENT;
}

static void wa_notation_skip_whitespace(wa_notation_parser_t *parser)
{
    while (strchr(" \t\r\n", parser->notation[parser->position]) != NULL && parser->notation[parser->position]) {
        ++parser->position;
    }
}

static int wa_notation_accept(wa_notation_parser_t *parser, char character)
{
    wa_notation_skip_whitespace(parser);
    if (parser->notation[parser->position] == character) {
        ++parser->position;
        return 1;
    }
    return 0;
}

static int wa_notation_accept_word(wa_notation_parser_t *parser, const char *word)
{
    size_t length = strlen(word);
    wa_notation_skip_whitespace(parser);
    if (strncmp(parser->notation + parser->position, word, length) == 0) {
        parser->position += length;
        return 1;
    }
    return 0;
}

/* A quoted string, the opening quote being next: its start and length, the parser moved past the closing quote */
static wa_status_t wa_notation_parse_quoted(wa_notation_parser_t *parser, const char **start_out,
                                            size_t *length_out)
{
    const char *closing_quote;
    if (!wa_notation_accept(parser, '\'')) {
        return wa_notation_error(parser, "quote expected");
    }
    closing_quote = strchr(parser->notation + parser->position, '\'');
    if (closing_quote == NULL) {
        return wa_notation_error(parser, "unterminated quote");
    }
    *start_out = parser->notation + parser->position;
    *length_out = (size_t)(closing_quote - *start_out);
    parser->position += *length_out + 1u;
    return WA_STATUS_OK;
}

static wa_status_t wa_notation_parse_hex_value(wa_notation_parser_t *parser, int is_uuid, wa_value_t **value_out)
{
    const char *start = NULL;
    size_t length = 0;
    char *hex;
    uint8_t *bytes;
    size_t bytes_length = 0;
    wa_status_t status;
    WA_RETURN_IF_ERROR(wa_notation_parse_quoted(parser, &start, &length));
    hex = (char *)malloc(length + 1u);
    if (hex == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    memcpy(hex, start, length);
    hex[length] = '\0';
    bytes = wa_test_decode_hex(hex, &bytes_length);
    free(hex);
    if (bytes == NULL || (is_uuid && bytes_length != WA_UUID_SIZE)) {
        free(bytes);
        return wa_notation_error(parser, "invalid hex");
    }
    status = is_uuid ? wa_value_create_uuid(parser->platform_hooks, bytes, value_out)
                     : wa_value_create_bytes(parser->platform_hooks, bytes, bytes_length, value_out);
    free(bytes);
    return status;
}

static wa_status_t wa_notation_parse_value(wa_notation_parser_t *parser, wa_value_t **value_out);

static wa_status_t wa_notation_parse_items(wa_notation_parser_t *parser, wa_value_t *container, int is_map,
                                           char closing_character)
{
    if (wa_notation_accept(parser, closing_character)) {
        return WA_STATUS_OK;
    }
    for (;;) {
        const char *key = NULL;
        size_t key_length = 0;
        wa_value_t *item = NULL;
        wa_status_t status;
        if (is_map) {
            WA_RETURN_IF_ERROR(wa_notation_parse_quoted(parser, &key, &key_length));
            if (!wa_notation_accept(parser, ':')) {
                return wa_notation_error(parser, "colon expected");
            }
        }
        WA_RETURN_IF_ERROR(wa_notation_parse_value(parser, &item));
        status = is_map ? wa_value_map_add(container, key, key_length, item) : wa_value_array_append(container, item);
        if (status != WA_STATUS_OK) {
            wa_value_destroy(item);
            return status;
        }
        if (wa_notation_accept(parser, closing_character)) {
            return WA_STATUS_OK;
        }
        if (!wa_notation_accept(parser, ',')) {
            return wa_notation_error(parser, "comma expected");
        }
    }
}

static wa_status_t wa_notation_parse_value(wa_notation_parser_t *parser, wa_value_t **value_out)
{
    char character;
    *value_out = NULL;
    wa_notation_skip_whitespace(parser);
    character = parser->notation[parser->position];
    if (character == '{' || character == '[') {
        wa_status_t status;
        ++parser->position;
        WA_RETURN_IF_ERROR(character == '{' ? wa_value_create_map(parser->platform_hooks, value_out)
                                            : wa_value_create_array(parser->platform_hooks, value_out));
        status = wa_notation_parse_items(parser, *value_out, character == '{', character == '{' ? '}' : ']');
        if (status != WA_STATUS_OK) {
            wa_value_destroy(*value_out);
            *value_out = NULL;
        }
        return status;
    }
    if (character == '\'') {
        const char *start = NULL;
        size_t length = 0;
        WA_RETURN_IF_ERROR(wa_notation_parse_quoted(parser, &start, &length));
        return wa_value_create_text(parser->platform_hooks, start, length, value_out);
    }
    if (character == '-' || (character >= '0' && character <= '9')) {
        char *end = NULL;
        long long integer = strtoll(parser->notation + parser->position, &end, 10);
        parser->position = (size_t)(end - parser->notation);
        return wa_value_create_integer(parser->platform_hooks, (int64_t)integer, value_out);
    }
    if (wa_notation_accept_word(parser, "u'")) {
        --parser->position;
        return wa_notation_parse_hex_value(parser, 1, value_out);
    }
    if (wa_notation_accept_word(parser, "b'")) {
        --parser->position;
        return wa_notation_parse_hex_value(parser, 0, value_out);
    }
    if (wa_notation_accept_word(parser, "null")) {
        return wa_value_create_null(parser->platform_hooks, value_out);
    }
    if (wa_notation_accept_word(parser, "true")) {
        return wa_value_create_boolean(parser->platform_hooks, 1, value_out);
    }
    if (wa_notation_accept_word(parser, "false")) {
        return wa_value_create_boolean(parser->platform_hooks, 0, value_out);
    }
    return wa_notation_error(parser, "value expected");
}

wa_status_t wa_test_build_value_tree(const wa_platform_hooks_t *platform_hooks, const char *notation,
                                     wa_value_t **tree_out)
{
    wa_notation_parser_t parser;
    wa_status_t status;
    parser.platform_hooks = platform_hooks;
    parser.notation = notation;
    parser.position = 0;
    status = wa_notation_parse_value(&parser, tree_out);
    if (status == WA_STATUS_OK) {
        wa_notation_skip_whitespace(&parser);
        if (parser.notation[parser.position] != '\0') {
            wa_value_destroy(*tree_out);
            *tree_out = NULL;
            status = wa_notation_error(&parser, "trailing characters");
        }
    }
    return status;
}
