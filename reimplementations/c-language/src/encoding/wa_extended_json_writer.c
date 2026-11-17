/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "encoding/wa_extended_json_writer.h"

#include <string.h>

#include "encoding/wa_base64_encoder.h"
#include "encoding/wa_buffered_sink_writer.h"
#include "encoding/wa_utf8_validation.h"
#include "encoding/wa_value_tree_internal.h"

static const char wa_json_hexadecimal_digits[] = "0123456789abcdef";

/* Code point order of UTF-8 keys is their bytewise order */
static int wa_json_compare_keys(const wa_value_map_entry_t *entry_a, const wa_value_map_entry_t *entry_b)
{
    size_t common_length = entry_a->key_length < entry_b->key_length ? entry_a->key_length : entry_b->key_length;
    int comparison = common_length == 0 ? 0 : memcmp(entry_a->key, entry_b->key, common_length);
    if (comparison != 0) {
        return comparison;
    }
    return entry_a->key_length < entry_b->key_length ? -1 : (entry_a->key_length > entry_b->key_length ? 1 : 0);
}

static void wa_json_write_unicode_escape(wa_buffered_sink_writer_t *writer, uint32_t code_unit)
{
    uint8_t escape[6];
    escape[0] = (uint8_t)'\\';
    escape[1] = (uint8_t)'u';
    escape[2] = (uint8_t)wa_json_hexadecimal_digits[(code_unit >> 12) & 0xFu];
    escape[3] = (uint8_t)wa_json_hexadecimal_digits[(code_unit >> 8) & 0xFu];
    escape[4] = (uint8_t)wa_json_hexadecimal_digits[(code_unit >> 4) & 0xFu];
    escape[5] = (uint8_t)wa_json_hexadecimal_digits[code_unit & 0xFu];
    wa_buffered_sink_writer_write(writer, escape, sizeof(escape));
}

static void wa_json_write_string(wa_buffered_sink_writer_t *writer, const uint8_t *text, size_t length)
{
    size_t position = 0;
    wa_buffered_sink_writer_write_byte(writer, (uint8_t)'"');
    while (position < length) {
        uint32_t code_point;
        position += wa_utf8_decode_code_point(text + position, &code_point);
        switch (code_point) {
        case '"':
            wa_buffered_sink_writer_write_text(writer, "\\\"");
            break;
        case '\\':
            wa_buffered_sink_writer_write_text(writer, "\\\\");
            break;
        case '\b':
            wa_buffered_sink_writer_write_text(writer, "\\b");
            break;
        case '\f':
            wa_buffered_sink_writer_write_text(writer, "\\f");
            break;
        case '\n':
            wa_buffered_sink_writer_write_text(writer, "\\n");
            break;
        case '\r':
            wa_buffered_sink_writer_write_text(writer, "\\r");
            break;
        case '\t':
            wa_buffered_sink_writer_write_text(writer, "\\t");
            break;
        default:
            if (code_point < 0x20u || code_point >= 0x7Fu) {
                if (code_point >= 0x10000u) { /* Surrogate pair beyond the BMP */
                    uint32_t offset = code_point - 0x10000u;
                    wa_json_write_unicode_escape(writer, 0xD800u | (offset >> 10));
                    wa_json_write_unicode_escape(writer, 0xDC00u | (offset & 0x3FFu));
                } else {
                    wa_json_write_unicode_escape(writer, code_point);
                }
            } else {
                wa_buffered_sink_writer_write_byte(writer, (uint8_t)code_point);
            }
            break;
        }
    }
    wa_buffered_sink_writer_write_byte(writer, (uint8_t)'"');
}

static void wa_json_write_integer(wa_buffered_sink_writer_t *writer, int64_t integer)
{
    uint8_t digits[20];
    size_t digit_count = 0;
    uint64_t magnitude;
    if (integer < 0) {
        wa_buffered_sink_writer_write_byte(writer, (uint8_t)'-');
        magnitude = (uint64_t)(-(integer + 1)) + 1u; /* No overflow for INT64_MIN */
    } else {
        magnitude = (uint64_t)integer;
    }
    do {
        digits[sizeof(digits) - 1 - digit_count] = (uint8_t)('0' + (int)(magnitude % 10u));
        digit_count++;
        magnitude /= 10u;
    } while (magnitude != 0);
    wa_buffered_sink_writer_write(writer, digits + sizeof(digits) - digit_count, digit_count);
}

static void wa_json_write_node(wa_buffered_sink_writer_t *writer, const wa_value_t *node)
{
    size_t index;
    switch (node->type) {
    case WA_VALUE_TYPE_NULL:
        wa_buffered_sink_writer_write_text(writer, "null");
        break;
    case WA_VALUE_TYPE_BOOLEAN:
        wa_buffered_sink_writer_write_text(writer, node->content.boolean ? "true" : "false");
        break;
    case WA_VALUE_TYPE_INTEGER:
        wa_json_write_integer(writer, node->content.integer);
        break;
    case WA_VALUE_TYPE_TEXT:
        wa_json_write_string(writer, node->content.string.data, node->content.string.length);
        break;
    case WA_VALUE_TYPE_BYTES: {
        wa_base64_encoder_t encoder;
        wa_buffered_sink_writer_write_text(writer, "{\"$binary\": {\"base64\": \"");
        wa_base64_encoder_initialize(&encoder, writer);
        wa_base64_encoder_update(&encoder, node->content.string.data, node->content.string.length);
        wa_base64_encoder_finish(&encoder);
        wa_buffered_sink_writer_write_text(writer, "\", \"subType\": \"00\"}}");
        break;
    }
    case WA_VALUE_TYPE_UUID:
        wa_buffered_sink_writer_write_text(writer, "{\"$uuid\": \"");
        for (index = 0; index < WA_UUID_SIZE; index++) {
            wa_buffered_sink_writer_write_byte(writer, (uint8_t)wa_json_hexadecimal_digits[node->content.uuid[index] >> 4]);
            wa_buffered_sink_writer_write_byte(writer, (uint8_t)wa_json_hexadecimal_digits[node->content.uuid[index] & 0xFu]);
        }
        wa_buffered_sink_writer_write_text(writer, "\"}");
        break;
    case WA_VALUE_TYPE_ARRAY:
        wa_buffered_sink_writer_write_byte(writer, (uint8_t)'[');
        for (index = 0; index < node->content.array.count; index++) {
            if (index != 0) {
                wa_buffered_sink_writer_write_text(writer, ", ");
            }
            wa_json_write_node(writer, node->content.array.items[index]);
        }
        wa_buffered_sink_writer_write_byte(writer, (uint8_t)']');
        break;
    case WA_VALUE_TYPE_MAP: {
        /* Selection of the next key in order at each step: no allocation, maps are small */
        const wa_value_map_entry_t *previous_entry = NULL;
        size_t written_count;
        wa_buffered_sink_writer_write_byte(writer, (uint8_t)'{');
        for (written_count = 0; written_count < node->content.map.count; written_count++) {
            const wa_value_map_entry_t *next_entry = NULL;
            for (index = 0; index < node->content.map.count; index++) {
                const wa_value_map_entry_t *candidate = &node->content.map.entries[index];
                if ((previous_entry == NULL || wa_json_compare_keys(candidate, previous_entry) > 0) &&
                    (next_entry == NULL || wa_json_compare_keys(candidate, next_entry) < 0)) {
                    next_entry = candidate;
                }
            }
            if (written_count != 0) {
                wa_buffered_sink_writer_write_text(writer, ", ");
            }
            wa_json_write_string(writer, (const uint8_t *)next_entry->key, next_entry->key_length);
            wa_buffered_sink_writer_write_text(writer, ": ");
            wa_json_write_node(writer, next_entry->value);
            previous_entry = next_entry;
        }
        wa_buffered_sink_writer_write_byte(writer, (uint8_t)'}');
        break;
    }
    }
}

wa_status_t wa_extended_json_writer_write_document(const wa_value_t *tree, const wa_output_sink_t *sink)
{
    wa_buffered_sink_writer_t writer;
    wa_buffered_sink_writer_initialize(&writer, sink);
    wa_json_write_node(&writer, tree);
    return wa_buffered_sink_writer_finish(&writer);
}
