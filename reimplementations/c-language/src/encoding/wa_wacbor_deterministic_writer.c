/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "encoding/wa_wacbor_deterministic_writer.h"

#include <string.h>

#include "encoding/wa_buffered_sink_writer.h"
#include "encoding/wa_value_tree_internal.h"

#define WA_CBOR_MAJOR_UNSIGNED 0u
#define WA_CBOR_MAJOR_NEGATIVE 1u
#define WA_CBOR_MAJOR_BYTES 2u
#define WA_CBOR_MAJOR_TEXT 3u
#define WA_CBOR_MAJOR_ARRAY 4u
#define WA_CBOR_MAJOR_MAP 5u
#define WA_CBOR_MAJOR_TAG 6u
#define WA_CBOR_UUID_TAG 37u

static void wa_cbor_write_head(wa_buffered_sink_writer_t *writer, unsigned int major_type, uint64_t argument)
{
    uint8_t head[9];
    size_t argument_size;
    size_t index;
    uint8_t initial = (uint8_t)(major_type << 5);
    if (argument < 24u) {
        wa_buffered_sink_writer_write_byte(writer, (uint8_t)(initial | argument));
        return;
    }
    if (argument <= 0xFFu) {
        head[0] = (uint8_t)(initial | 24u);
        argument_size = 1;
    } else if (argument <= 0xFFFFu) {
        head[0] = (uint8_t)(initial | 25u);
        argument_size = 2;
    } else if (argument <= 0xFFFFFFFFu) {
        head[0] = (uint8_t)(initial | 26u);
        argument_size = 4;
    } else {
        head[0] = (uint8_t)(initial | 27u);
        argument_size = 8;
    }
    for (index = 0; index < argument_size; index++) {
        head[1 + index] = (uint8_t)(argument >> (8u * (argument_size - 1u - index)));
    }
    wa_buffered_sink_writer_write(writer, head, 1 + argument_size);
}

/* Encoded text keys sort bytewise: shorter keys first (their heads are smaller), then by their UTF-8 bytes */
static int wa_cbor_compare_keys(const wa_value_map_entry_t *entry_a, const wa_value_map_entry_t *entry_b)
{
    if (entry_a->key_length != entry_b->key_length) {
        return entry_a->key_length < entry_b->key_length ? -1 : 1;
    }
    return entry_a->key_length == 0 ? 0 : memcmp(entry_a->key, entry_b->key, entry_a->key_length);
}

static void wa_cbor_write_node(wa_buffered_sink_writer_t *writer, const wa_value_t *node)
{
    size_t index;
    switch (node->type) {
    case WA_VALUE_TYPE_NULL:
        wa_buffered_sink_writer_write_byte(writer, 0xF6u);
        break;
    case WA_VALUE_TYPE_BOOLEAN:
        wa_buffered_sink_writer_write_byte(writer, node->content.boolean ? 0xF5u : 0xF4u);
        break;
    case WA_VALUE_TYPE_INTEGER:
        if (node->content.integer >= 0) {
            wa_cbor_write_head(writer, WA_CBOR_MAJOR_UNSIGNED, (uint64_t)node->content.integer);
        } else {
            wa_cbor_write_head(writer, WA_CBOR_MAJOR_NEGATIVE, (uint64_t)(-(node->content.integer + 1)));
        }
        break;
    case WA_VALUE_TYPE_TEXT:
    case WA_VALUE_TYPE_BYTES:
        wa_cbor_write_head(writer, node->type == WA_VALUE_TYPE_TEXT ? WA_CBOR_MAJOR_TEXT : WA_CBOR_MAJOR_BYTES,
                           (uint64_t)node->content.string.length);
        wa_buffered_sink_writer_write(writer, node->content.string.data, node->content.string.length);
        break;
    case WA_VALUE_TYPE_UUID:
        wa_cbor_write_head(writer, WA_CBOR_MAJOR_TAG, WA_CBOR_UUID_TAG);
        wa_cbor_write_head(writer, WA_CBOR_MAJOR_BYTES, WA_UUID_SIZE);
        wa_buffered_sink_writer_write(writer, node->content.uuid, WA_UUID_SIZE);
        break;
    case WA_VALUE_TYPE_ARRAY:
        wa_cbor_write_head(writer, WA_CBOR_MAJOR_ARRAY, (uint64_t)node->content.array.count);
        for (index = 0; index < node->content.array.count; index++) {
            wa_cbor_write_node(writer, node->content.array.items[index]);
        }
        break;
    case WA_VALUE_TYPE_MAP: {
        const wa_value_map_entry_t *previous_entry = NULL;
        size_t written_count;
        wa_cbor_write_head(writer, WA_CBOR_MAJOR_MAP, (uint64_t)node->content.map.count);
        for (written_count = 0; written_count < node->content.map.count; written_count++) {
            const wa_value_map_entry_t *next_entry = NULL;
            for (index = 0; index < node->content.map.count; index++) {
                const wa_value_map_entry_t *candidate = &node->content.map.entries[index];
                if ((previous_entry == NULL || wa_cbor_compare_keys(candidate, previous_entry) > 0) &&
                    (next_entry == NULL || wa_cbor_compare_keys(candidate, next_entry) < 0)) {
                    next_entry = candidate;
                }
            }
            wa_cbor_write_head(writer, WA_CBOR_MAJOR_TEXT, (uint64_t)next_entry->key_length);
            wa_buffered_sink_writer_write(writer, (const uint8_t *)next_entry->key, next_entry->key_length);
            wa_cbor_write_node(writer, next_entry->value);
            previous_entry = next_entry;
        }
        break;
    }
    }
}

wa_status_t wa_wacbor_deterministic_writer_write_document(const wa_value_t *tree, const wa_output_sink_t *sink)
{
    wa_buffered_sink_writer_t writer;
    wa_buffered_sink_writer_initialize(&writer, sink);
    wa_cbor_write_node(&writer, tree);
    return wa_buffered_sink_writer_finish(&writer);
}
