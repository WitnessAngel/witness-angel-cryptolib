/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "encoding/wa_growable_byte_buffer.h"

#include <string.h>

#include "core/wa_platform_hooks_calls.h"
#include "encoding/wa_value_tree_internal.h"
#include "primitives/wa_secure_memory_wipe.h"

#define WA_GROWABLE_BYTE_BUFFER_MINIMUM_CAPACITY 64u

void wa_growable_byte_buffer_initialize(wa_growable_byte_buffer_t *buffer, const wa_platform_hooks_t *platform_hooks,
                                        int is_secret)
{
    buffer->platform_hooks = platform_hooks;
    buffer->data = NULL;
    buffer->length = 0;
    buffer->capacity = 0;
    buffer->is_secret = is_secret;
}

static void wa_growable_byte_buffer_release_block(wa_growable_byte_buffer_t *buffer, uint8_t *block, size_t size)
{
    if (buffer->is_secret) {
        wa_release_secret_memory(buffer->platform_hooks, block, size);
    } else {
        wa_release_memory(buffer->platform_hooks, block, size);
    }
}

wa_status_t wa_growable_byte_buffer_reserve(wa_growable_byte_buffer_t *buffer, size_t minimum_capacity)
{
    size_t new_capacity;
    uint8_t *new_data;

    if (minimum_capacity <= buffer->capacity) {
        return WA_STATUS_OK;
    }
    new_capacity = buffer->capacity < WA_GROWABLE_BYTE_BUFFER_MINIMUM_CAPACITY ? WA_GROWABLE_BYTE_BUFFER_MINIMUM_CAPACITY
                                                                               : buffer->capacity;
    while (new_capacity < minimum_capacity) {
        if (new_capacity > (size_t)-1 / 2) {
            new_capacity = minimum_capacity;
            break;
        }
        new_capacity *= 2;
    }
    new_data = (uint8_t *)wa_allocate_memory(buffer->platform_hooks, new_capacity);
    if (new_data == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    if (buffer->length != 0) {
        memcpy(new_data, buffer->data, buffer->length);
    }
    wa_growable_byte_buffer_release_block(buffer, buffer->data, buffer->capacity);
    buffer->data = new_data;
    buffer->capacity = new_capacity;
    return WA_STATUS_OK;
}

wa_status_t wa_growable_byte_buffer_append(wa_growable_byte_buffer_t *buffer, const uint8_t *bytes, size_t length)
{
    if (length == 0) {
        return WA_STATUS_OK;
    }
    if (length > (size_t)-1 - buffer->length) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    WA_RETURN_IF_ERROR(wa_growable_byte_buffer_reserve(buffer, buffer->length + length));
    memcpy(buffer->data + buffer->length, bytes, length);
    buffer->length += length;
    return WA_STATUS_OK;
}

void wa_growable_byte_buffer_clear(wa_growable_byte_buffer_t *buffer)
{
    if (buffer->is_secret && buffer->data != NULL) {
        wa_secure_memory_wipe(buffer->data, buffer->length);
    }
    buffer->length = 0;
}

void wa_growable_byte_buffer_release(wa_growable_byte_buffer_t *buffer)
{
    wa_growable_byte_buffer_release_block(buffer, buffer->data, buffer->capacity);
    buffer->data = NULL;
    buffer->length = 0;
    buffer->capacity = 0;
}

static wa_status_t wa_growable_byte_buffer_write_to_sink(void *sink_context, const uint8_t *bytes, size_t length)
{
    return wa_growable_byte_buffer_append((wa_growable_byte_buffer_t *)sink_context, bytes, length);
}

wa_output_sink_t wa_growable_byte_buffer_get_sink(wa_growable_byte_buffer_t *buffer)
{
    wa_output_sink_t sink;
    sink.write = wa_growable_byte_buffer_write_to_sink;
    sink.sink_context = buffer;
    return sink;
}

wa_status_t wa_growable_byte_buffer_move_into_bytes_value(wa_growable_byte_buffer_t *buffer, wa_value_t **value_out)
{
    wa_status_t status;
    *value_out = NULL;
    if (buffer->data == NULL) {
        return wa_value_create_bytes(buffer->platform_hooks, NULL, 0, value_out);
    }
    status = wa_value_create_bytes_from_allocated_block(buffer->platform_hooks, buffer->data, buffer->length,
                                                         buffer->capacity, buffer->is_secret, value_out);
    if (status != WA_STATUS_OK) {
        wa_growable_byte_buffer_release(buffer);
        return status;
    }
    buffer->data = NULL; /* The node owns the block, and wipes it when destroyed if it is secret */
    buffer->length = 0;
    buffer->capacity = 0;
    return WA_STATUS_OK;
}
