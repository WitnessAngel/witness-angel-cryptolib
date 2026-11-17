/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Value tree nodes (design D7): builders, accessors, deep copy and release. Text and bytes contents and map keys
 * are wiped on release, since bytes nodes may hold secrets (e.g. key ciphertext sources). */

#include "encoding/wa_value_tree_internal.h"

#include <string.h>

#include "core/wa_platform_hooks_calls.h"
#include "encoding/wa_utf8_validation.h"

#define WA_VALUE_CONTAINER_MINIMUM_CAPACITY 4u

/* CREATION */

static wa_status_t wa_value_allocate_node(const wa_platform_hooks_t *platform_hooks, wa_value_type_t type,
                                          wa_value_t **value_out)
{
    wa_value_t *value;
    if (value_out == NULL) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    *value_out = NULL;
    if (!wa_platform_hooks_are_usable(platform_hooks)) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    value = (wa_value_t *)wa_allocate_memory(platform_hooks, sizeof(*value));
    if (value == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    memset(value, 0, sizeof(*value));
    value->type = type;
    value->is_borrowed = 0;
    value->platform_hooks = platform_hooks;
    *value_out = value;
    return WA_STATUS_OK;
}

wa_status_t wa_value_create_null(const wa_platform_hooks_t *platform_hooks, wa_value_t **value_out)
{
    return wa_value_allocate_node(platform_hooks, WA_VALUE_TYPE_NULL, value_out);
}

wa_status_t wa_value_create_boolean(const wa_platform_hooks_t *platform_hooks, int boolean, wa_value_t **value_out)
{
    WA_RETURN_IF_ERROR(wa_value_allocate_node(platform_hooks, WA_VALUE_TYPE_BOOLEAN, value_out));
    (*value_out)->content.boolean = boolean ? 1 : 0;
    return WA_STATUS_OK;
}

wa_status_t wa_value_create_integer(const wa_platform_hooks_t *platform_hooks, int64_t integer, wa_value_t **value_out)
{
    WA_RETURN_IF_ERROR(wa_value_allocate_node(platform_hooks, WA_VALUE_TYPE_INTEGER, value_out));
    (*value_out)->content.integer = integer;
    return WA_STATUS_OK;
}

static wa_status_t wa_value_create_string(const wa_platform_hooks_t *platform_hooks, wa_value_type_t type,
                                          const uint8_t *data, size_t length, wa_value_t **value_out)
{
    uint8_t *copy = NULL;
    if (value_out != NULL) {
        *value_out = NULL;
    }
    if (data == NULL && length != 0) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    WA_RETURN_IF_ERROR(wa_value_allocate_node(platform_hooks, type, value_out));
    if (length != 0) {
        copy = (uint8_t *)wa_allocate_memory(platform_hooks, length);
        if (copy == NULL) {
            wa_release_memory(platform_hooks, *value_out, sizeof(**value_out));
            *value_out = NULL;
            return WA_STATUS_OUT_OF_MEMORY;
        }
        memcpy(copy, data, length);
    }
    (*value_out)->content.string.data = copy;
    (*value_out)->content.string.length = length;
    return WA_STATUS_OK;
}

wa_status_t wa_value_create_text(const wa_platform_hooks_t *platform_hooks, const char *text, size_t text_length,
                                 wa_value_t **value_out)
{
    if (value_out != NULL) {
        *value_out = NULL;
    }
    if ((text == NULL && text_length != 0) || (text != NULL && !wa_utf8_is_valid((const uint8_t *)text, text_length))) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    return wa_value_create_string(platform_hooks, WA_VALUE_TYPE_TEXT, (const uint8_t *)text, text_length, value_out);
}

wa_status_t wa_value_create_bytes(const wa_platform_hooks_t *platform_hooks, const uint8_t *bytes,
                                  size_t bytes_length, wa_value_t **value_out)
{
    return wa_value_create_string(platform_hooks, WA_VALUE_TYPE_BYTES, bytes, bytes_length, value_out);
}

wa_status_t wa_value_create_bytes_from_allocated_block(const wa_platform_hooks_t *platform_hooks, uint8_t *data,
                                                       size_t length, size_t allocation_size,
                                                       wa_value_t **value_out)
{
    if (length == 0 || length != allocation_size) {
        /* Nodes release their content with its length as size: copy into an exact block otherwise */
        wa_status_t status = wa_value_create_bytes(platform_hooks, data, length, value_out);
        if (status == WA_STATUS_OK) {
            wa_release_secret_memory(platform_hooks, data, allocation_size);
        }
        return status;
    }
    WA_RETURN_IF_ERROR(wa_value_allocate_node(platform_hooks, WA_VALUE_TYPE_BYTES, value_out));
    (*value_out)->content.string.data = data;
    (*value_out)->content.string.length = length;
    return WA_STATUS_OK;
}

wa_status_t wa_value_create_uuid(const wa_platform_hooks_t *platform_hooks, const uint8_t uuid[WA_UUID_SIZE],
                                 wa_value_t **value_out)
{
    if (value_out != NULL) {
        *value_out = NULL;
    }
    if (uuid == NULL) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    WA_RETURN_IF_ERROR(wa_value_allocate_node(platform_hooks, WA_VALUE_TYPE_UUID, value_out));
    memcpy((*value_out)->content.uuid, uuid, WA_UUID_SIZE);
    return WA_STATUS_OK;
}

wa_status_t wa_value_create_array(const wa_platform_hooks_t *platform_hooks, wa_value_t **value_out)
{
    return wa_value_allocate_node(platform_hooks, WA_VALUE_TYPE_ARRAY, value_out);
}

wa_status_t wa_value_create_map(const wa_platform_hooks_t *platform_hooks, wa_value_t **value_out)
{
    return wa_value_allocate_node(platform_hooks, WA_VALUE_TYPE_MAP, value_out);
}

/* CONTAINERS */

/* Grow a container block of `count` items of `item_size` bytes, by allocate/copy/release. */
static wa_status_t wa_value_grow_container(const wa_platform_hooks_t *platform_hooks, void **items, size_t count,
                                           size_t *capacity, size_t item_size)
{
    size_t new_capacity;
    size_t new_size;
    void *new_items;
    if (count < *capacity) {
        return WA_STATUS_OK;
    }
    new_capacity = *capacity == 0 ? WA_VALUE_CONTAINER_MINIMUM_CAPACITY : *capacity * 2;
    if (new_capacity <= *capacity || wa_size_multiplication_overflows(new_capacity, item_size, &new_size)) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    new_items = wa_allocate_memory(platform_hooks, new_size);
    if (new_items == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    if (count != 0) {
        memcpy(new_items, *items, count * item_size);
    }
    wa_release_memory(platform_hooks, *items, *capacity * item_size);
    *items = new_items;
    *capacity = new_capacity;
    return WA_STATUS_OK;
}

wa_status_t wa_value_array_append(wa_value_t *array, wa_value_t *item)
{
    void *items;
    if (array == NULL || item == NULL || array->type != WA_VALUE_TYPE_ARRAY || array->is_borrowed || item == array) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    items = array->content.array.items;
    WA_RETURN_IF_ERROR(wa_value_grow_container(array->platform_hooks, &items, array->content.array.count,
                                               &array->content.array.capacity, sizeof(wa_value_t *)));
    array->content.array.items = (wa_value_t **)items;
    array->content.array.items[array->content.array.count++] = item;
    return WA_STATUS_OK;
}

int wa_value_keys_are_equal(const char *key_a, size_t length_a, const char *key_b, size_t length_b)
{
    return length_a == length_b && (length_a == 0 || memcmp(key_a, key_b, length_a) == 0);
}

static const wa_value_map_entry_t *wa_value_find_map_entry(const wa_value_t *map, const char *key, size_t key_length)
{
    size_t index;
    if (map == NULL || map->type != WA_VALUE_TYPE_MAP) {
        return NULL;
    }
    for (index = 0; index < map->content.map.count; index++) {
        const wa_value_map_entry_t *entry = &map->content.map.entries[index];
        if (wa_value_keys_are_equal(entry->key, entry->key_length, key, key_length)) {
            return entry;
        }
    }
    return NULL;
}

wa_status_t wa_value_map_add(wa_value_t *map, const char *key, size_t key_length, wa_value_t *value)
{
    void *entries;
    char *key_copy = NULL;
    wa_value_map_entry_t *entry;

    if (map == NULL || value == NULL || map->type != WA_VALUE_TYPE_MAP || map->is_borrowed || value == map ||
        (key == NULL && key_length != 0) ||
        (key_length != 0 && !wa_utf8_is_valid((const uint8_t *)key, key_length)) ||
        wa_value_find_map_entry(map, key, key_length) != NULL) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    if (key_length != 0) {
        key_copy = (char *)wa_allocate_memory(map->platform_hooks, key_length);
        if (key_copy == NULL) {
            return WA_STATUS_OUT_OF_MEMORY;
        }
        memcpy(key_copy, key, key_length);
    }
    entries = map->content.map.entries;
    if (wa_value_grow_container(map->platform_hooks, &entries, map->content.map.count, &map->content.map.capacity,
                                sizeof(wa_value_map_entry_t)) != WA_STATUS_OK) {
        wa_release_memory(map->platform_hooks, key_copy, key_length);
        return WA_STATUS_OUT_OF_MEMORY;
    }
    map->content.map.entries = (wa_value_map_entry_t *)entries;
    entry = &map->content.map.entries[map->content.map.count++];
    entry->key = key_copy;
    entry->key_length = key_length;
    entry->value = value;
    return WA_STATUS_OK;
}

wa_status_t wa_value_map_add_consuming(wa_value_t *map, const char *key, wa_value_t *value)
{
    wa_status_t status;
    if (value == NULL) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    status = wa_value_map_add(map, key, strlen(key), value);
    if (status != WA_STATUS_OK) {
        wa_value_destroy(value);
    }
    return status;
}

wa_value_t *wa_value_map_take_value(wa_value_t *map, const char *key)
{
    size_t key_length = strlen(key);
    size_t index;
    if (map == NULL || map->type != WA_VALUE_TYPE_MAP || map->is_borrowed) {
        return NULL;
    }
    for (index = 0; index < map->content.map.count; index++) {
        wa_value_map_entry_t *entry = &map->content.map.entries[index];
        if (wa_value_keys_are_equal(entry->key, entry->key_length, key, key_length)) {
            wa_value_t *value = entry->value;
            wa_release_memory(map->platform_hooks, entry->key, entry->key_length);
            memmove(entry, entry + 1, (map->content.map.count - index - 1) * sizeof(*entry));
            map->content.map.count--;
            return value;
        }
    }
    return NULL;
}

/* RELEASE */

void wa_value_destroy(wa_value_t *value_or_null)
{
    const wa_platform_hooks_t *platform_hooks;
    size_t index;
    if (value_or_null == NULL || value_or_null->is_borrowed) {
        return;
    }
    platform_hooks = value_or_null->platform_hooks;
    switch (value_or_null->type) {
    case WA_VALUE_TYPE_TEXT:
    case WA_VALUE_TYPE_BYTES:
        wa_release_secret_memory(platform_hooks, value_or_null->content.string.data,
                                 value_or_null->content.string.length);
        break;
    case WA_VALUE_TYPE_ARRAY:
        for (index = 0; index < value_or_null->content.array.count; index++) {
            wa_value_destroy(value_or_null->content.array.items[index]);
        }
        wa_release_memory(platform_hooks, value_or_null->content.array.items,
                          value_or_null->content.array.capacity * sizeof(wa_value_t *));
        break;
    case WA_VALUE_TYPE_MAP:
        for (index = 0; index < value_or_null->content.map.count; index++) {
            wa_value_map_entry_t *entry = &value_or_null->content.map.entries[index];
            wa_release_secret_memory(platform_hooks, entry->key, entry->key_length);
            wa_value_destroy(entry->value);
        }
        wa_release_memory(platform_hooks, value_or_null->content.map.entries,
                          value_or_null->content.map.capacity * sizeof(wa_value_map_entry_t));
        break;
    case WA_VALUE_TYPE_UUID:
    case WA_VALUE_TYPE_NULL:
    case WA_VALUE_TYPE_BOOLEAN:
    case WA_VALUE_TYPE_INTEGER:
        break;
    }
    wa_release_secret_memory(platform_hooks, value_or_null, sizeof(*value_or_null));
}

/* DEEP COPY */

wa_status_t wa_value_deep_copy(const wa_value_t *source, const wa_platform_hooks_t *platform_hooks,
                               wa_value_t **copy_out)
{
    wa_status_t status = WA_STATUS_OK;
    wa_value_t *copy = NULL;
    size_t index;

    *copy_out = NULL;
    switch (source->type) {
    case WA_VALUE_TYPE_NULL:
        return wa_value_create_null(platform_hooks, copy_out);
    case WA_VALUE_TYPE_BOOLEAN:
        return wa_value_create_boolean(platform_hooks, source->content.boolean, copy_out);
    case WA_VALUE_TYPE_INTEGER:
        return wa_value_create_integer(platform_hooks, source->content.integer, copy_out);
    case WA_VALUE_TYPE_TEXT:
    case WA_VALUE_TYPE_BYTES:
        return wa_value_create_string(platform_hooks, source->type, source->content.string.data,
                                      source->content.string.length, copy_out);
    case WA_VALUE_TYPE_UUID:
        return wa_value_create_uuid(platform_hooks, source->content.uuid, copy_out);
    case WA_VALUE_TYPE_ARRAY:
        WA_RETURN_IF_ERROR(wa_value_create_array(platform_hooks, &copy));
        for (index = 0; index < source->content.array.count && status == WA_STATUS_OK; index++) {
            wa_value_t *item_copy;
            status = wa_value_deep_copy(source->content.array.items[index], platform_hooks, &item_copy);
            if (status == WA_STATUS_OK) {
                status = wa_value_array_append(copy, item_copy);
                if (status != WA_STATUS_OK) {
                    wa_value_destroy(item_copy);
                }
            }
        }
        break;
    case WA_VALUE_TYPE_MAP:
        WA_RETURN_IF_ERROR(wa_value_create_map(platform_hooks, &copy));
        for (index = 0; index < source->content.map.count && status == WA_STATUS_OK; index++) {
            const wa_value_map_entry_t *entry = &source->content.map.entries[index];
            wa_value_t *value_copy;
            status = wa_value_deep_copy(entry->value, platform_hooks, &value_copy);
            if (status == WA_STATUS_OK) {
                status = wa_value_map_add(copy, entry->key, entry->key_length, value_copy);
                if (status != WA_STATUS_OK) {
                    wa_value_destroy(value_copy);
                }
            }
        }
        break;
    default:
        return WA_STATUS_INTERNAL_ERROR;
    }
    if (status != WA_STATUS_OK) {
        wa_value_destroy(copy);
        return status;
    }
    *copy_out = copy;
    return WA_STATUS_OK;
}

/* BORROWED NODES */

static void wa_value_initialize_borrowed_node(wa_value_t *node, wa_value_type_t type)
{
    memset(node, 0, sizeof(*node));
    node->type = type;
    node->is_borrowed = 1;
    node->platform_hooks = NULL;
}

void wa_value_initialize_borrowed_null(wa_value_t *node)
{
    wa_value_initialize_borrowed_node(node, WA_VALUE_TYPE_NULL);
}

void wa_value_initialize_borrowed_integer(wa_value_t *node, int64_t integer)
{
    wa_value_initialize_borrowed_node(node, WA_VALUE_TYPE_INTEGER);
    node->content.integer = integer;
}

void wa_value_initialize_borrowed_text(wa_value_t *node, const char *nul_terminated_text)
{
    wa_value_initialize_borrowed_node(node, WA_VALUE_TYPE_TEXT);
    node->content.string.data = (uint8_t *)(void *)(uintptr_t)nul_terminated_text;
    node->content.string.length = strlen(nul_terminated_text);
}

void wa_value_initialize_borrowed_bytes(wa_value_t *node, const uint8_t *bytes, size_t length)
{
    wa_value_initialize_borrowed_node(node, WA_VALUE_TYPE_BYTES);
    node->content.string.data = (uint8_t *)(uintptr_t)bytes;
    node->content.string.length = length;
}

void wa_value_initialize_borrowed_array(wa_value_t *node, wa_value_t **items, size_t count)
{
    wa_value_initialize_borrowed_node(node, WA_VALUE_TYPE_ARRAY);
    node->content.array.items = items;
    node->content.array.count = count;
    node->content.array.capacity = count;
}

void wa_value_initialize_borrowed_map(wa_value_t *node, wa_value_map_entry_t *entries, size_t count)
{
    wa_value_initialize_borrowed_node(node, WA_VALUE_TYPE_MAP);
    node->content.map.entries = entries;
    node->content.map.count = count;
    node->content.map.capacity = count;
}

void wa_value_initialize_borrowed_map_entry(wa_value_map_entry_t *entry, const char *nul_terminated_key,
                                            const wa_value_t *value)
{
    entry->key = (char *)(uintptr_t)nul_terminated_key;
    entry->key_length = strlen(nul_terminated_key);
    entry->value = (wa_value_t *)(uintptr_t)value;
}

/* ACCESSORS */

wa_value_type_t wa_value_get_type(const wa_value_t *value)
{
    return value->type;
}

int wa_value_get_boolean(const wa_value_t *value, int *boolean_out)
{
    if (value == NULL || value->type != WA_VALUE_TYPE_BOOLEAN) {
        return -1;
    }
    *boolean_out = value->content.boolean;
    return 0;
}

int wa_value_get_integer(const wa_value_t *value, int64_t *integer_out)
{
    if (value == NULL || value->type != WA_VALUE_TYPE_INTEGER) {
        return -1;
    }
    *integer_out = value->content.integer;
    return 0;
}

int wa_value_get_text(const wa_value_t *value, const char **text_out, size_t *text_length_out)
{
    if (value == NULL || value->type != WA_VALUE_TYPE_TEXT) {
        return -1;
    }
    *text_out = (const char *)value->content.string.data;
    *text_length_out = value->content.string.length;
    return 0;
}

int wa_value_get_bytes(const wa_value_t *value, const uint8_t **bytes_out, size_t *bytes_length_out)
{
    if (value == NULL || value->type != WA_VALUE_TYPE_BYTES) {
        return -1;
    }
    *bytes_out = value->content.string.data;
    *bytes_length_out = value->content.string.length;
    return 0;
}

int wa_value_get_uuid(const wa_value_t *value, const uint8_t **uuid_out)
{
    if (value == NULL || value->type != WA_VALUE_TYPE_UUID) {
        return -1;
    }
    *uuid_out = value->content.uuid;
    return 0;
}

size_t wa_value_get_item_count(const wa_value_t *value)
{
    if (value == NULL) {
        return 0;
    }
    if (value->type == WA_VALUE_TYPE_ARRAY) {
        return value->content.array.count;
    }
    if (value->type == WA_VALUE_TYPE_MAP) {
        return value->content.map.count;
    }
    return 0;
}

const wa_value_t *wa_value_get_array_item(const wa_value_t *array, size_t index)
{
    if (array == NULL || array->type != WA_VALUE_TYPE_ARRAY || index >= array->content.array.count) {
        return NULL;
    }
    return array->content.array.items[index];
}

int wa_value_get_map_entry(const wa_value_t *map, size_t index, const char **key_out, size_t *key_length_out,
                           const wa_value_t **value_out)
{
    const wa_value_map_entry_t *entry;
    if (map == NULL || map->type != WA_VALUE_TYPE_MAP || index >= map->content.map.count) {
        return -1;
    }
    entry = &map->content.map.entries[index];
    *key_out = entry->key;
    *key_length_out = entry->key_length;
    *value_out = entry->value;
    return 0;
}

const wa_value_t *wa_value_find_map_value(const wa_value_t *map, const char *key)
{
    const wa_value_map_entry_t *entry = wa_value_find_map_entry(map, key, strlen(key));
    return entry == NULL ? NULL : entry->value;
}

wa_value_t *wa_value_find_map_value_for_update(wa_value_t *map, const char *key)
{
    const wa_value_map_entry_t *entry = wa_value_find_map_entry(map, key, strlen(key));
    return entry == NULL ? NULL : entry->value;
}

int wa_value_is_text_equal_to(const wa_value_t *value_or_null, const char *text)
{
    size_t length = strlen(text);
    return value_or_null != NULL && value_or_null->type == WA_VALUE_TYPE_TEXT &&
           wa_value_keys_are_equal((const char *)value_or_null->content.string.data,
                                   value_or_null->content.string.length, text, length);
}
