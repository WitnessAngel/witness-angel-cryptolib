/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/wa_error_location_path.h"

#include <string.h>

/* Append characters as far as the capacity allows, the logical length counting them all */
static void wa_error_location_path_append(wa_error_location_path_t *path, const char *characters, size_t count)
{
    size_t index;
    for (index = 0; index < count; ++index) {
        if (path->logical_length + 1u < WA_ERROR_LOCATION_PATH_CAPACITY) {
            path->text[path->logical_length] = characters[index];
            path->text[path->logical_length + 1u] = '\0';
        }
        ++path->logical_length;
    }
}

void wa_error_location_path_initialize(wa_error_location_path_t *path)
{
    path->text[0] = '\0';
    path->logical_length = 0;
}

size_t wa_error_location_path_push_key(wa_error_location_path_t *path, const char *key, size_t key_length)
{
    size_t previous_logical_length = path->logical_length;
    if (path->logical_length > 0) {
        wa_error_location_path_append(path, ".", 1);
    }
    wa_error_location_path_append(path, key, key_length);
    return previous_logical_length;
}

size_t wa_error_location_path_push_index(wa_error_location_path_t *path, size_t index)
{
    char digits[3u * sizeof(size_t) + 1u];
    size_t digit_count = 0;
    size_t previous_logical_length = path->logical_length;
    char reversed[3u * sizeof(size_t) + 1u];
    do {
        reversed[digit_count++] = (char)('0' + (int)(index % 10u));
        index /= 10u;
    } while (index != 0);
    {
        size_t position;
        for (position = 0; position < digit_count; ++position) {
            digits[position] = reversed[digit_count - 1u - position];
        }
    }
    wa_error_location_path_append(path, "[", 1);
    wa_error_location_path_append(path, digits, digit_count);
    wa_error_location_path_append(path, "]", 1);
    return previous_logical_length;
}

void wa_error_location_path_pop(wa_error_location_path_t *path, size_t previous_logical_length)
{
    path->logical_length = previous_logical_length;
    if (previous_logical_length < WA_ERROR_LOCATION_PATH_CAPACITY) {
        path->text[previous_logical_length] = '\0';
    }
}

void wa_error_location_path_copy_to_buffer(const wa_error_location_path_t *path, char *buffer_or_null,
                                           size_t buffer_size)
{
    size_t length;
    if (buffer_or_null == NULL || buffer_size == 0) {
        return;
    }
    length = strlen(path->text);
    if (length > buffer_size - 1u) {
        length = buffer_size - 1u;
    }
    memcpy(buffer_or_null, path->text, length);
    buffer_or_null[length] = '\0';
}
