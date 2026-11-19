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

/* Append the characters of an escape sequence, all of them or none: a truncated path does not end inside one */
static void wa_error_location_path_append_whole(wa_error_location_path_t *path, const char *characters, size_t count)
{
    if (path->logical_length + count < WA_ERROR_LOCATION_PATH_CAPACITY) {
        memcpy(path->text + path->logical_length, characters, count);
        path->text[path->logical_length + count] = '\0';
    }
    path->logical_length += count; /* Beyond the capacity when not written: nothing more gets appended */
}

/* Whether a byte of a map key is written as is: printable ASCII, except the space (a location is one word), the
 * characters of the path syntax and the backslash of escape sequences */
static int wa_error_location_path_is_plain_key_byte(unsigned char byte)
{
    return byte > 0x20u && byte < 0x7Fu && byte != '.' && byte != '[' && byte != ']' && byte != '\\';
}

void wa_error_location_path_initialize(wa_error_location_path_t *path)
{
    path->text[0] = '\0';
    path->logical_length = 0;
}

size_t wa_error_location_path_push_key(wa_error_location_path_t *path, const char *key, size_t key_length)
{
    size_t previous_logical_length = path->logical_length;
    size_t index;
    if (path->logical_length > 0) {
        wa_error_location_path_append(path, ".", 1);
    }
    /* Keys come from the profile, whatever it holds: any other byte is written as \xNN, so that a location is
     * printable ASCII (no control character, no NUL, no partial UTF-8 sequence after a truncation) and cannot be
     * mistaken for another path */
    for (index = 0; index < key_length; ++index) {
        unsigned char byte = (unsigned char)key[index];
        if (wa_error_location_path_is_plain_key_byte(byte)) {
            wa_error_location_path_append(path, &key[index], 1);
        } else {
            static const char hexadecimal_digits[] = "0123456789ABCDEF";
            char escape_sequence[4];
            escape_sequence[0] = '\\';
            escape_sequence[1] = 'x';
            escape_sequence[2] = hexadecimal_digits[byte >> 4];
            escape_sequence[3] = hexadecimal_digits[byte & 0x0Fu];
            wa_error_location_path_append_whole(path, escape_sequence, sizeof(escape_sequence));
        }
    }
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
        size_t backward_offset;
        length = buffer_size - 1u;
        /* Not inside a \xNN escape sequence (a backslash only ever starts one) */
        for (backward_offset = 1; backward_offset <= 3u && backward_offset <= length; ++backward_offset) {
            if (path->text[length - backward_offset] == '\\') {
                length -= backward_offset;
                break;
            }
        }
    }
    memcpy(buffer_or_null, path->text, length);
    buffer_or_null[length] = '\0';
}
