/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wa_tool_common.h"

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

const char *wa_tool_get_status_name(wa_status_t status)
{
    switch (status) {
    case WA_STATUS_OK: return "WA_STATUS_OK";
    case WA_STATUS_INVALID_ARGUMENT: return "WA_STATUS_INVALID_ARGUMENT";
    case WA_STATUS_UNSUPPORTED_FORMAT: return "WA_STATUS_UNSUPPORTED_FORMAT";
    case WA_STATUS_DECODING_ERROR: return "WA_STATUS_DECODING_ERROR";
    case WA_STATUS_INVALID_PROFILE: return "WA_STATUS_INVALID_PROFILE";
    case WA_STATUS_UNSUPPORTED_TYPE: return "WA_STATUS_UNSUPPORTED_TYPE";
    case WA_STATUS_UNSUPPORTED_FEATURE: return "WA_STATUS_UNSUPPORTED_FEATURE";
    case WA_STATUS_UNSUPPORTED_SIGNATURE: return "WA_STATUS_UNSUPPORTED_SIGNATURE";
    case WA_STATUS_UNSUPPORTED_ALGORITHM: return "WA_STATUS_UNSUPPORTED_ALGORITHM";
    case WA_STATUS_MISSING_PUBLIC_KEY: return "WA_STATUS_MISSING_PUBLIC_KEY";
    case WA_STATUS_KEY_CONSTRAINT_VIOLATION: return "WA_STATUS_KEY_CONSTRAINT_VIOLATION";
    case WA_STATUS_NESTING_TOO_DEEP: return "WA_STATUS_NESTING_TOO_DEEP";
    case WA_STATUS_OUT_OF_MEMORY: return "WA_STATUS_OUT_OF_MEMORY";
    case WA_STATUS_RANDOMNESS_FAILURE: return "WA_STATUS_RANDOMNESS_FAILURE";
    case WA_STATUS_CRYPTO_BACKEND_FAILURE: return "WA_STATUS_CRYPTO_BACKEND_FAILURE";
    case WA_STATUS_SINK_WRITE_FAILURE: return "WA_STATUS_SINK_WRITE_FAILURE";
    case WA_STATUS_WRONG_STATE: return "WA_STATUS_WRONG_STATE";
    case WA_STATUS_INTERNAL_ERROR: return "WA_STATUS_INTERNAL_ERROR";
    }
    return "WA_STATUS_<unknown>";
}

uint8_t *wa_tool_read_file(const char *path, size_t *length_out)
{
    int is_stdin = strcmp(path, "-") == 0;
    FILE *file;
    uint8_t *content = NULL;
    size_t length = 0;
    size_t capacity = 0;
    *length_out = 0;
#if defined(_WIN32)
    if (is_stdin) {
        (void)_setmode(_fileno(stdin), _O_BINARY);
    }
#endif
    file = is_stdin ? stdin : fopen(path, "rb");
    if (file == NULL) {
        return NULL;
    }
    for (;;) {
        size_t read_count;
        if (length == capacity) {
            size_t new_capacity = capacity == 0 ? 65536u : capacity * 2u;
            uint8_t *new_content = new_capacity > capacity ? (uint8_t *)realloc(content, new_capacity) : NULL;
            if (new_content == NULL) {
                free(content);
                content = NULL;
                break;
            }
            content = new_content;
            capacity = new_capacity;
        }
        read_count = fread(content + length, 1, capacity - length, file);
        length += read_count;
        if (read_count == 0) {
            if (ferror(file)) {
                free(content);
                content = NULL;
            }
            break;
        }
    }
    if (!is_stdin) {
        (void)fclose(file);
    }
    *length_out = content == NULL ? 0 : length;
    return content;
}

int wa_tool_file_exists(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }
    (void)fclose(file);
    return 1;
}

FILE *wa_tool_open_output_file(const char *path, int force)
{
#if defined(_WIN32)
    int file_descriptor = _open(path, _O_WRONLY | _O_CREAT | _O_BINARY | (force ? _O_TRUNC : _O_EXCL),
                                _S_IREAD | _S_IWRITE);
    FILE *file;
    if (file_descriptor < 0) {
        return NULL;
    }
    file = _fdopen(file_descriptor, "wb");
    if (file == NULL) {
        (void)_close(file_descriptor);
    }
    return file;
#else
    int file_descriptor = open(path, O_WRONLY | O_CREAT | O_CLOEXEC | (force ? O_TRUNC : O_EXCL), 0644);
    FILE *file;
    if (file_descriptor < 0) {
        return NULL;
    }
    file = fdopen(file_descriptor, "wb");
    if (file == NULL) {
        (void)close(file_descriptor);
    }
    return file;
#endif
}

static wa_status_t wa_tool_write_to_file(void *sink_context, const uint8_t *bytes, size_t length)
{
    if (length == 0) {
        return WA_STATUS_OK;
    }
    return fwrite(bytes, 1, length, (FILE *)sink_context) == length ? WA_STATUS_OK : WA_STATUS_SINK_WRITE_FAILURE;
}

wa_output_sink_t wa_tool_get_file_sink(FILE *file)
{
    wa_output_sink_t sink;
    sink.write = wa_tool_write_to_file;
    sink.sink_context = file;
    return sink;
}

static int wa_tool_ends_with_ignoring_case(const char *text, size_t text_length, const char *suffix)
{
    size_t suffix_length = strlen(suffix);
    size_t index;
    if (text_length < suffix_length) {
        return 0;
    }
    for (index = 0; index < suffix_length; ++index) {
        char character = text[text_length - suffix_length + index];
        if (character >= 'A' && character <= 'Z') {
            character = (char)(character - 'A' + 'a');
        }
        if (character != suffix[index]) {
            return 0;
        }
    }
    return 1;
}

char *wa_tool_build_cryptainer_path(const char *basename, wa_document_format_t document_format)
{
    static const char *const typed_suffixes[] = {".crypt.json", ".crypt.cbor", ".crypt"};
    const char *suffix = wa_document_format_get_cryptainer_suffix(document_format);
    size_t basename_length = strlen(basename);
    size_t suffix_index;
    char *path;
    if (suffix == NULL) {
        return NULL;
    }
    for (suffix_index = 0; suffix_index < sizeof(typed_suffixes) / sizeof(typed_suffixes[0]); ++suffix_index) {
        if (wa_tool_ends_with_ignoring_case(basename, basename_length, typed_suffixes[suffix_index])) {
            basename_length -= strlen(typed_suffixes[suffix_index]);
            break;
        }
    }
    if (basename_length == 0 || basename[basename_length - 1] == '/' || basename[basename_length - 1] == '\\') {
        return NULL; /* Nothing left to name the file */
    }
    path = (char *)malloc(basename_length + strlen(suffix) + 1u);
    if (path == NULL) {
        return NULL;
    }
    memcpy(path, basename, basename_length);
    strcpy(path + basename_length, suffix);
    return path;
}

char *wa_tool_build_payload_path(const char *cryptainer_path)
{
    char *path = (char *)malloc(strlen(cryptainer_path) + sizeof(".payload"));
    if (path != NULL) {
        strcpy(path, cryptainer_path);
        strcat(path, ".payload");
    }
    return path;
}

int wa_tool_parse_document_format(const char *name, wa_document_format_t *format_out)
{
    size_t length = strlen(name);
    if (length == 4 && wa_tool_ends_with_ignoring_case(name, length, "json")) {
        *format_out = WA_DOCUMENT_FORMAT_JSON;
        return 1;
    }
    if (length == 4 && wa_tool_ends_with_ignoring_case(name, length, "cbor")) {
        *format_out = WA_DOCUMENT_FORMAT_CBOR;
        return 1;
    }
    return 0;
}

static int wa_tool_get_hex_digit_value(char character)
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

uint8_t *wa_tool_decode_hex(const char *hex, size_t *length_out)
{
    size_t hex_length = strlen(hex);
    uint8_t *bytes;
    size_t index;
    *length_out = 0;
    if (hex_length % 2u != 0) {
        return NULL;
    }
    bytes = (uint8_t *)malloc(hex_length / 2u + 1u);
    if (bytes == NULL) {
        return NULL;
    }
    for (index = 0; index < hex_length / 2u; ++index) {
        int high = wa_tool_get_hex_digit_value(hex[2u * index]);
        int low = wa_tool_get_hex_digit_value(hex[2u * index + 1u]);
        if (high < 0 || low < 0) {
            free(bytes);
            return NULL;
        }
        bytes[index] = (uint8_t)((high << 4) | low);
    }
    *length_out = hex_length / 2u;
    return bytes;
}

void wa_tool_print_hex(FILE *stream, const uint8_t *bytes, size_t length)
{
    size_t index;
    for (index = 0; index < length; ++index) {
        fprintf(stream, "%02x", (unsigned)bytes[index]);
    }
}
