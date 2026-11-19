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
#include <wchar.h>
#include <windows.h>

#include <shellapi.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#if defined(_WIN32)
/* Code page of the paths given to the functions of this file, all going through the wide-character APIs: the ANSI
 * one, that of main()'s arguments, or UTF-8 once wa_tool_get_utf8_arguments() has replaced these arguments */
static UINT wa_tool_path_code_page = CP_ACP;

/* malloc()'d wide-character path; NULL on failure (invalid UTF-8 included) */
static wchar_t *wa_tool_convert_path_to_wide(const char *path)
{
    DWORD flags = wa_tool_path_code_page == CP_UTF8 ? MB_ERR_INVALID_CHARS : 0;
    int length = MultiByteToWideChar(wa_tool_path_code_page, flags, path, -1, NULL, 0);
    wchar_t *wide_path;
    if (length <= 0) {
        return NULL;
    }
    wide_path = (wchar_t *)malloc((size_t)length * sizeof(wchar_t));
    if (wide_path != NULL &&
        MultiByteToWideChar(wa_tool_path_code_page, flags, path, -1, wide_path, length) != length) {
        free(wide_path);
        wide_path = NULL;
    }
    return wide_path;
}
#endif

int wa_tool_get_utf8_arguments(int *argument_count, char ***arguments)
{
#if defined(_WIN32)
    int wide_count = 0;
    wchar_t **wide_arguments = CommandLineToArgvW(GetCommandLineW(), &wide_count);
    char **utf8_arguments = NULL;
    int index = 0;
    if (wide_arguments != NULL && wide_count > 0) {
        utf8_arguments = (char **)calloc((size_t)wide_count + 1u, sizeof(char *));
    }
    for (; utf8_arguments != NULL && index < wide_count; ++index) {
        /* Unpaired surrogates are refused: they would name another file once converted */
        int length =
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide_arguments[index], -1, NULL, 0, NULL, NULL);
        utf8_arguments[index] = length > 0 ? (char *)malloc((size_t)length) : NULL;
        if (utf8_arguments[index] == NULL ||
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide_arguments[index], -1, utf8_arguments[index],
                                length, NULL, NULL) != length) {
            break;
        }
    }
    if (wide_arguments != NULL) {
        (void)LocalFree(wide_arguments);
    }
    if (utf8_arguments == NULL || index < wide_count) {
        for (; utf8_arguments != NULL && index >= 0; --index) {
            free(utf8_arguments[index]);
        }
        free(utf8_arguments);
        return 0;
    }
    wa_tool_path_code_page = CP_UTF8;
    *argument_count = wide_count;
    *arguments = utf8_arguments;
    return 1;
#else
    (void)argument_count;
    (void)arguments;
    return 1;
#endif
}

FILE *wa_tool_open_input_file(const char *path)
{
#if defined(_WIN32)
    wchar_t *wide_path = wa_tool_convert_path_to_wide(path);
    FILE *file = wide_path != NULL ? _wfopen(wide_path, L"rb") : NULL;
    free(wide_path);
    return file;
#else
    return fopen(path, "rb");
#endif
}

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
    file = is_stdin ? stdin : wa_tool_open_input_file(path);
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
#if defined(_WIN32)
    struct _stat64 file_status;
    wchar_t *wide_path = wa_tool_convert_path_to_wide(path);
    int is_existing = wide_path != NULL && _wstat64(wide_path, &file_status) == 0;
    free(wide_path);
    return is_existing;
#else
    struct stat file_status;
    return stat(path, &file_status) == 0;
#endif
}

int wa_tool_files_are_same(const char *path_a, const char *path_b)
{
#if defined(_WIN32)
    /* st_ino is always 0 on Windows: compare volume serial numbers and file indexes */
    BY_HANDLE_FILE_INFORMATION informations[2];
    const char *paths[2];
    int index;
    paths[0] = path_a;
    paths[1] = path_b;
    for (index = 0; index < 2; ++index) {
        BOOL is_read;
        wchar_t *wide_path = wa_tool_convert_path_to_wide(paths[index]);
        HANDLE handle = wide_path == NULL
                            ? INVALID_HANDLE_VALUE
                            : CreateFileW(wide_path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                          OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        free(wide_path);
        if (handle == INVALID_HANDLE_VALUE) {
            return 0;
        }
        is_read = GetFileInformationByHandle(handle, &informations[index]);
        (void)CloseHandle(handle);
        if (!is_read) {
            return 0;
        }
    }
    return informations[0].dwVolumeSerialNumber == informations[1].dwVolumeSerialNumber &&
           informations[0].nFileIndexHigh == informations[1].nFileIndexHigh &&
           informations[0].nFileIndexLow == informations[1].nFileIndexLow;
#else
    struct stat status_a;
    struct stat status_b;
    return stat(path_a, &status_a) == 0 && stat(path_b, &status_b) == 0 && status_a.st_dev == status_b.st_dev &&
           status_a.st_ino == status_b.st_ino;
#endif
}

FILE *wa_tool_open_temporary_output_file(const char *final_path, char **temporary_path_out)
{
    size_t length = strlen(final_path);
    char *temporary_path = (char *)malloc(length + sizeof(".tmp-000"));
    unsigned int attempt;
    *temporary_path_out = NULL;
    if (temporary_path == NULL) {
        return NULL;
    }
    for (attempt = 0; attempt < 1000u; ++attempt) {
        FILE *file;
        (void)sprintf(temporary_path, "%s.tmp-%03u", final_path, attempt);
        file = wa_tool_open_output_file(temporary_path, 0);
        if (file != NULL) {
            *temporary_path_out = temporary_path;
            return file;
        }
        if (!wa_tool_file_exists(temporary_path)) {
            break; /* Not a name clash: the directory is not writable */
        }
    }
    free(temporary_path);
    return NULL;
}

int wa_tool_replace_file(const char *source_path, const char *destination_path)
{
#if defined(_WIN32)
    wchar_t *wide_source_path = wa_tool_convert_path_to_wide(source_path);
    wchar_t *wide_destination_path = wa_tool_convert_path_to_wide(destination_path);
    BOOL is_moved = wide_source_path != NULL && wide_destination_path != NULL &&
                    MoveFileExW(wide_source_path, wide_destination_path,
                                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    free(wide_source_path);
    free(wide_destination_path);
    return is_moved ? 0 : -1;
#else
    return rename(source_path, destination_path) == 0 ? 0 : -1;
#endif
}

int wa_tool_remove_file(const char *path)
{
#if defined(_WIN32)
    wchar_t *wide_path = wa_tool_convert_path_to_wide(path);
    int result = wide_path != NULL && _wremove(wide_path) == 0 ? 0 : -1;
    free(wide_path);
    return result;
#else
    return remove(path) == 0 ? 0 : -1;
#endif
}

FILE *wa_tool_open_output_file(const char *path, int force)
{
#if defined(_WIN32)
    wchar_t *wide_path = wa_tool_convert_path_to_wide(path);
    int file_descriptor = -1;
    FILE *file;
    if (wide_path != NULL) {
        file_descriptor = _wopen(wide_path, _O_WRONLY | _O_CREAT | _O_BINARY | (force ? _O_TRUNC : _O_EXCL),
                                 _S_IREAD | _S_IWRITE);
        free(wide_path);
    }
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
