/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Helpers shared by the host CLI and the test driver: whole-file reading, exclusive file creation, file sinks,
 * cryptainer output naming (design D14), hex, status names. */

#ifndef WA_TOOL_COMMON_H
#define WA_TOOL_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "wa_flightbox/wa_flightbox.h"

/* "WA_STATUS_OK", "WA_STATUS_INVALID_PROFILE"... or "WA_STATUS_<unknown>" */
const char *wa_tool_get_status_name(wa_status_t status);

/* Read a whole file ("-" for stdin) into a malloc()'d buffer (at least 1 byte); NULL on failure */
uint8_t *wa_tool_read_file(const char *path, size_t *length_out);

/* 1 if a file (or directory) exists at `path`, readable or not */
int wa_tool_file_exists(const char *path);

/* 1 if both paths exist and are the same file (whatever their spelling, links included) */
int wa_tool_files_are_same(const char *path_a, const char *path_b);

/* Open for binary writing: exclusive creation (failing if the file exists), or truncation with `force` */
FILE *wa_tool_open_output_file(const char *path, int force);

/* Exclusive creation of a new file next to `final_path`, named "<final_path>.tmp-NNN"; its malloc()'d name goes
 * to `*temporary_path_out`. NULL on failure. */
FILE *wa_tool_open_temporary_output_file(const char *final_path, char **temporary_path_out);

/* Rename `source_path` to `destination_path`, replacing it if it exists (on the same file system); 0 or -1 */
int wa_tool_replace_file(const char *source_path, const char *destination_path);

/* A sink writing to an open FILE (context: the FILE) */
wa_output_sink_t wa_tool_get_file_sink(FILE *file);

/* Cryptainer path (design D14): a trailing ".crypt", ".crypt.json" or ".crypt.cbor", in any letter case, is
 * stripped from `basename`, then the lowercase suffix of `document_format` is appended. malloc()'d, NULL on
 * failure. */
char *wa_tool_build_cryptainer_path(const char *basename, wa_document_format_t document_format);

/* `path` + ".payload", malloc()'d */
char *wa_tool_build_payload_path(const char *cryptainer_path);

/* "json" -> JSON, "cbor" -> CBOR (any letter case); 0 if unknown */
int wa_tool_parse_document_format(const char *name, wa_document_format_t *format_out);

/* Hex decoding into a malloc()'d buffer (at least 1 byte); "" gives 0 bytes; NULL on invalid hex */
uint8_t *wa_tool_decode_hex(const char *hex, size_t *length_out);

/* Print bytes as lowercase hex */
void wa_tool_print_hex(FILE *stream, const uint8_t *bytes, size_t length);

#endif /* WA_TOOL_COMMON_H */
