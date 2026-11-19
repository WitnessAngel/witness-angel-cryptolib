/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Helpers shared by the host CLI and the test driver: whole-file reading, exclusive file creation, file sinks,
 * cryptainer output naming (design D14), hex, status names.
 *
 * Paths are those of main()'s arguments: in the ANSI code page on Windows, unless wa_tool_get_utf8_arguments() is
 * called first. */

#ifndef WA_TOOL_COMMON_H
#define WA_TOOL_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "wa_flightbox/wa_flightbox.h"

/* "WA_STATUS_OK", "WA_STATUS_INVALID_PROFILE"... or "WA_STATUS_<unknown>" */
const char *wa_tool_get_status_name(wa_status_t status);

/* On Windows, replace main()'s arguments by the UTF-8 conversion of the wide-character command line (kept for the
 * life of the process), every path given to the functions below being UTF-8 from then on: files are reachable
 * whatever their name, which the ANSI code page of main()'s arguments does not allow. Unlike main()'s, these
 * arguments have no wildcard expanded. Nothing to do elsewhere. 1, or 0 on failure (arguments unchanged). */
int wa_tool_get_utf8_arguments(int *argument_count, char ***arguments);

/* Open for binary reading; NULL on failure */
FILE *wa_tool_open_input_file(const char *path);

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

/* Rename `source_path` to `destination_path`, replacing it if it exists (on the same file system); 0 or -1. To
 * survive a power loss, the source is to be synchronized before, and the directory after. */
int wa_tool_replace_file(const char *source_path, const char *destination_path);

/* Rename the file at `path` to a new name next to it, "<path>.old-NNN", returned malloc()'d; NULL on failure, the
 * file being left in place */
char *wa_tool_move_file_aside(const char *path);

/* 1 if `path` is an existing file that the system refuses to replace or delete because of its read-only attribute
 * (Windows; always 0 on POSIX systems, where this only depends on the directory) */
int wa_tool_file_is_read_only(const char *path);

/* Delete a file; 0 or -1 */
int wa_tool_remove_file(const char *path);

/* Flush an open output file down to its storage device; 0 or -1 */
int wa_tool_sync_file(FILE *file);

/* Make the creations, renamings and deletions done in the directory of `path` durable (POSIX systems; nothing to
 * do on Windows, where renamings are written through); 0 or -1 */
int wa_tool_sync_directory_of_file(const char *path);

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
