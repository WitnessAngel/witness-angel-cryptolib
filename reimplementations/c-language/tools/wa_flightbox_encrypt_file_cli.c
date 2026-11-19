/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Host command-line tool: encrypt a file into a cryptainer with a device profile, like "flightbox encrypt" does
 * with a cryptoconf (output naming of design D14, spec section 9). The payload ciphertext is offloaded into
 * "<cryptainer file>.payload" unless --bundle is given; the payload file is written first and the cryptainer last,
 * so that a cryptainer never refers to a missing payload, and the files created are deleted on failure. With
 * --force, existing output files are only replaced (by renaming) once their new versions are complete, and a
 * replaced payload file is put back if its cryptainer cannot be replaced too; output files that are one of the
 * input files are always refused. With --bundle, an existing "<cryptainer file>.payload" is refused as well, and
 * deleted with --force once the cryptainer is written: it would pass for the payload of the new cryptainer. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

#include "wa_flightbox/wa_flightbox.h"
#include "wa_host_platform_hooks.h"
#include "wa_tool_common.h"

#define WA_CLI_DEFAULT_CHUNK_SIZE (1024u * 1024u)
#define WA_CLI_MAXIMUM_CHUNK_SIZE (1024u * 1024u * 1024u)
#define WA_CLI_ERROR_LOCATION_SIZE 256u

typedef struct wa_cli_arguments {
    const char *input_path;
    const char *profile_path;
    const char *metadata_path;   /* NULL: no metadata */
    const char *output_basename; /* NULL: the input path */
    wa_document_format_t document_format;
    int is_bundle;
    int is_forced;
    size_t chunk_size;
} wa_cli_arguments_t;

static void wa_cli_print_usage(FILE *stream)
{
    fprintf(stream,
            "Usage: wa_flightbox_encrypt_file_cli -p PROFILE [options] INPUT_FILE\n"
            "\n"
            "Encrypt INPUT_FILE (or '-' for stdin) into a cryptainer, with a WA-CBOR device profile.\n"
            "\n"
            "Options:\n"
            "  -p, --profile FILE          device profile (WA-CBOR), required\n"
            "  -o, --output-basename NAME  basename of the output files (default: INPUT_FILE); a trailing\n"
            "                              .crypt, .crypt.json or .crypt.cbor suffix, in any case, is stripped\n"
            "  -m, --metadata FILE         cryptainer metadata, a WA-CBOR map (default: none)\n"
            "  --format json|cbor          cryptainer format, also used for its key ciphertexts (default: %s)\n"
            "  --bundle                    embed the payload ciphertext in the cryptainer (default: offloaded\n"
            "                              into <cryptainer file>.payload, which must not exist with --bundle)\n"
            "  --chunk-size N              bytes read from the input at a time, at most 1 GiB (default: %u)\n"
            "  --force                     replace existing output files, once the new ones are complete (with\n"
            "                              --bundle, delete an existing <cryptainer file>.payload)\n"
            "  -h, --help                  show this help\n"
            "\n"
            "Formats of this build:%s%s\n",
            WA_DOCUMENT_FORMAT_JSON_ENABLED ? "json" : "cbor", (unsigned)WA_CLI_DEFAULT_CHUNK_SIZE,
            WA_DOCUMENT_FORMAT_JSON_ENABLED ? " json" : "", WA_DOCUMENT_FORMAT_CBOR_ENABLED ? " cbor" : "");
}

/* 0 on success, 1 on usage error, 2 for --help */
static int wa_cli_parse_arguments(int argument_count, char **arguments, wa_cli_arguments_t *parsed)
{
    int index;
    memset(parsed, 0, sizeof(*parsed));
    parsed->document_format = WA_DOCUMENT_FORMAT_BUILD_DEFAULT;
    parsed->chunk_size = WA_CLI_DEFAULT_CHUNK_SIZE;
    for (index = 1; index < argument_count; ++index) {
        const char *argument = arguments[index];
        const char *value = index + 1 < argument_count ? arguments[index + 1] : NULL;
        if (strcmp(argument, "-h") == 0 || strcmp(argument, "--help") == 0) {
            return 2;
        } else if (strcmp(argument, "--bundle") == 0) {
            parsed->is_bundle = 1;
        } else if (strcmp(argument, "--force") == 0) {
            parsed->is_forced = 1;
        } else if (strcmp(argument, "-p") == 0 || strcmp(argument, "--profile") == 0 || strcmp(argument, "-o") == 0 ||
                   strcmp(argument, "--output-basename") == 0 || strcmp(argument, "-m") == 0 ||
                   strcmp(argument, "--metadata") == 0 || strcmp(argument, "--format") == 0 ||
                   strcmp(argument, "--chunk-size") == 0) {
            if (value == NULL) {
                fprintf(stderr, "Error: option %s needs a value\n", argument);
                return 1;
            }
            ++index;
            if (argument[1] == 'p' || strcmp(argument, "--profile") == 0) {
                parsed->profile_path = value;
            } else if (argument[1] == 'o' || strcmp(argument, "--output-basename") == 0) {
                parsed->output_basename = value;
            } else if (argument[1] == 'm' || strcmp(argument, "--metadata") == 0) {
                parsed->metadata_path = value;
            } else if (strcmp(argument, "--format") == 0) {
                if (!wa_tool_parse_document_format(value, &parsed->document_format)) {
                    fprintf(stderr, "Error: unknown format %s (json or cbor)\n", value);
                    return 1;
                }
            } else {
                char *end = NULL;
                unsigned long chunk_size;
                errno = 0;
                /* Digits only: strtoul() would accept a sign (and wrap "-1" around) or leading spaces */
                chunk_size = value[0] >= '0' && value[0] <= '9' ? strtoul(value, &end, 10) : 0;
                if (end == NULL || *end != '\0' || chunk_size == 0 || errno == ERANGE ||
                    chunk_size > (unsigned long)WA_CLI_MAXIMUM_CHUNK_SIZE) {
                    fprintf(stderr, "Error: invalid chunk size %s\n", value);
                    return 1;
                }
                parsed->chunk_size = (size_t)chunk_size;
            }
        } else if (argument[0] == '-' && argument[1] != '\0') {
            fprintf(stderr, "Error: unknown option %s\n", argument);
            return 1;
        } else if (parsed->input_path == NULL) {
            parsed->input_path = argument;
        } else {
            fprintf(stderr, "Error: unexpected argument %s\n", argument);
            return 1;
        }
    }
    if (parsed->input_path == NULL || parsed->profile_path == NULL) {
        fprintf(stderr, "Error: an input file and a profile (-p) are required\n");
        return 1;
    }
    if ((strcmp(parsed->input_path, "-") == 0) + (strcmp(parsed->profile_path, "-") == 0) +
            (parsed->metadata_path != NULL && strcmp(parsed->metadata_path, "-") == 0) >
        1) {
        fprintf(stderr, "Error: stdin ('-') can only be one of the input file, the profile and the metadata\n");
        return 1;
    }
    if (strcmp(parsed->input_path, "-") == 0 && parsed->output_basename == NULL) {
        fprintf(stderr, "Error: an output basename (-o) is required when the input is stdin\n");
        return 1;
    }
    return 0;
}

static void wa_cli_print_status_error(const char *context, wa_status_t status, const char *location_or_null)
{
    fprintf(stderr, "Error: %s: %s [%s]", context, wa_status_get_description(status), wa_tool_get_status_name(status));
    if (location_or_null != NULL && location_or_null[0] != '\0') {
        fprintf(stderr, " at %s", location_or_null);
    }
    fprintf(stderr, "\n");
}

/* An output file. Without --force it is created exclusively at its final path; with --force it is written to a
 * new temporary file next to it, renamed over the final path only once complete, so that a failure never loses
 * the existing file. */
typedef struct wa_cli_output {
    const char *final_path;
    char *temporary_path; /* malloc()'d, with --force only */
    FILE *file;
    int is_created; /* the file at the write path was created by this run, and is deleted on failure */
} wa_cli_output_t;

static const char *wa_cli_output_get_write_path(const wa_cli_output_t *output)
{
    return output->temporary_path != NULL ? output->temporary_path : output->final_path;
}

static int wa_cli_output_open(wa_cli_output_t *output, int is_forced)
{
    output->file = is_forced ? wa_tool_open_temporary_output_file(output->final_path, &output->temporary_path)
                             : wa_tool_open_output_file(output->final_path, 0);
    if (output->file == NULL) {
        fprintf(stderr, "Error: cannot create %s%s\n", output->final_path,
                is_forced ? " (temporary file)" : " (existing file?)");
        return 0;
    }
    output->is_created = 1;
    return 1;
}

static int wa_cli_output_close(wa_cli_output_t *output)
{
    int close_result = fclose(output->file);
    output->file = NULL;
    return close_result == 0;
}

/* Move the temporary file of a complete output to its final path, which becomes its write path */
static int wa_cli_output_move_to_final_path(wa_cli_output_t *output)
{
    if (wa_tool_replace_file(output->temporary_path, output->final_path) != 0) {
        fprintf(stderr, "Error: cannot replace %s\n", output->final_path);
        return 0;
    }
    free(output->temporary_path);
    output->temporary_path = NULL;
    return 1;
}

/* Keep complete outputs. Without --force they are at their final paths already. With --force their temporary files
 * are renamed to the final paths, payload first; an existing payload file is moved aside before, and put back if
 * the new pair cannot be completed, so that the final paths hold either the previous outputs or the new ones,
 * never a cryptainer with the payload of another one. If it cannot even be put back, nothing is deleted, and the
 * files holding the previous payload and the new outputs are reported. With --bundle and --force, the payload file
 * of a previous offloaded cryptainer, `stale_payload_path_or_null`, is deleted once the cryptainer is replaced. */
static int wa_cli_commit_outputs(wa_cli_output_t *cryptainer_output, wa_cli_output_t *payload_output_or_null,
                                 const char *stale_payload_path_or_null)
{
    const char *payload_path = payload_output_or_null != NULL ? payload_output_or_null->final_path : NULL;
    char *payload_backup_path = NULL;
    int is_successful = 1;

    if (cryptainer_output->temporary_path != NULL) {
        /* What a read-only attribute forbids (Windows) is refused before anything is moved */
        const char *replaced_payload_path = payload_path != NULL ? payload_path : stale_payload_path_or_null;
        const char *read_only_path =
            wa_tool_file_is_read_only(cryptainer_output->final_path) ? cryptainer_output->final_path
            : replaced_payload_path != NULL && wa_tool_file_is_read_only(replaced_payload_path) ? replaced_payload_path
                                                                                                : NULL;
        if (read_only_path != NULL) {
            fprintf(stderr, "Error: cannot replace %s (read-only file)\n", read_only_path);
            return 0;
        }
        if (payload_path != NULL && wa_tool_file_exists(payload_path)) {
            payload_backup_path = wa_tool_move_file_aside(payload_path);
            if (payload_backup_path == NULL) {
                fprintf(stderr, "Error: cannot replace %s\n", payload_path);
                return 0;
            }
        }
        /* Once at its final path, a new payload file is still deleted from there on failure */
        is_successful =
            (payload_output_or_null == NULL || wa_cli_output_move_to_final_path(payload_output_or_null)) &&
            wa_cli_output_move_to_final_path(cryptainer_output);
        if (!is_successful && payload_backup_path != NULL) {
            if (wa_tool_replace_file(payload_backup_path, payload_path) == 0) {
                if (payload_output_or_null->temporary_path == NULL) {
                    payload_output_or_null->is_created = 0; /* Replaced by the previous payload file */
                }
            } else {
                fprintf(stderr,
                        "Error: cannot restore %s: nothing is deleted, the previous payload being in %s, the new "
                        "payload in %s and the new cryptainer in %s\n",
                        payload_path, payload_backup_path, wa_cli_output_get_write_path(payload_output_or_null),
                        wa_cli_output_get_write_path(cryptainer_output));
                payload_output_or_null->is_created = 0;
                cryptainer_output->is_created = 0;
            }
        }
        if (!is_successful) {
            free(payload_backup_path);
            return 0;
        }
    }
    /* The outputs are at their final paths, where they may have replaced existing files */
    cryptainer_output->is_created = 0;
    if (payload_output_or_null != NULL) {
        payload_output_or_null->is_created = 0;
    }
    if (payload_backup_path != NULL && wa_tool_remove_file(payload_backup_path) != 0) {
        fprintf(stderr, "Error: cannot delete %s (the previous payload file)\n", payload_backup_path);
        is_successful = 0;
    }
    free(payload_backup_path);
    if (stale_payload_path_or_null != NULL && wa_tool_file_exists(stale_payload_path_or_null) &&
        wa_tool_remove_file(stale_payload_path_or_null) != 0) {
        fprintf(stderr, "Error: cannot delete %s (the previous payload file)\n", stale_payload_path_or_null);
        is_successful = 0;
    }
    return is_successful;
}

/* Close, delete if created by this run and not committed, and release */
static void wa_cli_output_discard(wa_cli_output_t *output)
{
    if (output->file != NULL) {
        (void)fclose(output->file);
        output->file = NULL;
    }
    if (output->is_created) {
        (void)wa_tool_remove_file(wa_cli_output_get_write_path(output));
        output->is_created = 0;
    }
    free(output->temporary_path);
    output->temporary_path = NULL;
}

/* Run the encryption proper: the payload file first and the cryptainer last (also renamed in that order with
 * --force), so that a new cryptainer never refers to a missing payload. `stale_payload_path_or_null`: see
 * wa_cli_commit_outputs(). */
static int wa_cli_encrypt(const wa_cli_arguments_t *arguments, const wa_platform_hooks_t *platform_hooks,
                          const wa_device_profile_t *device_profile, const wa_value_t *metadata_or_null,
                          wa_cli_output_t *cryptainer_output, wa_cli_output_t *payload_output_or_null,
                          const char *stale_payload_path_or_null)
{
    wa_cryptainer_encryptor_options_t options;
    wa_cryptainer_encryptor_t *encryptor = NULL;
    wa_output_sink_t payload_sink;
    wa_output_sink_t cryptainer_sink;
    FILE *input_file;
    uint8_t *chunk;
    wa_status_t status;
    int is_stdin = strcmp(arguments->input_path, "-") == 0;
    int exit_code = 1;

#if defined(_WIN32)
    if (is_stdin) {
        (void)_setmode(_fileno(stdin), _O_BINARY);
    }
#endif
    input_file = is_stdin ? stdin : wa_tool_open_input_file(arguments->input_path);
    if (input_file == NULL) {
        fprintf(stderr, "Error: cannot open the input file %s\n", arguments->input_path);
        return 1;
    }
    chunk = (uint8_t *)malloc(arguments->chunk_size);
    if (chunk == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        goto cleanup;
    }

    if (payload_output_or_null != NULL) {
        if (!wa_cli_output_open(payload_output_or_null, arguments->is_forced)) {
            goto cleanup;
        }
        payload_sink = wa_tool_get_file_sink(payload_output_or_null->file);
    }
    options.platform_hooks = platform_hooks;
    options.document_format = arguments->document_format;
    options.ciphertext_location =
        payload_output_or_null != NULL ? WA_CIPHERTEXT_LOCATION_OFFLOADED : WA_CIPHERTEXT_LOCATION_INLINE;
    options.payload_ciphertext_sink = payload_output_or_null != NULL ? &payload_sink : NULL;
    status = wa_cryptainer_encryptor_create(device_profile, metadata_or_null, &options, &encryptor);
    if (status != WA_STATUS_OK) {
        wa_cli_print_status_error("cryptainer creation failed", status, NULL);
        goto cleanup;
    }
    for (;;) {
        size_t read_count = fread(chunk, 1, arguments->chunk_size, input_file);
        if (read_count > 0) {
            status = wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, chunk, read_count);
            if (status != WA_STATUS_OK) {
                wa_cli_print_status_error("payload encryption failed", status, NULL);
                goto cleanup;
            }
        }
        if (read_count < arguments->chunk_size) {
            if (ferror(input_file)) {
                fprintf(stderr, "Error: cannot read the input file %s\n", arguments->input_path);
                goto cleanup;
            }
            if (feof(input_file)) {
                break;
            }
        }
    }
    status = wa_cryptainer_encryptor_finalize(encryptor);
    if (status != WA_STATUS_OK) {
        wa_cli_print_status_error("finalization failed", status, NULL);
        goto cleanup;
    }
    if (payload_output_or_null != NULL && !wa_cli_output_close(payload_output_or_null)) {
        fprintf(stderr, "Error: cannot write %s\n", wa_cli_output_get_write_path(payload_output_or_null));
        goto cleanup;
    }

    if (!wa_cli_output_open(cryptainer_output, arguments->is_forced)) {
        goto cleanup;
    }
    cryptainer_sink = wa_tool_get_file_sink(cryptainer_output->file);
    status = wa_cryptainer_encryptor_write_cryptainer(encryptor, &cryptainer_sink);
    if (!wa_cli_output_close(cryptainer_output) && status == WA_STATUS_OK) {
        status = WA_STATUS_SINK_WRITE_FAILURE;
    }
    if (status != WA_STATUS_OK) {
        wa_cli_print_status_error("cryptainer writing failed", status, NULL);
        goto cleanup;
    }
    if (!wa_cli_commit_outputs(cryptainer_output, payload_output_or_null, stale_payload_path_or_null)) {
        goto cleanup;
    }
    printf("%s\n", cryptainer_output->final_path);
    if (payload_output_or_null != NULL) {
        printf("%s\n", payload_output_or_null->final_path);
    }
    exit_code = 0;

cleanup:
    wa_cryptainer_encryptor_destroy(encryptor);
    free(chunk);
    if (!is_stdin) {
        (void)fclose(input_file);
    }
    return exit_code;
}

/* Refuse an output path that is one of the input files: with --force, that input would be replaced (and the input
 * file read while being replaced). Only an existing output can be such a file. */
static int wa_cli_check_output_is_not_an_input(const wa_cli_arguments_t *arguments, const char *output_path)
{
    static const char *const input_names[3] = {"input file", "profile", "metadata file"};
    const char *input_paths[3];
    size_t index;
    input_paths[0] = arguments->input_path;
    input_paths[1] = arguments->profile_path;
    input_paths[2] = arguments->metadata_path;
    for (index = 0; index < 3u; ++index) {
        if (input_paths[index] != NULL && strcmp(input_paths[index], "-") != 0 &&
            wa_tool_files_are_same(output_path, input_paths[index])) {
            fprintf(stderr, "Error: the output file %s is the %s\n", output_path, input_names[index]);
            return 0;
        }
    }
    return 1;
}

int main(int argument_count, char **arguments)
{
    wa_cli_arguments_t parsed;
    wa_platform_hooks_t platform_hooks;
    wa_device_profile_t *device_profile = NULL;
    wa_value_t *metadata = NULL;
    char error_location[WA_CLI_ERROR_LOCATION_SIZE];
    char *cryptainer_path = NULL;
    char *payload_path = NULL;
    wa_cli_output_t cryptainer_output;
    wa_cli_output_t payload_output;
    uint8_t *file_content;
    size_t file_length = 0;
    wa_status_t status;
    int exit_code = 1;

    memset(&cryptainer_output, 0, sizeof(cryptainer_output));
    memset(&payload_output, 0, sizeof(payload_output));
    /* On Windows, main()'s arguments are in the ANSI code page, which cannot name every file */
    if (!wa_tool_get_utf8_arguments(&argument_count, &arguments)) {
        fprintf(stderr, "Error: cannot read the command line\n");
        return 1;
    }
    switch (wa_cli_parse_arguments(argument_count, arguments, &parsed)) {
    case 0:
        break;
    case 2:
        wa_cli_print_usage(stdout);
        return 0;
    default:
        wa_cli_print_usage(stderr);
        return 2;
    }
    wa_host_platform_hooks_initialize(&platform_hooks, NULL);
    if (!wa_document_format_is_enabled(parsed.document_format)) {
        fprintf(stderr, "Error: this build does not support the %s format\n",
                parsed.document_format == WA_DOCUMENT_FORMAT_CBOR ? "cbor" : "json");
        return 1;
    }

    /* Output names, refused early (nothing is generated then) when existing, or when one of the input files. With
     * --bundle, the payload file is the one a previous offloaded cryptainer of that name would have: left there, it
     * would pass for the payload of the new cryptainer, hence refused as well, and deleted with --force. */
    cryptainer_path = wa_tool_build_cryptainer_path(
        parsed.output_basename != NULL ? parsed.output_basename : parsed.input_path, parsed.document_format);
    if (cryptainer_path == NULL) {
        fprintf(stderr, "Error: invalid output basename\n");
        goto cleanup;
    }
    payload_path = wa_tool_build_payload_path(cryptainer_path);
    if (payload_path == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        goto cleanup;
    }
    if (!wa_cli_check_output_is_not_an_input(&parsed, cryptainer_path) ||
        !wa_cli_check_output_is_not_an_input(&parsed, payload_path)) {
        goto cleanup;
    }
    if (!parsed.is_forced) {
        if (wa_tool_file_exists(cryptainer_path)) {
            fprintf(stderr, "Error: %s already exists (use --force to overwrite it)\n", cryptainer_path);
            goto cleanup;
        }
        if (wa_tool_file_exists(payload_path)) {
            fprintf(stderr, "Error: %s already exists (use --force to %s it)\n", payload_path,
                    parsed.is_bundle ? "delete" : "overwrite");
            goto cleanup;
        }
    }

    /* Profile and metadata */
    file_content = wa_tool_read_file(parsed.profile_path, &file_length);
    if (file_content == NULL) {
        fprintf(stderr, "Error: cannot read the profile %s\n", parsed.profile_path);
        goto cleanup;
    }
    status = wa_device_profile_load_from_cbor(file_content, file_length, &platform_hooks, &device_profile,
                                              error_location, sizeof(error_location));
    free(file_content);
    if (status != WA_STATUS_OK) {
        wa_cli_print_status_error("invalid device profile", status, error_location);
        goto cleanup;
    }
    if (parsed.metadata_path != NULL) {
        file_content = wa_tool_read_file(parsed.metadata_path, &file_length);
        if (file_content == NULL) {
            fprintf(stderr, "Error: cannot read the metadata %s\n", parsed.metadata_path);
            goto cleanup;
        }
        status = wa_value_tree_decode_from_cbor(file_content, file_length, &platform_hooks, &metadata);
        free(file_content);
        if (status != WA_STATUS_OK) {
            wa_cli_print_status_error("invalid metadata", status, NULL);
            goto cleanup;
        }
    }

    cryptainer_output.final_path = cryptainer_path;
    payload_output.final_path = payload_path;
    exit_code = wa_cli_encrypt(&parsed, &platform_hooks, device_profile, metadata, &cryptainer_output,
                               parsed.is_bundle ? NULL : &payload_output,
                               parsed.is_bundle && parsed.is_forced ? payload_path : NULL);

cleanup:
    /* On failure, delete what this run created and did not move to a final path, cryptainer first */
    wa_cli_output_discard(&cryptainer_output);
    wa_cli_output_discard(&payload_output);
    wa_value_destroy(metadata);
    wa_device_profile_destroy(device_profile);
    free(cryptainer_path);
    free(payload_path);
    return exit_code;
}
