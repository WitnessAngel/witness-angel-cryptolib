/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Host command-line tool: encrypt a file into a cryptainer with a device profile, like "flightbox encrypt" does
 * with a cryptoconf (output naming of design D14, spec section 9). The payload ciphertext is offloaded into
 * "<cryptainer file>.payload" unless --bundle is given; the payload file is written first and the cryptainer last,
 * so that a cryptainer never refers to a missing payload, and the files created are deleted on failure. */

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
            "                              into <cryptainer file>.payload)\n"
            "  --chunk-size N              bytes read from the input at a time (default: %u)\n"
            "  --force                     overwrite existing output files\n"
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
                unsigned long chunk_size = strtoul(value, &end, 10);
                if (end == value || *end != '\0' || chunk_size == 0) {
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

/* Run the encryption proper; files are created here, and deleted by the caller on failure */
static int wa_cli_encrypt(const wa_cli_arguments_t *arguments, const wa_platform_hooks_t *platform_hooks,
                          const wa_device_profile_t *device_profile, const wa_value_t *metadata_or_null,
                          const char *cryptainer_path, const char *payload_path_or_null, int *is_payload_created,
                          int *is_cryptainer_created)
{
    wa_cryptainer_encryptor_options_t options;
    wa_cryptainer_encryptor_t *encryptor = NULL;
    wa_output_sink_t payload_sink;
    wa_output_sink_t cryptainer_sink;
    FILE *payload_file = NULL;
    FILE *cryptainer_file = NULL;
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
    input_file = is_stdin ? stdin : fopen(arguments->input_path, "rb");
    if (input_file == NULL) {
        fprintf(stderr, "Error: cannot open the input file %s\n", arguments->input_path);
        return 1;
    }
    chunk = (uint8_t *)malloc(arguments->chunk_size);
    if (chunk == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        goto cleanup;
    }

    if (payload_path_or_null != NULL) {
        payload_file = wa_tool_open_output_file(payload_path_or_null, arguments->is_forced);
        if (payload_file == NULL) {
            fprintf(stderr, "Error: cannot create %s (existing file?)\n", payload_path_or_null);
            goto cleanup;
        }
        *is_payload_created = 1;
        payload_sink = wa_tool_get_file_sink(payload_file);
    }
    options.platform_hooks = platform_hooks;
    options.document_format = arguments->document_format;
    options.ciphertext_location =
        payload_path_or_null != NULL ? WA_CIPHERTEXT_LOCATION_OFFLOADED : WA_CIPHERTEXT_LOCATION_INLINE;
    options.payload_ciphertext_sink = payload_path_or_null != NULL ? &payload_sink : NULL;
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
    if (payload_file != NULL) {
        int close_result = fclose(payload_file);
        payload_file = NULL;
        if (close_result != 0) {
            fprintf(stderr, "Error: cannot write %s\n", payload_path_or_null);
            goto cleanup;
        }
    }

    /* The cryptainer last */
    cryptainer_file = wa_tool_open_output_file(cryptainer_path, arguments->is_forced);
    if (cryptainer_file == NULL) {
        fprintf(stderr, "Error: cannot create %s (existing file?)\n", cryptainer_path);
        goto cleanup;
    }
    *is_cryptainer_created = 1;
    cryptainer_sink = wa_tool_get_file_sink(cryptainer_file);
    status = wa_cryptainer_encryptor_write_cryptainer(encryptor, &cryptainer_sink);
    if (fclose(cryptainer_file) != 0 && status == WA_STATUS_OK) {
        status = WA_STATUS_SINK_WRITE_FAILURE;
    }
    cryptainer_file = NULL;
    if (status != WA_STATUS_OK) {
        wa_cli_print_status_error("cryptainer writing failed", status, NULL);
        goto cleanup;
    }
    printf("%s\n", cryptainer_path);
    if (payload_path_or_null != NULL) {
        printf("%s\n", payload_path_or_null);
    }
    exit_code = 0;

cleanup:
    wa_cryptainer_encryptor_destroy(encryptor);
    if (payload_file != NULL) {
        (void)fclose(payload_file);
    }
    if (cryptainer_file != NULL) {
        (void)fclose(cryptainer_file);
    }
    free(chunk);
    if (!is_stdin) {
        (void)fclose(input_file);
    }
    return exit_code;
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
    uint8_t *file_content;
    size_t file_length = 0;
    wa_status_t status;
    int is_payload_created = 0;
    int is_cryptainer_created = 0;
    int exit_code = 1;

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

    /* Output names, refused early when existing (nothing is generated then) */
    cryptainer_path = wa_tool_build_cryptainer_path(
        parsed.output_basename != NULL ? parsed.output_basename : parsed.input_path, parsed.document_format);
    if (cryptainer_path == NULL) {
        fprintf(stderr, "Error: invalid output basename\n");
        goto cleanup;
    }
    if (!parsed.is_bundle) {
        payload_path = wa_tool_build_payload_path(cryptainer_path);
        if (payload_path == NULL) {
            fprintf(stderr, "Error: out of memory\n");
            goto cleanup;
        }
    }
    if (!parsed.is_forced) {
        const char *existing_path = wa_tool_file_exists(cryptainer_path) ? cryptainer_path
                                    : payload_path != NULL && wa_tool_file_exists(payload_path) ? payload_path
                                                                                                : NULL;
        if (existing_path != NULL) {
            fprintf(stderr, "Error: %s already exists (use --force to overwrite it)\n", existing_path);
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

    exit_code = wa_cli_encrypt(&parsed, &platform_hooks, device_profile, metadata, cryptainer_path, payload_path,
                               &is_payload_created, &is_cryptainer_created);
    if (exit_code != 0) {
        /* Delete what this run created, cryptainer first */
        if (is_cryptainer_created) {
            (void)remove(cryptainer_path);
        }
        if (is_payload_created) {
            (void)remove(payload_path);
        }
    }

cleanup:
    wa_value_destroy(metadata);
    wa_device_profile_destroy(device_profile);
    free(cryptainer_path);
    free(payload_path);
    return exit_code;
}
