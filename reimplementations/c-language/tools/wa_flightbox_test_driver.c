/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Test driver for the pytest interoperability tests (tests/interop): each subcommand runs one library function on
 * hex arguments (or "@FILE" for the raw bytes of a file, beyond command line limits) and prints one JSON object on
 * stdout, with byte strings in lowercase hex, and "status" holding the status name. Trees are printed as their serialization by every writer of the build ("json" and/or "cbor").
 * Exit code: 0 when the subcommand ran (whatever its status), 2 on usage errors, 1 on driver failures.
 *
 * Subcommands:
 *   build-info                                                crypto backend and enabled document formats
 *   symmetric-encrypt ALGO KEY IV_OR_NONCE PLAINTEXT          one-shot cipherdict of a given symkey
 *   hpke-seal x25519|ml-kem-768 PK RANDOMNESS INFO AAD PLAINTEXT
 *                                                             HPKE base mode seal, the KEM drawing RANDOMNESS
 *   ml-kem-encapsulate PK COINS                               ML-KEM-768 derandomized encapsulation
 *   cbor-decode CBOR                                          decode a WA-CBOR document, print it back
 *   serialize FORMAT symkey ALGO KEY IV_OR_NONCE              intermediate structures, serialized with S_F
 *   serialize FORMAT shard WRITTEN_INDEX SHARD                (WRITTEN_INDEX is the 1-based index of the shard)
 *   serialize FORMAT key-struct KEY_BYTES [METADATA_CBOR]
 *   wrap-key FORMAT ALGO PUBLIC_KEY KEY_BYTES [METADATA_CBOR] key struct wrap with system randomness; PUBLIC_KEY is
 *                                                             MODULUS:EXPONENT for RSA_OAEP
 *   load-profile PROFILE_FILE                                 profile loading status and error location
 *   encrypt-cryptainer --profile FILE --input FILE --output-cryptainer FILE [--output-payload FILE]
 *                      [--format json|cbor] [--metadata FILE] [--chunk-size N] [--seed N] [--time T]
 *                                                             deterministic cryptainer (seeded random, clock T in
 *                                                             1/10000 s incremented per call); offloaded when
 *                                                             --output-payload is given; N = 0 for one chunk
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_flightbox/wa_flightbox.h"

#include "backends/wa_crypto_backend.h"
#include "core/wa_key_cipher_layers_encryption.h"
#include "encoding/wa_document_serialization.h"
#include "encoding/wa_growable_byte_buffer.h"
#include "primitives/wa_asymmetric_key_wrapping.h"
#include "primitives/wa_hpke_base_mode_seal.h"
#include "primitives/wa_hpke_kem_dhkem_x25519.h"
#include "primitives/wa_hpke_kem_ml_kem_768.h"
#include "primitives/wa_public_key_constraints.h"
#include "primitives/wa_symmetric_cipher_streams.h"
#include "primitives/wa_symmetric_key_generation.h"

#include "wa_host_platform_hooks.h"
#include "wa_test_support.h"
#include "wa_tool_common.h"

#define WA_DRIVER_USAGE_ERROR 2
#define WA_DRIVER_FAILURE 1

/* JSON OUTPUT */

static int wa_driver_field_count = 0;

static void wa_driver_print_json_string(const char *text, size_t length)
{
    size_t index;
    putchar('"');
    for (index = 0; index < length; ++index) {
        unsigned char character = (unsigned char)text[index];
        if (character == '"' || character == '\\') {
            printf("\\%c", character);
        } else if (character < 0x20u) {
            printf("\\u%04x", (unsigned)character);
        } else {
            putchar(character);
        }
    }
    putchar('"');
}

static void wa_driver_begin_field(const char *name)
{
    printf(wa_driver_field_count++ == 0 ? "{" : ", ");
    wa_driver_print_json_string(name, strlen(name));
    printf(": ");
}

static void wa_driver_print_text_field(const char *name, const char *text)
{
    wa_driver_begin_field(name);
    wa_driver_print_json_string(text, strlen(text));
}

static void wa_driver_print_integer_field(const char *name, unsigned long long integer)
{
    wa_driver_begin_field(name);
    printf("%llu", integer);
}

static void wa_driver_print_hex_field(const char *name, const uint8_t *bytes, size_t length)
{
    wa_driver_begin_field(name);
    putchar('"');
    wa_tool_print_hex(stdout, bytes, length);
    putchar('"');
}

static void wa_driver_print_status_field(wa_status_t status)
{
    wa_driver_print_text_field("status", wa_tool_get_status_name(status));
}

static int wa_driver_end(void)
{
    printf(wa_driver_field_count == 0 ? "{}\n" : "}\n");
    return fflush(stdout) == 0 ? 0 : WA_DRIVER_FAILURE;
}

/* Fields "json" and/or "cbor": the tree serialized by each writer of the build. Returns the first failing status. */
static wa_status_t wa_driver_print_tree_fields(const wa_platform_hooks_t *platform_hooks, const wa_value_t *tree)
{
    static const wa_document_format_t formats[] = {WA_DOCUMENT_FORMAT_JSON, WA_DOCUMENT_FORMAT_CBOR};
    static const char *const names[] = {"json", "cbor"};
    size_t index;
    for (index = 0; index < 2u; ++index) {
        wa_growable_byte_buffer_t buffer;
        wa_status_t status;
        if (!wa_document_format_is_enabled(formats[index])) {
            continue;
        }
        wa_growable_byte_buffer_initialize(&buffer, platform_hooks, 0);
        status = wa_document_serialize_to_buffer(tree, formats[index], &buffer);
        if (status == WA_STATUS_OK) {
            wa_driver_print_hex_field(names[index], buffer.data, buffer.length);
        }
        wa_growable_byte_buffer_release(&buffer);
        if (status != WA_STATUS_OK) {
            return status;
        }
    }
    return WA_STATUS_OK;
}

/* ARGUMENT HELPERS */

typedef struct wa_driver_hex_argument {
    uint8_t *bytes;
    size_t length;
} wa_driver_hex_argument_t;

/* 0 on success; prints an error otherwise */
static int wa_driver_decode_hex_argument(const char *name, const char *hex, wa_driver_hex_argument_t *argument)
{
    if (hex[0] == '@') {
        argument->bytes = wa_tool_read_file(hex + 1, &argument->length);
        if (argument->bytes == NULL) {
            fprintf(stderr, "Error: cannot read %s for %s\n", hex + 1, name);
            return WA_DRIVER_USAGE_ERROR;
        }
        return 0;
    }
    argument->bytes = wa_tool_decode_hex(hex, &argument->length);
    if (argument->bytes == NULL) {
        fprintf(stderr, "Error: invalid hex for %s\n", name);
        return WA_DRIVER_USAGE_ERROR;
    }
    return 0;
}

static int wa_driver_parse_symkey(const char *algo_name, const char *key_hex, const char *iv_or_nonce_hex,
                                  wa_symkey_t *symkey)
{
    wa_driver_hex_argument_t key;
    wa_driver_hex_argument_t iv_or_nonce;
    size_t expected_iv_or_nonce_length;
    int result = WA_DRIVER_USAGE_ERROR;
    memset(symkey, 0, sizeof(*symkey));
    if (!wa_symmetric_cipher_algo_from_name(algo_name, strlen(algo_name), &symkey->cipher_algo)) {
        fprintf(stderr, "Error: unknown symmetric algo %s\n", algo_name);
        return WA_DRIVER_USAGE_ERROR;
    }
    /* Section 3.3: 16-byte IV (AES_CBC) or nonce (AES_EAX), 12-byte nonce (CHACHA20_POLY1305) */
    expected_iv_or_nonce_length = symkey->cipher_algo == WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305 ? 12u : 16u;
    if (wa_driver_decode_hex_argument("KEY", key_hex, &key) != 0) {
        return WA_DRIVER_USAGE_ERROR;
    }
    if (wa_driver_decode_hex_argument("IV_OR_NONCE", iv_or_nonce_hex, &iv_or_nonce) != 0) {
        free(key.bytes);
        return WA_DRIVER_USAGE_ERROR;
    }
    if (key.length != WA_SYMKEY_KEY_SIZE || iv_or_nonce.length != expected_iv_or_nonce_length) {
        fprintf(stderr, "Error: a %u-byte key and a %u-byte IV or nonce are expected\n", (unsigned)WA_SYMKEY_KEY_SIZE,
                (unsigned)expected_iv_or_nonce_length);
    } else {
        memcpy(symkey->key, key.bytes, key.length);
        memcpy(symkey->iv_or_nonce, iv_or_nonce.bytes, iv_or_nonce.length);
        symkey->iv_or_nonce_length = iv_or_nonce.length;
        result = 0;
    }
    free(key.bytes);
    free(iv_or_nonce.bytes);
    return result;
}

/* Decode optional WA-CBOR metadata ("" or a missing argument: none); on a decoding failure, prints the status */
static int wa_driver_decode_metadata(const wa_platform_hooks_t *platform_hooks, const char *hex_or_null,
                                     wa_value_t **metadata_out, wa_status_t *status_out)
{
    wa_driver_hex_argument_t cbor;
    *metadata_out = NULL;
    *status_out = WA_STATUS_OK;
    if (hex_or_null == NULL || hex_or_null[0] == '\0') {
        return 0;
    }
    if (wa_driver_decode_hex_argument("METADATA_CBOR", hex_or_null, &cbor) != 0) {
        return WA_DRIVER_USAGE_ERROR;
    }
    *status_out = wa_value_tree_decode_from_cbor(cbor.bytes, cbor.length, platform_hooks, metadata_out);
    free(cbor.bytes);
    return 0;
}

static int wa_driver_parse_format(const char *name, wa_document_format_t *format_out)
{
    if (!wa_tool_parse_document_format(name, format_out)) {
        fprintf(stderr, "Error: unknown format %s (json or cbor)\n", name);
        return WA_DRIVER_USAGE_ERROR;
    }
    if (!wa_document_format_is_enabled(*format_out)) {
        fprintf(stderr, "Error: this build does not support the %s format\n", name);
        return WA_DRIVER_USAGE_ERROR;
    }
    return 0;
}

static int wa_driver_parse_unsigned(const char *name, const char *text, unsigned long long *value_out)
{
    char *end = NULL;
    if (text[0] < '0' || text[0] > '9') {
        fprintf(stderr, "Error: invalid %s %s\n", name, text);
        return WA_DRIVER_USAGE_ERROR;
    }
    *value_out = strtoull(text, &end, 10);
    if (end == text || *end != '\0') {
        fprintf(stderr, "Error: invalid %s %s\n", name, text);
        return WA_DRIVER_USAGE_ERROR;
    }
    return 0;
}

/* SUBCOMMANDS */

static int wa_driver_symmetric_encrypt(const wa_platform_hooks_t *platform_hooks, int argument_count,
                                       char **arguments)
{
    wa_symkey_t symkey;
    wa_driver_hex_argument_t plaintext;
    wa_value_t *cipherdict = NULL;
    wa_status_t status;
    if (argument_count != 4) {
        return WA_DRIVER_USAGE_ERROR;
    }
    if (wa_driver_parse_symkey(arguments[0], arguments[1], arguments[2], &symkey) != 0 ||
        wa_driver_decode_hex_argument("PLAINTEXT", arguments[3], &plaintext) != 0) {
        return WA_DRIVER_USAGE_ERROR;
    }
    status = wa_symmetric_encrypt_to_cipherdict(platform_hooks, &symkey, plaintext.bytes, plaintext.length,
                                                &cipherdict);
    if (status == WA_STATUS_OK) {
        status = wa_driver_print_tree_fields(platform_hooks, cipherdict);
    }
    wa_driver_print_status_field(status);
    wa_value_destroy(cipherdict);
    free(plaintext.bytes);
    return wa_driver_end();
}

static int wa_driver_hpke_seal(int argument_count, char **arguments)
{
    const wa_hpke_kem_t *kem;
    wa_driver_hex_argument_t values[5]; /* PK RANDOMNESS INFO AAD PLAINTEXT */
    static const char *const names[] = {"PK", "RANDOMNESS", "INFO", "AAD", "PLAINTEXT"};
    wa_test_replayed_random_t replayed_random;
    wa_platform_hooks_t platform_hooks;
    uint8_t *enc = NULL;
    uint8_t *sealed = NULL;
    wa_status_t status;
    size_t index;
    int result = 0;
    if (argument_count != 6) {
        return WA_DRIVER_USAGE_ERROR;
    }
    if (strcmp(arguments[0], "x25519") == 0) {
        kem = &wa_hpke_kem_dhkem_x25519;
    } else if (strcmp(arguments[0], "ml-kem-768") == 0) {
        kem = &wa_hpke_kem_ml_kem_768;
    } else {
        fprintf(stderr, "Error: unknown KEM %s (x25519 or ml-kem-768)\n", arguments[0]);
        return WA_DRIVER_USAGE_ERROR;
    }
    memset(values, 0, sizeof(values));
    for (index = 0; index < 5u; ++index) {
        if (wa_driver_decode_hex_argument(names[index], arguments[index + 1u], &values[index]) != 0) {
            result = WA_DRIVER_USAGE_ERROR;
            goto cleanup;
        }
    }
    if (values[0].length != kem->public_key_length) {
        fprintf(stderr, "Error: a %u-byte public key is expected\n", (unsigned)kem->public_key_length);
        result = WA_DRIVER_USAGE_ERROR;
        goto cleanup;
    }
    /* The KEM draws its ephemeral randomness from the random hook: replay RANDOMNESS */
    wa_host_platform_hooks_initialize(&platform_hooks, NULL);
    wa_test_replayed_random_initialize(&replayed_random, values[1].bytes, values[1].length);
    platform_hooks.fill_random = wa_test_fill_replayed_random;
    platform_hooks.random_context = &replayed_random;
    enc = (uint8_t *)malloc(kem->enc_length);
    sealed = (uint8_t *)malloc(values[4].length + WA_SYMMETRIC_TAG_SIZE);
    if (enc == NULL || sealed == NULL) {
        result = WA_DRIVER_FAILURE;
        goto cleanup;
    }
    status = wa_hpke_base_mode_seal(&platform_hooks, kem, values[0].bytes, values[2].bytes, values[2].length,
                                    values[3].bytes, values[3].length, values[4].bytes, values[4].length, enc,
                                    sealed);
    if (status == WA_STATUS_OK) {
        wa_driver_print_hex_field("enc", enc, kem->enc_length);
        wa_driver_print_hex_field("sealed", sealed, values[4].length + WA_SYMMETRIC_TAG_SIZE);
    }
    wa_driver_print_integer_field("consumed_randomness_length", replayed_random.offset);
    wa_driver_print_status_field(status);
    result = wa_driver_end();

cleanup:
    for (index = 0; index < 5u; ++index) {
        free(values[index].bytes);
    }
    free(enc);
    free(sealed);
    return result;
}

static int wa_driver_ml_kem_encapsulate(const wa_platform_hooks_t *platform_hooks, int argument_count,
                                        char **arguments)
{
    wa_driver_hex_argument_t public_key;
    wa_driver_hex_argument_t coins;
    uint8_t kem_ciphertext[WA_ML_KEM_768_CIPHERTEXT_SIZE];
    uint8_t shared_secret[WA_ML_KEM_768_SHARED_SECRET_SIZE];
    wa_status_t status;
    int result = WA_DRIVER_USAGE_ERROR;
    if (argument_count != 2) {
        return WA_DRIVER_USAGE_ERROR;
    }
    if (wa_driver_decode_hex_argument("PK", arguments[0], &public_key) != 0) {
        return WA_DRIVER_USAGE_ERROR;
    }
    if (wa_driver_decode_hex_argument("COINS", arguments[1], &coins) != 0) {
        free(public_key.bytes);
        return WA_DRIVER_USAGE_ERROR;
    }
    if (public_key.length != WA_ML_KEM_768_PUBLIC_KEY_SIZE || coins.length != WA_ML_KEM_768_COINS_SIZE) {
        fprintf(stderr, "Error: a %u-byte public key and %u-byte coins are expected\n",
                (unsigned)WA_ML_KEM_768_PUBLIC_KEY_SIZE, (unsigned)WA_ML_KEM_768_COINS_SIZE);
    } else {
        /* The modulus check of profile loading first, as the library does */
        status = wa_public_key_check_ml_kem_768(public_key.bytes, public_key.length);
        if (status == WA_STATUS_OK) {
            status = wa_crypto_backend_ml_kem_768_encapsulate_derandomized(platform_hooks, public_key.bytes,
                                                                           coins.bytes, kem_ciphertext,
                                                                           shared_secret);
        }
        if (status == WA_STATUS_OK) {
            wa_driver_print_hex_field("kem_ciphertext", kem_ciphertext, sizeof(kem_ciphertext));
            wa_driver_print_hex_field("shared_secret", shared_secret, sizeof(shared_secret));
        }
        wa_driver_print_status_field(status);
        result = wa_driver_end();
    }
    free(public_key.bytes);
    free(coins.bytes);
    return result;
}

static int wa_driver_cbor_decode(const wa_platform_hooks_t *platform_hooks, int argument_count, char **arguments)
{
    wa_driver_hex_argument_t cbor;
    wa_value_t *tree = NULL;
    wa_status_t status;
    if (argument_count != 1 || wa_driver_decode_hex_argument("CBOR", arguments[0], &cbor) != 0) {
        return WA_DRIVER_USAGE_ERROR;
    }
    status = wa_value_tree_decode_from_cbor(cbor.bytes, cbor.length, platform_hooks, &tree);
    if (status == WA_STATUS_OK) {
        status = wa_driver_print_tree_fields(platform_hooks, tree);
    }
    wa_driver_print_status_field(status);
    wa_value_destroy(tree);
    free(cbor.bytes);
    return wa_driver_end();
}

static int wa_driver_serialize(const wa_platform_hooks_t *platform_hooks, int argument_count, char **arguments)
{
    wa_key_cipher_context_t context;
    wa_growable_byte_buffer_t serialized;
    wa_status_t status;
    if (argument_count < 2) {
        return WA_DRIVER_USAGE_ERROR;
    }
    memset(&context, 0, sizeof(context));
    context.platform_hooks = platform_hooks;
    if (wa_driver_parse_format(arguments[0], &context.resolved_format) != 0) {
        return WA_DRIVER_USAGE_ERROR;
    }
    if (strcmp(arguments[1], "symkey") == 0) {
        wa_symkey_t symkey;
        if (argument_count != 5 || wa_driver_parse_symkey(arguments[2], arguments[3], arguments[4], &symkey) != 0) {
            return WA_DRIVER_USAGE_ERROR;
        }
        status = wa_key_cipher_layers_serialize_symkey(&context, &symkey, &serialized);
        wa_symkey_wipe(&symkey);
    } else if (strcmp(arguments[1], "shard") == 0) {
        unsigned long long written_index = 0;
        wa_driver_hex_argument_t shard;
        if (argument_count != 4 || wa_driver_parse_unsigned("WRITTEN_INDEX", arguments[2], &written_index) != 0 ||
            written_index < 1u || written_index > 255u ||
            wa_driver_decode_hex_argument("SHARD", arguments[3], &shard) != 0) {
            return WA_DRIVER_USAGE_ERROR;
        }
        status = wa_key_cipher_layers_serialize_shard(&context, (size_t)(written_index - 1u), shard.bytes,
                                                      shard.length, &serialized);
        free(shard.bytes);
    } else if (strcmp(arguments[1], "key-struct") == 0) {
        wa_driver_hex_argument_t key_bytes;
        wa_value_t *metadata = NULL;
        if ((argument_count != 3 && argument_count != 4) ||
            wa_driver_decode_hex_argument("KEY_BYTES", arguments[2], &key_bytes) != 0) {
            return WA_DRIVER_USAGE_ERROR;
        }
        if (wa_driver_decode_metadata(platform_hooks, argument_count == 4 ? arguments[3] : NULL, &metadata,
                                      &status) != 0) {
            free(key_bytes.bytes);
            return WA_DRIVER_USAGE_ERROR;
        }
        if (status == WA_STATUS_OK) { /* The buffer is only initialized here */
            status = wa_asymmetric_serialize_key_struct(platform_hooks, context.resolved_format, key_bytes.bytes,
                                                        key_bytes.length, metadata, &serialized);
        }
        wa_value_destroy(metadata);
        free(key_bytes.bytes);
    } else {
        fprintf(stderr, "Error: unknown structure %s (symkey, shard or key-struct)\n", arguments[1]);
        return WA_DRIVER_USAGE_ERROR;
    }
    if (status == WA_STATUS_OK) {
        wa_driver_print_hex_field("serialized", serialized.data, serialized.length);
        wa_growable_byte_buffer_release(&serialized);
    }
    wa_driver_print_status_field(status);
    return wa_driver_end();
}

static int wa_driver_wrap_key(const wa_platform_hooks_t *platform_hooks, int argument_count, char **arguments)
{
    wa_document_format_t format;
    wa_asymmetric_public_key_t public_key;
    wa_driver_hex_argument_t first_key_part = {NULL, 0};
    wa_driver_hex_argument_t second_key_part = {NULL, 0};
    wa_driver_hex_argument_t key_bytes = {NULL, 0};
    wa_value_t *metadata = NULL;
    wa_value_t *cipherdict = NULL;
    char *key_text = NULL;
    wa_status_t status;
    int result = WA_DRIVER_USAGE_ERROR;
    if (argument_count != 4 && argument_count != 5) {
        return WA_DRIVER_USAGE_ERROR;
    }
    memset(&public_key, 0, sizeof(public_key));
    if (wa_driver_parse_format(arguments[0], &format) != 0) {
        return WA_DRIVER_USAGE_ERROR;
    }
    if (!wa_asymmetric_cipher_algo_from_name(arguments[1], strlen(arguments[1]), &public_key.cipher_algo)) {
        fprintf(stderr, "Error: unknown asymmetric algo %s\n", arguments[1]);
        return WA_DRIVER_USAGE_ERROR;
    }
    key_text = (char *)malloc(strlen(arguments[2]) + 1u);
    if (key_text == NULL) {
        return WA_DRIVER_FAILURE;
    }
    strcpy(key_text, arguments[2]);
    if (public_key.cipher_algo == WA_ASYMMETRIC_CIPHER_RSA_OAEP) {
        char *separator = strchr(key_text, ':');
        if (separator == NULL) {
            fprintf(stderr, "Error: an RSA_OAEP public key is given as MODULUS:EXPONENT\n");
            goto cleanup;
        }
        *separator = '\0';
        if (wa_driver_decode_hex_argument("MODULUS", key_text, &first_key_part) != 0 ||
            wa_driver_decode_hex_argument("EXPONENT", separator + 1, &second_key_part) != 0) {
            goto cleanup;
        }
        public_key.modulus = first_key_part.bytes;
        public_key.modulus_length = first_key_part.length;
        public_key.public_exponent = second_key_part.bytes;
        public_key.public_exponent_length = second_key_part.length;
    } else {
        if (wa_driver_decode_hex_argument("PUBLIC_KEY", key_text, &first_key_part) != 0) {
            goto cleanup;
        }
        public_key.key_bytes = first_key_part.bytes;
        public_key.key_bytes_length = first_key_part.length;
    }
    if (wa_driver_decode_hex_argument("KEY_BYTES", arguments[3], &key_bytes) != 0 ||
        wa_driver_decode_metadata(platform_hooks, argument_count == 5 ? arguments[4] : NULL, &metadata, &status) !=
            0) {
        goto cleanup;
    }
    /* The key constraints of profile loading first, as the library does */
    if (status == WA_STATUS_OK) {
        switch (public_key.cipher_algo) {
        case WA_ASYMMETRIC_CIPHER_RSA_OAEP:
            status = wa_public_key_check_rsa(public_key.modulus, public_key.modulus_length,
                                             public_key.public_exponent, public_key.public_exponent_length);
            break;
        case WA_ASYMMETRIC_CIPHER_ECIES_X25519:
            status = wa_public_key_check_x25519(public_key.key_bytes, public_key.key_bytes_length);
            break;
        case WA_ASYMMETRIC_CIPHER_ML_KEM_768:
            status = wa_public_key_check_ml_kem_768(public_key.key_bytes, public_key.key_bytes_length);
            break;
        }
    }
    if (status == WA_STATUS_OK) {
        status = wa_asymmetric_wrap_key_struct(platform_hooks, &public_key, format, key_bytes.bytes, key_bytes.length,
                                               metadata, &cipherdict);
    }
    if (status == WA_STATUS_OK) {
        status = wa_driver_print_tree_fields(platform_hooks, cipherdict);
    }
    wa_driver_print_status_field(status);
    result = wa_driver_end();

cleanup:
    wa_value_destroy(cipherdict);
    wa_value_destroy(metadata);
    free(key_bytes.bytes);
    free(first_key_part.bytes);
    free(second_key_part.bytes);
    free(key_text);
    return result;
}

static int wa_driver_load_profile(const wa_platform_hooks_t *platform_hooks, int argument_count, char **arguments)
{
    char error_location[1024];
    wa_device_profile_t *device_profile = NULL;
    uint8_t *profile_bytes;
    size_t profile_length = 0;
    wa_status_t status;
    if (argument_count != 1) {
        return WA_DRIVER_USAGE_ERROR;
    }
    profile_bytes = wa_tool_read_file(arguments[0], &profile_length);
    if (profile_bytes == NULL) {
        fprintf(stderr, "Error: cannot read %s\n", arguments[0]);
        return WA_DRIVER_FAILURE;
    }
    status = wa_device_profile_load_from_cbor(profile_bytes, profile_length, platform_hooks, &device_profile,
                                              error_location, sizeof(error_location));
    free(profile_bytes);
    wa_device_profile_destroy(device_profile);
    wa_driver_print_status_field(status);
    wa_driver_print_text_field("location", status == WA_STATUS_OK ? "" : error_location);
    return wa_driver_end();
}

typedef struct wa_driver_encryption_arguments {
    const char *profile_path;
    const char *input_path;
    const char *cryptainer_path;
    const char *payload_path_or_null;
    const char *metadata_path_or_null;
    wa_document_format_t document_format;
    unsigned long long chunk_size; /* 0: one chunk */
    unsigned long long seed;
    unsigned long long time;
} wa_driver_encryption_arguments_t;

static int wa_driver_parse_encryption_arguments(int argument_count, char **arguments,
                                                wa_driver_encryption_arguments_t *parsed)
{
    int index;
    memset(parsed, 0, sizeof(*parsed));
    parsed->document_format = WA_DOCUMENT_FORMAT_BUILD_DEFAULT;
    parsed->seed = 1;
    parsed->time = 17672256000000ull; /* 2026-01-01T00:00:00Z */
    for (index = 0; index + 1 < argument_count; index += 2) {
        const char *name = arguments[index];
        const char *value = arguments[index + 1];
        int result = 0;
        if (strcmp(name, "--profile") == 0) {
            parsed->profile_path = value;
        } else if (strcmp(name, "--input") == 0) {
            parsed->input_path = value;
        } else if (strcmp(name, "--output-cryptainer") == 0) {
            parsed->cryptainer_path = value;
        } else if (strcmp(name, "--output-payload") == 0) {
            parsed->payload_path_or_null = value;
        } else if (strcmp(name, "--metadata") == 0) {
            parsed->metadata_path_or_null = value;
        } else if (strcmp(name, "--format") == 0) {
            result = wa_driver_parse_format(value, &parsed->document_format);
        } else if (strcmp(name, "--chunk-size") == 0) {
            result = wa_driver_parse_unsigned("chunk size", value, &parsed->chunk_size);
        } else if (strcmp(name, "--seed") == 0) {
            result = wa_driver_parse_unsigned("seed", value, &parsed->seed);
        } else if (strcmp(name, "--time") == 0) {
            result = wa_driver_parse_unsigned("time", value, &parsed->time);
        } else {
            fprintf(stderr, "Error: unknown option %s\n", name);
            return WA_DRIVER_USAGE_ERROR;
        }
        if (result != 0) {
            return result;
        }
    }
    if (index != argument_count || parsed->profile_path == NULL || parsed->input_path == NULL ||
        parsed->cryptainer_path == NULL) {
        fprintf(stderr, "Error: --profile, --input and --output-cryptainer are required, options taking a value\n");
        return WA_DRIVER_USAGE_ERROR;
    }
    return 0;
}

static int wa_driver_write_file(const char *path, const uint8_t *bytes, size_t length)
{
    FILE *file = wa_tool_open_output_file(path, 1);
    int is_written;
    if (file == NULL) {
        return 0;
    }
    is_written = length == 0 || fwrite(bytes, 1, length, file) == length;
    return fclose(file) == 0 && is_written;
}

static int wa_driver_encrypt_cryptainer(int argument_count, char **arguments)
{
    wa_driver_encryption_arguments_t parsed;
    wa_test_platform_t *platform = NULL;
    wa_device_profile_t *device_profile = NULL;
    wa_value_t *metadata = NULL;
    wa_cryptainer_encryptor_t *encryptor = NULL;
    wa_cryptainer_encryptor_options_t options;
    wa_test_memory_sink_t payload_sink;
    wa_test_memory_sink_t cryptainer_sink;
    char error_location[1024] = "";
    uint8_t *profile_bytes = NULL;
    uint8_t *metadata_bytes = NULL;
    uint8_t *payload = NULL;
    size_t profile_length = 0;
    size_t metadata_length = 0;
    size_t payload_length = 0;
    wa_status_t status;
    int result;

    result = wa_driver_parse_encryption_arguments(argument_count, arguments, &parsed);
    if (result != 0) {
        return result;
    }
    wa_test_memory_sink_initialize(&payload_sink);
    wa_test_memory_sink_initialize(&cryptainer_sink);
    profile_bytes = wa_tool_read_file(parsed.profile_path, &profile_length);
    payload = wa_tool_read_file(parsed.input_path, &payload_length);
    if (parsed.metadata_path_or_null != NULL) {
        metadata_bytes = wa_tool_read_file(parsed.metadata_path_or_null, &metadata_length);
    }
    platform = wa_test_platform_create((uint64_t)parsed.seed);
    if (profile_bytes == NULL || payload == NULL || (parsed.metadata_path_or_null != NULL && metadata_bytes == NULL) ||
        platform == NULL) {
        fprintf(stderr, "Error: cannot read an input file, or out of memory\n");
        result = WA_DRIVER_FAILURE;
        goto cleanup;
    }
    platform->clock.unix_time_in_ten_thousandths_of_second = (uint64_t)parsed.time;

    status = wa_device_profile_load_from_cbor(profile_bytes, profile_length, &platform->hooks, &device_profile,
                                              error_location, sizeof(error_location));
    if (status == WA_STATUS_OK && metadata_bytes != NULL) {
        status = wa_value_tree_decode_from_cbor(metadata_bytes, metadata_length, &platform->hooks, &metadata);
    }
    if (status == WA_STATUS_OK) {
        options.platform_hooks = &platform->hooks;
        options.document_format = parsed.document_format;
        options.ciphertext_location = parsed.payload_path_or_null != NULL ? WA_CIPHERTEXT_LOCATION_OFFLOADED
                                                                          : WA_CIPHERTEXT_LOCATION_INLINE;
        options.payload_ciphertext_sink = parsed.payload_path_or_null != NULL ? &payload_sink.sink : NULL;
        status = wa_cryptainer_encryptor_create(device_profile, metadata, &options, &encryptor);
    }
    if (status == WA_STATUS_OK) {
        size_t offset = 0;
        size_t chunk_size = parsed.chunk_size == 0 || parsed.chunk_size > payload_length
                                ? payload_length
                                : (size_t)parsed.chunk_size;
        do {
            size_t length = payload_length - offset < chunk_size ? payload_length - offset : chunk_size;
            status = wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, payload + offset, length);
            offset += length;
        } while (status == WA_STATUS_OK && offset < payload_length);
    }
    if (status == WA_STATUS_OK) {
        status = wa_cryptainer_encryptor_finalize(encryptor);
    }
    if (status == WA_STATUS_OK) {
        status = wa_cryptainer_encryptor_write_cryptainer(encryptor, &cryptainer_sink.sink);
    }
    wa_cryptainer_encryptor_destroy(encryptor);
    wa_value_destroy(metadata);
    wa_device_profile_destroy(device_profile);

    if (status == WA_STATUS_OK) {
        if ((parsed.payload_path_or_null != NULL &&
             !wa_driver_write_file(parsed.payload_path_or_null, payload_sink.bytes, payload_sink.length)) ||
            !wa_driver_write_file(parsed.cryptainer_path, cryptainer_sink.bytes, cryptainer_sink.length)) {
            fprintf(stderr, "Error: cannot write the output files\n");
            result = WA_DRIVER_FAILURE;
            goto cleanup;
        }
    }
    wa_driver_print_status_field(status);
    wa_driver_print_text_field("location", error_location);
    wa_driver_print_integer_field("random_call_count", platform->random_generator.call_count);
    wa_driver_print_integer_field("peak_allocated_bytes", platform->allocator.peak_live_bytes);
    wa_driver_print_integer_field("leaked_block_count", platform->allocator.live_block_count);
    wa_driver_print_integer_field("unwiped_secret_release_count", platform->allocator.unwiped_secret_release_count);
    result = wa_driver_end();

cleanup:
    wa_test_memory_sink_release(&payload_sink);
    wa_test_memory_sink_release(&cryptainer_sink);
    wa_test_platform_destroy(platform);
    free(profile_bytes);
    free(metadata_bytes);
    free(payload);
    return result;
}

static int wa_driver_build_info(int argument_count)
{
#if defined(WA_CRYPTO_BACKEND_MBEDTLS)
    static const char backend_name[] = "MBEDTLS";
#elif defined(WA_CRYPTO_BACKEND_WOLFCRYPT)
    static const char backend_name[] = "WOLFCRYPT";
#else
#error "No crypto backend defined"
#endif
    if (argument_count != 0) {
        return WA_DRIVER_USAGE_ERROR;
    }
    wa_driver_print_text_field("backend", backend_name);
    wa_driver_begin_field("document_formats");
    printf("[%s%s%s]", WA_DOCUMENT_FORMAT_JSON_ENABLED ? "\"json\"" : "",
           WA_DOCUMENT_FORMAT_JSON_ENABLED && WA_DOCUMENT_FORMAT_CBOR_ENABLED ? ", " : "",
           WA_DOCUMENT_FORMAT_CBOR_ENABLED ? "\"cbor\"" : "");
    wa_driver_print_status_field(WA_STATUS_OK);
    return wa_driver_end();
}

static void wa_driver_print_usage(void)
{
    fprintf(stderr,
            "Usage: wa_flightbox_test_driver SUBCOMMAND ARGUMENTS... (byte strings in hex, or @FILE)\n"
            "  build-info\n"
            "  symmetric-encrypt ALGO KEY IV_OR_NONCE PLAINTEXT\n"
            "  hpke-seal x25519|ml-kem-768 PK RANDOMNESS INFO AAD PLAINTEXT\n"
            "  ml-kem-encapsulate PK COINS\n"
            "  cbor-decode CBOR\n"
            "  serialize json|cbor symkey ALGO KEY IV_OR_NONCE\n"
            "  serialize json|cbor shard WRITTEN_INDEX SHARD\n"
            "  serialize json|cbor key-struct KEY_BYTES [METADATA_CBOR]\n"
            "  wrap-key json|cbor ALGO PUBLIC_KEY KEY_BYTES [METADATA_CBOR]   (RSA_OAEP: PUBLIC_KEY = MODULUS:EXPONENT)\n"
            "  load-profile PROFILE_FILE\n"
            "  encrypt-cryptainer --profile FILE --input FILE --output-cryptainer FILE [--output-payload FILE]\n"
            "                     [--format json|cbor] [--metadata FILE] [--chunk-size N] [--seed N] [--time T]\n");
}

int main(int argument_count, char **arguments)
{
    wa_platform_hooks_t platform_hooks;
    const char *subcommand;
    int sub_argument_count = argument_count - 2;
    char **sub_arguments = arguments + 2;
    int result;
    if (argument_count < 2) {
        wa_driver_print_usage();
        return WA_DRIVER_USAGE_ERROR;
    }
    subcommand = arguments[1];
    wa_host_platform_hooks_initialize(&platform_hooks, NULL);
    if (strcmp(subcommand, "build-info") == 0) {
        result = wa_driver_build_info(sub_argument_count);
    } else if (strcmp(subcommand, "symmetric-encrypt") == 0) {
        result = wa_driver_symmetric_encrypt(&platform_hooks, sub_argument_count, sub_arguments);
    } else if (strcmp(subcommand, "hpke-seal") == 0) {
        result = wa_driver_hpke_seal(sub_argument_count, sub_arguments);
    } else if (strcmp(subcommand, "ml-kem-encapsulate") == 0) {
        result = wa_driver_ml_kem_encapsulate(&platform_hooks, sub_argument_count, sub_arguments);
    } else if (strcmp(subcommand, "cbor-decode") == 0) {
        result = wa_driver_cbor_decode(&platform_hooks, sub_argument_count, sub_arguments);
    } else if (strcmp(subcommand, "serialize") == 0) {
        result = wa_driver_serialize(&platform_hooks, sub_argument_count, sub_arguments);
    } else if (strcmp(subcommand, "wrap-key") == 0) {
        result = wa_driver_wrap_key(&platform_hooks, sub_argument_count, sub_arguments);
    } else if (strcmp(subcommand, "load-profile") == 0) {
        result = wa_driver_load_profile(&platform_hooks, sub_argument_count, sub_arguments);
    } else if (strcmp(subcommand, "encrypt-cryptainer") == 0) {
        result = wa_driver_encrypt_cryptainer(sub_argument_count, sub_arguments);
    } else {
        result = WA_DRIVER_USAGE_ERROR;
    }
    if (result == WA_DRIVER_USAGE_ERROR) {
        wa_driver_print_usage();
    }
    return result;
}
