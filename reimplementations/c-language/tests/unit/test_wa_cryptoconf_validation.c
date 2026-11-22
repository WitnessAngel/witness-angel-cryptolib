/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Cryptoconf validation (task 6.1): hand-built trees for each rule, with the expected status and error location
 * path; the error location path builder; trustee identities. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/wa_cryptoconf_validation.h"
#include "core/wa_error_location_path.h"
#include "primitives/wa_shamir_secret_sharing_gf128.h"
#include "wa_flightbox/wa_flightbox_config.h"
#include "wa_minimal_test_harness.h"
#include "wa_test_support.h"
#include "wa_test_value_notation.h"

/* NOTATION SNIPPETS */

#define UID "u'0123456789abcdef0123456789abcdef'"
#define OTHER_UID "u'fedcba9876543210fedcba9876543210'"
#define LOCAL_TRUSTEE "{'trustee_type': 'local_keyfactory'}"
#define AUTHENTICATOR_TRUSTEE "{'trustee_type': 'authenticator', 'keystore_uid': " UID ", 'keystore_owner': 'Jane'}"
#define JSONRPC_TRUSTEE "{'trustee_type': 'jsonrpc_api', 'jsonrpc_url': 'https://example.com/jsonrpc'}"
#define RSA_LAYER "{'key_cipher_algo': 'RSA_OAEP', 'key_cipher_trustee': " LOCAL_TRUSTEE "}"
#define LAYER_WITH(extra) "{'key_cipher_algo': 'RSA_OAEP', 'key_cipher_trustee': " LOCAL_TRUSTEE ", " extra "}"
#define TRUSTEE_LAYER(trustee) "{'key_cipher_algo': 'RSA_OAEP', 'key_cipher_trustee': " trustee "}"
#define PAYLOAD_LAYER_WITH(extra, key_layers)                                                       \
    "{'payload_cipher_algo': 'AES_CBC', 'payload_ciphertext_signatures': [], " extra "'key_cipher_layers': [" \
    key_layers "]}"
#define PAYLOAD_LAYER(key_layers) PAYLOAD_LAYER_WITH("", key_layers)
#define CRYPTOCONF(payload_layers) "{'payload_cipher_layers': [" payload_layers "], 'keychain_uid': " UID "}"
#define SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(key_layer) CRYPTOCONF(PAYLOAD_LAYER(key_layer))
#define SIGNATURE_CONF                                                                    \
    "{'payload_digest_algo': 'SHA256', 'payload_signature_algo': 'ECC_DSS', "           \
    "'payload_signature_trustee': " LOCAL_TRUSTEE ", 'keychain_uid': " OTHER_UID "}"
#define SHARED_SECRET_LAYER(threshold, shards)                                                         \
    "{'key_cipher_algo': '[SHARED_SECRET]', 'key_shared_secret_threshold': " threshold ", "            \
    "'key_shared_secret_shards': [" shards "]}"
#define SHARD(key_layers) "{'key_cipher_layers': [" key_layers "]}"

#define PAYLOAD_0 "cryptoconf.payload_cipher_layers[0]"
#define KEY_LAYER_0 PAYLOAD_0 ".key_cipher_layers[0]"

typedef struct cryptoconf_case {
    const char *notation;
    wa_status_t expected_status;
    const char *expected_location;
} cryptoconf_case_t;

static const cryptoconf_case_t cryptoconf_cases[] = {
    /* Valid cryptoconfs: the location is left as given */
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(RSA_LAYER), WA_STATUS_OK, "cryptoconf"},
    {"{'keychain_uid': " UID ", 'payload_plaintext_signatures': [], 'payload_cipher_layers': ["
     "{'payload_cipher_algo': 'AES_EAX', 'payload_signatures': [], 'key_cipher_layers': ["
     "{'key_cipher_algo': 'ECIES_X25519', 'key_cipher_trustee': " AUTHENTICATOR_TRUSTEE ", 'keychain_uid': "
     OTHER_UID "}, "
     "{'key_cipher_algo': 'ML_KEM_768', 'key_cipher_trustee': " JSONRPC_TRUSTEE "}]}, "
     "{'payload_cipher_algo': 'CHACHA20_POLY1305', 'payload_ciphertext_signatures': [], 'key_cipher_layers': ["
     "{'key_cipher_algo': 'AES_CBC', 'key_cipher_layers': [" RSA_LAYER "]}, " SHARED_SECRET_LAYER(
         "2", SHARD(RSA_LAYER) ", " SHARD("{'key_cipher_algo': 'CHACHA20_POLY1305', 'key_cipher_layers': [" RSA_LAYER
                                         "]}") ", " SHARD(RSA_LAYER)) "]}]}",
     WA_STATUS_OK, "cryptoconf"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(SHARED_SECRET_LAYER("1", SHARD(RSA_LAYER))), WA_STATUS_OK, "cryptoconf"},

    /* Root */
    {"[]", WA_STATUS_INVALID_PROFILE, "cryptoconf"},
    {"{'payload_cipher_layers': [" PAYLOAD_LAYER(RSA_LAYER) "], 'keychain_uid': " UID ", 'foo': 1}",
     WA_STATUS_INVALID_PROFILE, "cryptoconf.foo"},
    {"{'payload_cipher_layers': [" PAYLOAD_LAYER(RSA_LAYER) "]}", WA_STATUS_INVALID_PROFILE,
     "cryptoconf.keychain_uid"},
    {"{'payload_cipher_layers': [" PAYLOAD_LAYER(LAYER_WITH("'keychain_uid': " UID)) "]}", WA_STATUS_INVALID_PROFILE,
     "cryptoconf.keychain_uid"},
    {"{'payload_cipher_layers': [" PAYLOAD_LAYER(RSA_LAYER) "], 'keychain_uid': '0123456789abcdef0123456789abcdef'}",
     WA_STATUS_INVALID_PROFILE, "cryptoconf.keychain_uid"},
    {"{'payload_cipher_layers': [], 'keychain_uid': " UID "}", WA_STATUS_INVALID_PROFILE,
     "cryptoconf.payload_cipher_layers"},
    {"{'keychain_uid': " UID "}", WA_STATUS_INVALID_PROFILE, "cryptoconf.payload_cipher_layers"},
    {"{'payload_cipher_layers': {}, 'keychain_uid': " UID "}", WA_STATUS_INVALID_PROFILE,
     "cryptoconf.payload_cipher_layers"},
    {CRYPTOCONF("'AES_CBC'"), WA_STATUS_INVALID_PROFILE, PAYLOAD_0},

    /* Payload layers */
    {CRYPTOCONF("{'payload_cipher_algo': 'AES_XTS', 'payload_ciphertext_signatures': [], 'key_cipher_layers': ["
                RSA_LAYER "]}"),
     WA_STATUS_INVALID_PROFILE, PAYLOAD_0 ".payload_cipher_algo"},
    {CRYPTOCONF("{'payload_cipher_algo': 'RSA_OAEP', 'payload_ciphertext_signatures': [], 'key_cipher_layers': ["
                RSA_LAYER "]}"),
     WA_STATUS_INVALID_PROFILE, PAYLOAD_0 ".payload_cipher_algo"},
    {CRYPTOCONF("{'payload_ciphertext_signatures': [], 'key_cipher_layers': [" RSA_LAYER "]}"),
     WA_STATUS_INVALID_PROFILE, PAYLOAD_0 ".payload_cipher_algo"},
    {CRYPTOCONF(PAYLOAD_LAYER_WITH("'key_ciphertext_format': 'cbor', ", RSA_LAYER)), WA_STATUS_INVALID_PROFILE,
     PAYLOAD_0 ".key_ciphertext_format"},
    {CRYPTOCONF(PAYLOAD_LAYER_WITH("'payload_macs': null, ", RSA_LAYER)), WA_STATUS_INVALID_PROFILE,
     PAYLOAD_0 ".payload_macs"},
    {CRYPTOCONF(PAYLOAD_LAYER_WITH("'payload_signatures': [], ", RSA_LAYER)), WA_STATUS_INVALID_PROFILE, PAYLOAD_0},
    {CRYPTOCONF("{'payload_cipher_algo': 'AES_CBC', 'key_cipher_layers': [" RSA_LAYER "]}"),
     WA_STATUS_INVALID_PROFILE, PAYLOAD_0 ".payload_ciphertext_signatures"},
    {CRYPTOCONF("{'payload_cipher_algo': 'AES_CBC', 'payload_signatures': {}, 'key_cipher_layers': [" RSA_LAYER
                "]}"),
     WA_STATUS_INVALID_PROFILE, PAYLOAD_0 ".payload_signatures"},
    {CRYPTOCONF("{'payload_cipher_algo': 'AES_CBC', 'payload_ciphertext_signatures': []}"),
     WA_STATUS_INVALID_PROFILE, PAYLOAD_0 ".key_cipher_layers"},
    {CRYPTOCONF(PAYLOAD_LAYER("")), WA_STATUS_INVALID_PROFILE, PAYLOAD_0 ".key_cipher_layers"},
    {CRYPTOCONF(PAYLOAD_LAYER(RSA_LAYER) ", " PAYLOAD_LAYER("")), WA_STATUS_INVALID_PROFILE,
     "cryptoconf.payload_cipher_layers[1].key_cipher_layers"},

    /* Signatures: well-formed but unsupported, or malformed */
    {CRYPTOCONF("{'payload_cipher_algo': 'AES_CBC', 'payload_ciphertext_signatures': [" SIGNATURE_CONF
                "], 'key_cipher_layers': [" RSA_LAYER "]}"),
     WA_STATUS_UNSUPPORTED_SIGNATURE, PAYLOAD_0 ".payload_ciphertext_signatures"},
    {CRYPTOCONF("{'payload_cipher_algo': 'AES_CBC', 'payload_signatures': [" SIGNATURE_CONF
                "], 'key_cipher_layers': [" RSA_LAYER "]}"),
     WA_STATUS_UNSUPPORTED_SIGNATURE, PAYLOAD_0 ".payload_signatures"},
    {"{'payload_cipher_layers': [" PAYLOAD_LAYER(RSA_LAYER) "], 'keychain_uid': " UID
     ", 'payload_plaintext_signatures': [" SIGNATURE_CONF "]}",
     WA_STATUS_UNSUPPORTED_SIGNATURE, "cryptoconf.payload_plaintext_signatures"},
    {"{'payload_cipher_layers': [" PAYLOAD_LAYER(RSA_LAYER) "], 'keychain_uid': " UID
     ", 'payload_plaintext_signatures': " SIGNATURE_CONF "}",
     WA_STATUS_INVALID_PROFILE, "cryptoconf.payload_plaintext_signatures"},
    {CRYPTOCONF("{'payload_cipher_algo': 'AES_CBC', 'payload_ciphertext_signatures': [" SIGNATURE_CONF
                ", {'payload_digest_algo': 'MD5', 'payload_signature_algo': 'ECC_DSS', "
                "'payload_signature_trustee': " LOCAL_TRUSTEE "}], 'key_cipher_layers': [" RSA_LAYER "]}"),
     WA_STATUS_INVALID_PROFILE, PAYLOAD_0 ".payload_ciphertext_signatures[1].payload_digest_algo"},
    {CRYPTOCONF("{'payload_cipher_algo': 'AES_CBC', 'payload_ciphertext_signatures': [{'payload_digest_algo': "
                "'SHA512', 'payload_signature_algo': 'RSA_OAEP', 'payload_signature_trustee': " LOCAL_TRUSTEE
                "}], 'key_cipher_layers': [" RSA_LAYER "]}"),
     WA_STATUS_INVALID_PROFILE, PAYLOAD_0 ".payload_ciphertext_signatures[0].payload_signature_algo"},
    {CRYPTOCONF("{'payload_cipher_algo': 'AES_CBC', 'payload_ciphertext_signatures': [{'payload_digest_algo': "
                "'SHA3_256', 'payload_signature_algo': 'DSA_DSS', 'payload_signature_trustee': "
                "{'trustee_type': 'authenticator'}}], 'key_cipher_layers': [" RSA_LAYER "]}"),
     WA_STATUS_INVALID_PROFILE,
     PAYLOAD_0 ".payload_ciphertext_signatures[0].payload_signature_trustee.keystore_uid"},
    {CRYPTOCONF("{'payload_cipher_algo': 'AES_CBC', 'payload_ciphertext_signatures': [{'payload_digest_algo': "
                "'SHA3_512', 'payload_signature_algo': 'ML_DSA_65'}], 'key_cipher_layers': [" RSA_LAYER "]}"),
     WA_STATUS_INVALID_PROFILE, PAYLOAD_0 ".payload_ciphertext_signatures[0].payload_signature_trustee"},
    {CRYPTOCONF("{'payload_cipher_algo': 'AES_CBC', 'payload_ciphertext_signatures': [{'payload_digest_algo': "
                "'SHA256', 'payload_signature_algo': 'RSA_PSS', 'payload_signature_trustee': " LOCAL_TRUSTEE
                ", 'keychain_uid': 'abc'}], 'key_cipher_layers': [" RSA_LAYER "]}"),
     WA_STATUS_INVALID_PROFILE, PAYLOAD_0 ".payload_ciphertext_signatures[0].keychain_uid"},
    {CRYPTOCONF("{'payload_cipher_algo': 'AES_CBC', 'payload_ciphertext_signatures': [{'payload_digest_algo': "
                "'SHA256', 'payload_signature_algo': 'RSA_PSS', 'payload_signature_trustee': " LOCAL_TRUSTEE
                ", 'signature_value': b'00'}], 'key_cipher_layers': [" RSA_LAYER "]}"),
     WA_STATUS_INVALID_PROFILE, PAYLOAD_0 ".payload_ciphertext_signatures[0].signature_value"},
    {CRYPTOCONF("{'payload_cipher_algo': 'AES_CBC', 'payload_ciphertext_signatures': [[]], 'key_cipher_layers': ["
                RSA_LAYER "]}"),
     WA_STATUS_INVALID_PROFILE, PAYLOAD_0 ".payload_ciphertext_signatures[0]"},

    /* Key cipher layers */
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER("'RSA_OAEP'"), WA_STATUS_INVALID_PROFILE, KEY_LAYER_0},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER("{'key_cipher_trustee': " LOCAL_TRUSTEE "}"), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".key_cipher_algo"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER("{'key_cipher_algo': 'DSA_DSS', 'key_cipher_trustee': " LOCAL_TRUSTEE "}"),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_cipher_algo"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER("{'key_cipher_algo': 7, 'key_cipher_trustee': " LOCAL_TRUSTEE "}"),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_cipher_algo"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(LAYER_WITH("'key_ciphertext': b'00'")), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".key_ciphertext"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(LAYER_WITH("'key_ciphertext_format': 'cbor'")), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".key_ciphertext_format"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(LAYER_WITH("'key_cipher_layers': [" RSA_LAYER "]")),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_cipher_layers"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(LAYER_WITH("'keychain_uid': 'abc'")), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".keychain_uid"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER("{'key_cipher_algo': 'ECIES_X25519'}"), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".key_cipher_trustee"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(RSA_LAYER ", {'key_cipher_algo': 'AES_EAX', 'key_cipher_layers': []}"),
     WA_STATUS_INVALID_PROFILE, PAYLOAD_0 ".key_cipher_layers[1].key_cipher_layers"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER("{'key_cipher_algo': 'AES_EAX'}"), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".key_cipher_layers"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER("{'key_cipher_algo': 'AES_EAX', 'key_cipher_layers': [" RSA_LAYER
                                      "], 'key_cipher_trustee': " LOCAL_TRUSTEE "}"),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_cipher_trustee"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER("{'key_cipher_algo': 'AES_EAX', 'key_cipher_layers': [" RSA_LAYER ", "
                                      LAYER_WITH("'foo': null") "]}"),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_cipher_layers[1].foo"},

    /* Trustees */
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(TRUSTEE_LAYER("'local_keyfactory'")), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".key_cipher_trustee"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(TRUSTEE_LAYER("{'trustee_type': 'local'}")), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".key_cipher_trustee.trustee_type"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(TRUSTEE_LAYER("{}")), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".key_cipher_trustee.trustee_type"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(TRUSTEE_LAYER("{'trustee_type': 'local_keyfactory', 'keystore_uid': " UID
                                                    "}")),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_cipher_trustee.keystore_uid"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(TRUSTEE_LAYER("{'trustee_type': 'authenticator', 'keystore_owner': 'Jane'}")),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_cipher_trustee.keystore_uid"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(TRUSTEE_LAYER("{'trustee_type': 'authenticator', 'keystore_uid': "
                                                    "'0123456789abcdef0123456789abcdef'}")),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_cipher_trustee.keystore_uid"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(TRUSTEE_LAYER("{'trustee_type': 'authenticator', 'keystore_uid': " UID
                                                    ", 'keystore_owner': 3}")),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_cipher_trustee.keystore_owner"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(TRUSTEE_LAYER("{'trustee_type': 'authenticator', 'keystore_uid': " UID
                                                    ", 'jsonrpc_url': 'x'}")),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_cipher_trustee.jsonrpc_url"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(TRUSTEE_LAYER("{'trustee_type': 'jsonrpc_api'}")), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".key_cipher_trustee.jsonrpc_url"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(TRUSTEE_LAYER("{'trustee_type': 'jsonrpc_api', 'jsonrpc_url': b'00'}")),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_cipher_trustee.jsonrpc_url"},

    /* Shared secrets */
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(SHARED_SECRET_LAYER("0", SHARD(RSA_LAYER))), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".key_shared_secret_threshold"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(SHARED_SECRET_LAYER("-1", SHARD(RSA_LAYER))), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".key_shared_secret_threshold"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(SHARED_SECRET_LAYER("3", SHARD(RSA_LAYER) ", " SHARD(RSA_LAYER))),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_shared_secret_threshold"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(SHARED_SECRET_LAYER("'1'", SHARD(RSA_LAYER))), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".key_shared_secret_threshold"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(SHARED_SECRET_LAYER("1", "")), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".key_shared_secret_threshold"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER("{'key_cipher_algo': '[SHARED_SECRET]', 'key_shared_secret_shards': ["
                                      SHARD(RSA_LAYER) "]}"),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_shared_secret_threshold"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER("{'key_cipher_algo': '[SHARED_SECRET]', 'key_shared_secret_threshold': 1}"),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_shared_secret_shards"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER("{'key_cipher_algo': '[SHARED_SECRET]', 'key_shared_secret_threshold': 1, "
                                      "'key_shared_secret_shards': [" SHARD(RSA_LAYER) "], 'key_cipher_layers': ["
                                      RSA_LAYER "]}"),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_cipher_layers"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(SHARED_SECRET_LAYER("1", SHARD(RSA_LAYER) ", {'key_cipher_layers': ["
                                                          RSA_LAYER "], 'key_cipher_algo': 'AES_CBC'}")),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_shared_secret_shards[1].key_cipher_algo"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(SHARED_SECRET_LAYER("1", SHARD(RSA_LAYER) ", " SHARD(""))),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_shared_secret_shards[1].key_cipher_layers"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(SHARED_SECRET_LAYER("1", "[]")), WA_STATUS_INVALID_PROFILE,
     KEY_LAYER_0 ".key_shared_secret_shards[0]"},
    {SIMPLE_CRYPTOCONF_WITH_KEY_LAYER(SHARED_SECRET_LAYER("1", SHARD(LAYER_WITH("'keychain_uid': 5")))),
     WA_STATUS_INVALID_PROFILE, KEY_LAYER_0 ".key_shared_secret_shards[0].key_cipher_layers[0].keychain_uid"},
};

static void test_cryptoconf_cases(void)
{
    size_t case_index;
    wa_test_platform_t *platform = wa_test_platform_create(1);
    WA_REQUIRE(platform != NULL);
    for (case_index = 0; case_index < sizeof(cryptoconf_cases) / sizeof(cryptoconf_cases[0]); ++case_index) {
        const cryptoconf_case_t *test_case = &cryptoconf_cases[case_index];
        wa_value_t *cryptoconf = NULL;
        wa_error_location_path_t location;
        wa_status_t status;
        if (wa_test_build_value_tree(&platform->hooks, test_case->notation, &cryptoconf) != WA_STATUS_OK) {
            fprintf(stderr, "case %lu: notation error\n", (unsigned long)case_index);
            WA_CHECK(0);
            continue;
        }
        wa_error_location_path_initialize(&location);
        (void)wa_error_location_path_push_key(&location, "cryptoconf", strlen("cryptoconf"));
        status = wa_cryptoconf_validate(cryptoconf, &location);
        if (status != test_case->expected_status || strcmp(location.text, test_case->expected_location) != 0) {
            fprintf(stderr, "case %lu: status %d at '%s', expected %d at '%s'\n", (unsigned long)case_index,
                    (int)status, location.text, (int)test_case->expected_status, test_case->expected_location);
        }
        WA_CHECK_STATUS(status, test_case->expected_status);
        WA_CHECK(strcmp(location.text, test_case->expected_location) == 0);
        wa_value_destroy(cryptoconf);
    }
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

/* KEY CIPHER NESTING DEPTH */

/* A cryptoconf whose single payload layer nests `level_count` key_cipher_layers lists (level 1 being the payload
 * layer's own), alternating symmetric key layers and shared secret shards, and the location of the deepest list */
static void build_nested_cryptoconf(size_t level_count, char *notation, size_t notation_size, char *deepest_list,
                                    size_t deepest_list_size)
{
    size_t level;
    size_t closing_count = 0;
    char closings[64];
    strcpy(notation, "{'keychain_uid': " UID ", 'payload_cipher_layers': [{'payload_cipher_algo': 'AES_CBC', "
                     "'payload_ciphertext_signatures': [], 'key_cipher_layers': [");
    strcpy(deepest_list, PAYLOAD_0 ".key_cipher_layers");
    for (level = 2; level <= level_count; ++level) {
        if (level % 2 == 0) {
            strncat(notation, "{'key_cipher_algo': 'AES_EAX', 'key_cipher_layers': [",
                    notation_size - strlen(notation) - 1u);
            strncat(deepest_list, "[0].key_cipher_layers", deepest_list_size - strlen(deepest_list) - 1u);
            closings[closing_count++] = '1';
        } else {
            strncat(notation,
                    "{'key_cipher_algo': '[SHARED_SECRET]', 'key_shared_secret_threshold': 1, "
                    "'key_shared_secret_shards': [{'key_cipher_layers': [",
                    notation_size - strlen(notation) - 1u);
            strncat(deepest_list, "[0].key_shared_secret_shards[0].key_cipher_layers",
                    deepest_list_size - strlen(deepest_list) - 1u);
            closings[closing_count++] = '2';
        }
    }
    strncat(notation, RSA_LAYER, notation_size - strlen(notation) - 1u);
    while (closing_count > 0) {
        strncat(notation, closings[--closing_count] == '1' ? "]}" : "]}]}", notation_size - strlen(notation) - 1u);
    }
    strncat(notation, "]}]}", notation_size - strlen(notation) - 1u);
}

static void test_key_cipher_nesting_depth(void)
{
    static char notation[8192];
    char deepest_list[WA_ERROR_LOCATION_PATH_CAPACITY * 2u];
    size_t level_count;
    wa_test_platform_t *platform = wa_test_platform_create(2);
    WA_REQUIRE(platform != NULL);
    for (level_count = 1; level_count <= WA_MAX_KEY_CIPHER_NESTING_DEPTH + 2u; ++level_count) {
        wa_value_t *cryptoconf = NULL;
        wa_error_location_path_t location;
        wa_status_t status;
        build_nested_cryptoconf(level_count, notation, sizeof(notation), deepest_list, sizeof(deepest_list));
        WA_REQUIRE_STATUS(wa_test_build_value_tree(&platform->hooks, notation, &cryptoconf), WA_STATUS_OK);
        wa_error_location_path_initialize(&location);
        (void)wa_error_location_path_push_key(&location, "cryptoconf", strlen("cryptoconf"));
        status = wa_cryptoconf_validate(cryptoconf, &location);
        if (level_count <= WA_MAX_KEY_CIPHER_NESTING_DEPTH) {
            WA_CHECK_STATUS(status, WA_STATUS_OK);
            WA_CHECK(strcmp(location.text, "cryptoconf") == 0);
        } else {
            WA_CHECK_STATUS(status, WA_STATUS_NESTING_TOO_DEEP);
            /* The first list beyond the limit is named */
            if (level_count == WA_MAX_KEY_CIPHER_NESTING_DEPTH + 1u) {
                WA_CHECK(strncmp(location.text, deepest_list, WA_ERROR_LOCATION_PATH_CAPACITY - 1u) == 0);
                WA_CHECK_SIZE(location.logical_length, strlen(deepest_list));
            }
        }
        wa_value_destroy(cryptoconf);
    }
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

/* SHARD COUNT LIMIT */

/* A cryptoconf whose payload layer's key layer is `key_layer_prefix`, then a shared secret layer of `shard_count`
 * RSA shards, then `key_layer_suffix`, written into `notation` */
static void build_shard_count_cryptoconf(const char *key_layer_prefix, const char *threshold, size_t shard_count,
                                         const char *key_layer_suffix, char *notation, size_t notation_size)
{
    size_t shard_index;
    notation[0] = '\0';
    strncat(notation,
            "{'keychain_uid': " UID ", 'payload_cipher_layers': [{'payload_cipher_algo': 'AES_CBC', "
            "'payload_ciphertext_signatures': [], 'key_cipher_layers': [",
            notation_size - 1u);
    strncat(notation, key_layer_prefix, notation_size - strlen(notation) - 1u);
    strncat(notation, "{'key_cipher_algo': '[SHARED_SECRET]', 'key_shared_secret_threshold': ",
            notation_size - strlen(notation) - 1u);
    strncat(notation, threshold, notation_size - strlen(notation) - 1u);
    strncat(notation, ", 'key_shared_secret_shards': [", notation_size - strlen(notation) - 1u);
    for (shard_index = 0; shard_index < shard_count; ++shard_index) {
        strncat(notation, shard_index > 0 ? ", " SHARD(RSA_LAYER) : SHARD(RSA_LAYER),
                notation_size - strlen(notation) - 1u);
    }
    strncat(notation, "]}", notation_size - strlen(notation) - 1u);
    strncat(notation, key_layer_suffix, notation_size - strlen(notation) - 1u);
    strncat(notation, "]}]}", notation_size - strlen(notation) - 1u);
}

static void test_shared_secret_shard_count_limit(void)
{
    /* The shared secret layer as the key layer of the payload layer, in a shard of another shared secret, or
     * under a symmetric key layer */
    static const struct {
        const char *key_layer_prefix;
        const char *key_layer_suffix;
        const char *shard_list_location;
    } placements[] = {
        {"", "", KEY_LAYER_0 ".key_shared_secret_shards"},
        {"{'key_cipher_algo': '[SHARED_SECRET]', 'key_shared_secret_threshold': 1, 'key_shared_secret_shards': ["
         SHARD(RSA_LAYER) ", {'key_cipher_layers': [",
         "]}]}", KEY_LAYER_0 ".key_shared_secret_shards[1].key_cipher_layers[0].key_shared_secret_shards"},
        {"{'key_cipher_algo': 'AES_EAX', 'key_cipher_layers': [" RSA_LAYER ", ", "]}",
         KEY_LAYER_0 ".key_cipher_layers[1].key_shared_secret_shards"},
    };
    static const struct {
        const char *threshold;
        size_t shard_count;
        int is_valid;
    } shard_lists[] = {
        {"1", 30, 1},
        {"30", 30, 1},
        {"2", 31, 0},
        {"31", 31, 0},
        {"0", 31, 0}, /* The shard count is checked first */
        {"2", 300, 0}, /* Shard indices above 255 otherwise */
    };
    static char notation[65536];
    size_t placement_index;
    size_t list_index;
    wa_test_platform_t *platform = wa_test_platform_create(3);
    WA_REQUIRE(platform != NULL);
    WA_CHECK_SIZE(WA_MAX_SHARED_SECRET_SHARD_COUNT, 30);
    for (placement_index = 0; placement_index < sizeof(placements) / sizeof(placements[0]); ++placement_index) {
        for (list_index = 0; list_index < sizeof(shard_lists) / sizeof(shard_lists[0]); ++list_index) {
            wa_value_t *cryptoconf = NULL;
            wa_error_location_path_t location;
            wa_status_t status;
            const char *expected_location = shard_lists[list_index].is_valid
                                                ? "cryptoconf"
                                                : placements[placement_index].shard_list_location;
            build_shard_count_cryptoconf(placements[placement_index].key_layer_prefix,
                                         shard_lists[list_index].threshold, shard_lists[list_index].shard_count,
                                         placements[placement_index].key_layer_suffix, notation, sizeof(notation));
            WA_REQUIRE(strlen(notation) + 1u < sizeof(notation));
            WA_REQUIRE_STATUS(wa_test_build_value_tree(&platform->hooks, notation, &cryptoconf), WA_STATUS_OK);
            wa_error_location_path_initialize(&location);
            (void)wa_error_location_path_push_key(&location, "cryptoconf", strlen("cryptoconf"));
            status = wa_cryptoconf_validate(cryptoconf, &location);
            if ((status == WA_STATUS_OK) != shard_lists[list_index].is_valid ||
                strcmp(location.text, expected_location) != 0) {
                fprintf(stderr, "placement %lu, %lu shards (threshold %s): status %d at '%s'\n",
                        (unsigned long)placement_index, (unsigned long)shard_lists[list_index].shard_count,
                        shard_lists[list_index].threshold, (int)status, location.text);
            }
            WA_CHECK_STATUS(status, shard_lists[list_index].is_valid ? WA_STATUS_OK : WA_STATUS_INVALID_PROFILE);
            WA_CHECK(strcmp(location.text, expected_location) == 0);
            wa_value_destroy(cryptoconf);
        }
    }
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

/* ERROR LOCATION PATH */

static void test_error_location_path(void)
{
    wa_error_location_path_t path;
    char buffer[16];
    char long_key[300];
    size_t length_after_key;
    size_t length_after_index;
    wa_error_location_path_initialize(&path);
    WA_CHECK(strcmp(path.text, "") == 0);
    WA_CHECK_SIZE(wa_error_location_path_push_key(&path, "cryptoconf", 10), 0);
    length_after_key = wa_error_location_path_push_key(&path, "payload_cipher_layers", 21);
    WA_CHECK_SIZE(length_after_key, 10);
    (void)wa_error_location_path_push_index(&path, 0);
    WA_CHECK(strcmp(path.text, "cryptoconf.payload_cipher_layers[0]") == 0);
    length_after_index = wa_error_location_path_push_index(&path, 1234567890u);
    WA_CHECK(strcmp(path.text, "cryptoconf.payload_cipher_layers[0][1234567890]") == 0);
    wa_error_location_path_pop(&path, length_after_index);
    WA_CHECK(strcmp(path.text, "cryptoconf.payload_cipher_layers[0]") == 0);
    wa_error_location_path_pop(&path, length_after_key);
    WA_CHECK(strcmp(path.text, "cryptoconf") == 0);

    /* Copy, truncated to the buffer */
    wa_error_location_path_copy_to_buffer(&path, buffer, sizeof(buffer));
    WA_CHECK(strcmp(buffer, "cryptoconf") == 0);
    wa_error_location_path_copy_to_buffer(&path, buffer, 4);
    WA_CHECK(strcmp(buffer, "cry") == 0);
    buffer[0] = 'x';
    wa_error_location_path_copy_to_buffer(&path, buffer, 0);
    WA_CHECK(buffer[0] == 'x');
    wa_error_location_path_copy_to_buffer(&path, NULL, 10);

    /* Truncation beyond the capacity, pops still restoring the right prefix */
    memset(long_key, 'k', sizeof(long_key) - 1u);
    long_key[sizeof(long_key) - 1u] = '\0';
    length_after_key = wa_error_location_path_push_key(&path, long_key, strlen(long_key));
    WA_CHECK_SIZE(path.logical_length, 10u + 1u + 299u);
    WA_CHECK_SIZE(strlen(path.text), WA_ERROR_LOCATION_PATH_CAPACITY - 1u);
    length_after_index = wa_error_location_path_push_index(&path, 7);
    WA_CHECK_SIZE(path.logical_length, 10u + 1u + 299u + 3u);
    wa_error_location_path_pop(&path, length_after_index);
    WA_CHECK_SIZE(strlen(path.text), WA_ERROR_LOCATION_PATH_CAPACITY - 1u);
    wa_error_location_path_pop(&path, length_after_key);
    WA_CHECK(strcmp(path.text, "cryptoconf") == 0);
    (void)wa_error_location_path_push_index(&path, 3);
    WA_CHECK(strcmp(path.text, "cryptoconf[3]") == 0);
}

/* TRUSTEES */

static void test_trustee_validation_and_identities(void)
{
    static const char *const trustee_notations[] = {
        LOCAL_TRUSTEE,                                                                                   /* 0 */
        AUTHENTICATOR_TRUSTEE,                                                                           /* 1 */
        "{'trustee_type': 'authenticator', 'keystore_uid': " UID "}",                                    /* 2 */
        "{'keystore_owner': 'John', 'keystore_uid': " UID ", 'trustee_type': 'authenticator'}",          /* 3 */
        "{'trustee_type': 'authenticator', 'keystore_uid': " OTHER_UID ", 'keystore_owner': 'Jane'}",    /* 4 */
        JSONRPC_TRUSTEE,                                                                                 /* 5 */
        "{'trustee_type': 'jsonrpc_api', 'jsonrpc_url': 'https://example.com/jsonrpc/'}",                /* 6 */
    };
    /* Identity classes of the trustees above */
    static const int identity_classes[] = {0, 1, 1, 1, 2, 3, 4};
    wa_value_t *trustees[sizeof(trustee_notations) / sizeof(trustee_notations[0])];
    size_t index_a;
    size_t index_b;
    wa_test_platform_t *platform = wa_test_platform_create(3);
    WA_REQUIRE(platform != NULL);
    for (index_a = 0; index_a < sizeof(trustees) / sizeof(trustees[0]); ++index_a) {
        wa_error_location_path_t location;
        WA_REQUIRE_STATUS(wa_test_build_value_tree(&platform->hooks, trustee_notations[index_a], &trustees[index_a]),
                          WA_STATUS_OK);
        wa_error_location_path_initialize(&location);
        WA_CHECK_STATUS(wa_cryptoconf_validate_trustee(trustees[index_a], &location), WA_STATUS_OK);
        WA_CHECK(strcmp(location.text, "") == 0);
    }
    for (index_a = 0; index_a < sizeof(trustees) / sizeof(trustees[0]); ++index_a) {
        for (index_b = 0; index_b < sizeof(trustees) / sizeof(trustees[0]); ++index_b) {
            WA_CHECK(wa_trustee_identities_are_equal(trustees[index_a], trustees[index_b]) ==
                     (identity_classes[index_a] == identity_classes[index_b]));
        }
    }
    for (index_a = 0; index_a < sizeof(trustees) / sizeof(trustees[0]); ++index_a) {
        wa_value_destroy(trustees[index_a]);
    }
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

/* NOTATION BUILDER SELF-CHECK */

static void test_value_notation(void)
{
    wa_value_t *tree = NULL;
    const uint8_t *bytes = NULL;
    size_t length = 0;
    int64_t integer = 0;
    int boolean = 1;
    wa_test_platform_t *platform = wa_test_platform_create(4);
    WA_REQUIRE(platform != NULL);
    WA_REQUIRE_STATUS(wa_test_build_value_tree(&platform->hooks,
                                               " { 'a' : [ -12, null, false, b'00ff', u'" "000102030405060708090a0b0c0d0e0f'"
                                               " ], 'b': {} , 'c': '' } ",
                                               &tree),
                      WA_STATUS_OK);
    WA_CHECK_SIZE(wa_value_get_item_count(tree), 3);
    WA_CHECK(wa_value_get_integer(wa_value_get_array_item(wa_value_find_map_value(tree, "a"), 0), &integer) == 0);
    WA_CHECK(integer == -12);
    WA_CHECK(wa_value_get_type(wa_value_get_array_item(wa_value_find_map_value(tree, "a"), 1)) ==
             WA_VALUE_TYPE_NULL);
    WA_CHECK(wa_value_get_boolean(wa_value_get_array_item(wa_value_find_map_value(tree, "a"), 2), &boolean) == 0);
    WA_CHECK(boolean == 0);
    WA_CHECK(wa_value_get_bytes(wa_value_get_array_item(wa_value_find_map_value(tree, "a"), 3), &bytes, &length) ==
             0);
    WA_CHECK_HEX(bytes, length, "00ff");
    WA_CHECK(wa_value_get_uuid(wa_value_get_array_item(wa_value_find_map_value(tree, "a"), 4), &bytes) == 0);
    WA_CHECK_HEX(bytes, WA_UUID_SIZE, "000102030405060708090a0b0c0d0e0f");
    WA_CHECK(wa_value_get_type(wa_value_find_map_value(tree, "b")) == WA_VALUE_TYPE_MAP);
    WA_CHECK(wa_value_get_type(wa_value_find_map_value(tree, "c")) == WA_VALUE_TYPE_TEXT);
    wa_value_destroy(tree);
    WA_CHECK_STATUS(wa_test_build_value_tree(&platform->hooks, "{'a': 1, 'a': 2}", &tree),
                    WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK(tree == NULL);
    WA_CHECK_STATUS(wa_test_build_value_tree(&platform->hooks, "[1, 2", &tree), WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(wa_test_build_value_tree(&platform->hooks, "[1] 2", &tree), WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK(tree == NULL);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

int main(void)
{
    WA_RUN_TEST(test_value_notation);
    WA_RUN_TEST(test_cryptoconf_cases);
    WA_RUN_TEST(test_key_cipher_nesting_depth);
    WA_RUN_TEST(test_shared_secret_shard_count_limit);
    WA_RUN_TEST(test_error_location_path);
    WA_RUN_TEST(test_trustee_validation_and_identities);
    return wa_test_finish();
}
