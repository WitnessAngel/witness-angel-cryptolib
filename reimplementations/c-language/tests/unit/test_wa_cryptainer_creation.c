/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Cryptainer creation (tasks 7.1 to 7.4), in each enabled document format:
 * - key cipher chains: the cryptainer of a profile using every layer kind is read back with a test-only reader, and
 *   the nesting of spec section 6.7 is checked down to the exact length of every serialized structure, recomputed
 *   from the profile (key structs, shards, cipherdicts), since the trustees' private keys are not available here;
 * - base generation: every root and layer field after step 1, legacy signature list renaming, unchanged cryptoconf;
 * - payload pipeline: chunked and one-shot outputs identical for 1 to 3 layers of mixed algorithms;
 * - encryptor: options, metadata checks before any random draw, state machine, sinks, one-shot helper, suffixes. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/wa_cryptainer_base_generation.h"
#include "core/wa_payload_encryption_pipeline.h"
#include "core/wa_platform_hooks_calls.h"
#include "encoding/wa_device_profile_decoding.h"
#include "encoding/wa_document_serialization.h"
#include "encoding/wa_value_tree_internal.h"
#include "primitives/wa_shamir_secret_sharing_gf128.h"
#include "primitives/wa_symmetric_cipher_streams.h"
#include "wa_flightbox/wa_flightbox.h"
#include "wa_minimal_test_harness.h"
#include "wa_test_device_profile_samples.h"
#include "wa_test_document_reader.h"
#include "wa_test_support.h"

static const wa_document_format_t enabled_formats[] = {
#if WA_DOCUMENT_FORMAT_JSON_ENABLED
    WA_DOCUMENT_FORMAT_JSON,
#endif
#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
    WA_DOCUMENT_FORMAT_CBOR,
#endif
};
#define WA_ENABLED_FORMAT_COUNT (sizeof(enabled_formats) / sizeof(enabled_formats[0]))

/* 0d0d0d0d-0000-4000-8000-000000000001, the root keychain uid of the generated samples */
static const uint8_t samples_root_keychain_uid[WA_UUID_SIZE] = {0x0d, 0x0d, 0x0d, 0x0d, 0x00, 0x00, 0x40, 0x00,
                                                               0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

static const char *get_format_name(wa_document_format_t format)
{
    return format == WA_DOCUMENT_FORMAT_CBOR ? "cbor" : "json";
}

/* HELPERS */

/* Follow a path like "payload_cipher_layers[1].key_cipher_layers[0]" (NULL if anything is missing) */
static const wa_value_t *get_path(const wa_value_t *root, const char *path)
{
    const wa_value_t *current = root;
    char key[128];
    while (current != NULL && *path != '\0') {
        size_t key_length = 0;
        if (*path == '.') {
            ++path;
        }
        while (*path != '\0' && *path != '.' && *path != '[' && key_length + 1 < sizeof(key)) {
            key[key_length++] = *path++;
        }
        key[key_length] = '\0';
        if (key_length > 0) {
            current = wa_value_find_map_value(current, key);
        }
        while (current != NULL && *path == '[') {
            size_t index = (size_t)strtoul(path + 1, NULL, 10);
            current = wa_value_get_array_item(current, index);
            path = strchr(path, ']');
            if (path == NULL) {
                return NULL;
            }
            ++path;
        }
    }
    return current;
}

static size_t get_bytes_length(const wa_value_t *value)
{
    const uint8_t *bytes = NULL;
    size_t length = 0;
    return wa_value_get_bytes(value, &bytes, &length) == 0 ? length : (size_t)-1;
}

static int text_equals(const wa_value_t *value, const char *expected)
{
    return wa_value_is_text_equal_to(value, expected);
}

/* Read back a bytes node holding a document serialized in `format` (NULL on failure) */
static wa_value_t *read_bytes_document(const wa_platform_hooks_t *platform_hooks, wa_document_format_t format,
                                       const wa_value_t *bytes_node)
{
    const uint8_t *bytes = NULL;
    size_t length = 0;
    wa_value_t *tree = NULL;
    if (wa_value_get_bytes(bytes_node, &bytes, &length) != 0) {
        return NULL;
    }
    if (wa_test_read_document(platform_hooks, format, bytes, length, &tree) != WA_STATUS_OK) {
        return NULL;
    }
    return tree;
}

/* Length of S_F(tree) */
static size_t get_serialized_length(const wa_platform_hooks_t *platform_hooks, wa_document_format_t format,
                                    const wa_value_t *tree)
{
    wa_growable_byte_buffer_t buffer;
    size_t length;
    wa_growable_byte_buffer_initialize(&buffer, platform_hooks, 0);
    if (wa_document_serialize_to_buffer(tree, format, &buffer) != WA_STATUS_OK) {
        wa_growable_byte_buffer_release(&buffer);
        return (size_t)-1;
    }
    length = buffer.length;
    wa_growable_byte_buffer_release(&buffer);
    return length;
}

/* Whether two trees serialize identically in `format` */
static int trees_are_equal(const wa_platform_hooks_t *platform_hooks, wa_document_format_t format,
                           const wa_value_t *tree_a, const wa_value_t *tree_b)
{
    wa_growable_byte_buffer_t buffer_a;
    wa_growable_byte_buffer_t buffer_b;
    int are_equal;
    wa_growable_byte_buffer_initialize(&buffer_a, platform_hooks, 0);
    wa_growable_byte_buffer_initialize(&buffer_b, platform_hooks, 0);
    are_equal = wa_document_serialize_to_buffer(tree_a, format, &buffer_a) == WA_STATUS_OK &&
                wa_document_serialize_to_buffer(tree_b, format, &buffer_b) == WA_STATUS_OK &&
                buffer_a.length == buffer_b.length && memcmp(buffer_a.data, buffer_b.data, buffer_a.length) == 0;
    wa_growable_byte_buffer_release(&buffer_a);
    wa_growable_byte_buffer_release(&buffer_b);
    return are_equal;
}

/* LENGTHS OF THE STRUCTURES SERIALIZED IN KEY CIPHERTEXTS (they only depend on the lengths of their bytes) */

static size_t get_symkey_length(const wa_platform_hooks_t *platform_hooks, wa_document_format_t format,
                                wa_symmetric_cipher_algo_t cipher_algo)
{
    wa_symkey_t symkey;
    wa_value_t *tree = NULL;
    size_t length;
    memset(&symkey, 0, sizeof(symkey));
    symkey.cipher_algo = cipher_algo;
    symkey.iv_or_nonce_length = cipher_algo == WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305 ? 12u : 16u;
    if (wa_symkey_build_tree(platform_hooks, &symkey, &tree) != WA_STATUS_OK) {
        return (size_t)-1;
    }
    length = get_serialized_length(platform_hooks, format, tree);
    wa_value_destroy(tree);
    return length;
}

/* S_F({"key_bytes": bytes(key_bytes_length), "cryptainer_metadata": metadata or null}) */
static size_t get_key_struct_length(const wa_platform_hooks_t *platform_hooks, wa_document_format_t format,
                                    size_t key_bytes_length, const wa_value_t *metadata_or_null)
{
    uint8_t *zeros = (uint8_t *)calloc(key_bytes_length + 1u, 1);
    wa_value_t key_bytes_node;
    wa_value_t null_node;
    wa_value_map_entry_t entries[2];
    wa_value_t key_struct;
    size_t length;
    wa_value_initialize_borrowed_bytes(&key_bytes_node, zeros, key_bytes_length);
    wa_value_initialize_borrowed_null(&null_node);
    wa_value_initialize_borrowed_map_entry(&entries[0], "key_bytes", &key_bytes_node);
    wa_value_initialize_borrowed_map_entry(&entries[1], "cryptainer_metadata",
                                           metadata_or_null == NULL ? &null_node : metadata_or_null);
    wa_value_initialize_borrowed_map(&key_struct, entries, 2);
    length = get_serialized_length(platform_hooks, format, &key_struct);
    free(zeros);
    return length;
}

/* S_F([index, bytes(shard_length)]) */
static size_t get_shard_length(const wa_platform_hooks_t *platform_hooks, wa_document_format_t format,
                               int64_t shard_index, size_t shard_length)
{
    uint8_t *zeros = (uint8_t *)calloc(shard_length + 1u, 1);
    wa_value_t index_node;
    wa_value_t bytes_node;
    wa_value_t *items[2];
    wa_value_t shard;
    size_t length;
    wa_value_initialize_borrowed_integer(&index_node, shard_index);
    wa_value_initialize_borrowed_bytes(&bytes_node, zeros, shard_length);
    items[0] = &index_node;
    items[1] = &bytes_node;
    wa_value_initialize_borrowed_array(&shard, items, 2);
    length = get_serialized_length(platform_hooks, format, &shard);
    free(zeros);
    return length;
}

/* S_F({"ciphertext_chunks": [bytes(modulus_length)] * ceil(plaintext_length / 60)}) */
static size_t get_rsa_cipherdict_length(const wa_platform_hooks_t *platform_hooks, wa_document_format_t format,
                                        size_t plaintext_length, size_t modulus_length)
{
    size_t chunk_count = (plaintext_length + 59u) / 60u;
    uint8_t *zeros = (uint8_t *)calloc(modulus_length, 1);
    wa_value_t *chunk_nodes = (wa_value_t *)calloc(chunk_count + 1u, sizeof(wa_value_t));
    wa_value_t **chunk_pointers = (wa_value_t **)calloc(chunk_count + 1u, sizeof(wa_value_t *));
    wa_value_t chunks;
    wa_value_map_entry_t entry;
    wa_value_t cipherdict;
    size_t chunk_index;
    size_t length;
    for (chunk_index = 0; chunk_index < chunk_count; ++chunk_index) {
        wa_value_initialize_borrowed_bytes(&chunk_nodes[chunk_index], zeros, modulus_length);
        chunk_pointers[chunk_index] = &chunk_nodes[chunk_index];
    }
    wa_value_initialize_borrowed_array(&chunks, chunk_pointers, chunk_count);
    wa_value_initialize_borrowed_map_entry(&entry, "ciphertext_chunks", &chunks);
    wa_value_initialize_borrowed_map(&cipherdict, &entry, 1);
    length = get_serialized_length(platform_hooks, format, &cipherdict);
    free(zeros);
    free(chunk_nodes);
    free(chunk_pointers);
    return length;
}

static size_t get_shamir_shard_length(const wa_platform_hooks_t *platform_hooks, size_t secret_length,
                                      size_t shard_count, size_t threshold_count)
{
    uint8_t *secret = (uint8_t *)calloc(secret_length + 1u, 1);
    uint8_t *shards = NULL;
    size_t shard_length = 0;
    if (wa_shamir_split_secret_into_shards(platform_hooks, secret, secret_length, shard_count, threshold_count,
                                           &shards, &shard_length) != WA_STATUS_OK) {
        shard_length = (size_t)-1;
    } else {
        wa_release_secret_memory(platform_hooks, shards, shard_count * shard_length);
    }
    free(secret);
    return shard_length;
}

/* Check an asymmetric cipherdict read back from a key ciphertext, wrapping a key struct of `key_bytes_length`
 * bytes. Returns 1 if all is fine. */
static int check_asymmetric_cipherdict(const wa_platform_hooks_t *platform_hooks, wa_document_format_t format,
                                       const wa_value_t *cipherdict, wa_asymmetric_cipher_algo_t cipher_algo,
                                       size_t key_bytes_length, const wa_value_t *metadata_or_null,
                                       size_t modulus_length)
{
    size_t key_struct_length = get_key_struct_length(platform_hooks, format, key_bytes_length, metadata_or_null);
    if (cipher_algo == WA_ASYMMETRIC_CIPHER_RSA_OAEP) {
        const wa_value_t *chunks = wa_value_find_map_value(cipherdict, "ciphertext_chunks");
        size_t chunk_index;
        if (wa_value_get_item_count(cipherdict) != 1 ||
            wa_value_get_item_count(chunks) != (key_struct_length + 59u) / 60u) {
            return 0;
        }
        for (chunk_index = 0; chunk_index < wa_value_get_item_count(chunks); ++chunk_index) {
            if (get_bytes_length(wa_value_get_array_item(chunks, chunk_index)) != modulus_length) {
                return 0;
            }
        }
        return 1;
    }
    return wa_value_get_item_count(cipherdict) == 2 &&
           get_bytes_length(wa_value_find_map_value(cipherdict, "kem_ciphertext")) ==
               (cipher_algo == WA_ASYMMETRIC_CIPHER_ECIES_X25519 ? 32u : 1088u) &&
           get_bytes_length(wa_value_find_map_value(cipherdict, "ciphertext")) == key_struct_length + 16u;
}

/* ENCRYPTION HELPERS */

typedef struct encryption_result {
    wa_test_memory_sink_t cryptainer_sink;
    wa_test_memory_sink_t payload_sink;
    wa_value_t *cryptainer; /* Read back */
} encryption_result_t;

static void release_encryption_result(encryption_result_t *result)
{
    wa_test_memory_sink_release(&result->cryptainer_sink);
    wa_test_memory_sink_release(&result->payload_sink);
    wa_value_destroy(result->cryptainer);
    result->cryptainer = NULL;
}

/* Encrypt `payload` in chunks of `chunk_size` bytes, write and read back the cryptainer */
static wa_status_t encrypt_payload(const wa_platform_hooks_t *platform_hooks, const wa_device_profile_t *device_profile,
                                   const wa_value_t *metadata_or_null, wa_document_format_t format,
                                   wa_ciphertext_location_t location, const uint8_t *payload, size_t payload_length,
                                   size_t chunk_size, encryption_result_t *result)
{
    wa_cryptainer_encryptor_options_t options;
    wa_cryptainer_encryptor_t *encryptor = NULL;
    size_t offset = 0;
    wa_status_t status;
    wa_test_memory_sink_initialize(&result->cryptainer_sink);
    wa_test_memory_sink_initialize(&result->payload_sink);
    result->cryptainer = NULL;
    options.platform_hooks = platform_hooks;
    options.document_format = format;
    options.ciphertext_location = location;
    options.payload_ciphertext_sink = location == WA_CIPHERTEXT_LOCATION_OFFLOADED ? &result->payload_sink.sink : NULL;
    status = wa_cryptainer_encryptor_create(device_profile, metadata_or_null, &options, &encryptor);
    while (status == WA_STATUS_OK && offset < payload_length) {
        size_t length = payload_length - offset < chunk_size ? payload_length - offset : chunk_size;
        status = wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, payload + offset, length);
        offset += length;
    }
    if (status == WA_STATUS_OK) {
        status = wa_cryptainer_encryptor_finalize(encryptor);
    }
    if (status == WA_STATUS_OK) {
        status = wa_cryptainer_encryptor_write_cryptainer(encryptor, &result->cryptainer_sink.sink);
    }
    wa_cryptainer_encryptor_destroy(encryptor);
    if (status == WA_STATUS_OK) {
        status = wa_test_read_document(platform_hooks, format, result->cryptainer_sink.bytes,
                                       result->cryptainer_sink.length, &result->cryptainer);
    }
    return status;
}

static uint8_t *build_payload(size_t length)
{
    uint8_t *payload = (uint8_t *)malloc(length + 1u);
    size_t index;
    for (index = 0; index < length; ++index) {
        payload[index] = (uint8_t)(index * 7u + 3u);
    }
    return payload;
}

/* {"device_id": "fb-07", "sequence": 42} */
static wa_value_t *build_sample_metadata(const wa_platform_hooks_t *platform_hooks)
{
    wa_value_t *metadata = NULL;
    wa_value_t *device_id = NULL;
    wa_value_t *sequence = NULL;
    if (wa_value_create_map(platform_hooks, &metadata) != WA_STATUS_OK ||
        wa_value_create_text(platform_hooks, "fb-07", 5, &device_id) != WA_STATUS_OK ||
        wa_value_map_add_consuming(metadata, "device_id", device_id) != WA_STATUS_OK ||
        wa_value_create_integer(platform_hooks, 42, &sequence) != WA_STATUS_OK ||
        wa_value_map_add_consuming(metadata, "sequence", sequence) != WA_STATUS_OK) {
        wa_value_destroy(metadata);
        return NULL;
    }
    return metadata;
}

/* TASK 7.1: NESTING OF SECTION 6.7, EVERY LAYER KIND */

/* nested_all_layer_kinds:
 *   payload layer 0: AES_EAX, key through [ECIES_X25519 local]
 *   payload layer 1: CHACHA20_POLY1305, key through [RSA_OAEP authenticator, SHARED_SECRET 2 of 3:
 *       shard 1: [ECIES_X25519 other authenticator], shard 2: [ML_KEM_768 jsonrpc],
 *       shard 3: [CHACHA20_POLY1305 symmetric layer, its sub-key through [RSA_OAEP local, layer keychain uid]]] */
static void check_nested_cryptainer(const wa_platform_hooks_t *platform_hooks, const wa_device_profile_t *device_profile,
                                    wa_document_format_t format, const wa_value_t *cryptainer,
                                    const wa_value_t *metadata, size_t payload_length)
{
    const wa_value_t *payload_layer_0 = get_path(cryptainer, "payload_cipher_layers[0]");
    const wa_value_t *payload_layer_1 = get_path(cryptainer, "payload_cipher_layers[1]");
    const wa_value_t *rsa_layer = get_path(payload_layer_1, "key_cipher_layers[0]");
    const wa_value_t *shared_secret_layer = get_path(payload_layer_1, "key_cipher_layers[1]");
    const wa_value_t *symmetric_layer =
        get_path(shared_secret_layer, "key_shared_secret_shards[2].key_cipher_layers[0]");
    const wa_value_t *rsa_local_layer = get_path(symmetric_layer, "key_cipher_layers[0]");
    const wa_asymmetric_public_key_t *rsa_public_key = NULL;
    const uint8_t *uuid = NULL;
    wa_value_t *cipherdict;
    wa_value_t *shard_ciphertexts_dict;
    size_t shard_length;
    size_t rsa_cipherdict_length;
    size_t shard_index;
    int is_cbor = format == WA_DOCUMENT_FORMAT_CBOR;

    WA_REQUIRE(payload_layer_0 != NULL && payload_layer_1 != NULL && symmetric_layer != NULL &&
               rsa_local_layer != NULL);
    WA_REQUIRE_STATUS(wa_device_profile_find_layer_public_key(device_profile, rsa_layer, &rsa_public_key),
                      WA_STATUS_OK);

    /* Root fields (section 9.1): nothing else than the cryptoconf's fields and the 5 added ones */
    WA_CHECK_SIZE(wa_value_get_item_count(cryptainer), 7);
    WA_CHECK(text_equals(wa_value_find_map_value(cryptainer, "cryptainer_state"), "FINISHED"));
    WA_CHECK(text_equals(wa_value_find_map_value(cryptainer, "cryptainer_format"), "cryptainer_1.0"));
    WA_CHECK(wa_value_get_uuid(wa_value_find_map_value(cryptainer, "cryptainer_uid"), &uuid) == 0);
    WA_CHECK(wa_value_get_uuid(wa_value_find_map_value(cryptainer, "keychain_uid"), &uuid) == 0 &&
             memcmp(uuid, samples_root_keychain_uid, WA_UUID_SIZE) == 0);
    WA_CHECK(trees_are_equal(platform_hooks, format, wa_value_find_map_value(cryptainer, "cryptainer_metadata"),
                             metadata));
    WA_CHECK(text_equals(get_path(cryptainer, "payload_ciphertext_struct.ciphertext_location"), "inline"));
    WA_CHECK_SIZE(get_bytes_length(get_path(cryptainer, "payload_ciphertext_struct.ciphertext_value")),
                  payload_length); /* AES_EAX then CHACHA20_POLY1305: no padding */

    /* Payload layer fields: MACs, signature lists, format fields */
    WA_CHECK_SIZE(wa_value_get_item_count(get_path(payload_layer_0, "payload_macs")), 1);
    WA_CHECK_SIZE(get_bytes_length(get_path(payload_layer_0, "payload_macs.tag")), 16);
    WA_CHECK_SIZE(get_bytes_length(get_path(payload_layer_1, "payload_macs.tag")), 16);
    WA_CHECK(wa_value_get_type(get_path(payload_layer_1, "payload_ciphertext_signatures")) == WA_VALUE_TYPE_ARRAY &&
             wa_value_get_item_count(get_path(payload_layer_1, "payload_ciphertext_signatures")) == 0);
    WA_CHECK_SIZE(wa_value_get_item_count(payload_layer_0), is_cbor ? 6u : 5u);
    WA_CHECK_SIZE(wa_value_get_item_count(payload_layer_1), is_cbor ? 6u : 5u);
    WA_CHECK(is_cbor ? text_equals(get_path(payload_layer_0, "key_ciphertext_format"), "cbor")
                     : get_path(payload_layer_0, "key_ciphertext_format") == NULL);
    WA_CHECK(is_cbor ? text_equals(get_path(payload_layer_1, "key_ciphertext_format"), "cbor")
                     : get_path(payload_layer_1, "key_ciphertext_format") == NULL);

    /* Only symmetric key layers receive fields: asymmetric layers, shared secrets and shard confs are unchanged */
    WA_CHECK_SIZE(wa_value_get_item_count(rsa_layer), 2);
    WA_CHECK_SIZE(wa_value_get_item_count(shared_secret_layer), 3);
    WA_CHECK_SIZE(wa_value_get_item_count(get_path(shared_secret_layer, "key_shared_secret_shards[0]")), 1);
    WA_CHECK_SIZE(wa_value_get_item_count(rsa_local_layer), 3); /* Its own keychain uid only */
    WA_CHECK_SIZE(wa_value_get_item_count(symmetric_layer), is_cbor ? 4u : 3u);
    WA_CHECK(is_cbor ? text_equals(get_path(symmetric_layer, "key_ciphertext_format"), "cbor")
                     : get_path(symmetric_layer, "key_ciphertext_format") == NULL);

    /* Payload layer 0: ECIES_X25519(S_F(key struct of S_F(AES_EAX symkey))) */
    cipherdict = read_bytes_document(platform_hooks, format, get_path(payload_layer_0, "key_ciphertext"));
    WA_CHECK(cipherdict != NULL &&
             check_asymmetric_cipherdict(platform_hooks, format, cipherdict, WA_ASYMMETRIC_CIPHER_ECIES_X25519,
                                         get_symkey_length(platform_hooks, format, WA_SYMMETRIC_CIPHER_AES_EAX),
                                         metadata, 0));
    wa_value_destroy(cipherdict);

    /* Symmetric layer: its sub-symkey through RSA_OAEP (local) */
    cipherdict = read_bytes_document(platform_hooks, format, get_path(symmetric_layer, "key_ciphertext"));
    WA_CHECK(cipherdict != NULL &&
             check_asymmetric_cipherdict(
                 platform_hooks, format, cipherdict, WA_ASYMMETRIC_CIPHER_RSA_OAEP,
                 get_symkey_length(platform_hooks, format, WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305), metadata,
                 rsa_public_key->modulus_length));
    wa_value_destroy(cipherdict);

    /* Payload layer 1: the last layer is the shared secret, whose shards split S_F(RSA_OAEP cipherdict) */
    shard_ciphertexts_dict = read_bytes_document(platform_hooks, format, get_path(payload_layer_1, "key_ciphertext"));
    WA_REQUIRE(shard_ciphertexts_dict != NULL);
    WA_CHECK_SIZE(wa_value_get_item_count(shard_ciphertexts_dict), 1);
    WA_CHECK_SIZE(wa_value_get_item_count(get_path(shard_ciphertexts_dict, "shard_ciphertexts")), 3);
    rsa_cipherdict_length = get_rsa_cipherdict_length(
        platform_hooks, format,
        get_key_struct_length(platform_hooks, format,
                              get_symkey_length(platform_hooks, format, WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305),
                              metadata),
        rsa_public_key->modulus_length);
    shard_length = get_shamir_shard_length(platform_hooks, rsa_cipherdict_length, 3, 2);
    for (shard_index = 0; shard_index < 3; ++shard_index) {
        size_t serialized_shard_length = get_shard_length(platform_hooks, format, (int64_t)shard_index + 1, shard_length);
        cipherdict = read_bytes_document(platform_hooks, format,
                                         get_path(shard_ciphertexts_dict, "shard_ciphertexts")
                                             ? wa_value_get_array_item(
                                                   get_path(shard_ciphertexts_dict, "shard_ciphertexts"), shard_index)
                                             : NULL);
        WA_CHECK(cipherdict != NULL);
        if (shard_index == 0) {
            WA_CHECK(check_asymmetric_cipherdict(platform_hooks, format, cipherdict, WA_ASYMMETRIC_CIPHER_ECIES_X25519,
                                                 serialized_shard_length, metadata, 0));
        } else if (shard_index == 1) {
            WA_CHECK(check_asymmetric_cipherdict(platform_hooks, format, cipherdict, WA_ASYMMETRIC_CIPHER_ML_KEM_768,
                                                 serialized_shard_length, metadata, 0));
        } else {
            /* One-shot cipherdict of the symmetric layer over S_F([3, shard3]) */
            WA_CHECK_SIZE(wa_value_get_item_count(cipherdict), 2);
            WA_CHECK_SIZE(get_bytes_length(wa_value_find_map_value(cipherdict, "ciphertext")), serialized_shard_length);
            WA_CHECK_SIZE(get_bytes_length(wa_value_find_map_value(cipherdict, "tag")), 16);
        }
        wa_value_destroy(cipherdict);
    }
    wa_value_destroy(shard_ciphertexts_dict);
}

static void test_nested_cryptainer_in_each_format(void)
{
    size_t format_index;
    for (format_index = 0; format_index < WA_ENABLED_FORMAT_COUNT; ++format_index) {
        wa_document_format_t format = enabled_formats[format_index];
        wa_test_platform_t *platform = wa_test_platform_create(71u + format_index);
        wa_device_profile_t *device_profile = NULL;
        wa_value_t *metadata;
        encryption_result_t result;
        uint8_t *payload = build_payload(4099);
        WA_REQUIRE(platform != NULL && payload != NULL);
        printf("  format %s\n", get_format_name(format));
        metadata = build_sample_metadata(&platform->hooks);
        WA_REQUIRE(metadata != NULL);
        WA_REQUIRE_STATUS(wa_test_load_device_profile_sample("nested_all_layer_kinds", &platform->hooks, &device_profile),
                          WA_STATUS_OK);
        WA_REQUIRE_STATUS(encrypt_payload(&platform->hooks, device_profile, metadata, format,
                                          WA_CIPHERTEXT_LOCATION_INLINE, payload, 4099, 1000, &result),
                          WA_STATUS_OK);
        check_nested_cryptainer(&platform->hooks, device_profile, format, result.cryptainer, metadata, 4099);
        WA_CHECK_SIZE(result.payload_sink.length, 0);
        release_encryption_result(&result);
        wa_value_destroy(metadata);
        wa_device_profile_destroy(device_profile);
        free(payload);
        WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
        WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
        wa_test_platform_destroy(platform);
    }
}

/* Minimal profile (AES_CBC, RSA_OAEP), no metadata: payload_macs {}, padded ciphertext, null metadata everywhere */
static void test_minimal_cryptainer_without_metadata(void)
{
    static const size_t payload_lengths[] = {0, 1, 15, 16, 17, 4096, 10000};
    size_t format_index;
    size_t length_index;
    for (format_index = 0; format_index < WA_ENABLED_FORMAT_COUNT; ++format_index) {
        wa_document_format_t format = enabled_formats[format_index];
        wa_test_platform_t *platform = wa_test_platform_create(72u);
        wa_device_profile_t *device_profile = NULL;
        const wa_asymmetric_public_key_t *public_key = NULL;
        WA_REQUIRE(platform != NULL);
        WA_REQUIRE_STATUS(
            wa_test_load_device_profile_sample("minimal_rsa_authenticator", &platform->hooks, &device_profile),
            WA_STATUS_OK);
        WA_REQUIRE_STATUS(wa_device_profile_find_layer_public_key(
                              device_profile, get_path(device_profile->cryptoconf,
                                                       "payload_cipher_layers[0].key_cipher_layers[0]"),
                              &public_key),
                          WA_STATUS_OK);
        for (length_index = 0; length_index < sizeof(payload_lengths) / sizeof(payload_lengths[0]); ++length_index) {
            size_t payload_length = payload_lengths[length_index];
            uint8_t *payload = build_payload(payload_length);
            encryption_result_t result;
            wa_value_t *cipherdict;
            WA_REQUIRE_STATUS(encrypt_payload(&platform->hooks, device_profile, NULL, format,
                                              WA_CIPHERTEXT_LOCATION_INLINE, payload, payload_length, 7, &result),
                              WA_STATUS_OK);
            WA_CHECK(wa_value_get_type(wa_value_find_map_value(result.cryptainer, "cryptainer_metadata")) ==
                     WA_VALUE_TYPE_NULL);
            WA_CHECK(wa_value_get_type(get_path(result.cryptainer, "payload_cipher_layers[0].payload_macs")) ==
                         WA_VALUE_TYPE_MAP &&
                     wa_value_get_item_count(get_path(result.cryptainer, "payload_cipher_layers[0].payload_macs")) == 0);
            WA_CHECK_SIZE(get_bytes_length(get_path(result.cryptainer, "payload_ciphertext_struct.ciphertext_value")),
                          (payload_length / 16u + 1u) * 16u);
            WA_CHECK_SIZE(wa_value_get_item_count(get_path(result.cryptainer, "payload_ciphertext_struct")), 2);
            cipherdict = read_bytes_document(&platform->hooks, format,
                                             get_path(result.cryptainer, "payload_cipher_layers[0].key_ciphertext"));
            WA_CHECK(cipherdict != NULL &&
                     check_asymmetric_cipherdict(&platform->hooks, format, cipherdict, WA_ASYMMETRIC_CIPHER_RSA_OAEP,
                                                 get_symkey_length(&platform->hooks, format, WA_SYMMETRIC_CIPHER_AES_CBC),
                                                 NULL, public_key->modulus_length));
            wa_value_destroy(cipherdict);
            release_encryption_result(&result);
            free(payload);
        }
        wa_device_profile_destroy(device_profile);
        WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
        WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
        wa_test_platform_destroy(platform);
    }
}

/* Spec scenario "Fresh secrets for every cryptainer" */
static void test_fresh_secrets_for_every_cryptainer(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(73u);
    wa_device_profile_t *device_profile = NULL;
    encryption_result_t results[2];
    uint8_t *payload = build_payload(100);
    const uint8_t *uids[2];
    size_t index;
    WA_REQUIRE(platform != NULL);
    WA_REQUIRE_STATUS(wa_test_load_device_profile_sample("nested_all_layer_kinds", &platform->hooks, &device_profile),
                      WA_STATUS_OK);
    for (index = 0; index < 2; ++index) {
        WA_REQUIRE_STATUS(encrypt_payload(&platform->hooks, device_profile, NULL, enabled_formats[0],
                                          WA_CIPHERTEXT_LOCATION_INLINE, payload, 100, 100, &results[index]),
                          WA_STATUS_OK);
        WA_REQUIRE(wa_value_get_uuid(wa_value_find_map_value(results[index].cryptainer, "cryptainer_uid"),
                                     &uids[index]) == 0);
    }
    WA_CHECK(memcmp(uids[0], uids[1], WA_UUID_SIZE) != 0);
    WA_CHECK(!trees_are_equal(&platform->hooks, enabled_formats[0],
                              get_path(results[0].cryptainer, "payload_cipher_layers[1].key_ciphertext"),
                              get_path(results[1].cryptainer, "payload_cipher_layers[1].key_ciphertext")));
    WA_CHECK(!trees_are_equal(&platform->hooks, enabled_formats[0],
                              get_path(results[0].cryptainer, "payload_ciphertext_struct"),
                              get_path(results[1].cryptainer, "payload_ciphertext_struct")));
    for (index = 0; index < 2; ++index) {
        release_encryption_result(&results[index]);
    }
    wa_device_profile_destroy(device_profile);
    free(payload);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

/* TASK 7.2: BASE GENERATION */

static void check_base(const wa_cryptainer_base_t *base, wa_document_format_t format,
                       wa_ciphertext_location_t location, size_t expected_layer_count)
{
    const wa_value_t *cryptainer = base->cryptainer;
    const wa_value_t *ciphertext_struct = wa_value_find_map_value(cryptainer, "payload_ciphertext_struct");
    const uint8_t *uuid = NULL;
    size_t layer_index;
    WA_CHECK(text_equals(wa_value_find_map_value(cryptainer, "cryptainer_state"), "STARTED"));
    WA_CHECK(text_equals(wa_value_find_map_value(cryptainer, "cryptainer_format"), "cryptainer_1.0"));
    WA_CHECK(wa_value_get_uuid(wa_value_find_map_value(cryptainer, "cryptainer_uid"), &uuid) == 0);
    WA_CHECK(wa_value_get_uuid(wa_value_find_map_value(cryptainer, "keychain_uid"), &uuid) == 0 &&
             memcmp(uuid, samples_root_keychain_uid, WA_UUID_SIZE) == 0);
    WA_CHECK(wa_value_get_type(wa_value_find_map_value(cryptainer, "cryptainer_metadata")) == WA_VALUE_TYPE_NULL);
    if (location == WA_CIPHERTEXT_LOCATION_INLINE) {
        WA_CHECK(wa_value_get_type(ciphertext_struct) == WA_VALUE_TYPE_NULL);
    } else {
        WA_CHECK(wa_value_get_item_count(ciphertext_struct) == 1 &&
                 text_equals(wa_value_find_map_value(ciphertext_struct, "ciphertext_location"), "offloaded"));
    }
    WA_CHECK_SIZE(base->payload_layer_count, expected_layer_count);
    WA_CHECK_SIZE(wa_value_get_item_count(wa_value_find_map_value(cryptainer, "payload_cipher_layers")),
                  expected_layer_count);
    for (layer_index = 0; layer_index < expected_layer_count; ++layer_index) {
        const wa_value_t *layer = wa_value_get_array_item(wa_value_find_map_value(cryptainer, "payload_cipher_layers"),
                                                          layer_index);
        const wa_value_t *signatures = wa_value_find_map_value(layer, "payload_ciphertext_signatures");
        const char *algo_name = NULL;
        size_t algo_name_length = 0;
        wa_symmetric_cipher_algo_t cipher_algo = base->payload_symkeys[layer_index].cipher_algo;
        WA_CHECK(wa_value_get_type(wa_value_find_map_value(layer, "payload_macs")) == WA_VALUE_TYPE_NULL);
        WA_CHECK(get_bytes_length(wa_value_find_map_value(layer, "key_ciphertext")) > 0);
        WA_CHECK(format == WA_DOCUMENT_FORMAT_CBOR
                     ? text_equals(wa_value_find_map_value(layer, "key_ciphertext_format"), "cbor")
                     : wa_value_find_map_value(layer, "key_ciphertext_format") == NULL);
        WA_CHECK(wa_value_get_type(signatures) == WA_VALUE_TYPE_ARRAY && wa_value_get_item_count(signatures) == 0);
        WA_CHECK(wa_value_find_map_value(layer, "payload_signatures") == NULL);
        WA_CHECK(wa_value_get_text(wa_value_find_map_value(layer, "payload_cipher_algo"), &algo_name,
                                   &algo_name_length) == 0 &&
                 wa_symmetric_cipher_algo_from_name(algo_name, algo_name_length, &cipher_algo) &&
                 cipher_algo == base->payload_symkeys[layer_index].cipher_algo);
        WA_CHECK_SIZE(base->payload_symkeys[layer_index].iv_or_nonce_length,
                      cipher_algo == WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305 ? 12u : 16u);
    }
}

static void test_base_generation(void)
{
    static const struct {
        const char *sample_name;
        size_t layer_count;
    } cases[] = {
        {"nested_all_layer_kinds", 2},
        {"legacy_payload_signatures_alias", 1}, /* payload_signatures: [] becomes payload_ciphertext_signatures */
        {"minimal_rsa_authenticator", 1},
    };
    size_t case_index;
    size_t format_index;
    for (case_index = 0; case_index < sizeof(cases) / sizeof(cases[0]); ++case_index) {
        for (format_index = 0; format_index < WA_ENABLED_FORMAT_COUNT; ++format_index) {
            wa_document_format_t format = enabled_formats[format_index];
            wa_test_platform_t *platform = wa_test_platform_create(74u);
            wa_device_profile_t *device_profile = NULL;
            wa_ciphertext_location_t location;
            WA_REQUIRE(platform != NULL);
            printf("  %s, format %s\n", cases[case_index].sample_name, get_format_name(format));
            WA_REQUIRE_STATUS(
                wa_test_load_device_profile_sample(cases[case_index].sample_name, &platform->hooks, &device_profile),
                WA_STATUS_OK);
            for (location = WA_CIPHERTEXT_LOCATION_INLINE; location <= WA_CIPHERTEXT_LOCATION_OFFLOADED;
                 location = (wa_ciphertext_location_t)(location + 1)) {
                wa_cryptainer_base_t base;
                wa_value_t *cryptoconf_before = NULL;
                WA_REQUIRE_STATUS(wa_value_deep_copy(device_profile->cryptoconf, &platform->hooks, &cryptoconf_before),
                                  WA_STATUS_OK);
                WA_REQUIRE_STATUS(wa_cryptainer_base_generate(&platform->hooks, device_profile, NULL, format,
                                                              location, &base),
                                  WA_STATUS_OK);
                check_base(&base, format, location, cases[case_index].layer_count);
                /* The input cryptoconf is never mutated (section 6.1) */
                WA_CHECK(trees_are_equal(&platform->hooks, format, cryptoconf_before, device_profile->cryptoconf));
                wa_value_destroy(cryptoconf_before);
                wa_cryptainer_base_release(&base);
                WA_CHECK(base.cryptainer == NULL && base.payload_symkeys == NULL);
            }
            wa_device_profile_destroy(device_profile);
            WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
            WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
            wa_test_platform_destroy(platform);
        }
    }
}

/* TASK 7.3: PAYLOAD PIPELINE, CHUNKED VS ONE-SHOT */

/* One-shot reference of section 7.1: each layer encrypts the previous raw ciphertext; returns a malloc()'d final
 * ciphertext, and the tags */
static uint8_t *encrypt_in_one_shot(const wa_platform_hooks_t *platform_hooks, const wa_symkey_t *symkeys,
                                    size_t layer_count, const uint8_t *payload, size_t payload_length,
                                    size_t *ciphertext_length_out, uint8_t tags[][WA_SYMMETRIC_TAG_SIZE],
                                    size_t *tag_lengths)
{
    uint8_t *current = (uint8_t *)malloc(payload_length + 1u);
    size_t current_length = payload_length;
    size_t layer_index;
    memcpy(current, payload, payload_length);
    for (layer_index = 0; layer_index < layer_count; ++layer_index) {
        wa_value_t *cipherdict = NULL;
        const uint8_t *bytes = NULL;
        size_t length = 0;
        if (wa_symmetric_encrypt_to_cipherdict(platform_hooks, &symkeys[layer_index], current, current_length,
                                               &cipherdict) != WA_STATUS_OK ||
            wa_value_get_bytes(wa_value_find_map_value(cipherdict, "ciphertext"), &bytes, &length) != 0) {
            wa_value_destroy(cipherdict);
            free(current);
            return NULL;
        }
        free(current);
        current = (uint8_t *)malloc(length + 1u);
        if (length > 0) {
            memcpy(current, bytes, length); /* An empty bytes node has no data pointer */
        }
        current_length = length;
        tag_lengths[layer_index] = 0;
        if (wa_value_get_bytes(wa_value_find_map_value(cipherdict, "tag"), &bytes, &length) == 0) {
            memcpy(tags[layer_index], bytes, length);
            tag_lengths[layer_index] = length;
        }
        wa_value_destroy(cipherdict);
    }
    *ciphertext_length_out = current_length;
    return current;
}

/* Peak library allocation (test allocator) of an offloaded encryption, from encryptor creation to its destruction
 * after writing the cryptainer */
static size_t measure_offloaded_encryption_peak(wa_test_platform_t *platform, const wa_device_profile_t *device_profile,
                                                wa_document_format_t format, const uint8_t *payload,
                                                size_t payload_length, size_t chunk_size)
{
    wa_cryptainer_encryptor_options_t options;
    wa_cryptainer_encryptor_t *encryptor = NULL;
    wa_test_memory_sink_t payload_sink;
    wa_test_memory_sink_t cryptainer_sink;
    size_t offset = 0;
    size_t initial_live_bytes = platform->allocator.live_bytes;
    wa_status_t status;
    wa_test_memory_sink_initialize(&payload_sink); /* Sinks use the C allocator, not the measured one */
    wa_test_memory_sink_initialize(&cryptainer_sink);
    platform->allocator.peak_live_bytes = initial_live_bytes;
    options.platform_hooks = &platform->hooks;
    options.document_format = format;
    options.ciphertext_location = WA_CIPHERTEXT_LOCATION_OFFLOADED;
    options.payload_ciphertext_sink = &payload_sink.sink;
    status = wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor);
    while (status == WA_STATUS_OK && offset < payload_length) {
        size_t length = payload_length - offset < chunk_size ? payload_length - offset : chunk_size;
        status = wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, payload + offset, length);
        offset += length;
    }
    if (status == WA_STATUS_OK) {
        status = wa_cryptainer_encryptor_finalize(encryptor);
    }
    if (status == WA_STATUS_OK) {
        status = wa_cryptainer_encryptor_write_cryptainer(encryptor, &cryptainer_sink.sink);
    }
    wa_cryptainer_encryptor_destroy(encryptor);
    WA_CHECK_STATUS(status, WA_STATUS_OK);
    WA_CHECK(payload_sink.length >= payload_length && payload_sink.length <= payload_length + 16u);
    WA_CHECK_SIZE(platform->allocator.live_bytes, initial_live_bytes);
    wa_test_memory_sink_release(&payload_sink);
    wa_test_memory_sink_release(&cryptainer_sink);
    return platform->allocator.peak_live_bytes - initial_live_bytes;
}

/* Design D12: offloaded memory depends neither on the payload length nor on the caller's chunk size. A 4 KiB payload
 * in one chunk, and a 1 MiB payload in 4 KiB chunks or in one 1 MiB chunk, have the same peak allocation, within a
 * small fixed margin. */
#define WA_TEST_PEAK_ALLOCATION_MARGIN 64u

static void test_offloaded_peak_allocation_is_bounded(void)
{
    /* Two payload layers each: AES_CBC then CHACHA20_POLY1305, and AES_EAX then CHACHA20_POLY1305 */
    static const char *const sample_names[] = {"corpus_2026_cbor_key_ciphertexts_05", "nested_all_layer_kinds"};
    static const size_t small_length = 4096u;
    static const size_t large_length = 1024u * 1024u;
    wa_test_platform_t *platform = wa_test_platform_create(80u);
    uint8_t *payload = build_payload(large_length);
    size_t sample_index;
    size_t format_index;
    WA_REQUIRE(platform != NULL && payload != NULL);
    for (sample_index = 0; sample_index < sizeof(sample_names) / sizeof(sample_names[0]); ++sample_index) {
        wa_device_profile_t *device_profile = NULL;
        WA_REQUIRE_STATUS(
            wa_test_load_device_profile_sample(sample_names[sample_index], &platform->hooks, &device_profile),
            WA_STATUS_OK);
        for (format_index = 0; format_index < WA_ENABLED_FORMAT_COUNT; ++format_index) {
            wa_document_format_t format = enabled_formats[format_index];
            size_t small_peak = measure_offloaded_encryption_peak(platform, device_profile, format, payload,
                                                                  small_length, small_length);
            size_t large_chunked_peak = measure_offloaded_encryption_peak(platform, device_profile, format, payload,
                                                                          large_length, small_length);
            size_t large_one_chunk_peak = measure_offloaded_encryption_peak(platform, device_profile, format, payload,
                                                                            large_length, large_length);
            printf("    %s, format %d: peak %lu bytes (4 KiB), %lu (1 MiB in 4 KiB chunks), %lu (1 MiB in one chunk)\n",
                   sample_names[sample_index], (int)format, (unsigned long)small_peak,
                   (unsigned long)large_chunked_peak, (unsigned long)large_one_chunk_peak);
            WA_CHECK(small_peak > 0);
            WA_CHECK(large_chunked_peak <= small_peak + WA_TEST_PEAK_ALLOCATION_MARGIN);
            WA_CHECK(large_one_chunk_peak <= small_peak + WA_TEST_PEAK_ALLOCATION_MARGIN);
            WA_CHECK(small_peak <= large_chunked_peak + WA_TEST_PEAK_ALLOCATION_MARGIN);
            WA_CHECK(small_peak <= large_one_chunk_peak + WA_TEST_PEAK_ALLOCATION_MARGIN);
        }
        wa_device_profile_destroy(device_profile);
    }
    free(payload);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_pipeline_chunked_equals_one_shot(void)
{
    static const wa_symmetric_cipher_algo_t algo_combinations[][3] = {
        {WA_SYMMETRIC_CIPHER_AES_CBC, 0, 0},
        {WA_SYMMETRIC_CIPHER_AES_EAX, 0, 0},
        {WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305, 0, 0},
        {WA_SYMMETRIC_CIPHER_AES_CBC, WA_SYMMETRIC_CIPHER_AES_EAX, 0},
        {WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305, WA_SYMMETRIC_CIPHER_AES_CBC, 0},
        {WA_SYMMETRIC_CIPHER_AES_CBC, WA_SYMMETRIC_CIPHER_AES_CBC, WA_SYMMETRIC_CIPHER_AES_CBC},
        {WA_SYMMETRIC_CIPHER_AES_EAX, WA_SYMMETRIC_CIPHER_AES_CBC, WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305},
        {WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305, WA_SYMMETRIC_CIPHER_AES_EAX, WA_SYMMETRIC_CIPHER_AES_CBC},
    };
    static const size_t payload_lengths[] = {0, 1, 15, 16, 17, 31, 4095, 4096, 4097, 3 * 4096 + 5, 20000};
    static const size_t chunk_sizes[] = {1, 7, 16, 1000, 4096, 5000, 1u << 20};
    wa_test_platform_t *platform = wa_test_platform_create(75u);
    size_t combination_index;
    WA_REQUIRE(platform != NULL);
    for (combination_index = 0; combination_index < sizeof(algo_combinations) / sizeof(algo_combinations[0]);
         ++combination_index) {
        wa_symkey_t symkeys[3];
        size_t layer_count = 0;
        size_t length_index;
        while (layer_count < 3 && algo_combinations[combination_index][layer_count] != 0) {
            WA_REQUIRE_STATUS(wa_symkey_generate(&platform->hooks, algo_combinations[combination_index][layer_count],
                                                 &symkeys[layer_count]),
                              WA_STATUS_OK);
            ++layer_count;
        }
        for (length_index = 0; length_index < sizeof(payload_lengths) / sizeof(payload_lengths[0]); ++length_index) {
            size_t payload_length = payload_lengths[length_index];
            uint8_t *payload = build_payload(payload_length);
            uint8_t expected_tags[3][WA_SYMMETRIC_TAG_SIZE];
            size_t expected_tag_lengths[3];
            size_t expected_length = 0;
            uint8_t *expected = encrypt_in_one_shot(&platform->hooks, symkeys, layer_count, payload, payload_length,
                                                    &expected_length, expected_tags, expected_tag_lengths);
            size_t chunk_index;
            WA_REQUIRE(expected != NULL);
            for (chunk_index = 0; chunk_index < sizeof(chunk_sizes) / sizeof(chunk_sizes[0]); ++chunk_index) {
                size_t chunk_size = chunk_sizes[chunk_index];
                wa_payload_encryption_pipeline_t pipeline;
                wa_test_memory_sink_t sink;
                size_t offset = 0;
                size_t layer_index;
                if (chunk_size == 1 && payload_length > 5000) {
                    continue; /* Slow under sanitizers, and covered by 7 */
                }
                wa_test_memory_sink_initialize(&sink);
                WA_REQUIRE_STATUS(
                    wa_payload_encryption_pipeline_start(&platform->hooks, symkeys, layer_count, &sink.sink, &pipeline),
                    WA_STATUS_OK);
                /* Empty chunks are accepted anywhere */
                WA_CHECK_STATUS(wa_payload_encryption_pipeline_encrypt_chunk(&pipeline, NULL, 0), WA_STATUS_OK);
                while (offset < payload_length) {
                    size_t length = payload_length - offset < chunk_size ? payload_length - offset : chunk_size;
                    WA_CHECK_STATUS(wa_payload_encryption_pipeline_encrypt_chunk(&pipeline, payload + offset, length),
                                    WA_STATUS_OK);
                    offset += length;
                }
                WA_CHECK_STATUS(wa_payload_encryption_pipeline_finalize(&pipeline), WA_STATUS_OK);
                if (!wa_test_check_condition(sink.length == expected_length &&
                                                 (expected_length == 0 ||
                                                  memcmp(sink.bytes, expected, expected_length) == 0),
                                             __FILE__, __LINE__, "chunked output equals the one-shot output")) {
                    printf("    combination %u, payload %u bytes, chunks of %u bytes\n", (unsigned)combination_index,
                           (unsigned)payload_length, (unsigned)chunk_size);
                }
                for (layer_index = 0; layer_index < layer_count; ++layer_index) {
                    WA_CHECK_BYTES(pipeline.nodes[layer_index].tag, pipeline.nodes[layer_index].tag_length,
                                   expected_tags[layer_index], expected_tag_lengths[layer_index]);
                }
                wa_payload_encryption_pipeline_release(&pipeline);
                wa_test_memory_sink_release(&sink);
            }
            free(expected);
            free(payload);
        }
    }
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
    wa_test_platform_destroy(platform);
}

/* Offloaded location: the sink receives the ciphertext progressively, the cryptainer has the marker only */
static void test_offloaded_ciphertext(void)
{
    size_t format_index;
    for (format_index = 0; format_index < WA_ENABLED_FORMAT_COUNT; ++format_index) {
        wa_document_format_t format = enabled_formats[format_index];
        wa_test_platform_t *platform = wa_test_platform_create(76u);
        wa_device_profile_t *device_profile = NULL;
        uint8_t *payload = build_payload(50000);
        encryption_result_t result;
        WA_REQUIRE(platform != NULL);
        WA_REQUIRE_STATUS(
            wa_test_load_device_profile_sample("minimal_rsa_authenticator", &platform->hooks, &device_profile),
            WA_STATUS_OK);
        WA_REQUIRE_STATUS(encrypt_payload(&platform->hooks, device_profile, NULL, format,
                                          WA_CIPHERTEXT_LOCATION_OFFLOADED, payload, 50000, 9999, &result),
                          WA_STATUS_OK);
        WA_CHECK_SIZE(result.payload_sink.length, (50000u / 16u + 1u) * 16u);
        WA_CHECK(result.payload_sink.write_call_count > 10); /* Delivered progressively */
        WA_CHECK_SIZE(wa_value_get_item_count(get_path(result.cryptainer, "payload_ciphertext_struct")), 1);
        WA_CHECK(text_equals(get_path(result.cryptainer, "payload_ciphertext_struct.ciphertext_location"), "offloaded"));
        WA_CHECK(text_equals(get_path(result.cryptainer, "cryptainer_state"), "FINISHED"));
        WA_CHECK(result.cryptainer_sink.length < 10000); /* No 50 KB ciphertext in the cryptainer */
        release_encryption_result(&result);
        wa_device_profile_destroy(device_profile);
        free(payload);
        WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
        wa_test_platform_destroy(platform);
    }
}

/* TASK 7.4: ENCRYPTOR */

static void initialize_options(wa_cryptainer_encryptor_options_t *options, const wa_platform_hooks_t *platform_hooks)
{
    options->platform_hooks = platform_hooks;
    options->document_format = WA_DOCUMENT_FORMAT_BUILD_DEFAULT;
    options->ciphertext_location = WA_CIPHERTEXT_LOCATION_INLINE;
    options->payload_ciphertext_sink = NULL;
}

static void test_creation_arguments_and_options(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(77u);
    wa_device_profile_t *device_profile = NULL;
    wa_cryptainer_encryptor_t *encryptor = (wa_cryptainer_encryptor_t *)&platform; /* Must be reset to NULL */
    wa_cryptainer_encryptor_options_t options;
    wa_platform_hooks_t unusable_hooks;
    wa_test_memory_sink_t sink;
    wa_output_sink_t sink_without_write = {NULL, NULL};
    WA_REQUIRE(platform != NULL);
    wa_test_memory_sink_initialize(&sink);
    WA_REQUIRE_STATUS(wa_test_load_device_profile_sample("minimal_rsa_authenticator", &platform->hooks, &device_profile),
                      WA_STATUS_OK);
    platform->random_generator.call_count = 0;

    initialize_options(&options, &platform->hooks);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, NULL), WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(NULL, NULL, &options, &encryptor), WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK(encryptor == NULL);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, NULL, &encryptor), WA_STATUS_INVALID_ARGUMENT);
    options.platform_hooks = NULL;
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor),
                    WA_STATUS_INVALID_ARGUMENT);
    unusable_hooks = platform->hooks;
    unusable_hooks.fill_random = NULL;
    options.platform_hooks = &unusable_hooks;
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor),
                    WA_STATUS_INVALID_ARGUMENT);
    initialize_options(&options, &platform->hooks);
    options.document_format = (wa_document_format_t)99;
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor),
                    WA_STATUS_INVALID_ARGUMENT);
#if !WA_DOCUMENT_FORMAT_CBOR_ENABLED
    options.document_format = WA_DOCUMENT_FORMAT_CBOR;
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor),
                    WA_STATUS_UNSUPPORTED_FEATURE);
#endif
#if !WA_DOCUMENT_FORMAT_JSON_ENABLED
    options.document_format = WA_DOCUMENT_FORMAT_JSON;
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor),
                    WA_STATUS_UNSUPPORTED_FEATURE);
#endif
    initialize_options(&options, &platform->hooks);
    options.ciphertext_location = (wa_ciphertext_location_t)0;
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor),
                    WA_STATUS_INVALID_ARGUMENT);
    options.ciphertext_location = WA_CIPHERTEXT_LOCATION_INLINE;
    options.payload_ciphertext_sink = &sink.sink;
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor),
                    WA_STATUS_INVALID_ARGUMENT);
    options.ciphertext_location = WA_CIPHERTEXT_LOCATION_OFFLOADED;
    options.payload_ciphertext_sink = NULL;
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor),
                    WA_STATUS_INVALID_ARGUMENT);
    options.payload_ciphertext_sink = &sink_without_write;
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor),
                    WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK(encryptor == NULL);
    WA_CHECK_SIZE(platform->random_generator.call_count, 0); /* No key generated */

    /* The build default format */
    initialize_options(&options, &platform->hooks);
    WA_REQUIRE_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_finalize(encryptor), WA_STATUS_OK); /* Empty payload */
    WA_CHECK_STATUS(wa_cryptainer_encryptor_write_cryptainer(encryptor, &sink.sink), WA_STATUS_OK);
    WA_CHECK(sink.length > 0 &&
             sink.bytes[0] == (WA_DOCUMENT_FORMAT_JSON_ENABLED ? (uint8_t)'{' : (uint8_t)0xA7)); /* 7-entry map */
    wa_cryptainer_encryptor_destroy(encryptor);
    wa_cryptainer_encryptor_destroy(NULL);

    wa_test_memory_sink_release(&sink);
    wa_device_profile_destroy(device_profile);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

/* Nested maps {"a": {"a": ... {}}} of `level_count` levels */
static wa_value_t *build_nested_metadata(const wa_platform_hooks_t *platform_hooks, size_t level_count)
{
    wa_value_t *metadata = NULL;
    size_t level;
    if (wa_value_create_map(platform_hooks, &metadata) != WA_STATUS_OK) {
        return NULL;
    }
    for (level = 1; level < level_count; ++level) {
        wa_value_t *outer = NULL;
        if (wa_value_create_map(platform_hooks, &outer) != WA_STATUS_OK ||
            wa_value_map_add_consuming(outer, "a", metadata) != WA_STATUS_OK) {
            wa_value_destroy(outer);
            return NULL;
        }
        metadata = outer;
    }
    return metadata;
}

static void test_metadata_checks(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(78u);
    wa_device_profile_t *device_profile = NULL;
    wa_cryptainer_encryptor_t *encryptor = NULL;
    wa_cryptainer_encryptor_options_t options;
    wa_value_t *metadata = NULL;
    wa_value_t *text = NULL;
    size_t format_index;
    /* {"k": 1.0} (half float) and {"k": tag 0 datetime} */
    static const uint8_t float_metadata[] = {0xA1, 0x61, 0x6B, 0xF9, 0x3C, 0x00};
    static const uint8_t datetime_metadata[] = {0xA1, 0x61, 0x6B, 0xC0, 0x74, '2', '0', '2', '6', '-', '0', '1', '-',
                                                '0', '1', 'T', '0', '0', ':', '0', '0', ':', '0', '0', 'Z'};
    WA_REQUIRE(platform != NULL);
    WA_REQUIRE_STATUS(wa_test_load_device_profile_sample("minimal_rsa_authenticator", &platform->hooks, &device_profile),
                      WA_STATUS_OK);
    initialize_options(&options, &platform->hooks);
    platform->random_generator.call_count = 0;

    /* Not a map */
    WA_REQUIRE_STATUS(wa_value_create_text(&platform->hooks, "x", 1, &text), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, text, &options, &encryptor), WA_STATUS_INVALID_PROFILE);
    wa_value_destroy(text);
    /* Extended JSON keyword map {"$uuid": "0123"}, at any depth */
    WA_REQUIRE_STATUS(wa_value_create_map(&platform->hooks, &metadata), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_create_text(&platform->hooks, "0123", 4, &text), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_value_map_add_consuming(metadata, "$uuid", text), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, metadata, &options, &encryptor),
                    WA_STATUS_INVALID_PROFILE);
    {
        wa_value_t *outer = NULL;
        WA_REQUIRE_STATUS(wa_value_create_map(&platform->hooks, &outer), WA_STATUS_OK);
        WA_REQUIRE_STATUS(wa_value_map_add_consuming(outer, "inner", metadata), WA_STATUS_OK);
        WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, outer, &options, &encryptor),
                        WA_STATUS_INVALID_PROFILE);
        wa_value_destroy(outer);
    }
    /* Depth: 63 levels pass, 64 don't (metadata sits at depth 2) */
    metadata = build_nested_metadata(&platform->hooks, WA_MAX_CBOR_NESTING_DEPTH);
    WA_REQUIRE(metadata != NULL);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_create(device_profile, metadata, &options, &encryptor),
                    WA_STATUS_NESTING_TOO_DEEP);
    wa_value_destroy(metadata);
    WA_CHECK(encryptor == NULL);
    WA_CHECK_SIZE(platform->random_generator.call_count, 0); /* Before any key generation */
    /* Floats and datetimes never get into a tree */
    WA_CHECK_STATUS(wa_value_tree_decode_from_cbor(float_metadata, sizeof(float_metadata), &platform->hooks, &metadata),
                    WA_STATUS_UNSUPPORTED_TYPE);
    WA_CHECK_STATUS(
        wa_value_tree_decode_from_cbor(datetime_metadata, sizeof(datetime_metadata), &platform->hooks, &metadata),
        WA_STATUS_UNSUPPORTED_TYPE);

    for (format_index = 0; format_index < WA_ENABLED_FORMAT_COUNT; ++format_index) {
        encryption_result_t result;
        wa_value_t *deepest = NULL;
        metadata = build_nested_metadata(&platform->hooks, WA_MAX_CBOR_NESTING_DEPTH - 1u);
        WA_REQUIRE(metadata != NULL);
        WA_CHECK_STATUS(encrypt_payload(&platform->hooks, device_profile, metadata, enabled_formats[format_index],
                                        WA_CIPHERTEXT_LOCATION_INLINE, (const uint8_t *)"abc", 3, 3, &result),
                        WA_STATUS_OK);
        WA_CHECK(result.cryptainer != NULL &&
                 trees_are_equal(&platform->hooks, enabled_formats[format_index],
                                 wa_value_find_map_value(result.cryptainer, "cryptainer_metadata"), metadata));
        release_encryption_result(&result);
        wa_value_destroy(metadata);
        (void)deepest;
    }

#if WA_DOCUMENT_FORMAT_JSON_ENABLED
    {
        /* Spec scenario "Non-ASCII metadata": "Café ☕" escaped in Extended JSON */
        static const char cafe[] = "Caf\xC3\xA9 \xE2\x98\x95";
        static const char escaped[] = "\"Caf\\u00e9 \\u2615\"";
        encryption_result_t result;
        int is_found = 0;
        size_t offset;
        WA_REQUIRE_STATUS(wa_value_create_map(&platform->hooks, &metadata), WA_STATUS_OK);
        WA_REQUIRE_STATUS(wa_value_create_text(&platform->hooks, cafe, strlen(cafe), &text), WA_STATUS_OK);
        WA_REQUIRE_STATUS(wa_value_map_add_consuming(metadata, "label", text), WA_STATUS_OK);
        WA_REQUIRE_STATUS(encrypt_payload(&platform->hooks, device_profile, metadata, WA_DOCUMENT_FORMAT_JSON,
                                          WA_CIPHERTEXT_LOCATION_INLINE, (const uint8_t *)"abc", 3, 3, &result),
                          WA_STATUS_OK);
        for (offset = 0; offset + strlen(escaped) <= result.cryptainer_sink.length; ++offset) {
            if (memcmp(result.cryptainer_sink.bytes + offset, escaped, strlen(escaped)) == 0) {
                is_found = 1;
            }
        }
        WA_CHECK(is_found);
        WA_CHECK(text_equals(get_path(result.cryptainer, "cryptainer_metadata.label"), cafe));
        release_encryption_result(&result);
        wa_value_destroy(metadata);
    }
#endif

    wa_device_profile_destroy(device_profile);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

static void test_state_machine(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(79u);
    wa_device_profile_t *device_profile = NULL;
    wa_cryptainer_encryptor_t *encryptor = NULL;
    wa_cryptainer_encryptor_options_t options;
    wa_test_memory_sink_t sink;
    wa_test_memory_sink_t payload_sink;
    size_t first_length;
    WA_REQUIRE(platform != NULL);
    wa_test_memory_sink_initialize(&sink);
    wa_test_memory_sink_initialize(&payload_sink);
    WA_REQUIRE_STATUS(wa_test_load_device_profile_sample("minimal_rsa_authenticator", &platform->hooks, &device_profile),
                      WA_STATUS_OK);
    initialize_options(&options, &platform->hooks);

    WA_CHECK_STATUS(wa_cryptainer_encryptor_encrypt_payload_chunk(NULL, NULL, 0), WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_finalize(NULL), WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_write_cryptainer(NULL, &sink.sink), WA_STATUS_INVALID_ARGUMENT);

    /* CREATED and STREAMING: writing is refused without changing the state */
    WA_REQUIRE_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_write_cryptainer(encryptor, &sink.sink), WA_STATUS_WRONG_STATE);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, (const uint8_t *)"abc", 3), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_write_cryptainer(encryptor, &sink.sink), WA_STATUS_WRONG_STATE);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, NULL, 0), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_write_cryptainer(encryptor, NULL), WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_finalize(encryptor), WA_STATUS_OK);
    WA_CHECK_SIZE(sink.length, 0);
    /* FINISHED: written as many times as wanted, identically; a failing sink leaves the state unchanged */
    WA_CHECK_STATUS(wa_cryptainer_encryptor_write_cryptainer(encryptor, &sink.sink), WA_STATUS_OK);
    first_length = sink.length;
    sink.fail_after_byte_count = first_length + 10u;
    WA_CHECK_STATUS(wa_cryptainer_encryptor_write_cryptainer(encryptor, &sink.sink), WA_STATUS_SINK_WRITE_FAILURE);
    sink.fail_after_byte_count = WA_TEST_NO_FAILURE;
    sink.length = first_length;
    WA_CHECK_STATUS(wa_cryptainer_encryptor_write_cryptainer(encryptor, &sink.sink), WA_STATUS_OK);
    WA_CHECK(sink.length == 2u * first_length &&
             memcmp(sink.bytes, sink.bytes + first_length, first_length) == 0);
    /* Wrong-state calls: then only destroy is accepted */
    WA_CHECK_STATUS(wa_cryptainer_encryptor_finalize(encryptor), WA_STATUS_WRONG_STATE);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_write_cryptainer(encryptor, &sink.sink), WA_STATUS_WRONG_STATE);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, NULL, 0), WA_STATUS_WRONG_STATE);
    wa_cryptainer_encryptor_destroy(encryptor);

    /* Encrypting after finalization fails, and so does everything afterwards */
    WA_REQUIRE_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_finalize(encryptor), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, (const uint8_t *)"abc", 3),
                    WA_STATUS_WRONG_STATE);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_write_cryptainer(encryptor, &sink.sink), WA_STATUS_WRONG_STATE);
    wa_cryptainer_encryptor_destroy(encryptor);

    /* A NULL chunk with a length is an argument error, which fails the encryptor */
    WA_REQUIRE_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, NULL, 3), WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_finalize(encryptor), WA_STATUS_WRONG_STATE);
    wa_cryptainer_encryptor_destroy(encryptor);

    /* A failing payload sink fails the encryptor */
    options.ciphertext_location = WA_CIPHERTEXT_LOCATION_OFFLOADED;
    options.payload_ciphertext_sink = &payload_sink.sink;
    payload_sink.fail_after_byte_count = 100;
    WA_REQUIRE_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, (const uint8_t *)"0123456789abcdef", 16),
                    WA_STATUS_OK);
    {
        uint8_t *payload = build_payload(500);
        WA_CHECK_STATUS(wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, payload, 500),
                        WA_STATUS_SINK_WRITE_FAILURE);
        free(payload);
    }
    WA_CHECK_STATUS(wa_cryptainer_encryptor_finalize(encryptor), WA_STATUS_WRONG_STATE);
    wa_cryptainer_encryptor_destroy(encryptor);
    /* Also at finalization */
    payload_sink.fail_after_byte_count = 0;
    payload_sink.length = 0;
    WA_REQUIRE_STATUS(wa_cryptainer_encryptor_create(device_profile, NULL, &options, &encryptor), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, (const uint8_t *)"abc", 3), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_finalize(encryptor), WA_STATUS_SINK_WRITE_FAILURE);
    WA_CHECK_STATUS(wa_cryptainer_encryptor_write_cryptainer(encryptor, &sink.sink), WA_STATUS_WRONG_STATE);
    wa_cryptainer_encryptor_destroy(encryptor);

    wa_test_memory_sink_release(&sink);
    wa_test_memory_sink_release(&payload_sink);
    wa_device_profile_destroy(device_profile);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
    wa_test_platform_destroy(platform);
}

static void test_one_call_helper_and_suffixes(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(80u);
    wa_device_profile_t *device_profile = NULL;
    wa_cryptainer_encryptor_options_t options;
    wa_test_memory_sink_t sink;
    size_t format_index;
    WA_REQUIRE(platform != NULL);
    wa_test_memory_sink_initialize(&sink);
    WA_REQUIRE_STATUS(wa_test_load_device_profile_sample("nested_all_layer_kinds", &platform->hooks, &device_profile),
                      WA_STATUS_OK);
    initialize_options(&options, &platform->hooks);
    platform->random_generator.call_count = 0;
    WA_CHECK_STATUS(wa_cryptainer_encrypt_payload_in_one_call(device_profile, NULL, &options, NULL, 0, NULL),
                    WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_STATUS(wa_cryptainer_encrypt_payload_in_one_call(device_profile, NULL, &options, NULL, 1, &sink.sink),
                    WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK_SIZE(platform->random_generator.call_count, 0);
    for (format_index = 0; format_index < WA_ENABLED_FORMAT_COUNT; ++format_index) {
        wa_value_t *cryptainer = NULL;
        sink.length = 0;
        options.document_format = enabled_formats[format_index];
        WA_CHECK_STATUS(wa_cryptainer_encrypt_payload_in_one_call(device_profile, NULL, &options,
                                                                  (const uint8_t *)"payload", 7, &sink.sink),
                        WA_STATUS_OK);
        WA_REQUIRE_STATUS(wa_test_read_document(&platform->hooks, enabled_formats[format_index], sink.bytes,
                                                sink.length, &cryptainer),
                          WA_STATUS_OK);
        WA_CHECK(text_equals(get_path(cryptainer, "cryptainer_state"), "FINISHED"));
        WA_CHECK_SIZE(get_bytes_length(get_path(cryptainer, "payload_ciphertext_struct.ciphertext_value")), 7);
        wa_value_destroy(cryptainer);
    }
    /* A creation error goes through */
    options.ciphertext_location = WA_CIPHERTEXT_LOCATION_OFFLOADED;
    WA_CHECK_STATUS(wa_cryptainer_encrypt_payload_in_one_call(device_profile, NULL, &options,
                                                              (const uint8_t *)"payload", 7, &sink.sink),
                    WA_STATUS_INVALID_ARGUMENT);

    WA_CHECK(strcmp(wa_document_format_get_cryptainer_suffix(WA_DOCUMENT_FORMAT_BUILD_DEFAULT),
                    WA_DOCUMENT_FORMAT_JSON_ENABLED ? ".crypt.json" : ".crypt.cbor") == 0);
#if WA_DOCUMENT_FORMAT_JSON_ENABLED
    WA_CHECK(strcmp(wa_document_format_get_cryptainer_suffix(WA_DOCUMENT_FORMAT_JSON), ".crypt.json") == 0);
#else
    WA_CHECK(wa_document_format_get_cryptainer_suffix(WA_DOCUMENT_FORMAT_JSON) == NULL);
#endif
#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
    WA_CHECK(strcmp(wa_document_format_get_cryptainer_suffix(WA_DOCUMENT_FORMAT_CBOR), ".crypt.cbor") == 0);
#else
    WA_CHECK(wa_document_format_get_cryptainer_suffix(WA_DOCUMENT_FORMAT_CBOR) == NULL);
#endif
    WA_CHECK(wa_document_format_get_cryptainer_suffix((wa_document_format_t)99) == NULL);

    wa_test_memory_sink_release(&sink);
    wa_device_profile_destroy(device_profile);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

/* The test-only reader itself */
static void test_document_reader(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(81u);
    static const char json[] = " {\"a\": [1, -2, true, false, null, \"x\\u00e9\\ud83d\\ude00\\n\"], "
                               "\"b\": {\"$binary\": {\"base64\": \"AAEC/w==\", \"subType\": \"00\"}}, "
                               "\"c\": {\"$uuid\": \"0d0d0d0d000040008000000000000001\"}, \"d\": {}} ";
    static const char *const invalid_jsons[] = {
        "", "{", "{\"a\" 1}", "[1,]", "{\"a\": 1, \"a\": 2}", "1.5", "01", "{\"$date\": \"x\"}",
        "{\"$binary\": {\"base64\": \"AAE\", \"subType\": \"00\"}}", "{\"$binary\": {\"base64\": \"\", \"subType\": \"04\"}}",
        "{\"$uuid\": \"0D0D0D0D000040008000000000000001\"}", "\"\\ud83d\"", "[] x", "\"a\tb\"",
    };
    wa_value_t *tree = NULL;
    const uint8_t *bytes = NULL;
    size_t length = 0;
    const char *text = NULL;
    int64_t integer = 0;
    size_t index;
    WA_REQUIRE(platform != NULL);
    WA_REQUIRE_STATUS(wa_test_parse_extended_json(&platform->hooks, (const uint8_t *)json, strlen(json), &tree),
                      WA_STATUS_OK);
    WA_CHECK(wa_value_get_integer(get_path(tree, "a[1]"), &integer) == 0 && integer == -2);
    WA_CHECK(wa_value_get_text(get_path(tree, "a[5]"), &text, &length) == 0 && length == 8 &&
             memcmp(text, "x\xC3\xA9\xF0\x9F\x98\x80\n", 8) == 0);
    WA_CHECK(wa_value_get_bytes(get_path(tree, "b"), &bytes, &length) == 0);
    WA_CHECK_HEX(bytes, length, "000102ff");
    WA_CHECK(wa_value_get_uuid(get_path(tree, "c"), &bytes) == 0);
    WA_CHECK_HEX(bytes, WA_UUID_SIZE, "0d0d0d0d000040008000000000000001");
    WA_CHECK(wa_value_get_type(get_path(tree, "d")) == WA_VALUE_TYPE_MAP);
    wa_value_destroy(tree);
    for (index = 0; index < sizeof(invalid_jsons) / sizeof(invalid_jsons[0]); ++index) {
        tree = NULL;
        if (!wa_test_check_condition(wa_test_parse_extended_json(&platform->hooks, (const uint8_t *)invalid_jsons[index],
                                                                 strlen(invalid_jsons[index]), &tree) != WA_STATUS_OK &&
                                         tree == NULL,
                                     __FILE__, __LINE__, "invalid JSON rejected")) {
            printf("    %s\n", invalid_jsons[index]);
        }
    }
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

int main(void)
{
    WA_RUN_TEST(test_document_reader);
    WA_RUN_TEST(test_nested_cryptainer_in_each_format);
    WA_RUN_TEST(test_minimal_cryptainer_without_metadata);
    WA_RUN_TEST(test_fresh_secrets_for_every_cryptainer);
    WA_RUN_TEST(test_base_generation);
    WA_RUN_TEST(test_pipeline_chunked_equals_one_shot);
    WA_RUN_TEST(test_offloaded_ciphertext);
    WA_RUN_TEST(test_offloaded_peak_allocation_is_bounded);
    WA_RUN_TEST(test_creation_arguments_and_options);
    WA_RUN_TEST(test_metadata_checks);
    WA_RUN_TEST(test_state_machine);
    WA_RUN_TEST(test_one_call_helper_and_suffixes);
    return wa_test_finish();
}
