/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Sections 6.2 to 6.5 of the encryptor specification (Python: _flightbox.py, _encrypt_key_through_multiple_layers,
 * _encrypt_key_through_single_layer and _encrypt_key_with_asymmetric_cipher). The cryptoconf was validated at
 * profile load: layers are well-formed, and every asymmetric layer resolves to a public key. */

#include "core/wa_key_cipher_layers_encryption.h"

#include <string.h>

#include "core/wa_cryptoconf_validation.h"
#include "core/wa_platform_hooks_calls.h"
#include "encoding/wa_device_profile_decoding.h"
#include "encoding/wa_document_serialization.h"
#include "encoding/wa_value_tree_internal.h"
#include "primitives/wa_asymmetric_key_wrapping.h"
#include "primitives/wa_shamir_secret_sharing_gf128.h"
#include "primitives/wa_symmetric_cipher_streams.h"
#include "primitives/wa_symmetric_key_generation.h"

/* S_F(tree) into a secret buffer (initialized here, released on failure) */
static wa_status_t wa_serialize_secret_tree(const wa_key_cipher_context_t *context, const wa_value_t *tree,
                                            wa_growable_byte_buffer_t *serialized_out)
{
    wa_status_t status;
    wa_growable_byte_buffer_initialize(serialized_out, context->platform_hooks, 1);
    status = wa_document_serialize_to_buffer(tree, context->resolved_format, serialized_out);
    if (status != WA_STATUS_OK) {
        wa_growable_byte_buffer_release(serialized_out);
    }
    return status;
}

wa_status_t wa_key_cipher_layers_serialize_symkey(const wa_key_cipher_context_t *context, const void *symkey,
                                                  wa_growable_byte_buffer_t *serialized_out)
{
    wa_value_t *symkey_tree = NULL;
    wa_status_t status;
    wa_growable_byte_buffer_initialize(serialized_out, context->platform_hooks, 1);
    WA_RETURN_IF_ERROR(wa_symkey_build_tree(context->platform_hooks, (const wa_symkey_t *)symkey, &symkey_tree));
    status = wa_serialize_secret_tree(context, symkey_tree, serialized_out);
    wa_value_destroy(symkey_tree);
    return status;
}

wa_status_t wa_key_cipher_layers_store_key_ciphertext(const wa_key_cipher_context_t *context, wa_value_t *layer,
                                                      wa_growable_byte_buffer_t *key_ciphertext)
{
    wa_value_t *key_ciphertext_node = NULL;
    wa_value_t *format_node = NULL;
    WA_RETURN_IF_ERROR(wa_growable_byte_buffer_move_into_bytes_value(key_ciphertext, &key_ciphertext_node));
    WA_RETURN_IF_ERROR(wa_value_map_add_consuming(layer, "key_ciphertext", key_ciphertext_node));
    if (context->resolved_format != WA_DOCUMENT_FORMAT_CBOR) {
        return WA_STATUS_OK; /* An absent field means "json" (section 2) */
    }
    WA_RETURN_IF_ERROR(wa_value_create_text(context->platform_hooks, WA_KEY_CIPHERTEXT_FORMAT_CBOR,
                                            strlen(WA_KEY_CIPHERTEXT_FORMAT_CBOR), &format_node));
    return wa_value_map_add_consuming(layer, "key_ciphertext_format", format_node);
}

/* SHARED SECRET (section 6.4) */

/* S_F((index, shard_bytes)): a two-item array, built from borrowed nodes */
wa_status_t wa_key_cipher_layers_serialize_shard(const wa_key_cipher_context_t *context, size_t shard_index,
                                                 const uint8_t *shard, size_t shard_length,
                                                 wa_growable_byte_buffer_t *serialized_out)
{
    wa_value_t index_node;
    wa_value_t bytes_node;
    wa_value_t shard_node;
    wa_value_t *items[2];
    wa_value_initialize_borrowed_integer(&index_node, (int64_t)(shard_index + 1u));
    wa_value_initialize_borrowed_bytes(&bytes_node, shard, shard_length);
    items[0] = &index_node;
    items[1] = &bytes_node;
    wa_value_initialize_borrowed_array(&shard_node, items, 2);
    return wa_serialize_secret_tree(context, &shard_node, serialized_out);
}

static wa_status_t wa_encrypt_key_with_shared_secret(const wa_key_cipher_context_t *context, wa_value_t *layer,
                                                     const uint8_t *key_bytes, size_t key_bytes_length,
                                                     wa_value_t **cipherdict_out)
{
    wa_value_t *shard_confs = wa_value_find_map_value_for_update(layer, "key_shared_secret_shards");
    size_t shard_count = wa_value_get_item_count(shard_confs);
    int64_t threshold_count = 0;
    uint8_t *shards = NULL;
    size_t shard_length = 0;
    wa_value_t *shard_ciphertexts = NULL;
    wa_status_t status;
    size_t shard_index;
    if (wa_value_get_integer(wa_value_find_map_value(layer, "key_shared_secret_threshold"), &threshold_count) != 0 ||
        threshold_count < 1 || (uint64_t)threshold_count > (uint64_t)shard_count) {
        return WA_STATUS_INVALID_PROFILE; /* Section 5.2: the core checks it again */
    }
    WA_RETURN_IF_ERROR(wa_shamir_split_secret_into_shards(context->platform_hooks, key_bytes, key_bytes_length,
                                                          shard_count, (size_t)threshold_count, &shards,
                                                          &shard_length));
    status = wa_value_create_array(context->platform_hooks, &shard_ciphertexts);
    for (shard_index = 0; status == WA_STATUS_OK && shard_index < shard_count; ++shard_index) {
        wa_growable_byte_buffer_t serialized_shard;
        wa_growable_byte_buffer_t shard_ciphertext;
        wa_value_t *shard_ciphertext_node = NULL;
        status = wa_key_cipher_layers_serialize_shard(context, shard_index, shards + shard_index * shard_length,
                                                      shard_length, &serialized_shard);
        if (status != WA_STATUS_OK) {
            break;
        }
        /* Shard i goes through the i-th shard conf, recursively, with the same F */
        status = wa_key_cipher_layers_encrypt_key(context, (wa_value_t *)wa_value_get_array_item(shard_confs,
                                                                                                  shard_index),
                                                  serialized_shard.data, serialized_shard.length, &shard_ciphertext);
        wa_growable_byte_buffer_release(&serialized_shard);
        if (status == WA_STATUS_OK) {
            status = wa_growable_byte_buffer_move_into_bytes_value(&shard_ciphertext, &shard_ciphertext_node);
        }
        if (status == WA_STATUS_OK) {
            status = wa_value_array_append(shard_ciphertexts, shard_ciphertext_node);
            if (status != WA_STATUS_OK) {
                wa_value_destroy(shard_ciphertext_node);
            }
        }
    }
    wa_release_secret_memory(context->platform_hooks, shards, shard_count * shard_length);
    if (status == WA_STATUS_OK) {
        status = wa_value_create_map(context->platform_hooks, cipherdict_out);
    }
    if (status == WA_STATUS_OK) {
        status = wa_value_map_add_consuming(*cipherdict_out, "shard_ciphertexts", shard_ciphertexts);
        shard_ciphertexts = NULL;
        if (status != WA_STATUS_OK) {
            wa_value_destroy(*cipherdict_out);
            *cipherdict_out = NULL;
        }
    }
    wa_value_destroy(shard_ciphertexts);
    return status;
}

/* SYMMETRIC SUB-KEY (section 6.4) */

static wa_status_t wa_encrypt_key_with_symmetric_sub_key(const wa_key_cipher_context_t *context, wa_value_t *layer,
                                                         wa_symmetric_cipher_algo_t cipher_algo,
                                                         const uint8_t *key_bytes, size_t key_bytes_length,
                                                         wa_value_t **cipherdict_out)
{
    wa_symkey_t sub_symkey;
    wa_growable_byte_buffer_t serialized_sub_symkey;
    wa_growable_byte_buffer_t sub_key_ciphertext;
    wa_status_t status;
    WA_RETURN_IF_ERROR(wa_symkey_generate(context->platform_hooks, cipher_algo, &sub_symkey));
    status = wa_key_cipher_layers_serialize_symkey(context, &sub_symkey, &serialized_sub_symkey);
    if (status == WA_STATUS_OK) {
        /* The sub-symkey is protected by the layer's own key cipher layers, its ciphertext STORED IN PLACE */
        status = wa_key_cipher_layers_encrypt_key(context, layer, serialized_sub_symkey.data,
                                                  serialized_sub_symkey.length, &sub_key_ciphertext);
        wa_growable_byte_buffer_release(&serialized_sub_symkey);
    }
    if (status == WA_STATUS_OK) {
        status = wa_key_cipher_layers_store_key_ciphertext(context, layer, &sub_key_ciphertext);
    }
    if (status == WA_STATUS_OK) {
        status = wa_symmetric_encrypt_to_cipherdict(context->platform_hooks, &sub_symkey, key_bytes,
                                                    key_bytes_length, cipherdict_out);
    }
    wa_symkey_wipe(&sub_symkey);
    return status;
}

/* SINGLE LAYER (section 6.3) */

static wa_status_t wa_encrypt_key_through_single_layer(const wa_key_cipher_context_t *context, wa_value_t *layer,
                                                       const uint8_t *key_bytes, size_t key_bytes_length,
                                                       wa_value_t **cipherdict_out)
{
    const wa_value_t *key_cipher_algo = wa_value_find_map_value(layer, "key_cipher_algo");
    const char *algo_name = NULL;
    size_t algo_name_length = 0;
    wa_symmetric_cipher_algo_t symmetric_algo;
    wa_asymmetric_cipher_algo_t asymmetric_algo;
    *cipherdict_out = NULL;
    if (wa_value_get_text(key_cipher_algo, &algo_name, &algo_name_length) != 0) {
        return WA_STATUS_INVALID_PROFILE;
    }
    if (wa_value_is_text_equal_to(key_cipher_algo, WA_SHARED_SECRET_ALGO_MARKER)) {
        return wa_encrypt_key_with_shared_secret(context, layer, key_bytes, key_bytes_length, cipherdict_out);
    }
    if (wa_symmetric_cipher_algo_from_name(algo_name, algo_name_length, &symmetric_algo)) {
        return wa_encrypt_key_with_symmetric_sub_key(context, layer, symmetric_algo, key_bytes, key_bytes_length,
                                                     cipherdict_out);
    }
    if (wa_asymmetric_cipher_algo_from_name(algo_name, algo_name_length, &asymmetric_algo)) {
        /* Section 6.5: the key struct {"key_bytes", "cryptainer_metadata"}, serialized with S_F, then wrapped */
        const wa_asymmetric_public_key_t *public_key = NULL;
        WA_RETURN_IF_ERROR(wa_device_profile_find_layer_public_key(context->device_profile, layer, &public_key));
        return wa_asymmetric_wrap_key_struct(context->platform_hooks, public_key, context->resolved_format, key_bytes,
                                             key_bytes_length, context->cryptainer_metadata_or_null, cipherdict_out);
    }
    return WA_STATUS_UNSUPPORTED_ALGORITHM;
}

/* CHAIN (section 6.2) */

wa_status_t wa_key_cipher_layers_encrypt_key(const wa_key_cipher_context_t *context, wa_value_t *layer_owner,
                                             const uint8_t *key_bytes, size_t key_bytes_length,
                                             wa_growable_byte_buffer_t *key_ciphertext_out)
{
    wa_value_t *key_cipher_layers = wa_value_find_map_value_for_update(layer_owner, "key_cipher_layers");
    size_t layer_count = wa_value_get_item_count(key_cipher_layers);
    size_t layer_index;
    wa_status_t status = WA_STATUS_OK;
    wa_growable_byte_buffer_initialize(key_ciphertext_out, context->platform_hooks, 1);
    if (layer_count == 0) {
        return WA_STATUS_INVALID_PROFILE; /* Section 5.2: the core checks it again */
    }
    for (layer_index = 0; status == WA_STATUS_OK && layer_index < layer_count; ++layer_index) {
        wa_value_t *key_cipherdict = NULL;
        wa_growable_byte_buffer_t serialized_cipherdict;
        /* The k-th layer encrypts S_F of the (k-1)-th layer's cipherdict: key bytes stay bytes all along */
        const uint8_t *current_bytes = layer_index == 0 ? key_bytes : key_ciphertext_out->data;
        size_t current_length = layer_index == 0 ? key_bytes_length : key_ciphertext_out->length;
        status = wa_encrypt_key_through_single_layer(
            context, (wa_value_t *)wa_value_get_array_item(key_cipher_layers, layer_index), current_bytes,
            current_length, &key_cipherdict);
        if (status != WA_STATUS_OK) {
            break;
        }
        status = wa_serialize_secret_tree(context, key_cipherdict, &serialized_cipherdict);
        wa_value_destroy(key_cipherdict);
        if (status != WA_STATUS_OK) {
            break;
        }
        wa_growable_byte_buffer_release(key_ciphertext_out);
        *key_ciphertext_out = serialized_cipherdict;
    }
    /* Safety net of the reference: the output differs from the input */
    if (status == WA_STATUS_OK && key_ciphertext_out->length == key_bytes_length &&
        (key_bytes_length == 0 || memcmp(key_ciphertext_out->data, key_bytes, key_bytes_length) == 0)) {
        status = WA_STATUS_INTERNAL_ERROR;
    }
    if (status != WA_STATUS_OK) {
        wa_growable_byte_buffer_release(key_ciphertext_out);
    }
    return status;
}
