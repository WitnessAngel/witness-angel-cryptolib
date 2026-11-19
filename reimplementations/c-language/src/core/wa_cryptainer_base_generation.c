/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Section 6.1 of the encryptor specification (Python: _flightbox.py, generate_cryptainer_base_and_secrets and
 * _encrypt_payload_symkey). Random draws follow the reference order: the cryptainer uid, then for each payload
 * layer its symkey and its key cipher chain. The root keychain uid is mandatory in device profiles, so no second
 * UUID0 is ever drawn for it. */

#include "core/wa_cryptainer_base_generation.h"

#include <string.h>

#include "core/wa_key_cipher_layers_encryption.h"
#include "core/wa_platform_hooks_calls.h"
#include "encoding/wa_device_profile_decoding.h"
#include "encoding/wa_value_tree_internal.h"
#include "primitives/wa_uuid0_generation.h"

/* Replace (or add) a map entry, consuming `value` in any case */
static wa_status_t wa_set_map_value(wa_value_t *map, const char *key, wa_value_t *value)
{
    wa_value_destroy(wa_value_map_take_value(map, key));
    return wa_value_map_add_consuming(map, key, value);
}

static wa_status_t wa_set_text_value(const wa_platform_hooks_t *platform_hooks, wa_value_t *map, const char *key,
                                     const char *text)
{
    wa_value_t *text_node = NULL;
    WA_RETURN_IF_ERROR(wa_value_create_text(platform_hooks, text, strlen(text), &text_node));
    return wa_set_map_value(map, key, text_node);
}

static wa_status_t wa_set_null_value(const wa_platform_hooks_t *platform_hooks, wa_value_t *map, const char *key)
{
    wa_value_t *null_node = NULL;
    WA_RETURN_IF_ERROR(wa_value_create_null(platform_hooks, &null_node));
    return wa_set_map_value(map, key, null_node);
}

static wa_status_t wa_set_uuid_value(const wa_platform_hooks_t *platform_hooks, wa_value_t *map, const char *key,
                                     const uint8_t uuid[WA_UUID_SIZE])
{
    wa_value_t *uuid_node = NULL;
    WA_RETURN_IF_ERROR(wa_value_create_uuid(platform_hooks, uuid, &uuid_node));
    return wa_set_map_value(map, key, uuid_node);
}

/* Legacy naming of old cryptoconfs: "payload_signatures" becomes "payload_ciphertext_signatures" (the validation
 * allows only one of both names, so the new name never has precedence to apply here) */
static wa_status_t wa_rename_legacy_payload_signatures(wa_value_t *payload_layer)
{
    wa_value_t *legacy_payload_signatures = wa_value_map_take_value(payload_layer, "payload_signatures");
    if (legacy_payload_signatures == NULL) {
        return WA_STATUS_OK;
    }
    if (wa_value_find_map_value(payload_layer, "payload_ciphertext_signatures") != NULL) {
        wa_value_destroy(legacy_payload_signatures);
        return WA_STATUS_OK;
    }
    return wa_value_map_add_consuming(payload_layer, "payload_ciphertext_signatures", legacy_payload_signatures);
}

static wa_status_t wa_prepare_payload_cipher_layer(const wa_key_cipher_context_t *context, wa_value_t *payload_layer,
                                                   wa_symkey_t *payload_symkey)
{
    const char *algo_name = NULL;
    size_t algo_name_length = 0;
    wa_symmetric_cipher_algo_t cipher_algo;
    wa_growable_byte_buffer_t serialized_symkey;
    wa_growable_byte_buffer_t key_ciphertext;
    wa_status_t status;
    if (wa_value_get_text(wa_value_find_map_value(payload_layer, "payload_cipher_algo"), &algo_name,
                          &algo_name_length) != 0 ||
        !wa_symmetric_cipher_algo_from_name(algo_name, algo_name_length, &cipher_algo)) {
        return WA_STATUS_INVALID_PROFILE;
    }
    WA_RETURN_IF_ERROR(wa_rename_legacy_payload_signatures(payload_layer));
    WA_RETURN_IF_ERROR(wa_set_null_value(context->platform_hooks, payload_layer, "payload_macs")); /* Step 3 */
    WA_RETURN_IF_ERROR(wa_symkey_generate(context->platform_hooks, cipher_algo, payload_symkey));
    WA_RETURN_IF_ERROR(wa_key_cipher_layers_serialize_symkey(context, payload_symkey, &serialized_symkey));
    status = wa_key_cipher_layers_encrypt_key(context, payload_layer, serialized_symkey.data,
                                              serialized_symkey.length, &key_ciphertext);
    wa_growable_byte_buffer_release(&serialized_symkey);
    WA_RETURN_IF_ERROR(status);
    return wa_key_cipher_layers_store_key_ciphertext(context, payload_layer, &key_ciphertext);
}

static wa_status_t wa_set_root_fields(const wa_platform_hooks_t *platform_hooks, wa_value_t *cryptainer,
                                      const uint8_t cryptainer_uid[WA_UUID_SIZE], const uint8_t *keychain_uid,
                                      wa_ciphertext_location_t ciphertext_location, wa_value_t *metadata_copy)
{
    /* First, since it consumes the metadata copy in any case */
    WA_RETURN_IF_ERROR(wa_set_map_value(cryptainer, "cryptainer_metadata", metadata_copy));
    WA_RETURN_IF_ERROR(wa_set_text_value(platform_hooks, cryptainer, "cryptainer_state", WA_CRYPTAINER_STATE_STARTED));
    WA_RETURN_IF_ERROR(wa_set_text_value(platform_hooks, cryptainer, "cryptainer_format", WA_CRYPTAINER_FORMAT));
    WA_RETURN_IF_ERROR(wa_set_uuid_value(platform_hooks, cryptainer, "cryptainer_uid", cryptainer_uid));
    WA_RETURN_IF_ERROR(wa_set_uuid_value(platform_hooks, cryptainer, "keychain_uid", keychain_uid));
    if (ciphertext_location == WA_CIPHERTEXT_LOCATION_OFFLOADED) {
        /* Streaming mode: the offloaded marker right away (section 7.2) */
        wa_value_t *marker = NULL;
        WA_RETURN_IF_ERROR(wa_value_create_map(platform_hooks, &marker));
        WA_RETURN_IF_ERROR(wa_set_map_value(cryptainer, "payload_ciphertext_struct", marker));
        WA_RETURN_IF_ERROR(wa_set_text_value(platform_hooks, marker, "ciphertext_location",
                                             WA_CIPHERTEXT_LOCATION_OFFLOADED_NAME));
    } else {
        WA_RETURN_IF_ERROR(wa_set_null_value(platform_hooks, cryptainer, "payload_ciphertext_struct"));
    }
    return WA_STATUS_OK;
}

void wa_cryptainer_base_release_payload_symkeys(wa_cryptainer_base_t *base)
{
    if (base->payload_symkeys != NULL) {
        wa_release_secret_memory(base->platform_hooks, base->payload_symkeys,
                                 base->payload_layer_count * sizeof(wa_symkey_t));
        base->payload_symkeys = NULL;
    }
}

void wa_cryptainer_base_release(wa_cryptainer_base_t *base)
{
    wa_cryptainer_base_release_payload_symkeys(base);
    wa_value_destroy(base->cryptainer);
    memset(base, 0, sizeof(*base));
}

wa_status_t wa_cryptainer_base_generate(const wa_platform_hooks_t *platform_hooks,
                                        const wa_device_profile_t *device_profile,
                                        const wa_value_t *cryptainer_metadata_or_null,
                                        wa_document_format_t resolved_format,
                                        wa_ciphertext_location_t ciphertext_location, wa_cryptainer_base_t *base_out)
{
    uint8_t cryptainer_uid[WA_UUID_SIZE];
    wa_value_t *metadata_copy = NULL;
    wa_value_t *payload_layers;
    wa_key_cipher_context_t context;
    size_t symkeys_size = 0;
    size_t layer_index;
    wa_status_t status;

    memset(base_out, 0, sizeof(*base_out));
    base_out->platform_hooks = platform_hooks;

    status = wa_uuid0_generate(platform_hooks, cryptainer_uid); /* ALWAYS UNIQUE, drawn first */
    if (status == WA_STATUS_OK) {
        status = wa_value_deep_copy(device_profile->cryptoconf, platform_hooks, &base_out->cryptainer);
    }
    if (status == WA_STATUS_OK) {
        status = cryptainer_metadata_or_null == NULL
                     ? wa_value_create_null(platform_hooks, &metadata_copy)
                     : wa_value_deep_copy(cryptainer_metadata_or_null, platform_hooks, &metadata_copy);
    }
    payload_layers = status == WA_STATUS_OK
                         ? wa_value_find_map_value_for_update(base_out->cryptainer, "payload_cipher_layers")
                         : NULL;
    if (status == WA_STATUS_OK) {
        base_out->payload_layer_count = wa_value_get_item_count(payload_layers);
        if (base_out->payload_layer_count == 0) {
            status = WA_STATUS_INVALID_PROFILE; /* Rejected at profile load already */
        } else if (wa_size_multiplication_overflows(base_out->payload_layer_count, sizeof(wa_symkey_t),
                                                    &symkeys_size)) {
            status = WA_STATUS_OUT_OF_MEMORY;
        } else {
            base_out->payload_symkeys = (wa_symkey_t *)wa_allocate_memory(platform_hooks, symkeys_size);
            if (base_out->payload_symkeys == NULL) {
                status = WA_STATUS_OUT_OF_MEMORY;
            } else {
                memset(base_out->payload_symkeys, 0, symkeys_size);
            }
        }
    }
    if (status != WA_STATUS_OK) {
        base_out->payload_layer_count = 0; /* No symkey array to release */
    }

    context.platform_hooks = platform_hooks;
    context.device_profile = device_profile;
    context.resolved_format = resolved_format;
    context.cryptainer_metadata_or_null = cryptainer_metadata_or_null == NULL ? NULL : metadata_copy;
    for (layer_index = 0; status == WA_STATUS_OK && layer_index < base_out->payload_layer_count; ++layer_index) {
        status = wa_prepare_payload_cipher_layer(
            &context, (wa_value_t *)wa_value_get_array_item(payload_layers, layer_index),
            &base_out->payload_symkeys[layer_index]);
    }

    if (status == WA_STATUS_OK) {
        status = wa_set_root_fields(platform_hooks, base_out->cryptainer, cryptainer_uid,
                                    device_profile->root_keychain_uid, ciphertext_location, metadata_copy);
        metadata_copy = NULL; /* Consumed */
    }
    wa_value_destroy(metadata_copy);
    if (status != WA_STATUS_OK) {
        wa_cryptainer_base_release(base_out);
    }
    return status;
}
