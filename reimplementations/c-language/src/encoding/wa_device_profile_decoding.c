/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Device profile loading (design D9): decode the WA-CBOR sub-profile, check the root structure and format string,
 * validate the cryptoconf (D10) and the public key entries, check key constraints, then resolve every asymmetric
 * layer to its entry. */

#include "encoding/wa_device_profile_decoding.h"

#include <string.h>

#include "core/wa_cryptoconf_validation.h"
#include "core/wa_error_location_path.h"
#include "core/wa_platform_hooks_calls.h"
#include "encoding/wa_value_tree_internal.h"
#include "encoding/wa_wacbor_subprofile_decoder.h"
#include "primitives/wa_public_key_constraints.h"

static wa_status_t wa_fail_at_key(wa_error_location_path_t *location, const char *key, wa_status_t status)
{
    (void)wa_error_location_path_push_key(location, key, strlen(key));
    return status;
}

/* LOOKUPS */

static const wa_device_profile_key_entry_t *wa_device_profile_find_key_entry(
    const wa_device_profile_key_entry_t *key_entries, size_t key_entry_count, const wa_value_t *trustee,
    const uint8_t *keychain_uid, wa_asymmetric_cipher_algo_t cipher_algo)
{
    size_t entry_index;
    for (entry_index = 0; entry_index < key_entry_count; ++entry_index) {
        const wa_device_profile_key_entry_t *key_entry = &key_entries[entry_index];
        if (key_entry->public_key.cipher_algo == cipher_algo &&
            memcmp(key_entry->keychain_uid, keychain_uid, WA_UUID_SIZE) == 0 &&
            wa_trustee_identities_are_equal(key_entry->trustee, trustee)) {
            return key_entry;
        }
    }
    return NULL;
}

wa_status_t wa_device_profile_find_layer_public_key(const wa_device_profile_t *device_profile,
                                                    const wa_value_t *key_cipher_layer,
                                                    const wa_asymmetric_public_key_t **public_key_out)
{
    const char *algo_name = NULL;
    size_t algo_name_length = 0;
    const uint8_t *keychain_uid = device_profile->root_keychain_uid;
    const wa_value_t *layer_keychain_uid = wa_value_find_map_value(key_cipher_layer, "keychain_uid");
    wa_asymmetric_cipher_algo_t cipher_algo;
    const wa_device_profile_key_entry_t *key_entry;
    *public_key_out = NULL;
    if (wa_value_get_text(wa_value_find_map_value(key_cipher_layer, "key_cipher_algo"), &algo_name,
                          &algo_name_length) != 0 ||
        !wa_asymmetric_cipher_algo_from_name(algo_name, algo_name_length, &cipher_algo)) {
        return WA_STATUS_INTERNAL_ERROR; /* Layers are validated at load time */
    }
    if (layer_keychain_uid != NULL && wa_value_get_uuid(layer_keychain_uid, &keychain_uid) != 0) {
        return WA_STATUS_INTERNAL_ERROR;
    }
    key_entry = wa_device_profile_find_key_entry(device_profile->key_entries, device_profile->key_entry_count,
                                                 wa_value_find_map_value(key_cipher_layer, "key_cipher_trustee"),
                                                 keychain_uid, cipher_algo);
    if (key_entry == NULL) {
        return WA_STATUS_MISSING_PUBLIC_KEY;
    }
    *public_key_out = &key_entry->public_key;
    return WA_STATUS_OK;
}

/* PUBLIC KEY ENTRIES */

static wa_status_t wa_decode_public_key(const wa_value_t *key_entry_map, wa_asymmetric_public_key_t *public_key,
                                        wa_error_location_path_t *location)
{
    static const char *const rsa_public_key_keys[] = {"modulus", "public_exponent"};
    const wa_value_t *public_key_value = wa_value_find_map_value(key_entry_map, "public_key");
    size_t previous_length = wa_error_location_path_push_key(location, "public_key", strlen("public_key"));
    if (public_key_value == NULL) {
        return WA_STATUS_INVALID_PROFILE;
    }
    if (public_key->cipher_algo == WA_ASYMMETRIC_CIPHER_RSA_OAEP) {
        size_t entry_index;
        if (wa_value_get_type(public_key_value) != WA_VALUE_TYPE_MAP) {
            return WA_STATUS_INVALID_PROFILE;
        }
        for (entry_index = 0; entry_index < wa_value_get_item_count(public_key_value); ++entry_index) {
            const char *key = NULL;
            size_t key_length = 0;
            const wa_value_t *value = NULL;
            (void)wa_value_get_map_entry(public_key_value, entry_index, &key, &key_length, &value);
            if (!wa_value_keys_are_equal(key, key_length, rsa_public_key_keys[0], strlen(rsa_public_key_keys[0])) &&
                !wa_value_keys_are_equal(key, key_length, rsa_public_key_keys[1], strlen(rsa_public_key_keys[1]))) {
                (void)wa_error_location_path_push_key(location, key, key_length);
                return WA_STATUS_INVALID_PROFILE;
            }
        }
        if (wa_value_get_bytes(wa_value_find_map_value(public_key_value, "modulus"), &public_key->modulus,
                               &public_key->modulus_length) != 0) {
            return wa_fail_at_key(location, "modulus", WA_STATUS_INVALID_PROFILE);
        }
        if (wa_value_get_bytes(wa_value_find_map_value(public_key_value, "public_exponent"),
                               &public_key->public_exponent, &public_key->public_exponent_length) != 0) {
            return wa_fail_at_key(location, "public_exponent", WA_STATUS_INVALID_PROFILE);
        }
    } else {
        size_t expected_length = public_key->cipher_algo == WA_ASYMMETRIC_CIPHER_ECIES_X25519
                                     ? WA_X25519_PUBLIC_KEY_SIZE
                                     : WA_ML_KEM_768_PUBLIC_KEY_SIZE;
        if (wa_value_get_bytes(public_key_value, &public_key->key_bytes, &public_key->key_bytes_length) != 0 ||
            public_key->key_bytes_length != expected_length) {
            return WA_STATUS_INVALID_PROFILE;
        }
    }
    wa_error_location_path_pop(location, previous_length);
    return WA_STATUS_OK;
}

/* Structure of one entry: exactly trustee, keychain_uid, key_algo and public_key */
static wa_status_t wa_decode_key_entry(const wa_value_t *key_entry_map, wa_device_profile_key_entry_t *key_entry,
                                       wa_error_location_path_t *location)
{
    static const char *const key_entry_keys[] = {"trustee", "keychain_uid", "key_algo", "public_key"};
    const char *algo_name = NULL;
    size_t algo_name_length = 0;
    size_t entry_index;
    size_t previous_length;
    memset(key_entry, 0, sizeof(*key_entry));
    if (wa_value_get_type(key_entry_map) != WA_VALUE_TYPE_MAP) {
        return WA_STATUS_INVALID_PROFILE;
    }
    for (entry_index = 0; entry_index < wa_value_get_item_count(key_entry_map); ++entry_index) {
        const char *key = NULL;
        size_t key_length = 0;
        const wa_value_t *value = NULL;
        size_t allowed_index;
        int is_allowed = 0;
        (void)wa_value_get_map_entry(key_entry_map, entry_index, &key, &key_length, &value);
        for (allowed_index = 0; allowed_index < sizeof(key_entry_keys) / sizeof(key_entry_keys[0]); ++allowed_index) {
            if (wa_value_keys_are_equal(key, key_length, key_entry_keys[allowed_index],
                                        strlen(key_entry_keys[allowed_index]))) {
                is_allowed = 1;
            }
        }
        if (!is_allowed) {
            (void)wa_error_location_path_push_key(location, key, key_length);
            return WA_STATUS_INVALID_PROFILE;
        }
    }
    key_entry->trustee = wa_value_find_map_value(key_entry_map, "trustee");
    previous_length = wa_error_location_path_push_key(location, "trustee", strlen("trustee"));
    if (key_entry->trustee == NULL) {
        return WA_STATUS_INVALID_PROFILE;
    }
    WA_RETURN_IF_ERROR(wa_cryptoconf_validate_trustee(key_entry->trustee, location));
    wa_error_location_path_pop(location, previous_length);
    if (wa_value_get_uuid(wa_value_find_map_value(key_entry_map, "keychain_uid"), &key_entry->keychain_uid) != 0) {
        return wa_fail_at_key(location, "keychain_uid", WA_STATUS_INVALID_PROFILE);
    }
    if (wa_value_get_text(wa_value_find_map_value(key_entry_map, "key_algo"), &algo_name, &algo_name_length) != 0 ||
        !wa_asymmetric_cipher_algo_from_name(algo_name, algo_name_length, &key_entry->public_key.cipher_algo)) {
        return wa_fail_at_key(location, "key_algo", WA_STATUS_INVALID_PROFILE);
    }
    return wa_decode_public_key(key_entry_map, &key_entry->public_key, location);
}

static wa_status_t wa_check_public_key_constraints(const wa_asymmetric_public_key_t *public_key)
{
    switch (public_key->cipher_algo) {
    case WA_ASYMMETRIC_CIPHER_RSA_OAEP:
        return wa_public_key_check_rsa(public_key->modulus, public_key->modulus_length, public_key->public_exponent,
                                       public_key->public_exponent_length);
    case WA_ASYMMETRIC_CIPHER_ECIES_X25519:
        return wa_public_key_check_x25519(public_key->key_bytes, public_key->key_bytes_length);
    case WA_ASYMMETRIC_CIPHER_ML_KEM_768:
        return wa_public_key_check_ml_kem_768(public_key->key_bytes, public_key->key_bytes_length);
    default:
        return WA_STATUS_INTERNAL_ERROR;
    }
}

/* Decode every entry and check their uniqueness, then their key constraints */
static wa_status_t wa_decode_key_entries(wa_device_profile_t *device_profile, wa_error_location_path_t *location)
{
    const wa_value_t *key_entry_list = wa_value_find_map_value(device_profile->document, "trustee_public_keys");
    size_t key_entry_count;
    size_t entries_size = 0;
    size_t entry_index;
    size_t previous_length = wa_error_location_path_push_key(location, "trustee_public_keys",
                                                             strlen("trustee_public_keys"));
    if (key_entry_list == NULL || wa_value_get_type(key_entry_list) != WA_VALUE_TYPE_ARRAY) {
        return WA_STATUS_INVALID_PROFILE;
    }
    key_entry_count = wa_value_get_item_count(key_entry_list);
    if (key_entry_count > 0) {
        if (wa_size_multiplication_overflows(key_entry_count, sizeof(wa_device_profile_key_entry_t), &entries_size)) {
            return WA_STATUS_OUT_OF_MEMORY;
        }
        device_profile->key_entries =
            (wa_device_profile_key_entry_t *)wa_allocate_memory(device_profile->platform_hooks, entries_size);
        if (device_profile->key_entries == NULL) {
            return WA_STATUS_OUT_OF_MEMORY;
        }
        device_profile->key_entry_capacity = key_entry_count;
    }
    device_profile->key_entry_count = 0;
    for (entry_index = 0; entry_index < key_entry_count; ++entry_index) {
        wa_device_profile_key_entry_t *key_entry = &device_profile->key_entries[entry_index];
        size_t entry_previous_length = wa_error_location_path_push_index(location, entry_index);
        WA_RETURN_IF_ERROR(
            wa_decode_key_entry(wa_value_get_array_item(key_entry_list, entry_index), key_entry, location));
        if (wa_device_profile_find_key_entry(device_profile->key_entries, entry_index, key_entry->trustee,
                                             key_entry->keychain_uid, key_entry->public_key.cipher_algo) != NULL) {
            return WA_STATUS_INVALID_PROFILE; /* Duplicate (trustee identity, keychain uid, key algo) */
        }
        device_profile->key_entry_count = entry_index + 1u;
        wa_error_location_path_pop(location, entry_previous_length);
    }
    for (entry_index = 0; entry_index < key_entry_count; ++entry_index) {
        size_t entry_previous_length = wa_error_location_path_push_index(location, entry_index);
        WA_RETURN_IF_ERROR(wa_check_public_key_constraints(&device_profile->key_entries[entry_index].public_key));
        wa_error_location_path_pop(location, entry_previous_length);
    }
    wa_error_location_path_pop(location, previous_length);
    return WA_STATUS_OK;
}

/* LAYER RESOLUTION */

static wa_status_t wa_resolve_key_cipher_layers(const wa_device_profile_t *device_profile, const wa_value_t *map,
                                                wa_error_location_path_t *location);

static wa_status_t wa_resolve_key_cipher_layer(const wa_device_profile_t *device_profile,
                                               const wa_value_t *key_cipher_layer, wa_error_location_path_t *location)
{
    const wa_value_t *shards = wa_value_find_map_value(key_cipher_layer, "key_shared_secret_shards");
    const wa_asymmetric_public_key_t *public_key = NULL;
    if (shards != NULL) {
        size_t shard_index;
        size_t previous_length = wa_error_location_path_push_key(location, "key_shared_secret_shards",
                                                                 strlen("key_shared_secret_shards"));
        for (shard_index = 0; shard_index < wa_value_get_item_count(shards); ++shard_index) {
            size_t shard_previous_length = wa_error_location_path_push_index(location, shard_index);
            WA_RETURN_IF_ERROR(
                wa_resolve_key_cipher_layers(device_profile, wa_value_get_array_item(shards, shard_index), location));
            wa_error_location_path_pop(location, shard_previous_length);
        }
        wa_error_location_path_pop(location, previous_length);
        return WA_STATUS_OK;
    }
    if (wa_value_find_map_value(key_cipher_layer, "key_cipher_layers") != NULL) {
        return wa_resolve_key_cipher_layers(device_profile, key_cipher_layer, location);
    }
    return wa_device_profile_find_layer_public_key(device_profile, key_cipher_layer, &public_key);
}

static wa_status_t wa_resolve_key_cipher_layers(const wa_device_profile_t *device_profile, const wa_value_t *map,
                                                wa_error_location_path_t *location)
{
    const wa_value_t *key_cipher_layers = wa_value_find_map_value(map, "key_cipher_layers");
    size_t layer_index;
    size_t previous_length = wa_error_location_path_push_key(location, "key_cipher_layers", strlen("key_cipher_layers"));
    for (layer_index = 0; layer_index < wa_value_get_item_count(key_cipher_layers); ++layer_index) {
        size_t layer_previous_length = wa_error_location_path_push_index(location, layer_index);
        WA_RETURN_IF_ERROR(wa_resolve_key_cipher_layer(
            device_profile, wa_value_get_array_item(key_cipher_layers, layer_index), location));
        wa_error_location_path_pop(location, layer_previous_length);
    }
    wa_error_location_path_pop(location, previous_length);
    return WA_STATUS_OK;
}

static wa_status_t wa_resolve_all_layers(const wa_device_profile_t *device_profile,
                                         wa_error_location_path_t *location)
{
    const wa_value_t *payload_cipher_layers = wa_value_find_map_value(device_profile->cryptoconf,
                                                                      "payload_cipher_layers");
    size_t layer_index;
    size_t previous_length = wa_error_location_path_push_key(location, "cryptoconf", strlen("cryptoconf"));
    size_t list_previous_length =
        wa_error_location_path_push_key(location, "payload_cipher_layers", strlen("payload_cipher_layers"));
    for (layer_index = 0; layer_index < wa_value_get_item_count(payload_cipher_layers); ++layer_index) {
        size_t layer_previous_length = wa_error_location_path_push_index(location, layer_index);
        WA_RETURN_IF_ERROR(wa_resolve_key_cipher_layers(
            device_profile, wa_value_get_array_item(payload_cipher_layers, layer_index), location));
        wa_error_location_path_pop(location, layer_previous_length);
    }
    wa_error_location_path_pop(location, list_previous_length);
    wa_error_location_path_pop(location, previous_length);
    return WA_STATUS_OK;
}

/* LOADING */

static wa_status_t wa_check_root_structure(const wa_value_t *document, wa_error_location_path_t *location)
{
    size_t entry_index;
    if (wa_value_get_type(document) != WA_VALUE_TYPE_MAP) {
        return WA_STATUS_INVALID_PROFILE;
    }
    /* The format comes first: another version may have other root keys */
    if (!wa_value_is_text_equal_to(wa_value_find_map_value(document, "device_profile_format"),
                                   WA_DEVICE_PROFILE_FORMAT)) {
        return wa_fail_at_key(location, "device_profile_format", WA_STATUS_UNSUPPORTED_FORMAT);
    }
    for (entry_index = 0; entry_index < wa_value_get_item_count(document); ++entry_index) {
        const char *key = NULL;
        size_t key_length = 0;
        const wa_value_t *value = NULL;
        (void)wa_value_get_map_entry(document, entry_index, &key, &key_length, &value);
        if (!wa_value_keys_are_equal(key, key_length, "device_profile_format", strlen("device_profile_format")) &&
            !wa_value_keys_are_equal(key, key_length, "cryptoconf", strlen("cryptoconf")) &&
            !wa_value_keys_are_equal(key, key_length, "trustee_public_keys", strlen("trustee_public_keys"))) {
            (void)wa_error_location_path_push_key(location, key, key_length);
            return WA_STATUS_INVALID_PROFILE;
        }
    }
    return WA_STATUS_OK;
}

static wa_status_t wa_device_profile_load(wa_device_profile_t *device_profile, const uint8_t *cbor,
                                          size_t cbor_length, wa_error_location_path_t *location)
{
    size_t previous_length;
    WA_RETURN_IF_ERROR(wa_wacbor_subprofile_decode_document(cbor, cbor_length, device_profile->platform_hooks,
                                                            &device_profile->document));
    WA_RETURN_IF_ERROR(wa_check_root_structure(device_profile->document, location));

    device_profile->cryptoconf = wa_value_find_map_value(device_profile->document, "cryptoconf");
    previous_length = wa_error_location_path_push_key(location, "cryptoconf", strlen("cryptoconf"));
    if (device_profile->cryptoconf == NULL) {
        return WA_STATUS_INVALID_PROFILE;
    }
    WA_RETURN_IF_ERROR(wa_cryptoconf_validate(device_profile->cryptoconf, location));
    wa_error_location_path_pop(location, previous_length);
    if (wa_value_get_uuid(wa_value_find_map_value(device_profile->cryptoconf, "keychain_uid"),
                          &device_profile->root_keychain_uid) != 0) {
        return WA_STATUS_INTERNAL_ERROR; /* Checked by the cryptoconf validation */
    }

    WA_RETURN_IF_ERROR(wa_decode_key_entries(device_profile, location));
    return wa_resolve_all_layers(device_profile, location);
}

wa_status_t wa_device_profile_load_from_cbor(const uint8_t *cbor, size_t cbor_length,
                                             const wa_platform_hooks_t *platform_hooks,
                                             wa_device_profile_t **device_profile_out,
                                             char *error_location_buffer_or_null,
                                             size_t error_location_buffer_size)
{
    wa_device_profile_t *device_profile;
    wa_error_location_path_t location;
    wa_status_t status;
    wa_error_location_path_initialize(&location);
    wa_error_location_path_copy_to_buffer(&location, error_location_buffer_or_null, error_location_buffer_size);
    if (device_profile_out == NULL) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    *device_profile_out = NULL;
    if ((cbor == NULL && cbor_length > 0) || !wa_platform_hooks_are_usable(platform_hooks)) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    device_profile = (wa_device_profile_t *)wa_allocate_memory(platform_hooks, sizeof(*device_profile));
    if (device_profile == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    memset(device_profile, 0, sizeof(*device_profile));
    device_profile->platform_hooks = platform_hooks;
    status = wa_device_profile_load(device_profile, cbor, cbor_length, &location);
    if (status != WA_STATUS_OK) {
        wa_error_location_path_copy_to_buffer(&location, error_location_buffer_or_null, error_location_buffer_size);
        wa_device_profile_destroy(device_profile);
        return status;
    }
    *device_profile_out = device_profile;
    return WA_STATUS_OK;
}

void wa_device_profile_destroy(wa_device_profile_t *device_profile_or_null)
{
    const wa_platform_hooks_t *platform_hooks;
    if (device_profile_or_null == NULL) {
        return;
    }
    platform_hooks = device_profile_or_null->platform_hooks;
    wa_value_destroy(device_profile_or_null->document);
    wa_release_memory(platform_hooks, device_profile_or_null->key_entries,
                      device_profile_or_null->key_entry_capacity * sizeof(wa_device_profile_key_entry_t));
    wa_release_memory(platform_hooks, device_profile_or_null, sizeof(*device_profile_or_null));
}
