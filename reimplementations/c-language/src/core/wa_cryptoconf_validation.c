/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/wa_cryptoconf_validation.h"

#include <string.h>

#include "core/wa_platform_hooks_calls.h"
#include "encoding/wa_value_tree_internal.h"
#include "primitives/wa_asymmetric_key_wrapping.h"
#include "primitives/wa_symmetric_key_generation.h"
#include "wa_flightbox/wa_flightbox_config.h"

#define WA_ARRAY_LENGTH(array) (sizeof(array) / sizeof((array)[0]))

/* SUPPORTED_HASH_ALGOS and SUPPORTED_SIGNATURE_ALGOS of wacryptolib, for the signature conf grammar */
static const char *const wa_hash_algo_names[] = {"SHA256", "SHA512", "SHA3_256", "SHA3_512"};
static const char *const wa_signature_algo_names[] = {"DSA_DSS", "ECC_DSS", "ML_DSA_65", "RSA_PSS"};

static int wa_key_is(const char *key, size_t key_length, const char *literal)
{
    return wa_value_keys_are_equal(key, key_length, literal, strlen(literal));
}

static int wa_text_is_one_of(const wa_value_t *value, const char *const *names, size_t name_count)
{
    size_t index;
    for (index = 0; index < name_count; ++index) {
        if (wa_value_is_text_equal_to(value, names[index])) {
            return 1;
        }
    }
    return 0;
}

wa_status_t wa_check_allowed_keys(const wa_value_t *map, const char *const *allowed_keys, size_t allowed_key_count,
                                  wa_error_location_path_t *location)
{
    size_t entry_index;
    for (entry_index = 0; entry_index < wa_value_get_item_count(map); ++entry_index) {
        const char *key = NULL;
        size_t key_length = 0;
        const wa_value_t *value = NULL;
        size_t allowed_index;
        int is_allowed = 0;
        (void)wa_value_get_map_entry(map, entry_index, &key, &key_length, &value);
        for (allowed_index = 0; allowed_index < allowed_key_count; ++allowed_index) {
            if (wa_key_is(key, key_length, allowed_keys[allowed_index])) {
                is_allowed = 1;
                break;
            }
        }
        if (!is_allowed) {
            (void)wa_error_location_path_push_key(location, key, key_length);
            return WA_STATUS_INVALID_PROFILE;
        }
    }
    return WA_STATUS_OK;
}

/* WA_STATUS_INVALID_PROFILE, located at the value or else at the missing key, unless the value is present
 * (or optional and absent) and of the given type */
static wa_status_t wa_check_typed_value(const wa_value_t *map, const char *key, int is_required,
                                        wa_value_type_t expected_type, wa_error_location_path_t *location)
{
    const wa_value_t *value = wa_value_find_map_value(map, key);
    if (value == NULL && !is_required) {
        return WA_STATUS_OK;
    }
    if (value == NULL || wa_value_get_type(value) != expected_type) {
        (void)wa_error_location_path_push_key(location, key, strlen(key));
        return WA_STATUS_INVALID_PROFILE;
    }
    return WA_STATUS_OK;
}

static wa_status_t wa_check_map(const wa_value_t *value)
{
    return wa_value_get_type(value) == WA_VALUE_TYPE_MAP ? WA_STATUS_OK : WA_STATUS_INVALID_PROFILE;
}

wa_status_t wa_cryptoconf_validate_trustee(const wa_value_t *trustee, wa_error_location_path_t *location)
{
    static const char *const local_keyfactory_keys[] = {"trustee_type"};
    static const char *const authenticator_keys[] = {"trustee_type", "keystore_uid", "keystore_owner"};
    static const char *const jsonrpc_api_keys[] = {"trustee_type", "jsonrpc_url"};
    const wa_value_t *trustee_type;
    WA_RETURN_IF_ERROR(wa_check_map(trustee));
    trustee_type = wa_value_find_map_value(trustee, "trustee_type");
    if (wa_value_is_text_equal_to(trustee_type, "local_keyfactory")) {
        return wa_check_allowed_keys(trustee, local_keyfactory_keys, WA_ARRAY_LENGTH(local_keyfactory_keys),
                                     location);
    }
    if (wa_value_is_text_equal_to(trustee_type, "authenticator")) {
        WA_RETURN_IF_ERROR(
            wa_check_allowed_keys(trustee, authenticator_keys, WA_ARRAY_LENGTH(authenticator_keys), location));
        WA_RETURN_IF_ERROR(wa_check_typed_value(trustee, "keystore_uid", 1, WA_VALUE_TYPE_UUID, location));
        return wa_check_typed_value(trustee, "keystore_owner", 0, WA_VALUE_TYPE_TEXT, location);
    }
    if (wa_value_is_text_equal_to(trustee_type, "jsonrpc_api")) {
        WA_RETURN_IF_ERROR(
            wa_check_allowed_keys(trustee, jsonrpc_api_keys, WA_ARRAY_LENGTH(jsonrpc_api_keys), location));
        return wa_check_typed_value(trustee, "jsonrpc_url", 1, WA_VALUE_TYPE_TEXT, location);
    }
    (void)wa_error_location_path_push_key(location, "trustee_type", strlen("trustee_type"));
    return WA_STATUS_INVALID_PROFILE;
}

static int wa_values_are_equal_leaves(const wa_value_t *value_a, const wa_value_t *value_b)
{
    const uint8_t *bytes_a = NULL;
    const uint8_t *bytes_b = NULL;
    const char *text_a = NULL;
    const char *text_b = NULL;
    size_t length_a = 0;
    size_t length_b = 0;
    if (value_a == NULL || value_b == NULL) {
        return value_a == value_b;
    }
    if (wa_value_get_uuid(value_a, &bytes_a) == 0 && wa_value_get_uuid(value_b, &bytes_b) == 0) {
        return memcmp(bytes_a, bytes_b, WA_UUID_SIZE) == 0;
    }
    if (wa_value_get_text(value_a, &text_a, &length_a) == 0 && wa_value_get_text(value_b, &text_b, &length_b) == 0) {
        return wa_value_keys_are_equal(text_a, length_a, text_b, length_b);
    }
    return 0;
}

int wa_trustee_identities_are_equal(const wa_value_t *trustee_a, const wa_value_t *trustee_b)
{
    const wa_value_t *trustee_type = wa_value_find_map_value(trustee_a, "trustee_type");
    if (!wa_values_are_equal_leaves(trustee_type, wa_value_find_map_value(trustee_b, "trustee_type"))) {
        return 0;
    }
    if (wa_value_is_text_equal_to(trustee_type, "authenticator")) {
        return wa_values_are_equal_leaves(wa_value_find_map_value(trustee_a, "keystore_uid"),
                                          wa_value_find_map_value(trustee_b, "keystore_uid"));
    }
    if (wa_value_is_text_equal_to(trustee_type, "jsonrpc_api")) {
        return wa_values_are_equal_leaves(wa_value_find_map_value(trustee_a, "jsonrpc_url"),
                                          wa_value_find_map_value(trustee_b, "jsonrpc_url"));
    }
    return 1;
}

/* A signature conf of a signature list: payload_digest_algo, payload_signature_algo, payload_signature_trustee and
 * an optional keychain_uid */
static wa_status_t wa_validate_signature_conf(const wa_value_t *signature_conf, wa_error_location_path_t *location)
{
    static const char *const signature_conf_keys[] = {"payload_digest_algo", "payload_signature_algo",
                                                      "payload_signature_trustee", "keychain_uid"};
    const wa_value_t *trustee;
    size_t previous_length;
    WA_RETURN_IF_ERROR(wa_check_map(signature_conf));
    WA_RETURN_IF_ERROR(
        wa_check_allowed_keys(signature_conf, signature_conf_keys, WA_ARRAY_LENGTH(signature_conf_keys), location));
    if (!wa_text_is_one_of(wa_value_find_map_value(signature_conf, "payload_digest_algo"), wa_hash_algo_names,
                           WA_ARRAY_LENGTH(wa_hash_algo_names))) {
        (void)wa_error_location_path_push_key(location, "payload_digest_algo", strlen("payload_digest_algo"));
        return WA_STATUS_INVALID_PROFILE;
    }
    if (!wa_text_is_one_of(wa_value_find_map_value(signature_conf, "payload_signature_algo"),
                           wa_signature_algo_names, WA_ARRAY_LENGTH(wa_signature_algo_names))) {
        (void)wa_error_location_path_push_key(location, "payload_signature_algo", strlen("payload_signature_algo"));
        return WA_STATUS_INVALID_PROFILE;
    }
    previous_length =
        wa_error_location_path_push_key(location, "payload_signature_trustee", strlen("payload_signature_trustee"));
    trustee = wa_value_find_map_value(signature_conf, "payload_signature_trustee");
    if (trustee == NULL) {
        return WA_STATUS_INVALID_PROFILE;
    }
    WA_RETURN_IF_ERROR(wa_cryptoconf_validate_trustee(trustee, location));
    wa_error_location_path_pop(location, previous_length);
    return wa_check_typed_value(signature_conf, "keychain_uid", 0, WA_VALUE_TYPE_UUID, location);
}

/* A signature list, validated item by item, then refused if non-empty (signatures are not supported yet) */
static wa_status_t wa_validate_signature_list(const wa_value_t *map, const char *key,
                                              wa_error_location_path_t *location)
{
    const wa_value_t *signature_list = wa_value_find_map_value(map, key);
    size_t previous_length = wa_error_location_path_push_key(location, key, strlen(key));
    size_t item_index;
    if (signature_list == NULL || wa_value_get_type(signature_list) != WA_VALUE_TYPE_ARRAY) {
        return WA_STATUS_INVALID_PROFILE;
    }
    for (item_index = 0; item_index < wa_value_get_item_count(signature_list); ++item_index) {
        size_t item_previous_length = wa_error_location_path_push_index(location, item_index);
        WA_RETURN_IF_ERROR(wa_validate_signature_conf(wa_value_get_array_item(signature_list, item_index), location));
        wa_error_location_path_pop(location, item_previous_length);
    }
    if (wa_value_get_item_count(signature_list) > 0) {
        return WA_STATUS_UNSUPPORTED_SIGNATURE;
    }
    wa_error_location_path_pop(location, previous_length);
    return WA_STATUS_OK;
}

static wa_status_t wa_validate_key_cipher_layers(const wa_value_t *map, size_t nesting_level,
                                                 wa_error_location_path_t *location);

static wa_status_t wa_validate_shared_secret_layer(const wa_value_t *layer, size_t nesting_level,
                                                   wa_error_location_path_t *location)
{
    static const char *const shared_secret_keys[] = {"key_cipher_algo", "key_shared_secret_shards",
                                                     "key_shared_secret_threshold"};
    static const char *const shard_keys[] = {"key_cipher_layers"};
    const wa_value_t *shards = wa_value_find_map_value(layer, "key_shared_secret_shards");
    const wa_value_t *threshold = wa_value_find_map_value(layer, "key_shared_secret_threshold");
    int64_t threshold_count = 0;
    size_t previous_length;
    size_t shard_index;
    WA_RETURN_IF_ERROR(
        wa_check_allowed_keys(layer, shared_secret_keys, WA_ARRAY_LENGTH(shared_secret_keys), location));
    WA_RETURN_IF_ERROR(wa_check_typed_value(layer, "key_shared_secret_shards", 1, WA_VALUE_TYPE_ARRAY, location));
    previous_length =
        wa_error_location_path_push_key(location, "key_shared_secret_shards", strlen("key_shared_secret_shards"));
    if (wa_value_get_item_count(shards) == 0) {
        return WA_STATUS_INVALID_PROFILE; /* An empty list is the fault, whatever the threshold */
    }
    for (shard_index = 0; shard_index < wa_value_get_item_count(shards); ++shard_index) {
        const wa_value_t *shard = wa_value_get_array_item(shards, shard_index);
        size_t shard_previous_length = wa_error_location_path_push_index(location, shard_index);
        WA_RETURN_IF_ERROR(wa_check_map(shard));
        WA_RETURN_IF_ERROR(wa_check_allowed_keys(shard, shard_keys, WA_ARRAY_LENGTH(shard_keys), location));
        WA_RETURN_IF_ERROR(wa_validate_key_cipher_layers(shard, nesting_level + 1u, location));
        wa_error_location_path_pop(location, shard_previous_length);
    }
    wa_error_location_path_pop(location, previous_length);
    if (threshold == NULL || wa_value_get_integer(threshold, &threshold_count) != 0 || threshold_count < 1 ||
        (uint64_t)threshold_count > (uint64_t)wa_value_get_item_count(shards)) {
        (void)wa_error_location_path_push_key(location, "key_shared_secret_threshold",
                                              strlen("key_shared_secret_threshold"));
        return WA_STATUS_INVALID_PROFILE;
    }
    return WA_STATUS_OK;
}

static wa_status_t wa_validate_key_cipher_layer(const wa_value_t *layer, size_t nesting_level,
                                                wa_error_location_path_t *location)
{
    static const char *const symmetric_layer_keys[] = {"key_cipher_algo", "key_cipher_layers"};
    static const char *const asymmetric_layer_keys[] = {"key_cipher_algo", "key_cipher_trustee", "keychain_uid"};
    const wa_value_t *key_cipher_algo;
    const char *algo_name = NULL;
    size_t algo_name_length = 0;
    wa_symmetric_cipher_algo_t symmetric_algo;
    wa_asymmetric_cipher_algo_t asymmetric_algo;
    WA_RETURN_IF_ERROR(wa_check_map(layer));
    key_cipher_algo = wa_value_find_map_value(layer, "key_cipher_algo");
    if (key_cipher_algo == NULL || wa_value_get_text(key_cipher_algo, &algo_name, &algo_name_length) != 0) {
        (void)wa_error_location_path_push_key(location, "key_cipher_algo", strlen("key_cipher_algo"));
        return WA_STATUS_INVALID_PROFILE;
    }
    if (wa_value_is_text_equal_to(key_cipher_algo, WA_SHARED_SECRET_ALGO_MARKER)) {
        return wa_validate_shared_secret_layer(layer, nesting_level, location);
    }
    if (wa_symmetric_cipher_algo_from_name(algo_name, algo_name_length, &symmetric_algo)) {
        WA_RETURN_IF_ERROR(
            wa_check_allowed_keys(layer, symmetric_layer_keys, WA_ARRAY_LENGTH(symmetric_layer_keys), location));
        return wa_validate_key_cipher_layers(layer, nesting_level + 1u, location);
    }
    if (wa_asymmetric_cipher_algo_from_name(algo_name, algo_name_length, &asymmetric_algo)) {
        const wa_value_t *trustee = wa_value_find_map_value(layer, "key_cipher_trustee");
        size_t previous_length;
        WA_RETURN_IF_ERROR(
            wa_check_allowed_keys(layer, asymmetric_layer_keys, WA_ARRAY_LENGTH(asymmetric_layer_keys), location));
        previous_length =
            wa_error_location_path_push_key(location, "key_cipher_trustee", strlen("key_cipher_trustee"));
        if (trustee == NULL) {
            return WA_STATUS_INVALID_PROFILE;
        }
        WA_RETURN_IF_ERROR(wa_cryptoconf_validate_trustee(trustee, location));
        wa_error_location_path_pop(location, previous_length);
        return wa_check_typed_value(layer, "keychain_uid", 0, WA_VALUE_TYPE_UUID, location);
    }
    (void)wa_error_location_path_push_key(location, "key_cipher_algo", strlen("key_cipher_algo"));
    return WA_STATUS_INVALID_PROFILE;
}

/* The non-empty "key_cipher_layers" list of `map`, at `nesting_level` */
static wa_status_t wa_validate_key_cipher_layers(const wa_value_t *map, size_t nesting_level,
                                                 wa_error_location_path_t *location)
{
    const wa_value_t *layers = wa_value_find_map_value(map, "key_cipher_layers");
    size_t previous_length = wa_error_location_path_push_key(location, "key_cipher_layers", strlen("key_cipher_layers"));
    size_t layer_index;
    if (layers == NULL || wa_value_get_type(layers) != WA_VALUE_TYPE_ARRAY || wa_value_get_item_count(layers) == 0) {
        return WA_STATUS_INVALID_PROFILE;
    }
    if (nesting_level > WA_MAX_KEY_CIPHER_NESTING_DEPTH) {
        return WA_STATUS_NESTING_TOO_DEEP;
    }
    for (layer_index = 0; layer_index < wa_value_get_item_count(layers); ++layer_index) {
        size_t layer_previous_length = wa_error_location_path_push_index(location, layer_index);
        WA_RETURN_IF_ERROR(
            wa_validate_key_cipher_layer(wa_value_get_array_item(layers, layer_index), nesting_level, location));
        wa_error_location_path_pop(location, layer_previous_length);
    }
    wa_error_location_path_pop(location, previous_length);
    return WA_STATUS_OK;
}

static wa_status_t wa_validate_payload_cipher_layer(const wa_value_t *layer, wa_error_location_path_t *location)
{
    static const char *const payload_layer_keys[] = {"payload_cipher_algo", "payload_ciphertext_signatures",
                                                     "payload_signatures", "key_cipher_layers"};
    const wa_value_t *payload_cipher_algo;
    const char *algo_name = NULL;
    size_t algo_name_length = 0;
    wa_symmetric_cipher_algo_t symmetric_algo;
    int has_signatures = wa_value_find_map_value(layer, "payload_ciphertext_signatures") != NULL;
    int has_legacy_signatures = wa_value_find_map_value(layer, "payload_signatures") != NULL;
    WA_RETURN_IF_ERROR(wa_check_map(layer));
    WA_RETURN_IF_ERROR(
        wa_check_allowed_keys(layer, payload_layer_keys, WA_ARRAY_LENGTH(payload_layer_keys), location));
    payload_cipher_algo = wa_value_find_map_value(layer, "payload_cipher_algo");
    if (payload_cipher_algo == NULL || wa_value_get_text(payload_cipher_algo, &algo_name, &algo_name_length) != 0 ||
        !wa_symmetric_cipher_algo_from_name(algo_name, algo_name_length, &symmetric_algo)) {
        (void)wa_error_location_path_push_key(location, "payload_cipher_algo", strlen("payload_cipher_algo"));
        return WA_STATUS_INVALID_PROFILE;
    }
    /* The Python schema is an Or of two closed schemas, one per signature list name: exactly one is required */
    if (has_signatures && has_legacy_signatures) {
        return WA_STATUS_INVALID_PROFILE;
    }
    WA_RETURN_IF_ERROR(wa_validate_signature_list(
        layer, has_legacy_signatures ? "payload_signatures" : "payload_ciphertext_signatures", location));
    return wa_validate_key_cipher_layers(layer, 1, location);
}

wa_status_t wa_cryptoconf_validate(const wa_value_t *cryptoconf, wa_error_location_path_t *location)
{
    static const char *const cryptoconf_keys[] = {"payload_cipher_layers", "payload_plaintext_signatures",
                                                  "keychain_uid"};
    const wa_value_t *payload_cipher_layers;
    size_t previous_length;
    size_t layer_index;
    WA_RETURN_IF_ERROR(wa_check_map(cryptoconf));
    WA_RETURN_IF_ERROR(wa_check_allowed_keys(cryptoconf, cryptoconf_keys, WA_ARRAY_LENGTH(cryptoconf_keys), location));
    if (wa_value_find_map_value(cryptoconf, "payload_plaintext_signatures") != NULL) {
        WA_RETURN_IF_ERROR(wa_validate_signature_list(cryptoconf, "payload_plaintext_signatures", location));
    }
    payload_cipher_layers = wa_value_find_map_value(cryptoconf, "payload_cipher_layers");
    previous_length =
        wa_error_location_path_push_key(location, "payload_cipher_layers", strlen("payload_cipher_layers"));
    if (payload_cipher_layers == NULL || wa_value_get_type(payload_cipher_layers) != WA_VALUE_TYPE_ARRAY ||
        wa_value_get_item_count(payload_cipher_layers) == 0) {
        return WA_STATUS_INVALID_PROFILE;
    }
    for (layer_index = 0; layer_index < wa_value_get_item_count(payload_cipher_layers); ++layer_index) {
        size_t layer_previous_length = wa_error_location_path_push_index(location, layer_index);
        WA_RETURN_IF_ERROR(
            wa_validate_payload_cipher_layer(wa_value_get_array_item(payload_cipher_layers, layer_index), location));
        wa_error_location_path_pop(location, layer_previous_length);
    }
    wa_error_location_path_pop(location, previous_length);
    /* Optional in wacryptolib, mandatory here (design D9) */
    return wa_check_typed_value(cryptoconf, "keychain_uid", 1, WA_VALUE_TYPE_UUID, location);
}
