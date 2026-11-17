/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_symmetric_key_generation.h"

#include <string.h>

#include "core/wa_platform_hooks_calls.h"
#include "encoding/wa_value_tree_internal.h"
#include "primitives/wa_secure_memory_wipe.h"

typedef struct wa_symmetric_cipher_algo_descriptor {
    wa_symmetric_cipher_algo_t cipher_algo;
    const char *name;
    const char *iv_or_nonce_field_name;
    size_t iv_or_nonce_length;
    int has_tag;
} wa_symmetric_cipher_algo_descriptor_t;

/* Sections 3.3 and 3.4 */
static const wa_symmetric_cipher_algo_descriptor_t wa_symmetric_cipher_algo_descriptors[] = {
    {WA_SYMMETRIC_CIPHER_AES_CBC, "AES_CBC", "iv", 16, 0},
    {WA_SYMMETRIC_CIPHER_AES_EAX, "AES_EAX", "nonce", 16, 1},
    {WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305, "CHACHA20_POLY1305", "nonce", 12, 1},
};

#define WA_SYMMETRIC_CIPHER_ALGO_COUNT \
    (sizeof(wa_symmetric_cipher_algo_descriptors) / sizeof(wa_symmetric_cipher_algo_descriptors[0]))

static const wa_symmetric_cipher_algo_descriptor_t *wa_find_symmetric_cipher_algo(
    wa_symmetric_cipher_algo_t cipher_algo)
{
    size_t index;
    for (index = 0; index < WA_SYMMETRIC_CIPHER_ALGO_COUNT; ++index) {
        if (wa_symmetric_cipher_algo_descriptors[index].cipher_algo == cipher_algo) {
            return &wa_symmetric_cipher_algo_descriptors[index];
        }
    }
    return NULL;
}

int wa_symmetric_cipher_algo_from_name(const char *name, size_t name_length, wa_symmetric_cipher_algo_t *algo_out)
{
    size_t index;
    for (index = 0; index < WA_SYMMETRIC_CIPHER_ALGO_COUNT; ++index) {
        const char *candidate = wa_symmetric_cipher_algo_descriptors[index].name;
        if (strlen(candidate) == name_length && memcmp(candidate, name, name_length) == 0) {
            *algo_out = wa_symmetric_cipher_algo_descriptors[index].cipher_algo;
            return 1;
        }
    }
    return 0;
}

const char *wa_symmetric_cipher_algo_get_name(wa_symmetric_cipher_algo_t cipher_algo)
{
    const wa_symmetric_cipher_algo_descriptor_t *descriptor = wa_find_symmetric_cipher_algo(cipher_algo);
    return descriptor != NULL ? descriptor->name : NULL;
}

const char *wa_symmetric_cipher_algo_get_iv_or_nonce_field_name(wa_symmetric_cipher_algo_t cipher_algo)
{
    const wa_symmetric_cipher_algo_descriptor_t *descriptor = wa_find_symmetric_cipher_algo(cipher_algo);
    return descriptor != NULL ? descriptor->iv_or_nonce_field_name : NULL;
}

int wa_symmetric_cipher_algo_has_tag(wa_symmetric_cipher_algo_t cipher_algo)
{
    const wa_symmetric_cipher_algo_descriptor_t *descriptor = wa_find_symmetric_cipher_algo(cipher_algo);
    return descriptor != NULL ? descriptor->has_tag : 0;
}

wa_status_t wa_symkey_generate(const wa_platform_hooks_t *platform_hooks, wa_symmetric_cipher_algo_t cipher_algo,
                               wa_symkey_t *symkey_out)
{
    const wa_symmetric_cipher_algo_descriptor_t *descriptor = wa_find_symmetric_cipher_algo(cipher_algo);
    wa_status_t status;
    memset(symkey_out, 0, sizeof(*symkey_out));
    if (descriptor == NULL) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    symkey_out->cipher_algo = cipher_algo;
    symkey_out->iv_or_nonce_length = descriptor->iv_or_nonce_length;
    status = wa_fill_random_bytes(platform_hooks, symkey_out->key, WA_SYMKEY_KEY_SIZE);
    if (status == WA_STATUS_OK) {
        status = wa_fill_random_bytes(platform_hooks, symkey_out->iv_or_nonce, symkey_out->iv_or_nonce_length);
    }
    if (status != WA_STATUS_OK) {
        wa_symkey_wipe(symkey_out);
    }
    return status;
}

wa_status_t wa_symkey_build_tree(const wa_platform_hooks_t *platform_hooks, const wa_symkey_t *symkey,
                                 wa_value_t **tree_out)
{
    const char *iv_or_nonce_field_name = wa_symmetric_cipher_algo_get_iv_or_nonce_field_name(symkey->cipher_algo);
    wa_value_t *tree = NULL;
    wa_value_t *value = NULL;
    wa_status_t status;
    *tree_out = NULL;
    if (iv_or_nonce_field_name == NULL) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    status = wa_value_create_map(platform_hooks, &tree);
    if (status == WA_STATUS_OK) {
        status = wa_value_create_bytes(platform_hooks, symkey->key, WA_SYMKEY_KEY_SIZE, &value);
        if (status == WA_STATUS_OK) {
            status = wa_value_map_add_consuming(tree, "key", value);
        }
    }
    if (status == WA_STATUS_OK) {
        status = wa_value_create_bytes(platform_hooks, symkey->iv_or_nonce, symkey->iv_or_nonce_length, &value);
        if (status == WA_STATUS_OK) {
            status = wa_value_map_add_consuming(tree, iv_or_nonce_field_name, value);
        }
    }
    if (status != WA_STATUS_OK) {
        wa_value_destroy(tree);
        return status;
    }
    *tree_out = tree;
    return WA_STATUS_OK;
}

void wa_symkey_wipe(wa_symkey_t *symkey)
{
    wa_secure_memory_wipe(symkey, sizeof(*symkey));
}
