/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_hpke_base_mode_seal.h"

#include <string.h>

#include "core/wa_platform_hooks_calls.h"
#include "encoding/wa_value_tree_internal.h"
#include "primitives/wa_secure_memory_wipe.h"

static const uint8_t wa_hpke_version_label[7] = {'H', 'P', 'K', 'E', '-', 'v', '1'};

#define WA_HPKE_MODE_BASE 0x00u

wa_status_t wa_hpke_labeled_extract(const uint8_t *suite_id, size_t suite_id_length, const uint8_t *salt,
                                    size_t salt_length, const char *label, const uint8_t *ikm, size_t ikm_length,
                                    uint8_t prk[WA_HKDF_SHA256_PRK_SIZE])
{
    wa_byte_span_t parts[4];
    parts[0].bytes = wa_hpke_version_label;
    parts[0].length = sizeof(wa_hpke_version_label);
    parts[1].bytes = suite_id;
    parts[1].length = suite_id_length;
    parts[2].bytes = (const uint8_t *)label;
    parts[2].length = strlen(label);
    parts[3].bytes = ikm;
    parts[3].length = ikm_length;
    return wa_hkdf_sha256_extract(salt, salt_length, parts, 4, prk);
}

wa_status_t wa_hpke_labeled_expand(const uint8_t *suite_id, size_t suite_id_length,
                                   const uint8_t prk[WA_HKDF_SHA256_PRK_SIZE], const char *label, const uint8_t *info,
                                   size_t info_length, uint8_t *output, size_t output_length)
{
    uint8_t length_bytes[2];
    wa_byte_span_t parts[5];
    if (output_length > 0xffffu) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    length_bytes[0] = (uint8_t)(output_length >> 8);
    length_bytes[1] = (uint8_t)output_length;
    parts[0].bytes = length_bytes;
    parts[0].length = sizeof(length_bytes);
    parts[1].bytes = wa_hpke_version_label;
    parts[1].length = sizeof(wa_hpke_version_label);
    parts[2].bytes = suite_id;
    parts[2].length = suite_id_length;
    parts[3].bytes = (const uint8_t *)label;
    parts[3].length = strlen(label);
    parts[4].bytes = info;
    parts[4].length = info_length;
    return wa_hkdf_sha256_expand(prk, parts, 5, output, output_length);
}

wa_status_t wa_hpke_base_mode_key_schedule(uint16_t kem_id, const uint8_t shared_secret[WA_HPKE_SHARED_SECRET_SIZE],
                                           const uint8_t *info, size_t info_length, uint8_t key[WA_HPKE_KEY_SIZE],
                                           uint8_t base_nonce[WA_HPKE_NONCE_SIZE])
{
    uint8_t suite_id[WA_HPKE_SUITE_ID_SIZE] = {'H', 'P', 'K', 'E', 0, 0, 0, 0, 0, 0};
    /* key_schedule_context = mode || psk_id_hash || info_hash */
    uint8_t key_schedule_context[1u + 2u * WA_HKDF_SHA256_PRK_SIZE];
    uint8_t secret[WA_HKDF_SHA256_PRK_SIZE];
    wa_status_t status;
    suite_id[4] = (uint8_t)(kem_id >> 8);
    suite_id[5] = (uint8_t)kem_id;
    suite_id[6] = (uint8_t)(WA_HPKE_KDF_ID_HKDF_SHA256 >> 8);
    suite_id[7] = (uint8_t)WA_HPKE_KDF_ID_HKDF_SHA256;
    suite_id[8] = (uint8_t)(WA_HPKE_AEAD_ID_CHACHA20_POLY1305 >> 8);
    suite_id[9] = (uint8_t)WA_HPKE_AEAD_ID_CHACHA20_POLY1305;
    key_schedule_context[0] = WA_HPKE_MODE_BASE;
    status = wa_hpke_labeled_extract(suite_id, sizeof(suite_id), NULL, 0, "psk_id_hash", NULL, 0,
                                     key_schedule_context + 1);
    if (status == WA_STATUS_OK) {
        status = wa_hpke_labeled_extract(suite_id, sizeof(suite_id), NULL, 0, "info_hash", info, info_length,
                                         key_schedule_context + 1 + WA_HKDF_SHA256_PRK_SIZE);
    }
    if (status == WA_STATUS_OK) {
        /* secret = LabeledExtract(shared_secret, "secret", psk = "") */
        status = wa_hpke_labeled_extract(suite_id, sizeof(suite_id), shared_secret, WA_HPKE_SHARED_SECRET_SIZE,
                                         "secret", NULL, 0, secret);
    }
    if (status == WA_STATUS_OK) {
        status = wa_hpke_labeled_expand(suite_id, sizeof(suite_id), secret, "key", key_schedule_context,
                                        sizeof(key_schedule_context), key, WA_HPKE_KEY_SIZE);
    }
    if (status == WA_STATUS_OK) {
        status = wa_hpke_labeled_expand(suite_id, sizeof(suite_id), secret, "base_nonce", key_schedule_context,
                                        sizeof(key_schedule_context), base_nonce, WA_HPKE_NONCE_SIZE);
    }
    wa_secure_memory_wipe(secret, sizeof(secret));
    if (status != WA_STATUS_OK) {
        wa_secure_memory_wipe(key, WA_HPKE_KEY_SIZE);
        wa_secure_memory_wipe(base_nonce, WA_HPKE_NONCE_SIZE);
    }
    return status;
}

wa_status_t wa_hpke_base_mode_seal(const wa_platform_hooks_t *platform_hooks, const wa_hpke_kem_t *kem,
                                   const uint8_t *public_key, const uint8_t *info, size_t info_length,
                                   const uint8_t *aad, size_t aad_length, const uint8_t *plaintext,
                                   size_t plaintext_length, uint8_t *enc, uint8_t *sealed)
{
    uint8_t shared_secret[WA_HPKE_SHARED_SECRET_SIZE];
    uint8_t key[WA_HPKE_KEY_SIZE];
    uint8_t base_nonce[WA_HPKE_NONCE_SIZE];
    wa_crypto_backend_chacha20_poly1305_t *aead = NULL;
    wa_status_t status;
    status = kem->encapsulate(platform_hooks, public_key, enc, shared_secret);
    if (status == WA_STATUS_OK) {
        status = wa_hpke_base_mode_key_schedule(kem->kem_id, shared_secret, info, info_length, key, base_nonce);
    }
    wa_secure_memory_wipe(shared_secret, sizeof(shared_secret));
    /* Sequence number 0: the nonce is the base nonce */
    if (status == WA_STATUS_OK) {
        status = wa_crypto_backend_chacha20_poly1305_create(platform_hooks, key, base_nonce, aad, aad_length, &aead);
    }
    wa_secure_memory_wipe(key, sizeof(key));
    wa_secure_memory_wipe(base_nonce, sizeof(base_nonce));
    if (status == WA_STATUS_OK) {
        status = wa_crypto_backend_chacha20_poly1305_encrypt(aead, plaintext, sealed, plaintext_length);
    }
    if (status == WA_STATUS_OK) {
        status = wa_crypto_backend_chacha20_poly1305_finish(aead, sealed + plaintext_length);
    }
    wa_crypto_backend_chacha20_poly1305_destroy(aead);
    return status;
}

/* Add `key` -> a bytes node taking over `block` (`length` bytes); the block is released by the caller on failure */
static wa_status_t wa_add_bytes_block_entry(const wa_platform_hooks_t *platform_hooks, wa_value_t *map,
                                            const char *key, uint8_t **block, size_t length)
{
    wa_value_t *value = NULL;
    wa_status_t status = wa_value_create_bytes_from_allocated_block(platform_hooks, *block, length, length, &value);
    if (status != WA_STATUS_OK) {
        return status;
    }
    *block = NULL; /* Owned by the node, even if the map refuses it (then destroyed with it) */
    return wa_value_map_add_consuming(map, key, value);
}

wa_status_t wa_hpke_base_mode_seal_to_cipherdict(const wa_platform_hooks_t *platform_hooks, const wa_hpke_kem_t *kem,
                                                 const uint8_t *public_key, const uint8_t *plaintext,
                                                 size_t plaintext_length, wa_value_t **cipherdict_out)
{
    wa_value_t *cipherdict = NULL;
    uint8_t *enc = NULL;
    uint8_t *sealed = NULL;
    size_t sealed_length;
    wa_status_t status;
    *cipherdict_out = NULL;
    if (plaintext_length > (size_t)-1 - WA_AEAD_TAG_SIZE) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    sealed_length = plaintext_length + WA_AEAD_TAG_SIZE;
    enc = (uint8_t *)wa_allocate_memory(platform_hooks, kem->enc_length);
    sealed = (uint8_t *)wa_allocate_memory(platform_hooks, sealed_length);
    status = enc != NULL && sealed != NULL ? WA_STATUS_OK : WA_STATUS_OUT_OF_MEMORY;
    if (status == WA_STATUS_OK) {
        status = wa_hpke_base_mode_seal(platform_hooks, kem, public_key, NULL, 0, NULL, 0, plaintext,
                                        plaintext_length, enc, sealed);
    }
    if (status == WA_STATUS_OK) {
        status = wa_value_create_map(platform_hooks, &cipherdict);
    }
    if (status == WA_STATUS_OK) {
        status = wa_add_bytes_block_entry(platform_hooks, cipherdict, "kem_ciphertext", &enc, kem->enc_length);
    }
    if (status == WA_STATUS_OK) {
        status = wa_add_bytes_block_entry(platform_hooks, cipherdict, "ciphertext", &sealed, sealed_length);
    }
    /* The sealed block may hold plaintext after a failure in the middle of the AEAD */
    wa_release_memory(platform_hooks, enc, kem->enc_length);
    wa_release_secret_memory(platform_hooks, sealed, sealed_length);
    if (status != WA_STATUS_OK) {
        wa_value_destroy(cipherdict);
        return status;
    }
    *cipherdict_out = cipherdict;
    return WA_STATUS_OK;
}
