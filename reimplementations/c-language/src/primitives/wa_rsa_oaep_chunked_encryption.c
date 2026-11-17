/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_rsa_oaep_chunked_encryption.h"

#include "backends/wa_crypto_backend.h"
#include "core/wa_platform_hooks_calls.h"
#include "encoding/wa_value_tree_internal.h"
#include "primitives/wa_rsa_oaep_sha512_padding.h"
#include "primitives/wa_secure_memory_wipe.h"

/* Encrypt one chunk into a new bytes node of `modulus_length` bytes. `encoded_message` is a scratch block. */
static wa_status_t wa_rsa_oaep_encrypt_chunk(const wa_platform_hooks_t *platform_hooks, const uint8_t *modulus,
                                             size_t modulus_length, const uint8_t *public_exponent,
                                             size_t public_exponent_length, const uint8_t *chunk,
                                             size_t chunk_length, uint8_t *encoded_message, wa_value_t **chunk_out)
{
    uint8_t seed[WA_RSA_OAEP_SEED_SIZE];
    uint8_t *ciphertext;
    wa_status_t status;
    *chunk_out = NULL;
    ciphertext = (uint8_t *)wa_allocate_memory(platform_hooks, modulus_length);
    if (ciphertext == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    status = wa_fill_random_bytes(platform_hooks, seed, sizeof(seed));
    if (status == WA_STATUS_OK) {
        status = wa_rsa_oaep_sha512_encode_padding(chunk, chunk_length, seed, encoded_message, modulus_length);
    }
    wa_secure_memory_wipe(seed, sizeof(seed));
    if (status == WA_STATUS_OK) {
        status = wa_crypto_backend_rsa_compute_public_operation(platform_hooks, modulus, modulus_length,
                                                                public_exponent, public_exponent_length,
                                                                encoded_message, ciphertext);
    }
    wa_secure_memory_wipe(encoded_message, modulus_length);
    if (status == WA_STATUS_OK) {
        status = wa_value_create_bytes_from_allocated_block(platform_hooks, ciphertext, modulus_length,
                                                            modulus_length, chunk_out);
    }
    if (status != WA_STATUS_OK) {
        wa_release_memory(platform_hooks, ciphertext, modulus_length);
    }
    return status;
}

wa_status_t wa_rsa_oaep_encrypt_into_chunks(const wa_platform_hooks_t *platform_hooks, const uint8_t *modulus,
                                            size_t modulus_length, const uint8_t *public_exponent,
                                            size_t public_exponent_length, const uint8_t *plaintext,
                                            size_t plaintext_length, wa_value_t **cipherdict_out)
{
    wa_value_t *cipherdict = NULL;
    wa_value_t *chunks = NULL;
    uint8_t *encoded_message;
    size_t offset;
    wa_status_t status;
    *cipherdict_out = NULL;
    if (modulus_length < WA_RSA_OAEP_SHA512_OVERHEAD + WA_RSA_OAEP_CHUNK_SIZE || modulus[0] == 0) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    /* Holds each chunk in OAEP-encoded form, so released wiped */
    encoded_message = (uint8_t *)wa_allocate_memory(platform_hooks, modulus_length);
    if (encoded_message == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    status = wa_value_create_map(platform_hooks, &cipherdict);
    if (status == WA_STATUS_OK) {
        status = wa_value_create_array(platform_hooks, &chunks);
        if (status == WA_STATUS_OK) {
            status = wa_value_map_add_consuming(cipherdict, "ciphertext_chunks", chunks);
        }
    }
    for (offset = 0; status == WA_STATUS_OK && offset < plaintext_length; offset += WA_RSA_OAEP_CHUNK_SIZE) {
        size_t chunk_length = plaintext_length - offset < WA_RSA_OAEP_CHUNK_SIZE ? plaintext_length - offset
                                                                                   : WA_RSA_OAEP_CHUNK_SIZE;
        wa_value_t *chunk_ciphertext = NULL;
        status = wa_rsa_oaep_encrypt_chunk(platform_hooks, modulus, modulus_length, public_exponent,
                                           public_exponent_length, plaintext + offset, chunk_length, encoded_message,
                                           &chunk_ciphertext);
        if (status == WA_STATUS_OK) {
            status = wa_value_array_append(chunks, chunk_ciphertext);
            if (status != WA_STATUS_OK) {
                wa_value_destroy(chunk_ciphertext);
            }
        }
    }
    wa_release_secret_memory(platform_hooks, encoded_message, modulus_length);
    if (status != WA_STATUS_OK) {
        wa_value_destroy(cipherdict);
        return status;
    }
    *cipherdict_out = cipherdict;
    return WA_STATUS_OK;
}
