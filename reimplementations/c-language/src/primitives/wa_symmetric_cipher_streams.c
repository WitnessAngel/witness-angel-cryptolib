/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_symmetric_cipher_streams.h"

#include <string.h>

#include "core/wa_platform_hooks_calls.h"
#include "encoding/wa_value_tree_internal.h"
#include "primitives/wa_aes_cbc_pkcs7_padding.h"
#include "primitives/wa_secure_memory_wipe.h"

wa_status_t wa_symmetric_cipher_stream_start(const wa_platform_hooks_t *platform_hooks, const wa_symkey_t *symkey,
                                             wa_symmetric_cipher_stream_t *stream)
{
    wa_status_t status;
    memset(stream, 0, sizeof(*stream));
    stream->cipher_algo = symkey->cipher_algo;
    switch (symkey->cipher_algo) {
    case WA_SYMMETRIC_CIPHER_AES_CBC:
        if (symkey->iv_or_nonce_length != WA_AES_BLOCK_SIZE) {
            return WA_STATUS_INVALID_ARGUMENT;
        }
        memcpy(stream->state.aes_cbc.chaining_value, symkey->iv_or_nonce, WA_AES_BLOCK_SIZE);
        status = wa_crypto_backend_aes_256_create(platform_hooks, symkey->key, &stream->state.aes_cbc.aes);
        break;
    case WA_SYMMETRIC_CIPHER_AES_EAX:
        status = wa_aes_eax_encryption_start(platform_hooks, symkey->key, symkey->iv_or_nonce,
                                             symkey->iv_or_nonce_length, &stream->state.aes_eax);
        break;
    case WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305:
        if (symkey->iv_or_nonce_length != WA_CHACHA20_POLY1305_NONCE_SIZE) {
            return WA_STATUS_INVALID_ARGUMENT;
        }
        status = wa_crypto_backend_chacha20_poly1305_create(platform_hooks, symkey->key, symkey->iv_or_nonce, NULL, 0,
                                                            &stream->state.chacha20_poly1305);
        break;
    default:
        return WA_STATUS_INVALID_ARGUMENT;
    }
    if (status != WA_STATUS_OK) {
        wa_symmetric_cipher_stream_release(platform_hooks, stream);
    }
    return status;
}

static wa_status_t wa_aes_cbc_stream_encrypt(wa_symmetric_cipher_stream_t *stream, const uint8_t *input,
                                             size_t length, uint8_t *output, size_t *output_length)
{
    size_t fill_length;
    size_t bulk_length;
    wa_status_t status;
    *output_length = 0;
    if (length == 0) {
        return WA_STATUS_OK; /* Nothing to do, and `input` may then be NULL, which memcpy() does not accept */
    }
    /* Complete the pending block first */
    if (stream->state.aes_cbc.pending_length > 0) {
        fill_length = WA_AES_BLOCK_SIZE - stream->state.aes_cbc.pending_length;
        if (fill_length > length) {
            fill_length = length;
        }
        memcpy(stream->state.aes_cbc.pending_block + stream->state.aes_cbc.pending_length, input, fill_length);
        stream->state.aes_cbc.pending_length += fill_length;
        input += fill_length;
        length -= fill_length;
        if (stream->state.aes_cbc.pending_length < WA_AES_BLOCK_SIZE) {
            return WA_STATUS_OK;
        }
        status = wa_crypto_backend_aes_256_encrypt_cbc_blocks(stream->state.aes_cbc.aes,
                                                             stream->state.aes_cbc.chaining_value,
                                                             stream->state.aes_cbc.pending_block, output,
                                                             WA_AES_BLOCK_SIZE);
        if (status != WA_STATUS_OK) {
            return status;
        }
        stream->state.aes_cbc.pending_length = 0;
        output += WA_AES_BLOCK_SIZE;
        *output_length += WA_AES_BLOCK_SIZE;
    }
    /* Whole blocks in bulk (PKCS#7 always adds a block, so a full last block needs not be kept back) */
    bulk_length = (length / WA_AES_BLOCK_SIZE) * WA_AES_BLOCK_SIZE;
    status = wa_crypto_backend_aes_256_encrypt_cbc_blocks(stream->state.aes_cbc.aes, stream->state.aes_cbc.chaining_value,
                                                         input, output, bulk_length);
    if (status != WA_STATUS_OK) {
        return status;
    }
    *output_length += bulk_length;
    stream->state.aes_cbc.pending_length = length - bulk_length;
    memcpy(stream->state.aes_cbc.pending_block, input + bulk_length, stream->state.aes_cbc.pending_length);
    return WA_STATUS_OK;
}

wa_status_t wa_symmetric_cipher_stream_encrypt(wa_symmetric_cipher_stream_t *stream, const uint8_t *input,
                                               size_t length, uint8_t *output, size_t *output_length)
{
    wa_status_t status;
    *output_length = 0;
    switch (stream->cipher_algo) {
    case WA_SYMMETRIC_CIPHER_AES_CBC:
        return wa_aes_cbc_stream_encrypt(stream, input, length, output, output_length);
    case WA_SYMMETRIC_CIPHER_AES_EAX:
        status = wa_aes_eax_encryption_update(&stream->state.aes_eax, input, output, length);
        break;
    case WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305:
        status = wa_crypto_backend_chacha20_poly1305_encrypt(stream->state.chacha20_poly1305, input, output, length);
        break;
    default:
        return WA_STATUS_INTERNAL_ERROR;
    }
    if (status == WA_STATUS_OK) {
        *output_length = length;
    }
    return status;
}

wa_status_t wa_symmetric_cipher_stream_finish(wa_symmetric_cipher_stream_t *stream,
                                              uint8_t final_output[WA_AES_BLOCK_SIZE], size_t *final_output_length,
                                              uint8_t tag[WA_SYMMETRIC_TAG_SIZE], size_t *tag_length_out)
{
    wa_status_t status;
    *final_output_length = 0;
    *tag_length_out = 0;
    switch (stream->cipher_algo) {
    case WA_SYMMETRIC_CIPHER_AES_CBC:
        wa_pkcs7_pad_final_block(stream->state.aes_cbc.pending_block, stream->state.aes_cbc.pending_length);
        status = wa_crypto_backend_aes_256_encrypt_cbc_blocks(stream->state.aes_cbc.aes,
                                                             stream->state.aes_cbc.chaining_value,
                                                             stream->state.aes_cbc.pending_block, final_output,
                                                             WA_AES_BLOCK_SIZE);
        wa_secure_memory_wipe(stream->state.aes_cbc.pending_block, WA_AES_BLOCK_SIZE);
        stream->state.aes_cbc.pending_length = 0;
        if (status == WA_STATUS_OK) {
            *final_output_length = WA_AES_BLOCK_SIZE;
        }
        return status;
    case WA_SYMMETRIC_CIPHER_AES_EAX:
        status = wa_aes_eax_encryption_finish(&stream->state.aes_eax, tag);
        break;
    case WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305:
        status = wa_crypto_backend_chacha20_poly1305_finish(stream->state.chacha20_poly1305, tag);
        break;
    default:
        return WA_STATUS_INTERNAL_ERROR;
    }
    if (status == WA_STATUS_OK) {
        *tag_length_out = WA_SYMMETRIC_TAG_SIZE;
    }
    return status;
}

void wa_symmetric_cipher_stream_release(const wa_platform_hooks_t *platform_hooks, wa_symmetric_cipher_stream_t *stream)
{
    (void)platform_hooks; /* Backend contexts know their hooks */
    switch (stream->cipher_algo) {
    case WA_SYMMETRIC_CIPHER_AES_CBC:
        wa_crypto_backend_aes_256_destroy(stream->state.aes_cbc.aes);
        break;
    case WA_SYMMETRIC_CIPHER_AES_EAX:
        wa_aes_eax_encryption_release(&stream->state.aes_eax);
        break;
    case WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305:
        wa_crypto_backend_chacha20_poly1305_destroy(stream->state.chacha20_poly1305);
        break;
    default:
        break;
    }
    wa_secure_memory_wipe(stream, sizeof(*stream));
}

static wa_status_t wa_add_bytes_entry(const wa_platform_hooks_t *platform_hooks, wa_value_t *map, const char *key,
                                      const uint8_t *bytes, size_t length)
{
    wa_value_t *value = NULL;
    wa_status_t status = wa_value_create_bytes(platform_hooks, bytes, length, &value);
    if (status != WA_STATUS_OK) {
        return status;
    }
    return wa_value_map_add_consuming(map, key, value);
}

wa_status_t wa_symmetric_encrypt_to_cipherdict(const wa_platform_hooks_t *platform_hooks, const wa_symkey_t *symkey,
                                               const uint8_t *plaintext, size_t plaintext_length,
                                               wa_value_t **cipherdict_out)
{
    wa_symmetric_cipher_stream_t stream;
    wa_value_t *cipherdict = NULL;
    wa_value_t *ciphertext_value = NULL;
    uint8_t tag[WA_SYMMETRIC_TAG_SIZE];
    uint8_t *ciphertext;
    size_t capacity;
    size_t ciphertext_length = 0;
    size_t final_output_length = 0;
    size_t tag_length = 0;
    wa_status_t status;
    *cipherdict_out = NULL;
    if (plaintext_length > (size_t)-1 - WA_SYMMETRIC_CIPHER_STREAM_MAXIMUM_EXTRA_OUTPUT) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    /* The exact ciphertext length, so that the bytes node takes the block over without a copy (a fresh stream
     * outputs whole blocks then the padding block for AES_CBC, as many bytes as the input for the others) */
    capacity = plaintext_length;
    if (symkey->cipher_algo == WA_SYMMETRIC_CIPHER_AES_CBC) {
        capacity += wa_pkcs7_get_padding_length(plaintext_length);
    }
    if (capacity == 0) {
        capacity = 1; /* No zero-size allocation */
    }
    ciphertext = (uint8_t *)wa_allocate_memory(platform_hooks, capacity);
    if (ciphertext == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    status = wa_symmetric_cipher_stream_start(platform_hooks, symkey, &stream);
    if (status == WA_STATUS_OK) {
        status = wa_symmetric_cipher_stream_encrypt(&stream, plaintext, plaintext_length, ciphertext,
                                                    &ciphertext_length);
        if (status == WA_STATUS_OK) {
            status = wa_symmetric_cipher_stream_finish(&stream, ciphertext + ciphertext_length, &final_output_length,
                                                       tag, &tag_length);
            ciphertext_length += final_output_length;
        }
        wa_symmetric_cipher_stream_release(platform_hooks, &stream);
    }
    if (status == WA_STATUS_OK) {
        status = wa_value_create_map(platform_hooks, &cipherdict);
    }
    if (status == WA_STATUS_OK) {
        status = wa_value_create_bytes_from_allocated_block(platform_hooks, ciphertext, ciphertext_length, capacity, 0,
                                                            &ciphertext_value);
        if (status == WA_STATUS_OK) {
            ciphertext = NULL; /* Owned by the node */
            status = wa_value_map_add_consuming(cipherdict, "ciphertext", ciphertext_value);
        }
    }
    if (status == WA_STATUS_OK && tag_length > 0) {
        status = wa_add_bytes_entry(platform_hooks, cipherdict, "tag", tag, tag_length);
    }
    wa_release_secret_memory(platform_hooks, ciphertext, capacity);
    if (status != WA_STATUS_OK) {
        wa_value_destroy(cipherdict);
        return status;
    }
    *cipherdict_out = cipherdict;
    return WA_STATUS_OK;
}

wa_status_t wa_symmetric_build_payload_macs(const wa_platform_hooks_t *platform_hooks,
                                            wa_symmetric_cipher_algo_t cipher_algo, const uint8_t *tag,
                                            size_t tag_length, wa_value_t **payload_macs_out)
{
    wa_value_t *payload_macs = NULL;
    wa_status_t status;
    *payload_macs_out = NULL;
    if (wa_symmetric_cipher_algo_get_name(cipher_algo) == NULL ||
        tag_length != (wa_symmetric_cipher_algo_has_tag(cipher_algo) ? WA_SYMMETRIC_TAG_SIZE : 0u)) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    status = wa_value_create_map(platform_hooks, &payload_macs);
    if (status == WA_STATUS_OK && tag_length > 0) {
        status = wa_add_bytes_entry(platform_hooks, payload_macs, "tag", tag, tag_length);
    }
    if (status != WA_STATUS_OK) {
        wa_value_destroy(payload_macs);
        return status;
    }
    *payload_macs_out = payload_macs;
    return WA_STATUS_OK;
}
