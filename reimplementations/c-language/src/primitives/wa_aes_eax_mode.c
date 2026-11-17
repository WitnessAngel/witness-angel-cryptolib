/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_aes_eax_mode.h"

#include <string.h>

#include "primitives/wa_secure_memory_wipe.h"

/* OMAC^t of a whole message */
static wa_status_t wa_eax_compute_omac(wa_crypto_backend_aes_256_t *aes, uint8_t tweak, const uint8_t *data,
                                       size_t length, uint8_t mac[WA_AES_CMAC_SIZE])
{
    wa_aes_cmac_t cmac;
    wa_status_t status = wa_aes_cmac_start_omac_with_tweak(&cmac, aes, tweak);
    if (status == WA_STATUS_OK) {
        status = wa_aes_cmac_update(&cmac, data, length);
    }
    if (status == WA_STATUS_OK) {
        return wa_aes_cmac_finish(&cmac, mac);
    }
    wa_aes_cmac_wipe(&cmac);
    return status;
}

wa_status_t wa_aes_eax_encryption_start(const wa_platform_hooks_t *platform_hooks, const uint8_t key[WA_AES_256_KEY_SIZE],
                                        const uint8_t *nonce, size_t nonce_length,
                                        wa_aes_eax_encryption_t *encryption)
{
    uint8_t header_omac[WA_AES_CMAC_SIZE];
    size_t index;
    wa_status_t status;
    memset(encryption, 0, sizeof(*encryption));
    encryption->keystream_used_length = WA_AES_BLOCK_SIZE;
    status = wa_crypto_backend_aes_256_create(platform_hooks, key, &encryption->aes);
    if (status == WA_STATUS_OK) {
        /* N = OMAC0(nonce), the initial counter */
        status = wa_eax_compute_omac(encryption->aes, 0, nonce, nonce_length, encryption->counter_block);
    }
    if (status == WA_STATUS_OK) {
        /* H = OMAC1(empty header) */
        status = wa_eax_compute_omac(encryption->aes, 1, NULL, 0, header_omac);
    }
    if (status == WA_STATUS_OK) {
        for (index = 0; index < WA_AES_BLOCK_SIZE; ++index) {
            encryption->nonce_and_header_omacs[index] = (uint8_t)(encryption->counter_block[index] ^ header_omac[index]);
        }
        status = wa_aes_cmac_start_omac_with_tweak(&encryption->ciphertext_omac, encryption->aes, 2);
    }
    wa_secure_memory_wipe(header_omac, sizeof(header_omac));
    if (status != WA_STATUS_OK) {
        wa_aes_eax_encryption_release(encryption);
    }
    return status;
}

wa_status_t wa_aes_eax_encryption_update(wa_aes_eax_encryption_t *encryption, const uint8_t *input, uint8_t *output,
                                         size_t length)
{
    uint8_t *ciphertext = output;
    size_t ciphertext_length = length;
    size_t bulk_length;
    size_t offset = 0;
    wa_status_t status;
    /* Rest of the previous keystream block */
    while (offset < length && encryption->keystream_used_length < WA_AES_BLOCK_SIZE) {
        output[offset] = (uint8_t)(input[offset] ^ encryption->keystream_block[encryption->keystream_used_length++]);
        ++offset;
    }
    /* Whole blocks in bulk */
    bulk_length = ((length - offset) / WA_AES_BLOCK_SIZE) * WA_AES_BLOCK_SIZE;
    status = wa_crypto_backend_aes_256_encrypt_ctr_blocks(encryption->aes, encryption->counter_block, input + offset,
                                                         output + offset, bulk_length);
    if (status != WA_STATUS_OK) {
        return status;
    }
    offset += bulk_length;
    /* Final partial block, from a fresh keystream block (the CTR encryption of zeros) */
    if (offset < length) {
        memset(encryption->keystream_block, 0, WA_AES_BLOCK_SIZE);
        status = wa_crypto_backend_aes_256_encrypt_ctr_blocks(encryption->aes, encryption->counter_block,
                                                             encryption->keystream_block,
                                                             encryption->keystream_block, WA_AES_BLOCK_SIZE);
        if (status != WA_STATUS_OK) {
            return status;
        }
        encryption->keystream_used_length = 0;
        while (offset < length) {
            output[offset] = (uint8_t)(input[offset] ^ encryption->keystream_block[encryption->keystream_used_length++]);
            ++offset;
        }
    }
    return wa_aes_cmac_update(&encryption->ciphertext_omac, ciphertext, ciphertext_length);
}

wa_status_t wa_aes_eax_encryption_finish(wa_aes_eax_encryption_t *encryption, uint8_t tag[WA_AES_EAX_TAG_SIZE])
{
    uint8_t ciphertext_omac[WA_AES_CMAC_SIZE];
    size_t index;
    wa_status_t status = wa_aes_cmac_finish(&encryption->ciphertext_omac, ciphertext_omac);
    if (status == WA_STATUS_OK) {
        for (index = 0; index < WA_AES_EAX_TAG_SIZE; ++index) {
            tag[index] = (uint8_t)(encryption->nonce_and_header_omacs[index] ^ ciphertext_omac[index]);
        }
    }
    wa_secure_memory_wipe(ciphertext_omac, sizeof(ciphertext_omac));
    return status;
}

void wa_aes_eax_encryption_release(wa_aes_eax_encryption_t *encryption)
{
    wa_crypto_backend_aes_256_destroy(encryption->aes);
    wa_secure_memory_wipe(encryption, sizeof(*encryption));
}
