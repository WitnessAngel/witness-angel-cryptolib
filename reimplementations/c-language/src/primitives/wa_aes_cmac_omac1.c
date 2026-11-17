/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_aes_cmac_omac1.h"

#include <string.h>

#include "primitives/wa_secure_memory_wipe.h"

/* Whole blocks are passed to the backend in pieces of this size, the CBC output going to a stack scratch buffer */
#define WA_AES_CMAC_SCRATCH_SIZE 256u

/* Multiply by x in GF(2^128), big-endian, reduction polynomial x^128 + x^7 + x^2 + x + 1, in constant time */
static void wa_cmac_double_subkey(const uint8_t input[WA_AES_BLOCK_SIZE], uint8_t output[WA_AES_BLOCK_SIZE])
{
    uint8_t carry_mask = (uint8_t)(0u - (unsigned)(input[0] >> 7));
    size_t index;
    for (index = 0; index < WA_AES_BLOCK_SIZE - 1; ++index) {
        output[index] = (uint8_t)((input[index] << 1) | (input[index + 1] >> 7));
    }
    output[WA_AES_BLOCK_SIZE - 1] = (uint8_t)(((unsigned)input[WA_AES_BLOCK_SIZE - 1] << 1) ^ (0x87u & carry_mask));
}

/* CBC-MAC the given whole blocks into the chaining value */
static wa_status_t wa_cmac_process_blocks(wa_aes_cmac_t *cmac, const uint8_t *blocks, size_t length)
{
    uint8_t scratch[WA_AES_CMAC_SCRATCH_SIZE];
    wa_status_t status = WA_STATUS_OK;
    while (length > 0 && status == WA_STATUS_OK) {
        size_t piece_length = length < sizeof(scratch) ? length : sizeof(scratch);
        status = wa_crypto_backend_aes_256_encrypt_cbc_blocks(cmac->aes, cmac->chaining_value, blocks, scratch,
                                                             piece_length);
        blocks += piece_length;
        length -= piece_length;
    }
    wa_secure_memory_wipe(scratch, sizeof(scratch));
    return status;
}

wa_status_t wa_aes_cmac_start(wa_aes_cmac_t *cmac, wa_crypto_backend_aes_256_t *aes)
{
    uint8_t encrypted_zero_block[WA_AES_BLOCK_SIZE];
    wa_status_t status;
    memset(cmac, 0, sizeof(*cmac));
    cmac->aes = aes;
    /* L = E_K(0^128): the CBC encryption of a zero block with a zero IV */
    memset(encrypted_zero_block, 0, sizeof(encrypted_zero_block));
    status = wa_crypto_backend_aes_256_encrypt_cbc_blocks(aes, cmac->chaining_value, encrypted_zero_block,
                                                         encrypted_zero_block, WA_AES_BLOCK_SIZE);
    if (status == WA_STATUS_OK) {
        wa_cmac_double_subkey(encrypted_zero_block, cmac->subkey_1);
        wa_cmac_double_subkey(cmac->subkey_1, cmac->subkey_2);
    }
    memset(cmac->chaining_value, 0, sizeof(cmac->chaining_value)); /* The MAC itself starts from a zero IV */
    wa_secure_memory_wipe(encrypted_zero_block, sizeof(encrypted_zero_block));
    if (status != WA_STATUS_OK) {
        wa_aes_cmac_wipe(cmac);
    }
    return status;
}

wa_status_t wa_aes_cmac_update(wa_aes_cmac_t *cmac, const uint8_t *data, size_t length)
{
    size_t bulk_length;
    size_t fill_length;
    wa_status_t status;
    if (length == 0) {
        return WA_STATUS_OK;
    }
    fill_length = WA_AES_BLOCK_SIZE - cmac->pending_length;
    if (fill_length > length) {
        fill_length = length;
    }
    memcpy(cmac->pending_block + cmac->pending_length, data, fill_length);
    cmac->pending_length += fill_length;
    data += fill_length;
    length -= fill_length;
    if (length == 0) {
        return WA_STATUS_OK; /* The pending block may be the last one */
    }
    /* More data follows: the full pending block is not the last one */
    status = wa_cmac_process_blocks(cmac, cmac->pending_block, WA_AES_BLOCK_SIZE);
    if (status != WA_STATUS_OK) {
        return status;
    }
    /* Whole blocks in bulk, keeping back the last 1..16 bytes */
    bulk_length = ((length - 1u) / WA_AES_BLOCK_SIZE) * WA_AES_BLOCK_SIZE;
    status = wa_cmac_process_blocks(cmac, data, bulk_length);
    if (status != WA_STATUS_OK) {
        return status;
    }
    cmac->pending_length = length - bulk_length;
    memcpy(cmac->pending_block, data + bulk_length, cmac->pending_length);
    return WA_STATUS_OK;
}

wa_status_t wa_aes_cmac_finish(wa_aes_cmac_t *cmac, uint8_t mac[WA_AES_CMAC_SIZE])
{
    const uint8_t *subkey;
    size_t index;
    wa_status_t status;
    if (cmac->pending_length == WA_AES_BLOCK_SIZE) {
        subkey = cmac->subkey_1; /* Complete final block */
    } else {
        /* Incomplete (or empty) final block: 10* padding */
        cmac->pending_block[cmac->pending_length] = 0x80;
        memset(cmac->pending_block + cmac->pending_length + 1, 0, WA_AES_BLOCK_SIZE - cmac->pending_length - 1);
        subkey = cmac->subkey_2;
    }
    for (index = 0; index < WA_AES_BLOCK_SIZE; ++index) {
        cmac->pending_block[index] ^= subkey[index];
    }
    status = wa_cmac_process_blocks(cmac, cmac->pending_block, WA_AES_BLOCK_SIZE);
    if (status == WA_STATUS_OK) {
        memcpy(mac, cmac->chaining_value, WA_AES_CMAC_SIZE);
    }
    wa_aes_cmac_wipe(cmac);
    return status;
}

void wa_aes_cmac_wipe(wa_aes_cmac_t *cmac)
{
    wa_secure_memory_wipe(cmac, sizeof(*cmac));
}

wa_status_t wa_aes_cmac_start_omac_with_tweak(wa_aes_cmac_t *cmac, wa_crypto_backend_aes_256_t *aes, uint8_t tweak)
{
    uint8_t tweak_block[WA_AES_BLOCK_SIZE];
    wa_status_t status = wa_aes_cmac_start(cmac, aes);
    if (status != WA_STATUS_OK) {
        return status;
    }
    memset(tweak_block, 0, sizeof(tweak_block));
    tweak_block[WA_AES_BLOCK_SIZE - 1] = tweak;
    status = wa_aes_cmac_update(cmac, tweak_block, sizeof(tweak_block));
    if (status != WA_STATUS_OK) {
        wa_aes_cmac_wipe(cmac);
    }
    return status;
}
