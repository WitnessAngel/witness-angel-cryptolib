/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_aes_cbc_pkcs7_padding.h"

#include <string.h>

size_t wa_pkcs7_get_padding_length(size_t data_length)
{
    return WA_PKCS7_BLOCK_SIZE - (data_length % WA_PKCS7_BLOCK_SIZE);
}

void wa_pkcs7_pad_final_block(uint8_t block[WA_PKCS7_BLOCK_SIZE], size_t data_length_in_block)
{
    size_t padding_length = WA_PKCS7_BLOCK_SIZE - (data_length_in_block % WA_PKCS7_BLOCK_SIZE);
    memset(block + (WA_PKCS7_BLOCK_SIZE - padding_length), (int)padding_length, padding_length);
}
