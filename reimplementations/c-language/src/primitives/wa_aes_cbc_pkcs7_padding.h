/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* PKCS#7 padding to 16-byte blocks (encryptor specification, sections 3.4 and 3.7): always 1 to 16 bytes, a full
 * block when the data length is already a multiple of 16. */

#ifndef WA_AES_CBC_PKCS7_PADDING_H
#define WA_AES_CBC_PKCS7_PADDING_H

#include <stddef.h>
#include <stdint.h>

#define WA_PKCS7_BLOCK_SIZE 16u

/* Number of padding bytes (1..16) after `data_length` bytes. */
size_t wa_pkcs7_get_padding_length(size_t data_length);

/* Complete the final block, whose first `data_length_in_block` bytes (0..15) are data, with its padding. */
void wa_pkcs7_pad_final_block(uint8_t block[WA_PKCS7_BLOCK_SIZE], size_t data_length_in_block);

#endif /* WA_AES_CBC_PKCS7_PADDING_H */
