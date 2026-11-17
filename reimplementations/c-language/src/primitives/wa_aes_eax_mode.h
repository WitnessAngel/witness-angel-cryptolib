/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* AES-256 EAX encryption (Bellare-Rogaway-Wagner, as pycryptodome's AES.MODE_EAX), streaming, 16-byte tag, no
 * header (design D4): N = OMAC0(nonce), H = OMAC1(empty header), ciphertext = backend AES-CTR from N, then
 * tag = N xor H xor OMAC2(ciphertext), OMAC2 being updated as the ciphertext is produced. */

#ifndef WA_AES_EAX_MODE_H
#define WA_AES_EAX_MODE_H

#include <stddef.h>
#include <stdint.h>

#include "backends/wa_crypto_backend.h"
#include "primitives/wa_aes_cmac_omac1.h"

#define WA_AES_EAX_TAG_SIZE 16u

typedef struct wa_aes_eax_encryption {
    wa_crypto_backend_aes_256_t *aes; /* Owned */
    wa_aes_cmac_t ciphertext_omac;
    uint8_t nonce_and_header_omacs[WA_AES_BLOCK_SIZE]; /* N xor H */
    uint8_t counter_block[WA_AES_BLOCK_SIZE];
    uint8_t keystream_block[WA_AES_BLOCK_SIZE];
    size_t keystream_used_length; /* Bytes of keystream_block already used (16: none left) */
} wa_aes_eax_encryption_t;

wa_status_t wa_aes_eax_encryption_start(const wa_platform_hooks_t *platform_hooks, const uint8_t key[WA_AES_256_KEY_SIZE],
                                        const uint8_t *nonce, size_t nonce_length,
                                        wa_aes_eax_encryption_t *encryption);

/* Encrypt the next `length` bytes (any length, 0 allowed). In-place allowed. */
wa_status_t wa_aes_eax_encryption_update(wa_aes_eax_encryption_t *encryption, const uint8_t *input, uint8_t *output,
                                         size_t length);

wa_status_t wa_aes_eax_encryption_finish(wa_aes_eax_encryption_t *encryption, uint8_t tag[WA_AES_EAX_TAG_SIZE]);

/* Release the backend context and wipe everything (also after errors; a zeroed structure is accepted). */
void wa_aes_eax_encryption_release(wa_aes_eax_encryption_t *encryption);

#endif /* WA_AES_EAX_MODE_H */
