/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* AES-256 CMAC (OMAC1, SP 800-38B / RFC 4493), streaming, over the backend's bulk AES-CBC (design D4): the MAC
 * state is the CBC chaining value of a zero-IV encryption, and the subkeys derive from E_K(0^128), obtained the same
 * way. Mbed TLS's CMAC module is therefore not required. */

#ifndef WA_AES_CMAC_OMAC1_H
#define WA_AES_CMAC_OMAC1_H

#include <stddef.h>
#include <stdint.h>

#include "backends/wa_crypto_backend.h"

#define WA_AES_CMAC_SIZE 16u

typedef struct wa_aes_cmac {
    wa_crypto_backend_aes_256_t *aes; /* Borrowed: must outlive the CMAC */
    uint8_t subkey_1[WA_AES_BLOCK_SIZE];
    uint8_t subkey_2[WA_AES_BLOCK_SIZE];
    uint8_t chaining_value[WA_AES_BLOCK_SIZE];
    /* The last 0..16 bytes received, kept back since the final block gets a subkey */
    uint8_t pending_block[WA_AES_BLOCK_SIZE];
    size_t pending_length;
} wa_aes_cmac_t;

/* Start a CMAC with the key of `aes` (no allocation). */
wa_status_t wa_aes_cmac_start(wa_aes_cmac_t *cmac, wa_crypto_backend_aes_256_t *aes);

/* MAC the next `length` bytes (any length, 0 allowed). Whole blocks go to the backend in bulk. */
wa_status_t wa_aes_cmac_update(wa_aes_cmac_t *cmac, const uint8_t *data, size_t length);

/* Output the MAC, then wipe the state (only wa_aes_cmac_start() may follow). */
wa_status_t wa_aes_cmac_finish(wa_aes_cmac_t *cmac, uint8_t mac[WA_AES_CMAC_SIZE]);

/* Wipe the state, e.g. after an error. */
void wa_aes_cmac_wipe(wa_aes_cmac_t *cmac);

/* OMAC^t of EAX: the CMAC of [t]_16 (15 zero bytes, then t) || data, started here. */
wa_status_t wa_aes_cmac_start_omac_with_tweak(wa_aes_cmac_t *cmac, wa_crypto_backend_aes_256_t *aes, uint8_t tweak);

#endif /* WA_AES_CMAC_OMAC1_H */
