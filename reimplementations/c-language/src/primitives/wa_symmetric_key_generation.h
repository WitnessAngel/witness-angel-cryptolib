/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Symmetric cipher algorithms and symkeys (encryptor specification, sections 3.3 and 3.4). */

#ifndef WA_SYMMETRIC_KEY_GENERATION_H
#define WA_SYMMETRIC_KEY_GENERATION_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_status_codes.h"
#include "wa_flightbox/wa_value_tree.h"

typedef enum wa_symmetric_cipher_algo {
    WA_SYMMETRIC_CIPHER_AES_CBC = 1,
    WA_SYMMETRIC_CIPHER_AES_EAX = 2,
    WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305 = 3
} wa_symmetric_cipher_algo_t;

#define WA_SYMKEY_KEY_SIZE 32u
#define WA_SYMKEY_MAXIMUM_IV_OR_NONCE_SIZE 16u
#define WA_SYMMETRIC_TAG_SIZE 16u

/* A symkey dict: {"key": 32 bytes, "iv" (AES_CBC: 16 bytes) or "nonce" (AES_EAX: 16, CHACHA20_POLY1305: 12)} */
typedef struct wa_symkey {
    wa_symmetric_cipher_algo_t cipher_algo;
    uint8_t key[WA_SYMKEY_KEY_SIZE];
    uint8_t iv_or_nonce[WA_SYMKEY_MAXIMUM_IV_OR_NONCE_SIZE];
    size_t iv_or_nonce_length;
} wa_symkey_t;

/* 1 and the algo if the (non NUL-terminated) `name` is a symmetric cipher algo name, else 0. */
int wa_symmetric_cipher_algo_from_name(const char *name, size_t name_length, wa_symmetric_cipher_algo_t *algo_out);
/* "AES_CBC", "AES_EAX" or "CHACHA20_POLY1305", or NULL for an unknown value. */
const char *wa_symmetric_cipher_algo_get_name(wa_symmetric_cipher_algo_t cipher_algo);
/* "iv" for AES_CBC, "nonce" for the others, NULL for an unknown value. */
const char *wa_symmetric_cipher_algo_get_iv_or_nonce_field_name(wa_symmetric_cipher_algo_t cipher_algo);
/* 1 for the algos producing a 16-byte "tag" (AES_EAX, CHACHA20_POLY1305), else 0. */
int wa_symmetric_cipher_algo_has_tag(wa_symmetric_cipher_algo_t cipher_algo);

/* Draw the key, then the IV or nonce, from the random hook (the order of wacryptolib's keygen). On failure, the
 * symkey is wiped. */
wa_status_t wa_symkey_generate(const wa_platform_hooks_t *platform_hooks, wa_symmetric_cipher_algo_t cipher_algo,
                               wa_symkey_t *symkey_out);

/* Build the symkey dict as a value tree (whose nodes are wiped when destroyed). */
wa_status_t wa_symkey_build_tree(const wa_platform_hooks_t *platform_hooks, const wa_symkey_t *symkey,
                                 wa_value_t **tree_out);

void wa_symkey_wipe(wa_symkey_t *symkey);

#endif /* WA_SYMMETRIC_KEY_GENERATION_H */
