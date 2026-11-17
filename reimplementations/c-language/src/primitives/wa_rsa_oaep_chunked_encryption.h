/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* RSA_OAEP key cipher (encryptor specification, section 3.5): the plaintext is cut into 60-byte chunks, the last one
 * possibly shorter, each encrypted with its own OAEP seed from the random hook; an empty plaintext gives no chunk. */

#ifndef WA_RSA_OAEP_CHUNKED_ENCRYPTION_H
#define WA_RSA_OAEP_CHUNKED_ENCRYPTION_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_status_codes.h"
#include "wa_flightbox/wa_value_tree.h"

#define WA_RSA_OAEP_CHUNK_SIZE 60u

/* Cipherdict {"ciphertext_chunks": [bytes(k), ...]} for the big-endian modulus (k bytes, no leading zero byte, at
 * least 130 + 60 bytes) and public exponent, as checked by the profile loader. */
wa_status_t wa_rsa_oaep_encrypt_into_chunks(const wa_platform_hooks_t *platform_hooks, const uint8_t *modulus,
                                            size_t modulus_length, const uint8_t *public_exponent,
                                            size_t public_exponent_length, const uint8_t *plaintext,
                                            size_t plaintext_length, wa_value_t **cipherdict_out);

#endif /* WA_RSA_OAEP_CHUNKED_ENCRYPTION_H */
