/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* EME-OAEP encoding (RFC 8017, section 7.1.1) with SHA-512, MGF1-SHA-512 and an empty label, as pycryptodome's
 * PKCS1_OAEP.new(key, hashAlgo=SHA512) used by wacryptolib (encryptor specification, section 3.5). The seed is a
 * parameter: callers draw it from the random hook, tests replay a fixed one. */

#ifndef WA_RSA_OAEP_SHA512_PADDING_H
#define WA_RSA_OAEP_SHA512_PADDING_H

#include <stddef.h>
#include <stdint.h>

#include "backends/wa_crypto_backend.h"
#include "wa_flightbox/wa_status_codes.h"

#define WA_RSA_OAEP_SEED_SIZE WA_SHA512_DIGEST_SIZE
/* Encoding overhead: 2 * hLen + 2 */
#define WA_RSA_OAEP_SHA512_OVERHEAD (2u * WA_SHA512_DIGEST_SIZE + 2u)

/* Write EM = 0x00 || maskedSeed || maskedDB into `encoded_message` (`modulus_length` bytes). The message must not
 * exceed modulus_length - 130 bytes (WA_STATUS_INVALID_ARGUMENT otherwise). */
wa_status_t wa_rsa_oaep_sha512_encode_padding(const uint8_t *message, size_t message_length,
                                              const uint8_t seed[WA_RSA_OAEP_SEED_SIZE], uint8_t *encoded_message,
                                              size_t modulus_length);

#endif /* WA_RSA_OAEP_SHA512_PADDING_H */
