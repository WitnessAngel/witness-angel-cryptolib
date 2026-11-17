/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Asymmetric key wrapping (encryptor specification, sections 3.5 and 6.5): the key struct
 * {"key_bytes": ..., "cryptainer_metadata": ... or null} is serialized in the cryptainer's document format, then
 * encrypted with RSA_OAEP, ECIES_X25519 or ML_KEM_768 into a cipherdict. */

#ifndef WA_ASYMMETRIC_KEY_WRAPPING_H
#define WA_ASYMMETRIC_KEY_WRAPPING_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_document_formats.h"
#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_status_codes.h"
#include "wa_flightbox/wa_value_tree.h"

#include "encoding/wa_growable_byte_buffer.h"

typedef enum wa_asymmetric_cipher_algo {
    WA_ASYMMETRIC_CIPHER_RSA_OAEP = 1,
    WA_ASYMMETRIC_CIPHER_ECIES_X25519 = 2,
    WA_ASYMMETRIC_CIPHER_ML_KEM_768 = 3
} wa_asymmetric_cipher_algo_t;

/* A public key, borrowing the bytes of its device profile entry: `modulus` and `public_exponent` for RSA_OAEP,
 * `key_bytes` (32 or 1184 bytes) for the others. Constraints are checked at profile loading. */
typedef struct wa_asymmetric_public_key {
    wa_asymmetric_cipher_algo_t cipher_algo;
    const uint8_t *key_bytes;
    size_t key_bytes_length;
    const uint8_t *modulus;
    size_t modulus_length;
    const uint8_t *public_exponent;
    size_t public_exponent_length;
} wa_asymmetric_public_key_t;

/* 1 and the algo if `name` (of `name_length` bytes) is an asymmetric cipher name, else 0. */
int wa_asymmetric_cipher_algo_from_name(const char *name, size_t name_length, wa_asymmetric_cipher_algo_t *algo_out);
const char *wa_asymmetric_cipher_algo_get_name(wa_asymmetric_cipher_algo_t cipher_algo);

/* Encrypt raw bytes: {"ciphertext_chunks": [...]} for RSA_OAEP, {"kem_ciphertext", "ciphertext"} otherwise. */
wa_status_t wa_asymmetric_encrypt_to_cipherdict(const wa_platform_hooks_t *platform_hooks,
                                                const wa_asymmetric_public_key_t *public_key,
                                                const uint8_t *plaintext, size_t plaintext_length,
                                                wa_value_t **cipherdict_out);

/* Serialize the key struct {"key_bytes": ..., "cryptainer_metadata": map or null} (section 6.5) in
 * `resolved_format` into `serialized_out` (initialized here, secret, released on failure). */
wa_status_t wa_asymmetric_serialize_key_struct(const wa_platform_hooks_t *platform_hooks,
                                               wa_document_format_t resolved_format, const uint8_t *key_bytes,
                                               size_t key_bytes_length,
                                               const wa_value_t *cryptainer_metadata_or_null,
                                               wa_growable_byte_buffer_t *serialized_out);

/* Serialize the key struct of `key_bytes` and `cryptainer_metadata_or_null` (a map, satisfying the document tree
 * constraints) in `resolved_format`, into a secret buffer wiped afterwards, and encrypt it. */
wa_status_t wa_asymmetric_wrap_key_struct(const wa_platform_hooks_t *platform_hooks,
                                          const wa_asymmetric_public_key_t *public_key,
                                          wa_document_format_t resolved_format, const uint8_t *key_bytes,
                                          size_t key_bytes_length, const wa_value_t *cryptainer_metadata_or_null,
                                          wa_value_t **cipherdict_out);

#endif /* WA_ASYMMETRIC_KEY_WRAPPING_H */
