/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Sections 6.2 to 6.5 of the encryptor specification: a key goes through a chain of key cipher layers
 * (asymmetric wrapping of a key struct, shared secret split into shards, symmetric sub-key), every intermediate
 * structure being serialized in the cryptainer's document format F (S_F) through wa_document_serialization. */

#ifndef WA_KEY_CIPHER_LAYERS_ENCRYPTION_H
#define WA_KEY_CIPHER_LAYERS_ENCRYPTION_H

#include <stddef.h>
#include <stdint.h>

#include "encoding/wa_growable_byte_buffer.h"
#include "wa_flightbox/wa_device_profile.h"
#include "wa_flightbox/wa_document_formats.h"
#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_value_tree.h"

#define WA_KEY_CIPHERTEXT_FORMAT_CBOR "cbor"

typedef struct wa_key_cipher_context {
    const wa_platform_hooks_t *platform_hooks;
    const wa_device_profile_t *device_profile; /* Public keys, and the root keychain uid */
    wa_document_format_t resolved_format;      /* F, for every serialized structure */
    const wa_value_t *cryptainer_metadata_or_null;
} wa_key_cipher_context_t;

/* encrypt_key_through_multiple_layers() (section 6.2): encrypt `key_bytes` through the non-empty
 * "key_cipher_layers" list of `layer_owner` (a payload layer, a symmetric key layer or a shard conf of the
 * cryptainer), whose symmetric key layers receive their own "key_ciphertext" (and, in WA-CBOR,
 * "key_ciphertext_format") in place. On success, `key_ciphertext_out` (initialized by this function, secret-aware)
 * holds S_F of the last layer's cipherdict; on failure it is released. */
wa_status_t wa_key_cipher_layers_encrypt_key(const wa_key_cipher_context_t *context, wa_value_t *layer_owner,
                                             const uint8_t *key_bytes, size_t key_bytes_length,
                                             wa_growable_byte_buffer_t *key_ciphertext_out);

/* Add "key_ciphertext" (taking over the content of `key_ciphertext`, released in any case) and, in WA-CBOR,
 * "key_ciphertext_format": "cbor" to a payload layer or a symmetric key layer. */
wa_status_t wa_key_cipher_layers_store_key_ciphertext(const wa_key_cipher_context_t *context, wa_value_t *layer,
                                                      wa_growable_byte_buffer_t *key_ciphertext);

/* Serialize the symkey dict (section 3.3) with S_F into `serialized_out` (initialized here, secret, released on
 * failure). */
wa_status_t wa_key_cipher_layers_serialize_symkey(const wa_key_cipher_context_t *context, const void *symkey,
                                                  wa_growable_byte_buffer_t *serialized_out);

/* Serialize the shard (shard_index + 1, shard) (section 6.4) with S_F into `serialized_out` (initialized here,
 * secret, released on failure); `shard_index` is 0-based. */
wa_status_t wa_key_cipher_layers_serialize_shard(const wa_key_cipher_context_t *context, size_t shard_index,
                                                 const uint8_t *shard, size_t shard_length,
                                                 wa_growable_byte_buffer_t *serialized_out);

#endif /* WA_KEY_CIPHER_LAYERS_ENCRYPTION_H */
