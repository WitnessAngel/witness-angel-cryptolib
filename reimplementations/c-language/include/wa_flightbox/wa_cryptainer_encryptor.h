/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Cryptainer encryptor: steps 1, 2 and 3 of docs/flightbox_specifications/flightbox_encryptor_specification.md.
 *
 * States: CREATED -> STREAMING -> FINISHED, plus FAILED after any error, which only accepts destroy. */

#ifndef WA_CRYPTAINER_ENCRYPTOR_H
#define WA_CRYPTAINER_ENCRYPTOR_H

#include <stddef.h>
#include <stdint.h>

#include "wa_device_profile.h"
#include "wa_document_formats.h"
#include "wa_platform_hooks.h"
#include "wa_status_codes.h"
#include "wa_value_tree.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wa_cryptainer_encryptor wa_cryptainer_encryptor_t;

typedef enum wa_ciphertext_location {
    /* The whole ciphertext is kept in memory, and embedded in the cryptainer (meant for small payloads). */
    WA_CIPHERTEXT_LOCATION_INLINE = 1,
    /* The ciphertext is delivered progressively to `payload_ciphertext_sink`, to be stored as the
     * "<cryptainer file name>.payload" sibling file; the cryptainer only holds the offloaded marker. */
    WA_CIPHERTEXT_LOCATION_OFFLOADED = 2
} wa_ciphertext_location_t;

typedef struct wa_cryptainer_encryptor_options {
    const wa_platform_hooks_t *platform_hooks;
    /* Format of the cryptainer AND of every structure serialized into its key ciphertexts. */
    wa_document_format_t document_format;
    wa_ciphertext_location_t ciphertext_location;
    const wa_output_sink_t *payload_ciphertext_sink;  /* offloaded location only, else NULL */
} wa_cryptainer_encryptor_options_t;

/* Step 1: create the cryptainer base and its secrets (every key ciphertext). Metadata, a map or NULL, is checked
 * against the document tree constraints and deep-copied, before any key is generated. `*encryptor_out` is NULL
 * on failure. */
wa_status_t wa_cryptainer_encryptor_create(const wa_device_profile_t *device_profile,
                                           const wa_value_t *cryptainer_metadata_or_null,
                                           const wa_cryptainer_encryptor_options_t *options,
                                           wa_cryptainer_encryptor_t **encryptor_out);

/* Step 2: encrypt a payload chunk of any size, empty chunks included. */
wa_status_t wa_cryptainer_encryptor_encrypt_payload_chunk(wa_cryptainer_encryptor_t *encryptor,
                                                          const uint8_t *chunk, size_t chunk_length);

/* End of step 2 (padding, flushes, tags) and step 3: the cryptainer becomes FINISHED. */
wa_status_t wa_cryptainer_encryptor_finalize(wa_cryptainer_encryptor_t *encryptor);

/* Serialize the FINISHED cryptainer to a sink, in the document format chosen at creation. May be called several
 * times. */
wa_status_t wa_cryptainer_encryptor_write_cryptainer(const wa_cryptainer_encryptor_t *encryptor,
                                                     const wa_output_sink_t *cryptainer_sink);

/* Release an encryptor, wiping every secret. NULL is a no-op. */
void wa_cryptainer_encryptor_destroy(wa_cryptainer_encryptor_t *encryptor_or_null);

/* Convenience: create, encrypt `payload` in one chunk, finalize, write the cryptainer to `cryptainer_sink`, and
 * destroy. */
wa_status_t wa_cryptainer_encrypt_payload_in_one_call(const wa_device_profile_t *device_profile,
                                                      const wa_value_t *cryptainer_metadata_or_null,
                                                      const wa_cryptainer_encryptor_options_t *options,
                                                      const uint8_t *payload, size_t payload_length,
                                                      const wa_output_sink_t *cryptainer_sink);

#ifdef __cplusplus
}
#endif

#endif /* WA_CRYPTAINER_ENCRYPTOR_H */
