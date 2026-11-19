/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Step 1 of the encryptor specification (section 6.1): the cryptainer base, i.e. a deep copy of the validated
 * cryptoconf completed with every key ciphertext and the root fields, and the in-memory secrets (one payload
 * symkey per payload cipher layer). Signatures being rejected at profile load, there are no hash algos. */

#ifndef WA_CRYPTAINER_BASE_GENERATION_H
#define WA_CRYPTAINER_BASE_GENERATION_H

#include <stddef.h>

#include "primitives/wa_symmetric_key_generation.h"
#include "wa_flightbox/wa_cryptainer_encryptor.h"
#include "wa_flightbox/wa_device_profile.h"
#include "wa_flightbox/wa_document_formats.h"
#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_value_tree.h"

#define WA_CRYPTAINER_FORMAT "cryptainer_1.0"
#define WA_CRYPTAINER_STATE_STARTED "STARTED"
#define WA_CRYPTAINER_STATE_FINISHED "FINISHED"
#define WA_CIPHERTEXT_LOCATION_INLINE_NAME "inline"
#define WA_CIPHERTEXT_LOCATION_OFFLOADED_NAME "offloaded"

typedef struct wa_cryptainer_base {
    const wa_platform_hooks_t *platform_hooks;
    wa_value_t *cryptainer;          /* The cryptainer tree, state STARTED */
    wa_symkey_t *payload_symkeys;    /* One per payload cipher layer, in order: SECRET; NULL once released */
    size_t payload_layer_count;
} wa_cryptainer_base_t;

/* generate_cryptainer_base_and_secrets() (section 6.1), in the resolved format F. `cryptainer_metadata_or_null`
 * (a map checked against the document tree constraints, or NULL) is deep-copied into the cryptainer, and that copy
 * goes into every key struct. The payload ciphertext struct is null for an inline location, and the offloaded
 * marker otherwise (section 7.2). On failure, `base_out` is left empty and everything is wiped and released. */
wa_status_t wa_cryptainer_base_generate(const wa_platform_hooks_t *platform_hooks,
                                        const wa_device_profile_t *device_profile,
                                        const wa_value_t *cryptainer_metadata_or_null,
                                        wa_document_format_t resolved_format,
                                        wa_ciphertext_location_t ciphertext_location, wa_cryptainer_base_t *base_out);

/* Wipe and release the payload symkeys alone, once the payload is encrypted and its MACs are built (a no-op when
 * they are released already). */
void wa_cryptainer_base_release_payload_symkeys(wa_cryptainer_base_t *base);

/* Wipe the secrets and release everything (an empty or zeroed base is accepted). */
void wa_cryptainer_base_release(wa_cryptainer_base_t *base);

#endif /* WA_CRYPTAINER_BASE_GENERATION_H */
