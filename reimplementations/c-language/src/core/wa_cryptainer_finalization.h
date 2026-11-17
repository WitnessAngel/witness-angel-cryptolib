/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Step 3 of the encryptor specification (section 8, without signing since signature confs are rejected at profile
 * load): payload MACs of every payload layer, inline payload ciphertext struct, FINISHED state. */

#ifndef WA_CRYPTAINER_FINALIZATION_H
#define WA_CRYPTAINER_FINALIZATION_H

#include "core/wa_cryptainer_base_generation.h"
#include "core/wa_payload_encryption_pipeline.h"
#include "encoding/wa_growable_byte_buffer.h"

/* add_authentication_data_to_cryptainer(): `pipeline` was finalized. With an inline location,
 * `inline_ciphertext_or_null` holds the whole payload ciphertext, which it hands over to the cryptainer (the
 * buffer is left empty, or released on failure); with an offloaded location it is NULL, the marker being set at
 * step 1 already. */
wa_status_t wa_cryptainer_add_authentication_data(wa_cryptainer_base_t *base,
                                                  const wa_payload_encryption_pipeline_t *pipeline,
                                                  wa_growable_byte_buffer_t *inline_ciphertext_or_null);

#endif /* WA_CRYPTAINER_FINALIZATION_H */
