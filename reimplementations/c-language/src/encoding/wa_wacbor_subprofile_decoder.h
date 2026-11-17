/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Decoder of the device profile sub-profile of WA-CBOR (design D8, device profile specification section 1), into a
 * value tree. Accepts exactly the WA-CBOR documents made of definite-length maps with text keys and arrays, byte and
 * text strings, int64 integers, false/true/null and tag 37 UUIDs. Statuses:
 * - WA_STATUS_DECODING_ERROR for bytes that are not WA-CBOR (what wacryptolib's load_from_cbor_bytes() rejects);
 * - WA_STATUS_UNSUPPORTED_TYPE for valid WA-CBOR items outside the sub-profile;
 * - WA_STATUS_NESTING_TOO_DEEP beyond WA_MAX_CBOR_NESTING_DEPTH levels of arrays and maps. */

#ifndef WA_WACBOR_SUBPROFILE_DECODER_H
#define WA_WACBOR_SUBPROFILE_DECODER_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_value_tree.h"

wa_status_t wa_wacbor_subprofile_decode_document(const uint8_t *cbor, size_t cbor_length,
                                                 const wa_platform_hooks_t *platform_hooks, wa_value_t **value_out);

#endif /* WA_WACBOR_SUBPROFILE_DECODER_H */
