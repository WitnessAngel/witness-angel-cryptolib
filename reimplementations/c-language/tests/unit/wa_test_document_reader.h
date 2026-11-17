/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Test-only document reader: parse what the encryptor writes back into value trees, to check cryptainers and the
 * structures serialized into their key ciphertexts. WA-CBOR goes through the library's sub-profile decoder; relaxed
 * Extended JSON through a small strict parser of the subset the writer produces (objects, arrays, strings with
 * escapes, integers, true/false/null, {"$binary": {"base64": ..., "subType": "00"}} and {"$uuid": <32 hex>}). */

#ifndef WA_TEST_DOCUMENT_READER_H
#define WA_TEST_DOCUMENT_READER_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_document_formats.h"
#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_value_tree.h"

/* WA_STATUS_DECODING_ERROR for any malformed or unexpected input. */
wa_status_t wa_test_parse_extended_json(const wa_platform_hooks_t *platform_hooks, const uint8_t *json,
                                        size_t json_length, wa_value_t **tree_out);

/* Dispatch on a resolved format (JSON or CBOR). */
wa_status_t wa_test_read_document(const wa_platform_hooks_t *platform_hooks, wa_document_format_t format,
                                  const uint8_t *document, size_t document_length, wa_value_t **tree_out);

#endif /* WA_TEST_DOCUMENT_READER_H */
