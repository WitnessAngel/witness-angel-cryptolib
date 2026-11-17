/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Value tree -> relaxed Extended JSON, byte-identical to wacryptolib's dump_to_json_bytes() (encryptor
 * specification, section 2): keys sorted by code point, ", " and ": " separators, ASCII-only output with lowercase
 * \uXXXX escapes, bytes as {"$binary": {"base64": ..., "subType": "00"}}, UUIDs as {"$uuid": "<hex>"}. */

#ifndef WA_EXTENDED_JSON_WRITER_H
#define WA_EXTENDED_JSON_WRITER_H

#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_value_tree.h"

/* The tree must satisfy the document tree constraints. */
wa_status_t wa_extended_json_writer_write_document(const wa_value_t *tree, const wa_output_sink_t *sink);

#endif /* WA_EXTENDED_JSON_WRITER_H */
