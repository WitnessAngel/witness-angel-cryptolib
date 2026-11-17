/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Value tree -> WA-CBOR core deterministic encoding, byte-identical to wacryptolib's dump_to_cbor_bytes(): shortest
 * heads, definite lengths, map keys sorted by their encoded bytes, UUIDs as tag 37 over 16 bytes. */

#ifndef WA_WACBOR_DETERMINISTIC_WRITER_H
#define WA_WACBOR_DETERMINISTIC_WRITER_H

#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_value_tree.h"

/* The tree must satisfy the document tree constraints. */
wa_status_t wa_wacbor_deterministic_writer_write_document(const wa_value_t *tree, const wa_output_sink_t *sink);

#endif /* WA_WACBOR_DETERMINISTIC_WRITER_H */
