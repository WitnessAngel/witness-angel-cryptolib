/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* The only dispatch point between document formats and their writers (design D15): the core serializes every
 * structure through these functions, never through a specific writer. */

#ifndef WA_DOCUMENT_SERIALIZATION_H
#define WA_DOCUMENT_SERIALIZATION_H

#include "encoding/wa_growable_byte_buffer.h"
#include "wa_flightbox/wa_document_formats.h"
#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_value_tree.h"

/* Resolve the build default, and check the format: WA_STATUS_INVALID_ARGUMENT for a value outside the enum,
 * WA_STATUS_UNSUPPORTED_FEATURE for a format not compiled in. */
wa_status_t wa_document_format_resolve(wa_document_format_t requested_format, wa_document_format_t *resolved_out);

/* Serialize a tree (satisfying the document tree constraints) in a resolved, enabled format. */
wa_status_t wa_document_serialize_to_sink(const wa_value_t *tree, wa_document_format_t resolved_format,
                                          const wa_output_sink_t *sink);

/* Same, appending to a buffer (secret buffers for structures that are then encrypted). */
wa_status_t wa_document_serialize_to_buffer(const wa_value_t *tree, wa_document_format_t resolved_format,
                                            wa_growable_byte_buffer_t *buffer);

#endif /* WA_DOCUMENT_SERIALIZATION_H */
