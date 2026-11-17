/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "encoding/wa_document_serialization.h"

#include "wa_flightbox/wa_flightbox_config.h"

#if WA_DOCUMENT_FORMAT_JSON_ENABLED
#include "encoding/wa_extended_json_writer.h"
#endif
#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
#include "encoding/wa_wacbor_deterministic_writer.h"
#endif

wa_status_t wa_document_format_resolve(wa_document_format_t requested_format, wa_document_format_t *resolved_out)
{
    switch (requested_format) {
    case WA_DOCUMENT_FORMAT_BUILD_DEFAULT:
        *resolved_out = WA_DOCUMENT_FORMAT_JSON_ENABLED ? WA_DOCUMENT_FORMAT_JSON : WA_DOCUMENT_FORMAT_CBOR;
        return WA_STATUS_OK;
    case WA_DOCUMENT_FORMAT_JSON:
        if (!WA_DOCUMENT_FORMAT_JSON_ENABLED) {
            return WA_STATUS_UNSUPPORTED_FEATURE;
        }
        *resolved_out = requested_format;
        return WA_STATUS_OK;
    case WA_DOCUMENT_FORMAT_CBOR:
        if (!WA_DOCUMENT_FORMAT_CBOR_ENABLED) {
            return WA_STATUS_UNSUPPORTED_FEATURE;
        }
        *resolved_out = requested_format;
        return WA_STATUS_OK;
    }
    return WA_STATUS_INVALID_ARGUMENT;
}

int wa_document_format_is_enabled(wa_document_format_t document_format)
{
    wa_document_format_t resolved_format;
    return wa_document_format_resolve(document_format, &resolved_format) == WA_STATUS_OK;
}

const char *wa_document_format_get_cryptainer_suffix(wa_document_format_t document_format)
{
    wa_document_format_t resolved_format;
    if (wa_document_format_resolve(document_format, &resolved_format) != WA_STATUS_OK) {
        return NULL;
    }
    return resolved_format == WA_DOCUMENT_FORMAT_CBOR ? ".crypt.cbor" : ".crypt.json";
}

wa_status_t wa_document_serialize_to_sink(const wa_value_t *tree, wa_document_format_t resolved_format,
                                          const wa_output_sink_t *sink)
{
#if WA_DOCUMENT_FORMAT_JSON_ENABLED
    if (resolved_format == WA_DOCUMENT_FORMAT_JSON) {
        return wa_extended_json_writer_write_document(tree, sink);
    }
#endif
#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
    if (resolved_format == WA_DOCUMENT_FORMAT_CBOR) {
        return wa_wacbor_deterministic_writer_write_document(tree, sink);
    }
#endif
    (void)tree;
    (void)sink;
    return WA_STATUS_UNSUPPORTED_FEATURE;
}

wa_status_t wa_document_serialize_to_buffer(const wa_value_t *tree, wa_document_format_t resolved_format,
                                            wa_growable_byte_buffer_t *buffer)
{
    wa_output_sink_t sink = wa_growable_byte_buffer_get_sink(buffer);
    return wa_document_serialize_to_sink(tree, resolved_format, &sink);
}
