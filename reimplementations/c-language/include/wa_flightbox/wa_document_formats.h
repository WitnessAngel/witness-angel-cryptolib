/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Document formats of cryptainers, and of the structures serialized then encrypted into their key ciphertexts. */

#ifndef WA_DOCUMENT_FORMATS_H
#define WA_DOCUMENT_FORMATS_H

#include "wa_flightbox_config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wa_document_format {
    WA_DOCUMENT_FORMAT_BUILD_DEFAULT = 0,  /* the only enabled format, or Extended JSON when both are enabled */
    WA_DOCUMENT_FORMAT_JSON = 1,           /* relaxed Extended JSON, ASCII-only, sorted keys */
    WA_DOCUMENT_FORMAT_CBOR = 2            /* WA-CBOR, core deterministic encoding */
} wa_document_format_t;

/* Lowercase cryptainer file suffix of a format: ".crypt.json" or ".crypt.cbor" (the build default being resolved
 * first), or NULL for an unknown or disabled format. Cryptainer files are named <basename> + suffix, and offloaded
 * payloads <cryptainer file name> + ".payload". */
const char *wa_document_format_get_cryptainer_suffix(wa_document_format_t document_format);

/* 1 if the format (the build default being resolved first) is compiled in, else 0. */
int wa_document_format_is_enabled(wa_document_format_t document_format);

#ifdef __cplusplus
}
#endif

#endif /* WA_DOCUMENT_FORMATS_H */
