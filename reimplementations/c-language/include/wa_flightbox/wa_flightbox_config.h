/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Compile-time limits and document formats. Each macro may be overridden with -D, identically for the library and
 * for the code including its headers. */

#ifndef WA_FLIGHTBOX_CONFIG_H
#define WA_FLIGHTBOX_CONFIG_H

/* Key cipher nesting depth: a payload layer's key_cipher_layers list is level 1, and each shard or symmetric key
 * layer containing key_cipher_layers adds one level. Bounds the recursion of the core. */
#ifndef WA_MAX_KEY_CIPHER_NESTING_DEPTH
#define WA_MAX_KEY_CIPHER_NESTING_DEPTH 8
#endif
#if WA_MAX_KEY_CIPHER_NESTING_DEPTH < 1 || WA_MAX_KEY_CIPHER_NESTING_DEPTH > 64
#error "WA_MAX_KEY_CIPHER_NESTING_DEPTH must be between 1 and 64"
#endif

/* Nesting depth of CBOR arrays and maps, the top-level item counting as 1, for device profiles and metadata.
 * Metadata sits at depth 2 in cryptainers and key structs, so it is limited to WA_MAX_CBOR_NESTING_DEPTH - 1
 * levels. May be lowered to save stack, never raised above the WA-CBOR maximum of 64. */
#ifndef WA_MAX_CBOR_NESTING_DEPTH
#define WA_MAX_CBOR_NESTING_DEPTH 64
#endif
#if WA_MAX_CBOR_NESTING_DEPTH > 64
#error "WA_MAX_CBOR_NESTING_DEPTH can't exceed 64, the maximum nesting depth of WA-CBOR documents"
#endif
#if WA_MAX_CBOR_NESTING_DEPTH < 8
#error "WA_MAX_CBOR_NESTING_DEPTH must be at least 8, the depth of the simplest device profile"
#endif

/* Largest accepted RSA modulus, in bits (smallest: 2048). */
#ifndef WA_MAX_RSA_MODULUS_BITS
#define WA_MAX_RSA_MODULUS_BITS 4096
#endif
#if WA_MAX_RSA_MODULUS_BITS < 2048 || WA_MAX_RSA_MODULUS_BITS > 8192 || WA_MAX_RSA_MODULUS_BITS % 8 != 0
#error "WA_MAX_RSA_MODULUS_BITS must be a multiple of 8 between 2048 and 8192"
#endif

/* Payload chunks are processed in internal slices of at most this many bytes, which bounds memory use. */
#ifndef WA_PAYLOAD_PROCESSING_SLICE_SIZE
#define WA_PAYLOAD_PROCESSING_SLICE_SIZE 4096
#endif
#if WA_PAYLOAD_PROCESSING_SLICE_SIZE < 16 || WA_PAYLOAD_PROCESSING_SLICE_SIZE % 16 != 0
#error "WA_PAYLOAD_PROCESSING_SLICE_SIZE must be a multiple of 16, at least 16"
#endif

/* Document formats compiled in (1 or 0): Extended JSON on big chips, WA-CBOR only on small ones. A disabled
 * format's writer (and, for Extended JSON, the base64 encoder) is not part of the build. */
#ifndef WA_DOCUMENT_FORMAT_JSON_ENABLED
#define WA_DOCUMENT_FORMAT_JSON_ENABLED 1
#endif
#ifndef WA_DOCUMENT_FORMAT_CBOR_ENABLED
#define WA_DOCUMENT_FORMAT_CBOR_ENABLED 1
#endif
#if (WA_DOCUMENT_FORMAT_JSON_ENABLED != 0 && WA_DOCUMENT_FORMAT_JSON_ENABLED != 1) || \
    (WA_DOCUMENT_FORMAT_CBOR_ENABLED != 0 && WA_DOCUMENT_FORMAT_CBOR_ENABLED != 1)
#error "WA_DOCUMENT_FORMAT_JSON_ENABLED and WA_DOCUMENT_FORMAT_CBOR_ENABLED must be 0 or 1"
#endif
#if !WA_DOCUMENT_FORMAT_JSON_ENABLED && !WA_DOCUMENT_FORMAT_CBOR_ENABLED
#error "No document format enabled: define WA_DOCUMENT_FORMAT_JSON_ENABLED=1 and/or WA_DOCUMENT_FORMAT_CBOR_ENABLED=1"
#endif

#endif /* WA_FLIGHTBOX_CONFIG_H */
