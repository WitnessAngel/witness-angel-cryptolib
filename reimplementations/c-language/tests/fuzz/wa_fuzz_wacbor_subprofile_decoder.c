/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* libFuzzer target of the WA-CBOR sub-profile decoder (wa_value_tree_decode_from_cbor).
 *
 * Besides memory errors (ASan/UBSan), it aborts when:
 * - a decoding leaks a block, or fails with a status outside the decoder's (unsupported, invalid, too deep, out of
 *   memory);
 * - an accepted tree is not written by an enabled writer;
 * - the WA-CBOR writing of an accepted tree does not decode to a tree written to the same bytes (the deterministic
 *   encoding is a fixed point). */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_flightbox/wa_flightbox.h"

#include "encoding/wa_document_serialization.h"
#include "encoding/wa_growable_byte_buffer.h"

#include "wa_test_support.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void wa_fuzz_fail(const char *reason)
{
    fprintf(stderr, "wa_fuzz_wacbor_subprofile_decoder: %s\n", reason);
    abort();
}

static int wa_fuzz_is_decoder_status(wa_status_t status)
{
    return status == WA_STATUS_OK || status == WA_STATUS_UNSUPPORTED_TYPE || status == WA_STATUS_DECODING_ERROR ||
           status == WA_STATUS_NESTING_TOO_DEEP || status == WA_STATUS_OUT_OF_MEMORY;
}

#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
/* The WA-CBOR writing of a tree, decoded again, is written to the same bytes */
static void wa_fuzz_check_cbor_fixed_point(const wa_platform_hooks_t *platform_hooks, const wa_value_t *tree)
{
    wa_growable_byte_buffer_t first_writing;
    wa_growable_byte_buffer_t second_writing;
    wa_value_t *decoded_again = NULL;
    wa_growable_byte_buffer_initialize(&first_writing, platform_hooks, 0);
    wa_growable_byte_buffer_initialize(&second_writing, platform_hooks, 0);
    if (wa_document_serialize_to_buffer(tree, WA_DOCUMENT_FORMAT_CBOR, &first_writing) != WA_STATUS_OK) {
        wa_fuzz_fail("an accepted tree is not written as WA-CBOR");
    }
    if (wa_value_tree_decode_from_cbor(first_writing.data, first_writing.length, platform_hooks, &decoded_again) !=
        WA_STATUS_OK) {
        wa_fuzz_fail("the WA-CBOR writing of an accepted tree is not decoded");
    }
    if (wa_document_serialize_to_buffer(decoded_again, WA_DOCUMENT_FORMAT_CBOR, &second_writing) != WA_STATUS_OK ||
        second_writing.length != first_writing.length ||
        memcmp(second_writing.data, first_writing.data, first_writing.length) != 0) {
        wa_fuzz_fail("the WA-CBOR writing is not a fixed point");
    }
    wa_value_destroy(decoded_again);
    wa_growable_byte_buffer_release(&first_writing);
    wa_growable_byte_buffer_release(&second_writing);
}
#endif

#if WA_DOCUMENT_FORMAT_JSON_ENABLED
static void wa_fuzz_check_json_writing(const wa_platform_hooks_t *platform_hooks, const wa_value_t *tree)
{
    wa_growable_byte_buffer_t writing;
    size_t index;
    wa_growable_byte_buffer_initialize(&writing, platform_hooks, 0);
    if (wa_document_serialize_to_buffer(tree, WA_DOCUMENT_FORMAT_JSON, &writing) != WA_STATUS_OK) {
        wa_fuzz_fail("an accepted tree is not written as Extended JSON");
    }
    for (index = 0; index < writing.length; ++index) {
        if (writing.data[index] >= 0x80u) {
            wa_fuzz_fail("the Extended JSON writing is not ASCII");
        }
    }
    wa_growable_byte_buffer_release(&writing);
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wa_test_platform_t *platform = wa_test_platform_create(1u);
    wa_value_t *tree = NULL;
    wa_status_t status;
    if (platform == NULL) {
        wa_fuzz_fail("cannot create the test platform");
    }
    status = wa_value_tree_decode_from_cbor(data, size, &platform->hooks, &tree);
    if (!wa_fuzz_is_decoder_status(status)) {
        wa_fuzz_fail("unexpected decoding status");
    }
    if ((status == WA_STATUS_OK) != (tree != NULL)) {
        wa_fuzz_fail("a tree is returned if and only if decoding succeeds");
    }
    if (tree != NULL) {
#if WA_DOCUMENT_FORMAT_CBOR_ENABLED
        wa_fuzz_check_cbor_fixed_point(&platform->hooks, tree);
#endif
#if WA_DOCUMENT_FORMAT_JSON_ENABLED
        wa_fuzz_check_json_writing(&platform->hooks, tree);
#endif
        wa_value_destroy(tree);
    }
    if (!wa_test_allocator_is_clean(&platform->allocator)) {
        wa_fuzz_fail("leaked or mismatched blocks");
    }
    wa_test_platform_destroy(platform);
    return 0;
}
