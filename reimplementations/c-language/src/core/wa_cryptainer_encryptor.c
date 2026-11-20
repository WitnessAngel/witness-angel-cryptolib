/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Public API and lifecycle of the cryptainer encryptor (design D11): steps 1 (creation), 2 (chunks) and 3
 * (finalization) of the encryptor specification, then serialization in the document format chosen at creation. */

#include "wa_flightbox/wa_cryptainer_encryptor.h"

#include <string.h>

#include "core/wa_cryptainer_base_generation.h"
#include "core/wa_cryptainer_finalization.h"
#include "core/wa_payload_encryption_pipeline.h"
#include "core/wa_platform_hooks_calls.h"
#include "encoding/wa_document_serialization.h"
#include "encoding/wa_document_tree_constraints.h"
#include "encoding/wa_growable_byte_buffer.h"

typedef enum wa_cryptainer_encryptor_state {
    WA_CRYPTAINER_ENCRYPTOR_STATE_CREATED = 1,
    WA_CRYPTAINER_ENCRYPTOR_STATE_STREAMING,
    WA_CRYPTAINER_ENCRYPTOR_STATE_FINISHED,
    WA_CRYPTAINER_ENCRYPTOR_STATE_FAILED
} wa_cryptainer_encryptor_state_t;

struct wa_cryptainer_encryptor {
    const wa_platform_hooks_t *platform_hooks;
    wa_cryptainer_encryptor_state_t state;
    wa_document_format_t resolved_format;
    wa_ciphertext_location_t ciphertext_location;
    wa_cryptainer_base_t base;                      /* Cryptainer tree and payload symkeys */
    wa_payload_encryption_pipeline_t pipeline;
    wa_growable_byte_buffer_t inline_ciphertext;    /* Inline location only */
    /* Where the pipeline writes: a sink appending to inline_ciphertext, or a copy of the caller's offloaded sink (so
     * that the caller's wa_output_sink_t and options need not outlive the creation call) */
    wa_output_sink_t payload_ciphertext_sink;
};

/* Wipe and release what was only needed to encrypt the payload: the cipher contexts and scratch buffers of the
 * pipeline, and the payload symkeys (a second call is a no-op) */
static void wa_release_payload_encryption_secrets(wa_cryptainer_encryptor_t *encryptor)
{
    wa_payload_encryption_pipeline_release(&encryptor->pipeline);
    wa_cryptainer_base_release_payload_symkeys(&encryptor->base);
}

/* Enter the FAILED state, which only accepts destroy: its payload secrets are of no use anymore */
static void wa_fail_encryptor(wa_cryptainer_encryptor_t *encryptor)
{
    wa_release_payload_encryption_secrets(encryptor);
    encryptor->state = WA_CRYPTAINER_ENCRYPTOR_STATE_FAILED;
}

/* Metadata goes at depth 2 of cryptainers and key structs: one level less than the CBOR nesting limit */
static wa_status_t wa_check_cryptainer_metadata(const wa_value_t *cryptainer_metadata_or_null)
{
    if (cryptainer_metadata_or_null == NULL) {
        return WA_STATUS_OK;
    }
    if (wa_value_get_type(cryptainer_metadata_or_null) != WA_VALUE_TYPE_MAP) {
        return WA_STATUS_INVALID_PROFILE;
    }
    return wa_document_tree_check_constraints(cryptainer_metadata_or_null, (size_t)WA_MAX_CBOR_NESTING_DEPTH - 1u);
}

static wa_status_t wa_check_options(const wa_cryptainer_encryptor_options_t *options,
                                    wa_document_format_t *resolved_format_out)
{
    if (options == NULL || !wa_platform_hooks_are_usable(options->platform_hooks)) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    switch (options->ciphertext_location) {
    case WA_CIPHERTEXT_LOCATION_INLINE:
        if (options->payload_ciphertext_sink != NULL) {
            return WA_STATUS_INVALID_ARGUMENT;
        }
        break;
    case WA_CIPHERTEXT_LOCATION_OFFLOADED:
        if (options->payload_ciphertext_sink == NULL || options->payload_ciphertext_sink->write == NULL) {
            return WA_STATUS_INVALID_ARGUMENT;
        }
        break;
    default:
        return WA_STATUS_INVALID_ARGUMENT;
    }
    return wa_document_format_resolve(options->document_format, resolved_format_out);
}

wa_status_t wa_cryptainer_encryptor_create(const wa_device_profile_t *device_profile,
                                           const wa_value_t *cryptainer_metadata_or_null,
                                           const wa_cryptainer_encryptor_options_t *options,
                                           wa_cryptainer_encryptor_t **encryptor_out)
{
    wa_cryptainer_encryptor_t *encryptor;
    wa_document_format_t resolved_format = WA_DOCUMENT_FORMAT_BUILD_DEFAULT;
    wa_status_t status;

    if (encryptor_out == NULL) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    *encryptor_out = NULL;
    if (device_profile == NULL) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    WA_RETURN_IF_ERROR(wa_check_options(options, &resolved_format));
    WA_RETURN_IF_ERROR(wa_check_cryptainer_metadata(cryptainer_metadata_or_null)); /* Before any key generation */

    encryptor = (wa_cryptainer_encryptor_t *)wa_allocate_memory(options->platform_hooks, sizeof(*encryptor));
    if (encryptor == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    memset(encryptor, 0, sizeof(*encryptor));
    encryptor->platform_hooks = options->platform_hooks;
    encryptor->state = WA_CRYPTAINER_ENCRYPTOR_STATE_CREATED;
    encryptor->resolved_format = resolved_format;
    encryptor->ciphertext_location = options->ciphertext_location;
    wa_growable_byte_buffer_initialize(&encryptor->inline_ciphertext, options->platform_hooks, 0);
    encryptor->payload_ciphertext_sink = options->ciphertext_location == WA_CIPHERTEXT_LOCATION_INLINE
                                             ? wa_growable_byte_buffer_get_sink(&encryptor->inline_ciphertext)
                                             : *options->payload_ciphertext_sink;

    status = wa_cryptainer_base_generate(options->platform_hooks, device_profile, cryptainer_metadata_or_null,
                                         resolved_format, options->ciphertext_location, &encryptor->base);
    if (status == WA_STATUS_OK) {
        status = wa_payload_encryption_pipeline_start(options->platform_hooks, encryptor->base.payload_symkeys,
                                                      encryptor->base.payload_layer_count,
                                                      &encryptor->payload_ciphertext_sink, &encryptor->pipeline);
    }
    if (status != WA_STATUS_OK) {
        wa_cryptainer_encryptor_destroy(encryptor);
        return status;
    }
    *encryptor_out = encryptor;
    return WA_STATUS_OK;
}

wa_status_t wa_cryptainer_encryptor_encrypt_payload_chunk(wa_cryptainer_encryptor_t *encryptor,
                                                          const uint8_t *chunk, size_t chunk_length)
{
    wa_status_t status;
    if (encryptor == NULL) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    if (encryptor->state != WA_CRYPTAINER_ENCRYPTOR_STATE_CREATED &&
        encryptor->state != WA_CRYPTAINER_ENCRYPTOR_STATE_STREAMING) {
        /* A FINISHED encryptor stays so: its cryptainer is complete, and can still be written */
        return WA_STATUS_WRONG_STATE;
    }
    if (chunk == NULL && chunk_length > 0) {
        wa_fail_encryptor(encryptor);
        return WA_STATUS_INVALID_ARGUMENT;
    }
    status = wa_payload_encryption_pipeline_encrypt_chunk(&encryptor->pipeline, chunk, chunk_length);
    if (status != WA_STATUS_OK) {
        wa_fail_encryptor(encryptor);
        return status;
    }
    encryptor->state = WA_CRYPTAINER_ENCRYPTOR_STATE_STREAMING;
    return WA_STATUS_OK;
}

wa_status_t wa_cryptainer_encryptor_finalize(wa_cryptainer_encryptor_t *encryptor)
{
    wa_status_t status;
    if (encryptor == NULL) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    if (encryptor->state != WA_CRYPTAINER_ENCRYPTOR_STATE_CREATED &&
        encryptor->state != WA_CRYPTAINER_ENCRYPTOR_STATE_STREAMING) {
        /* A FINISHED encryptor stays so: its cryptainer is complete, and can still be written */
        return WA_STATUS_WRONG_STATE;
    }
    status = wa_payload_encryption_pipeline_finalize(&encryptor->pipeline);
    if (status == WA_STATUS_OK) {
        status = wa_cryptainer_add_authentication_data(
            &encryptor->base, &encryptor->pipeline,
            encryptor->ciphertext_location == WA_CIPHERTEXT_LOCATION_INLINE ? &encryptor->inline_ciphertext : NULL);
    }
    /* The cipher contexts, the scratch buffers and the payload symkeys are not needed anymore, whatever the outcome:
     * they are wiped now rather than when the encryptor is destroyed (section 11.1, rule 12) */
    wa_release_payload_encryption_secrets(encryptor);
    encryptor->state =
        status == WA_STATUS_OK ? WA_CRYPTAINER_ENCRYPTOR_STATE_FINISHED : WA_CRYPTAINER_ENCRYPTOR_STATE_FAILED;
    return status;
}

wa_status_t wa_cryptainer_encryptor_write_cryptainer(const wa_cryptainer_encryptor_t *encryptor,
                                                     const wa_output_sink_t *cryptainer_sink)
{
    if (encryptor == NULL || cryptainer_sink == NULL || cryptainer_sink->write == NULL) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    if (encryptor->state != WA_CRYPTAINER_ENCRYPTOR_STATE_FINISHED) {
        return WA_STATUS_WRONG_STATE; /* The encryptor is const: its state is left unchanged */
    }
    return wa_document_serialize_to_sink(encryptor->base.cryptainer, encryptor->resolved_format, cryptainer_sink);
}

void wa_cryptainer_encryptor_destroy(wa_cryptainer_encryptor_t *encryptor_or_null)
{
    const wa_platform_hooks_t *platform_hooks;
    if (encryptor_or_null == NULL) {
        return;
    }
    platform_hooks = encryptor_or_null->platform_hooks;
    wa_payload_encryption_pipeline_release(&encryptor_or_null->pipeline);
    wa_growable_byte_buffer_release(&encryptor_or_null->inline_ciphertext);
    wa_cryptainer_base_release(&encryptor_or_null->base);
    wa_release_secret_memory(platform_hooks, encryptor_or_null, sizeof(*encryptor_or_null));
}

wa_status_t wa_cryptainer_encrypt_payload_in_one_call(const wa_device_profile_t *device_profile,
                                                      const wa_value_t *cryptainer_metadata_or_null,
                                                      const wa_cryptainer_encryptor_options_t *options,
                                                      const uint8_t *payload, size_t payload_length,
                                                      const wa_output_sink_t *cryptainer_sink)
{
    wa_cryptainer_encryptor_t *encryptor = NULL;
    wa_status_t status;
    /* Argument errors before any key generation */
    if (cryptainer_sink == NULL || cryptainer_sink->write == NULL || (payload == NULL && payload_length > 0)) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    status = wa_cryptainer_encryptor_create(device_profile, cryptainer_metadata_or_null, options, &encryptor);
    if (status == WA_STATUS_OK) {
        status = wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, payload, payload_length);
    }
    if (status == WA_STATUS_OK) {
        status = wa_cryptainer_encryptor_finalize(encryptor);
    }
    if (status == WA_STATUS_OK) {
        status = wa_cryptainer_encryptor_write_cryptainer(encryptor, cryptainer_sink);
    }
    wa_cryptainer_encryptor_destroy(encryptor);
    return status;
}
