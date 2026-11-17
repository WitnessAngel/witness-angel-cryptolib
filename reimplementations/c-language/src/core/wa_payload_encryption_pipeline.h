/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Step 2 of the encryptor specification (section 7.2, PayloadEncryptionPipeline): the payload goes through every
 * payload cipher layer as a chain of streaming nodes, and the raw output of the last one goes to a sink. Chunks are
 * cut into slices of at most WA_PAYLOAD_PROCESSING_SLICE_SIZE bytes, so that memory use depends neither on the
 * payload length nor on the caller's chunk size (design D12). No digest is computed, signatures being rejected. */

#ifndef WA_PAYLOAD_ENCRYPTION_PIPELINE_H
#define WA_PAYLOAD_ENCRYPTION_PIPELINE_H

#include <stddef.h>
#include <stdint.h>

#include "primitives/wa_symmetric_cipher_streams.h"
#include "primitives/wa_symmetric_key_generation.h"
#include "wa_flightbox/wa_flightbox_config.h"
#include "wa_flightbox/wa_platform_hooks.h"

#if WA_PAYLOAD_PROCESSING_SLICE_SIZE < 16 || WA_PAYLOAD_PROCESSING_SLICE_SIZE % 16 != 0
#error "WA_PAYLOAD_PROCESSING_SLICE_SIZE must be a multiple of 16, at least 16"
#endif

typedef struct wa_payload_encryption_node {
    wa_symmetric_cipher_stream_t stream;
    uint8_t *output;          /* Scratch buffer: WA_PAYLOAD_PROCESSING_SLICE_SIZE + 16 * (index + 1) bytes */
    uint8_t tag[WA_SYMMETRIC_TAG_SIZE];
    size_t tag_length;        /* 0 (AES_CBC) or 16, once finalized */
} wa_payload_encryption_node_t;

typedef struct wa_payload_encryption_pipeline {
    const wa_platform_hooks_t *platform_hooks;
    const wa_output_sink_t *output_sink;
    wa_payload_encryption_node_t *nodes;
    size_t node_count;
    uint8_t *scratch_block;   /* All node outputs, in one allocation */
    size_t scratch_block_size;
} wa_payload_encryption_pipeline_t;

/* Start one streaming node per payload symkey, in payload cipher layer order. On failure, the pipeline is
 * released. */
wa_status_t wa_payload_encryption_pipeline_start(const wa_platform_hooks_t *platform_hooks,
                                                 const wa_symkey_t *payload_symkeys, size_t payload_layer_count,
                                                 const wa_output_sink_t *output_sink,
                                                 wa_payload_encryption_pipeline_t *pipeline_out);

/* pipeline.encrypt_chunk(chunk): any length, 0 included. */
wa_status_t wa_payload_encryption_pipeline_encrypt_chunk(wa_payload_encryption_pipeline_t *pipeline,
                                                         const uint8_t *chunk, size_t chunk_length);

/* pipeline.finalize(): flush every node in order, write the last pending bytes, and keep the tag of each node. */
wa_status_t wa_payload_encryption_pipeline_finalize(wa_payload_encryption_pipeline_t *pipeline);

/* Release the cipher contexts and wipe the scratch buffers (an empty or zeroed pipeline is accepted). */
void wa_payload_encryption_pipeline_release(wa_payload_encryption_pipeline_t *pipeline);

#endif /* WA_PAYLOAD_ENCRYPTION_PIPELINE_H */
