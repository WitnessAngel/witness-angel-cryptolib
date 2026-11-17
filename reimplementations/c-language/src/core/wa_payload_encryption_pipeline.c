/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Section 7.2 of the encryptor specification. The CBC remainder of each node lives in its symmetric cipher stream
 * (pending_block), which outputs whole blocks only; AES_EAX and CHACHA20_POLY1305 output as many bytes as they get.
 *
 * Scratch sizes: with S = WA_PAYLOAD_PROCESSING_SLICE_SIZE (a multiple of 16), node i receives at most S + 16 * i
 * bytes per slice, and the stream writes at most that length + 15 bytes: S + 16 * (i + 1) bytes suffice. At
 * finalization, the bytes pending for node i are a multiple of 16 of at most 16 * i (an AES_CBC node adds one block
 * at most, the others none), and node i outputs at most them + 15, then its final block of 16 bytes. */

#include "core/wa_payload_encryption_pipeline.h"

#include <string.h>

#include "core/wa_platform_hooks_calls.h"

static size_t wa_get_node_output_capacity(size_t node_index)
{
    return (size_t)WA_PAYLOAD_PROCESSING_SLICE_SIZE + (size_t)WA_AES_BLOCK_SIZE * (node_index + 1u);
}

void wa_payload_encryption_pipeline_release(wa_payload_encryption_pipeline_t *pipeline)
{
    size_t node_index;
    if (pipeline->nodes != NULL) {
        for (node_index = 0; node_index < pipeline->node_count; ++node_index) {
            wa_symmetric_cipher_stream_release(pipeline->platform_hooks, &pipeline->nodes[node_index].stream);
        }
        wa_release_secret_memory(pipeline->platform_hooks, pipeline->nodes,
                                 pipeline->node_count * sizeof(wa_payload_encryption_node_t));
    }
    if (pipeline->scratch_block != NULL) {
        wa_release_secret_memory(pipeline->platform_hooks, pipeline->scratch_block, pipeline->scratch_block_size);
    }
    memset(pipeline, 0, sizeof(*pipeline));
}

wa_status_t wa_payload_encryption_pipeline_start(const wa_platform_hooks_t *platform_hooks,
                                                 const wa_symkey_t *payload_symkeys, size_t payload_layer_count,
                                                 const wa_output_sink_t *output_sink,
                                                 wa_payload_encryption_pipeline_t *pipeline_out)
{
    size_t nodes_size = 0;
    size_t scratch_block_size = 0;
    size_t node_index;
    wa_status_t status = WA_STATUS_OK;

    memset(pipeline_out, 0, sizeof(*pipeline_out));
    pipeline_out->platform_hooks = platform_hooks;
    pipeline_out->output_sink = output_sink;
    if (payload_layer_count == 0 || output_sink == NULL || output_sink->write == NULL) {
        return WA_STATUS_INTERNAL_ERROR;
    }
    for (node_index = 0; node_index < payload_layer_count; ++node_index) {
        size_t capacity = wa_get_node_output_capacity(node_index);
        if (capacity < WA_PAYLOAD_PROCESSING_SLICE_SIZE || scratch_block_size + capacity < scratch_block_size) {
            return WA_STATUS_OUT_OF_MEMORY;
        }
        scratch_block_size += capacity;
    }
    if (wa_size_multiplication_overflows(payload_layer_count, sizeof(wa_payload_encryption_node_t), &nodes_size)) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    pipeline_out->nodes = (wa_payload_encryption_node_t *)wa_allocate_memory(platform_hooks, nodes_size);
    if (pipeline_out->nodes == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    memset(pipeline_out->nodes, 0, nodes_size); /* Zeroed streams are accepted by the release */
    pipeline_out->node_count = payload_layer_count;
    pipeline_out->scratch_block = (uint8_t *)wa_allocate_memory(platform_hooks, scratch_block_size);
    if (pipeline_out->scratch_block == NULL) {
        wa_payload_encryption_pipeline_release(pipeline_out);
        return WA_STATUS_OUT_OF_MEMORY;
    }
    pipeline_out->scratch_block_size = scratch_block_size;
    scratch_block_size = 0;
    for (node_index = 0; status == WA_STATUS_OK && node_index < payload_layer_count; ++node_index) {
        wa_payload_encryption_node_t *node = &pipeline_out->nodes[node_index];
        node->output = pipeline_out->scratch_block + scratch_block_size;
        scratch_block_size += wa_get_node_output_capacity(node_index);
        status = wa_symmetric_cipher_stream_start(platform_hooks, &payload_symkeys[node_index], &node->stream);
    }
    if (status != WA_STATUS_OK) {
        wa_payload_encryption_pipeline_release(pipeline_out);
    }
    return status;
}

/* Same status mapping as wa_buffered_sink_writer: out of memory (e.g. a growable buffer sink) passes through */
static wa_status_t wa_write_to_sink(const wa_payload_encryption_pipeline_t *pipeline, const uint8_t *bytes,
                                    size_t length)
{
    wa_status_t status = pipeline->output_sink->write(pipeline->output_sink->sink_context, bytes, length);
    if (status == WA_STATUS_OK || status == WA_STATUS_OUT_OF_MEMORY) {
        return status;
    }
    return WA_STATUS_SINK_WRITE_FAILURE;
}

/* One slice through every node, then to the sink */
static wa_status_t wa_encrypt_slice(wa_payload_encryption_pipeline_t *pipeline, const uint8_t *slice,
                                    size_t slice_length)
{
    size_t node_index;
    for (node_index = 0; node_index < pipeline->node_count; ++node_index) {
        wa_payload_encryption_node_t *node = &pipeline->nodes[node_index];
        size_t output_length = 0;
        if (slice_length == 0) {
            return WA_STATUS_OK; /* An AES_CBC node kept everything in its remainder: nothing to pass on */
        }
        WA_RETURN_IF_ERROR(
            wa_symmetric_cipher_stream_encrypt(&node->stream, slice, slice_length, node->output, &output_length));
        slice = node->output;
        slice_length = output_length;
    }
    if (slice_length == 0) {
        return WA_STATUS_OK;
    }
    return wa_write_to_sink(pipeline, slice, slice_length);
}

wa_status_t wa_payload_encryption_pipeline_encrypt_chunk(wa_payload_encryption_pipeline_t *pipeline,
                                                         const uint8_t *chunk, size_t chunk_length)
{
    while (chunk_length > 0) {
        size_t slice_length =
            chunk_length < WA_PAYLOAD_PROCESSING_SLICE_SIZE ? chunk_length : WA_PAYLOAD_PROCESSING_SLICE_SIZE;
        WA_RETURN_IF_ERROR(wa_encrypt_slice(pipeline, chunk, slice_length));
        chunk += slice_length;
        chunk_length -= slice_length;
    }
    return WA_STATUS_OK;
}

wa_status_t wa_payload_encryption_pipeline_finalize(wa_payload_encryption_pipeline_t *pipeline)
{
    const uint8_t *pending = NULL;
    size_t pending_length = 0;
    size_t node_index;
    /* pending = b""; for node in nodes: pending = (node.encrypt(pending) if pending else b"") + node.finalize() */
    for (node_index = 0; node_index < pipeline->node_count; ++node_index) {
        wa_payload_encryption_node_t *node = &pipeline->nodes[node_index];
        size_t output_length = 0;
        size_t final_length = 0;
        if (pending_length > 0) {
            WA_RETURN_IF_ERROR(wa_symmetric_cipher_stream_encrypt(&node->stream, pending, pending_length,
                                                                  node->output, &output_length));
        }
        if (output_length + WA_AES_BLOCK_SIZE > wa_get_node_output_capacity(node_index)) {
            return WA_STATUS_INTERNAL_ERROR; /* Excluded by the bound in the header comment */
        }
        WA_RETURN_IF_ERROR(wa_symmetric_cipher_stream_finish(&node->stream, node->output + output_length,
                                                             &final_length, node->tag, &node->tag_length));
        pending = node->output;
        pending_length = output_length + final_length;
    }
    if (pending_length == 0) {
        return WA_STATUS_OK;
    }
    return wa_write_to_sink(pipeline, pending, pending_length);
}
