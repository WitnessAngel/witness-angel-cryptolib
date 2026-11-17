/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Sections 7.1, 8 and 9.2 of the encryptor specification. The signature lists are empty (or the plaintext one
 * absent), so inject_digests_and_signatures() has nothing to inject: no digest is computed nor stored. */

#include "core/wa_cryptainer_finalization.h"

#include <string.h>

#include "core/wa_platform_hooks_calls.h"
#include "encoding/wa_value_tree_internal.h"
#include "primitives/wa_symmetric_cipher_streams.h"

static wa_status_t wa_build_inline_ciphertext_struct(const wa_platform_hooks_t *platform_hooks,
                                                     wa_growable_byte_buffer_t *inline_ciphertext,
                                                     wa_value_t **struct_out)
{
    wa_value_t *location_node = NULL;
    wa_value_t *ciphertext_node = NULL;
    wa_status_t status = wa_value_create_map(platform_hooks, struct_out);
    if (status != WA_STATUS_OK) {
        wa_growable_byte_buffer_release(inline_ciphertext);
        return status;
    }
    status = wa_value_create_text(platform_hooks, WA_CIPHERTEXT_LOCATION_INLINE_NAME,
                                  strlen(WA_CIPHERTEXT_LOCATION_INLINE_NAME), &location_node);
    if (status == WA_STATUS_OK) {
        status = wa_value_map_add_consuming(*struct_out, "ciphertext_location", location_node);
    }
    if (status == WA_STATUS_OK) {
        status = wa_growable_byte_buffer_move_into_bytes_value(inline_ciphertext, &ciphertext_node);
    } else {
        wa_growable_byte_buffer_release(inline_ciphertext);
    }
    if (status == WA_STATUS_OK) {
        status = wa_value_map_add_consuming(*struct_out, "ciphertext_value", ciphertext_node);
    }
    if (status != WA_STATUS_OK) {
        wa_value_destroy(*struct_out);
        *struct_out = NULL;
    }
    return status;
}

wa_status_t wa_cryptainer_add_authentication_data(wa_cryptainer_base_t *base,
                                                  const wa_payload_encryption_pipeline_t *pipeline,
                                                  wa_growable_byte_buffer_t *inline_ciphertext_or_null)
{
    const wa_platform_hooks_t *platform_hooks = base->platform_hooks;
    wa_value_t *payload_layers = wa_value_find_map_value_for_update(base->cryptainer, "payload_cipher_layers");
    wa_value_t *state_node = NULL;
    size_t layer_index;
    wa_status_t status = WA_STATUS_OK;

    if (pipeline->node_count != base->payload_layer_count ||
        wa_value_get_item_count(payload_layers) != base->payload_layer_count) {
        status = WA_STATUS_INTERNAL_ERROR;
    }
    for (layer_index = 0; status == WA_STATUS_OK && layer_index < base->payload_layer_count; ++layer_index) {
        wa_value_t *payload_layer = (wa_value_t *)wa_value_get_array_item(payload_layers, layer_index);
        const wa_payload_encryption_node_t *node = &pipeline->nodes[layer_index];
        wa_value_t *payload_macs = NULL;
        wa_value_t *previous_payload_macs = wa_value_map_take_value(payload_layer, "payload_macs");
        int previous_was_null =
            previous_payload_macs != NULL && wa_value_get_type(previous_payload_macs) == WA_VALUE_TYPE_NULL;
        wa_value_destroy(previous_payload_macs);
        if (!previous_was_null) {
            status = WA_STATUS_INTERNAL_ERROR; /* assert layer["payload_macs"] is null */
            break;
        }
        status = wa_symmetric_build_payload_macs(platform_hooks, base->payload_symkeys[layer_index].cipher_algo,
                                                 node->tag, node->tag_length, &payload_macs);
        if (status == WA_STATUS_OK) {
            status = wa_value_map_add_consuming(payload_layer, "payload_macs", payload_macs);
        }
    }

    if (inline_ciphertext_or_null != NULL) {
        if (status == WA_STATUS_OK) {
            wa_value_t *ciphertext_struct = NULL;
            status = wa_build_inline_ciphertext_struct(platform_hooks, inline_ciphertext_or_null, &ciphertext_struct);
            if (status == WA_STATUS_OK) {
                wa_value_destroy(wa_value_map_take_value(base->cryptainer, "payload_ciphertext_struct"));
                status = wa_value_map_add_consuming(base->cryptainer, "payload_ciphertext_struct", ciphertext_struct);
            }
        } else {
            wa_growable_byte_buffer_release(inline_ciphertext_or_null);
        }
    }

    if (status == WA_STATUS_OK) {
        status = wa_value_create_text(platform_hooks, WA_CRYPTAINER_STATE_FINISHED,
                                      strlen(WA_CRYPTAINER_STATE_FINISHED), &state_node);
    }
    if (status == WA_STATUS_OK) {
        wa_value_destroy(wa_value_map_take_value(base->cryptainer, "cryptainer_state"));
        status = wa_value_map_add_consuming(base->cryptainer, "cryptainer_state", state_node);
    }
    return status;
}
