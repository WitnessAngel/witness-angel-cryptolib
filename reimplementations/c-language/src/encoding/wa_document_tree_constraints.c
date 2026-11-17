/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "encoding/wa_document_tree_constraints.h"

#include <string.h>

#include "encoding/wa_value_tree_internal.h"

static const char *const wa_document_tree_keyword_names[] = {"$binary",    "$uuid",        "$date",
                                                        "$numberInt", "$numberLong",  "$numberDouble",
                                                        "$numberDecimal", "$undefined"};

int wa_document_tree_is_extended_json_keyword(const char *key, size_t key_length)
{
    size_t index;
    for (index = 0; index < sizeof(wa_document_tree_keyword_names) / sizeof(wa_document_tree_keyword_names[0]); index++) {
        const char *keyword = wa_document_tree_keyword_names[index];
        if (wa_value_keys_are_equal(key, key_length, keyword, strlen(keyword))) {
            return 1;
        }
    }
    return 0;
}

static wa_status_t wa_document_tree_check_node(const wa_value_t *node, size_t depth, size_t maximum_depth)
{
    size_t index;
    if (node->type == WA_VALUE_TYPE_ARRAY) {
        if (depth + 1 > maximum_depth) {
            return WA_STATUS_NESTING_TOO_DEEP;
        }
        for (index = 0; index < node->content.array.count; index++) {
            wa_status_t status = wa_document_tree_check_node(node->content.array.items[index], depth + 1,
                                                             maximum_depth);
            if (status != WA_STATUS_OK) {
                return status;
            }
        }
    } else if (node->type == WA_VALUE_TYPE_MAP) {
        if (depth + 1 > maximum_depth) {
            return WA_STATUS_NESTING_TOO_DEEP;
        }
        if (node->content.map.count == 1 &&
            wa_document_tree_is_extended_json_keyword(node->content.map.entries[0].key,
                                                      node->content.map.entries[0].key_length)) {
            return WA_STATUS_INVALID_PROFILE;
        }
        for (index = 0; index < node->content.map.count; index++) {
            wa_status_t status = wa_document_tree_check_node(node->content.map.entries[index].value, depth + 1,
                                                             maximum_depth);
            if (status != WA_STATUS_OK) {
                return status;
            }
        }
    }
    return WA_STATUS_OK;
}

wa_status_t wa_document_tree_check_constraints(const wa_value_t *tree, size_t maximum_depth)
{
    return wa_document_tree_check_node(tree, 0, maximum_depth);
}
