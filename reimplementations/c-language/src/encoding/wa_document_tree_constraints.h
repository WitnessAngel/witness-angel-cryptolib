/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* WA-CBOR tree rules that both writers rely on (design D8): no single-key map whose key is an Extended JSON
 * keyword, and a bounded nesting depth of arrays and maps. */

#ifndef WA_DOCUMENT_TREE_CONSTRAINTS_H
#define WA_DOCUMENT_TREE_CONSTRAINTS_H

#include <stddef.h>

#include "wa_flightbox/wa_value_tree.h"

/* 1 if the key is one of the Extended JSON keywords of WA-CBOR ("$binary", "$uuid"...), else 0. */
int wa_document_tree_is_extended_json_keyword(const char *key, size_t key_length);

/* Check a tree whose root sits at nesting depth 1 when it is an array or a map:
 * WA_STATUS_NESTING_TOO_DEEP when arrays and maps nest more than `maximum_depth` levels,
 * WA_STATUS_INVALID_PROFILE for an Extended JSON keyword map. */
wa_status_t wa_document_tree_check_constraints(const wa_value_t *tree, size_t maximum_depth);

#endif /* WA_DOCUMENT_TREE_CONSTRAINTS_H */
