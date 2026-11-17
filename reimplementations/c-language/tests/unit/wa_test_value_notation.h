/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Test-only builder of value trees from a compact notation, so that tests can hand-build trees readably:
 *
 *   {'key': value, ...}   map (keys in the given order, duplicates rejected by wa_value_map_add)
 *   [value, ...]          array
 *   'text'                text (no escapes; the text cannot contain a quote)
 *   -12, 0, 42            integers
 *   null, true, false
 *   u'<32 hex digits>'    UUID
 *   b'<hex digits>'       bytes
 *
 * Whitespace is ignored outside quotes. */

#ifndef WA_TEST_VALUE_NOTATION_H
#define WA_TEST_VALUE_NOTATION_H

#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_status_codes.h"
#include "wa_flightbox/wa_value_tree.h"

/* WA_STATUS_INVALID_ARGUMENT on a notation error (reported on stderr with its position), or the status of a
 * failed builder call (e.g. out of memory); `*tree_out` is NULL on failure. */
wa_status_t wa_test_build_value_tree(const wa_platform_hooks_t *platform_hooks, const char *notation,
                                     wa_value_t **tree_out);

#endif /* WA_TEST_VALUE_NOTATION_H */
