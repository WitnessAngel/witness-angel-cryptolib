/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WA_UTF8_VALIDATION_H
#define WA_UTF8_VALIDATION_H

#include <stddef.h>
#include <stdint.h>

/* 1 if the bytes are valid UTF-8 (shortest forms, no encoded surrogates, at most U+10FFFF), else 0. */
int wa_utf8_is_valid(const uint8_t *bytes, size_t length);

/* Decode the code point starting at `bytes` (which MUST be valid UTF-8), and return its encoded length. */
size_t wa_utf8_decode_code_point(const uint8_t *bytes, uint32_t *code_point_out);

#endif /* WA_UTF8_VALIDATION_H */
