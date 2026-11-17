/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "encoding/wa_utf8_validation.h"

static int wa_utf8_is_continuation_byte(uint8_t byte)
{
    return (byte & 0xC0u) == 0x80u;
}

int wa_utf8_is_valid(const uint8_t *bytes, size_t length)
{
    size_t position = 0;
    while (position < length) {
        uint8_t lead = bytes[position];
        size_t sequence_length;
        uint32_t code_point;
        size_t index;

        if (lead < 0x80u) {
            position++;
            continue;
        }
        if (lead >= 0xC2u && lead <= 0xDFu) {
            sequence_length = 2;
            code_point = lead & 0x1Fu;
        } else if (lead >= 0xE0u && lead <= 0xEFu) {
            sequence_length = 3;
            code_point = lead & 0x0Fu;
        } else if (lead >= 0xF0u && lead <= 0xF4u) {
            sequence_length = 4;
            code_point = lead & 0x07u;
        } else {
            return 0; /* Continuation byte, overlong 2-byte lead (C0, C1), or F5..FF */
        }
        if (length - position < sequence_length) {
            return 0;
        }
        for (index = 1; index < sequence_length; index++) {
            if (!wa_utf8_is_continuation_byte(bytes[position + index])) {
                return 0;
            }
            code_point = (code_point << 6) | (bytes[position + index] & 0x3Fu);
        }
        if ((sequence_length == 3 && code_point < 0x800u) || (sequence_length == 4 && code_point < 0x10000u) ||
            code_point > 0x10FFFFu || (code_point >= 0xD800u && code_point <= 0xDFFFu)) {
            return 0; /* Overlong form, beyond Unicode, or encoded surrogate */
        }
        position += sequence_length;
    }
    return 1;
}

size_t wa_utf8_decode_code_point(const uint8_t *bytes, uint32_t *code_point_out)
{
    uint8_t lead = bytes[0];
    if (lead < 0x80u) {
        *code_point_out = lead;
        return 1;
    }
    if (lead < 0xE0u) {
        *code_point_out = ((uint32_t)(lead & 0x1Fu) << 6) | (bytes[1] & 0x3Fu);
        return 2;
    }
    if (lead < 0xF0u) {
        *code_point_out = ((uint32_t)(lead & 0x0Fu) << 12) | ((uint32_t)(bytes[1] & 0x3Fu) << 6) | (bytes[2] & 0x3Fu);
        return 3;
    }
    *code_point_out = ((uint32_t)(lead & 0x07u) << 18) | ((uint32_t)(bytes[1] & 0x3Fu) << 12) |
                      ((uint32_t)(bytes[2] & 0x3Fu) << 6) | (bytes[3] & 0x3Fu);
    return 4;
}
