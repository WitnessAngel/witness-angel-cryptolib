/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "encoding/wa_base64_encoder.h"

#include "primitives/wa_secure_memory_wipe.h"

static const char wa_base64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void wa_base64_encoder_write_group(wa_base64_encoder_t *encoder, const uint8_t *group, size_t group_length)
{
    uint8_t characters[4];
    uint32_t bits = (uint32_t)group[0] << 16;
    if (group_length > 1) {
        bits |= (uint32_t)group[1] << 8;
    }
    if (group_length > 2) {
        bits |= group[2];
    }
    characters[0] = (uint8_t)wa_base64_alphabet[(bits >> 18) & 0x3Fu];
    characters[1] = (uint8_t)wa_base64_alphabet[(bits >> 12) & 0x3Fu];
    characters[2] = group_length > 1 ? (uint8_t)wa_base64_alphabet[(bits >> 6) & 0x3Fu] : (uint8_t)'=';
    characters[3] = group_length > 2 ? (uint8_t)wa_base64_alphabet[bits & 0x3Fu] : (uint8_t)'=';
    wa_buffered_sink_writer_write(encoder->writer, characters, sizeof(characters));
}

void wa_base64_encoder_initialize(wa_base64_encoder_t *encoder, wa_buffered_sink_writer_t *writer)
{
    encoder->writer = writer;
    encoder->pending_length = 0;
}

void wa_base64_encoder_update(wa_base64_encoder_t *encoder, const uint8_t *bytes, size_t length)
{
    size_t position = 0;
    while (encoder->pending_length != 0 && encoder->pending_length < 3 && position < length) {
        encoder->pending[encoder->pending_length++] = bytes[position++];
    }
    if (encoder->pending_length == 3) {
        wa_base64_encoder_write_group(encoder, encoder->pending, 3);
        encoder->pending_length = 0;
    }
    while (length - position >= 3) {
        if (wa_buffered_sink_writer_has_failed(encoder->writer)) {
            return; /* The rest of a large content would be encoded for nothing */
        }
        wa_base64_encoder_write_group(encoder, bytes + position, 3);
        position += 3;
    }
    while (position < length) {
        encoder->pending[encoder->pending_length++] = bytes[position++];
    }
}

void wa_base64_encoder_finish(wa_base64_encoder_t *encoder)
{
    if (encoder->pending_length != 0) {
        wa_base64_encoder_write_group(encoder, encoder->pending, encoder->pending_length);
    }
    wa_secure_memory_wipe(encoder->pending, sizeof(encoder->pending));
    encoder->pending_length = 0;
}
