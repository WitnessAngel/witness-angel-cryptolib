/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Streaming base64 encoder (RFC 4648 section 4: standard alphabet, with padding), for Extended JSON builds. */

#ifndef WA_BASE64_ENCODER_H
#define WA_BASE64_ENCODER_H

#include <stddef.h>
#include <stdint.h>

#include "encoding/wa_buffered_sink_writer.h"

typedef struct wa_base64_encoder {
    wa_buffered_sink_writer_t *writer;
    uint8_t pending[3];
    size_t pending_length;
} wa_base64_encoder_t;

void wa_base64_encoder_initialize(wa_base64_encoder_t *encoder, wa_buffered_sink_writer_t *writer);
void wa_base64_encoder_update(wa_base64_encoder_t *encoder, const uint8_t *bytes, size_t length);
/* Write the last group with its padding, and wipe the pending bytes. */
void wa_base64_encoder_finish(wa_base64_encoder_t *encoder);

#endif /* WA_BASE64_ENCODER_H */
