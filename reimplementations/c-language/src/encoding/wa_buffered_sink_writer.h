/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Small staging buffer in front of an output sink, with a sticky status, used by the document writers so that
 * sinks receive a few large writes rather than one per token. After the first error of the sink, nothing more is
 * staged nor delivered, and the writers stop walking their tree. The staging buffer is wiped by finish(), since
 * serialized structures may hold secrets: until then, it keeps the last bytes delivered to the sink. */

#ifndef WA_BUFFERED_SINK_WRITER_H
#define WA_BUFFERED_SINK_WRITER_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_status_codes.h"

#define WA_BUFFERED_SINK_WRITER_BUFFER_SIZE 128u

typedef struct wa_buffered_sink_writer {
    const wa_output_sink_t *sink;
    uint8_t buffer[WA_BUFFERED_SINK_WRITER_BUFFER_SIZE];
    size_t length;
    wa_status_t status;  /* first error of the sink, kept until the end */
} wa_buffered_sink_writer_t;

void wa_buffered_sink_writer_initialize(wa_buffered_sink_writer_t *writer, const wa_output_sink_t *sink);
void wa_buffered_sink_writer_write(wa_buffered_sink_writer_t *writer, const uint8_t *bytes, size_t length);
void wa_buffered_sink_writer_write_byte(wa_buffered_sink_writer_t *writer, uint8_t byte);
void wa_buffered_sink_writer_write_text(wa_buffered_sink_writer_t *writer, const char *nul_terminated_text);

/* 1 once the sink has failed (every later write is then a no-op), else 0. */
int wa_buffered_sink_writer_has_failed(const wa_buffered_sink_writer_t *writer);

/* Deliver pending bytes, wipe the staging buffer, and return the sticky status. */
wa_status_t wa_buffered_sink_writer_finish(wa_buffered_sink_writer_t *writer);

#endif /* WA_BUFFERED_SINK_WRITER_H */
