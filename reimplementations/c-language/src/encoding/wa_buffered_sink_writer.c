/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "encoding/wa_buffered_sink_writer.h"

#include <string.h>

#include "primitives/wa_secure_memory_wipe.h"

void wa_buffered_sink_writer_initialize(wa_buffered_sink_writer_t *writer, const wa_output_sink_t *sink)
{
    writer->sink = sink;
    writer->length = 0;
    writer->status = WA_STATUS_OK;
}

static void wa_buffered_sink_writer_deliver(wa_buffered_sink_writer_t *writer, const uint8_t *bytes, size_t length)
{
    if (writer->status == WA_STATUS_OK && length != 0) {
        wa_status_t status = writer->sink->write(writer->sink->sink_context, bytes, length);
        if (status != WA_STATUS_OK) {
            /* Keep allocator failures of buffer sinks recognizable, any other failure is the sink's */
            writer->status = status == WA_STATUS_OUT_OF_MEMORY ? status : WA_STATUS_SINK_WRITE_FAILURE;
        }
    }
}

static void wa_buffered_sink_writer_flush(wa_buffered_sink_writer_t *writer)
{
    wa_buffered_sink_writer_deliver(writer, writer->buffer, writer->length);
    writer->length = 0;
}

void wa_buffered_sink_writer_write(wa_buffered_sink_writer_t *writer, const uint8_t *bytes, size_t length)
{
    if (length > WA_BUFFERED_SINK_WRITER_BUFFER_SIZE - writer->length) {
        wa_buffered_sink_writer_flush(writer);
        if (length >= WA_BUFFERED_SINK_WRITER_BUFFER_SIZE) {
            wa_buffered_sink_writer_deliver(writer, bytes, length); /* Large items go straight to the sink */
            return;
        }
    }
    if (length != 0) {
        memcpy(writer->buffer + writer->length, bytes, length);
        writer->length += length;
    }
}

void wa_buffered_sink_writer_write_byte(wa_buffered_sink_writer_t *writer, uint8_t byte)
{
    if (writer->length == WA_BUFFERED_SINK_WRITER_BUFFER_SIZE) {
        wa_buffered_sink_writer_flush(writer);
    }
    writer->buffer[writer->length++] = byte;
}

void wa_buffered_sink_writer_write_text(wa_buffered_sink_writer_t *writer, const char *nul_terminated_text)
{
    wa_buffered_sink_writer_write(writer, (const uint8_t *)nul_terminated_text, strlen(nul_terminated_text));
}

wa_status_t wa_buffered_sink_writer_finish(wa_buffered_sink_writer_t *writer)
{
    wa_buffered_sink_writer_flush(writer);
    wa_secure_memory_wipe(writer->buffer, sizeof(writer->buffer));
    return writer->status;
}
