/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_secure_memory_wipe.h"

void wa_secure_memory_wipe(void *buffer, size_t length)
{
    /* Writes through a volatile pointer are observable behaviour, so they can't be elided */
    volatile uint8_t *bytes = (volatile uint8_t *)buffer;
    size_t index;
    for (index = 0; index < length; index++) {
        bytes[index] = 0;
    }
}

int wa_constant_time_is_all_zero(const uint8_t *bytes, size_t length)
{
    uint8_t accumulator = 0;
    size_t index;
    for (index = 0; index < length; index++) {
        accumulator = (uint8_t)(accumulator | bytes[index]);
    }
    return (int)(1 & ((unsigned int)(accumulator - 1u) >> 8));
}
