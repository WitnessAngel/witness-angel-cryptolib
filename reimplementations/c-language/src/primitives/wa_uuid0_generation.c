/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_uuid0_generation.h"

#include "core/wa_platform_hooks_calls.h"

wa_status_t wa_uuid0_generate(const wa_platform_hooks_t *platform_hooks, uint8_t uuid[WA_UUID_SIZE])
{
    uint64_t unix_time = 0; /* In 1/10000 s */
    size_t index;
    if (platform_hooks->get_unix_time_in_ten_thousandths_of_second == NULL ||
        platform_hooks->get_unix_time_in_ten_thousandths_of_second(platform_hooks->clock_context, &unix_time) != 0) {
        unix_time = 0; /* No clock: zero prefix (section 3.2 only requires the 80 random bits) */
    }
    /* The big-endian uint64 without its 2 most significant bytes */
    for (index = 0; index < WA_UUID0_TIME_PREFIX_SIZE; ++index) {
        uuid[index] = (uint8_t)(unix_time >> (8u * (WA_UUID0_TIME_PREFIX_SIZE - 1u - index)));
    }
    return wa_fill_random_bytes(platform_hooks, uuid + WA_UUID0_TIME_PREFIX_SIZE, WA_UUID0_RANDOM_PART_SIZE);
}
