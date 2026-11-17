/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* UUID0 (encryptor specification, section 3.2): used for cryptainer_uid and the default keychain_uid. */

#ifndef WA_UUID0_GENERATION_H
#define WA_UUID0_GENERATION_H

#include <stdint.h>

#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_status_codes.h"
#include "wa_flightbox/wa_value_tree.h"

#define WA_UUID0_TIME_PREFIX_SIZE 6u
#define WA_UUID0_RANDOM_PART_SIZE 10u

/* uuid = last 6 bytes of the big-endian uint64 Unix time in 1/10000 s || 10 random bytes, with no RFC 4122
 * version or variant bits. Without a clock hook, or when it reports no clock, the time prefix is zero. */
wa_status_t wa_uuid0_generate(const wa_platform_hooks_t *platform_hooks, uint8_t uuid[WA_UUID_SIZE]);

#endif /* WA_UUID0_GENERATION_H */
