/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WA_SECURE_MEMORY_WIPE_H
#define WA_SECURE_MEMORY_WIPE_H

#include <stddef.h>
#include <stdint.h>

/* Overwrite a buffer with zeros, in a way the compiler can't optimize away. NULL is accepted with length 0. */
void wa_secure_memory_wipe(void *buffer, size_t length);

/* 1 if every byte is zero, in time independent of the content, else 0. */
int wa_constant_time_is_all_zero(const uint8_t *bytes, size_t length);

#endif /* WA_SECURE_MEMORY_WIPE_H */
