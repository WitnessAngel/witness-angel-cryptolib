/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* HPKE KEM 0x0020, DHKEM(X25519, HKDF-SHA256) (RFC 9180, section 4.1): the ECIES_X25519 key cipher. The ephemeral
 * scalar is 32 bytes from the random hook, used as the X25519 private key (as pycryptodome does). */

#ifndef WA_HPKE_KEM_DHKEM_X25519_H
#define WA_HPKE_KEM_DHKEM_X25519_H

#include "primitives/wa_hpke_base_mode_seal.h"

#define WA_HPKE_KEM_ID_DHKEM_X25519 0x0020u

/* Encapsulation fails with WA_STATUS_KEY_CONSTRAINT_VIOLATION if the Diffie-Hellman output is all zeros (a
 * low-order recipient key, which the profile loader rejects beforehand anyway). */
extern const wa_hpke_kem_t wa_hpke_kem_dhkem_x25519;

#endif /* WA_HPKE_KEM_DHKEM_X25519_H */
