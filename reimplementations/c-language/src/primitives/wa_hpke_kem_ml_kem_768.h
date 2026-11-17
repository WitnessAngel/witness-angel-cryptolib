/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* HPKE KEM 0x0041, ML-KEM-768 (draft-ietf-hpke-pq, as pycryptodome 4.2's Crypto.Protocol.HPKE): the ML_KEM_768 key
 * cipher. `enc` is the ML-KEM ciphertext and the ML-KEM shared secret is used directly; the 32 encapsulation coins
 * come from the random hook. */

#ifndef WA_HPKE_KEM_ML_KEM_768_H
#define WA_HPKE_KEM_ML_KEM_768_H

#include "primitives/wa_hpke_base_mode_seal.h"

#define WA_HPKE_KEM_ID_ML_KEM_768 0x0041u

extern const wa_hpke_kem_t wa_hpke_kem_ml_kem_768;

#endif /* WA_HPKE_KEM_ML_KEM_768_H */
