/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_hpke_kem_ml_kem_768.h"

#include "core/wa_platform_hooks_calls.h"
#include "primitives/wa_secure_memory_wipe.h"

static wa_status_t wa_hpke_ml_kem_768_encapsulate(const wa_platform_hooks_t *platform_hooks,
                                                  const uint8_t *public_key, uint8_t *enc,
                                                  uint8_t shared_secret[WA_HPKE_SHARED_SECRET_SIZE])
{
    uint8_t coins[WA_ML_KEM_768_COINS_SIZE];
    wa_status_t status = wa_fill_random_bytes(platform_hooks, coins, sizeof(coins));
    if (status == WA_STATUS_OK) {
        status = wa_crypto_backend_ml_kem_768_encapsulate_derandomized(platform_hooks, public_key, coins, enc,
                                                                       shared_secret);
    }
    wa_secure_memory_wipe(coins, sizeof(coins));
    if (status != WA_STATUS_OK) {
        wa_secure_memory_wipe(shared_secret, WA_HPKE_SHARED_SECRET_SIZE);
    }
    return status;
}

const wa_hpke_kem_t wa_hpke_kem_ml_kem_768 = {WA_HPKE_KEM_ID_ML_KEM_768, WA_ML_KEM_768_PUBLIC_KEY_SIZE,
                                              WA_ML_KEM_768_CIPHERTEXT_SIZE, wa_hpke_ml_kem_768_encapsulate};
