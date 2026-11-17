/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_hpke_kem_dhkem_x25519.h"

#include <string.h>

#include "core/wa_platform_hooks_calls.h"
#include "primitives/wa_secure_memory_wipe.h"

static wa_status_t wa_hpke_dhkem_x25519_encapsulate(const wa_platform_hooks_t *platform_hooks,
                                                    const uint8_t *public_key, uint8_t *enc,
                                                    uint8_t shared_secret[WA_HPKE_SHARED_SECRET_SIZE])
{
    static const uint8_t kem_suite_id[WA_HPKE_KEM_SUITE_ID_SIZE] = {
        'K', 'E', 'M', (uint8_t)(WA_HPKE_KEM_ID_DHKEM_X25519 >> 8), (uint8_t)WA_HPKE_KEM_ID_DHKEM_X25519};
    uint8_t ephemeral_scalar[WA_X25519_KEY_SIZE];
    uint8_t dh[WA_X25519_KEY_SIZE];
    uint8_t eae_prk[WA_HKDF_SHA256_PRK_SIZE];
    uint8_t kem_context[2u * WA_X25519_KEY_SIZE]; /* enc || pkRm */
    wa_status_t status;
    status = wa_fill_random_bytes(platform_hooks, ephemeral_scalar, sizeof(ephemeral_scalar));
    if (status == WA_STATUS_OK) {
        status = wa_crypto_backend_x25519_compute_public_key(ephemeral_scalar, enc);
    }
    if (status == WA_STATUS_OK) {
        status = wa_crypto_backend_x25519_compute_shared_secret(ephemeral_scalar, public_key, dh);
        if (status == WA_STATUS_OK && wa_constant_time_is_all_zero(dh, sizeof(dh))) {
            status = WA_STATUS_KEY_CONSTRAINT_VIOLATION;
        }
    }
    wa_secure_memory_wipe(ephemeral_scalar, sizeof(ephemeral_scalar));
    if (status == WA_STATUS_OK) {
        memcpy(kem_context, enc, WA_X25519_KEY_SIZE);
        memcpy(kem_context + WA_X25519_KEY_SIZE, public_key, WA_X25519_KEY_SIZE);
        status = wa_hpke_labeled_extract(kem_suite_id, sizeof(kem_suite_id), NULL, 0, "eae_prk", dh, sizeof(dh),
                                         eae_prk);
    }
    if (status == WA_STATUS_OK) {
        status = wa_hpke_labeled_expand(kem_suite_id, sizeof(kem_suite_id), eae_prk, "shared_secret", kem_context,
                                        sizeof(kem_context), shared_secret, WA_HPKE_SHARED_SECRET_SIZE);
    }
    wa_secure_memory_wipe(dh, sizeof(dh));
    wa_secure_memory_wipe(eae_prk, sizeof(eae_prk));
    return status;
}

const wa_hpke_kem_t wa_hpke_kem_dhkem_x25519 = {WA_HPKE_KEM_ID_DHKEM_X25519, WA_X25519_KEY_SIZE, WA_X25519_KEY_SIZE,
                                                wa_hpke_dhkem_x25519_encapsulate};
