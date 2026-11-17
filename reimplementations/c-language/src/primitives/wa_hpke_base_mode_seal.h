/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* HPKE (RFC 9180) Base mode, single-shot seal, KDF HKDF-SHA256 (0x0001), AEAD ChaCha20-Poly1305 (0x0003): the
 * ECIES_X25519 and ML_KEM_768 key ciphers of the encryptor specification, section 3.5. The KEM is a parameter
 * (wa_hpke_kem_dhkem_x25519.h, wa_hpke_kem_ml_kem_768.h); info and AAD are empty in cryptainers, and only settable
 * here for the RFC 9180 test vectors. */

#ifndef WA_HPKE_BASE_MODE_SEAL_H
#define WA_HPKE_BASE_MODE_SEAL_H

#include <stddef.h>
#include <stdint.h>

#include "backends/wa_crypto_backend.h"
#include "primitives/wa_hkdf_sha256.h"
#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_status_codes.h"
#include "wa_flightbox/wa_value_tree.h"

#define WA_HPKE_KDF_ID_HKDF_SHA256 0x0001u
#define WA_HPKE_AEAD_ID_CHACHA20_POLY1305 0x0003u
#define WA_HPKE_SHARED_SECRET_SIZE 32u
#define WA_HPKE_KEY_SIZE WA_CHACHA20_POLY1305_KEY_SIZE
#define WA_HPKE_NONCE_SIZE WA_CHACHA20_POLY1305_NONCE_SIZE
/* "KEM" || kem_id, or "HPKE" || kem_id || kdf_id || aead_id */
#define WA_HPKE_KEM_SUITE_ID_SIZE 5u
#define WA_HPKE_SUITE_ID_SIZE 10u

/* A KEM: its id, the lengths of its public keys and of `enc`, and its encapsulation, which draws its randomness
 * from the random hook and writes `enc` and the 32-byte shared secret. */
typedef struct wa_hpke_kem {
    uint16_t kem_id;
    size_t public_key_length;
    size_t enc_length;
    wa_status_t (*encapsulate)(const wa_platform_hooks_t *platform_hooks, const uint8_t *public_key, uint8_t *enc,
                               uint8_t shared_secret[WA_HPKE_SHARED_SECRET_SIZE]);
} wa_hpke_kem_t;

/* LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id || label || ikm) */
wa_status_t wa_hpke_labeled_extract(const uint8_t *suite_id, size_t suite_id_length, const uint8_t *salt,
                                    size_t salt_length, const char *label, const uint8_t *ikm, size_t ikm_length,
                                    uint8_t prk[WA_HKDF_SHA256_PRK_SIZE]);

/* LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L) */
wa_status_t wa_hpke_labeled_expand(const uint8_t *suite_id, size_t suite_id_length,
                                   const uint8_t prk[WA_HKDF_SHA256_PRK_SIZE], const char *label, const uint8_t *info,
                                   size_t info_length, uint8_t *output, size_t output_length);

/* KeySchedule for mode Base (empty psk and psk_id): the AEAD key and base nonce. */
wa_status_t wa_hpke_base_mode_key_schedule(uint16_t kem_id, const uint8_t shared_secret[WA_HPKE_SHARED_SECRET_SIZE],
                                           const uint8_t *info, size_t info_length, uint8_t key[WA_HPKE_KEY_SIZE],
                                           uint8_t base_nonce[WA_HPKE_NONCE_SIZE]);

/* Encapsulate to `public_key` (kem->public_key_length bytes), then seal `plaintext` at sequence number 0:
 * `enc` receives kem->enc_length bytes, `sealed` plaintext_length + 16 bytes (ciphertext || tag). */
wa_status_t wa_hpke_base_mode_seal(const wa_platform_hooks_t *platform_hooks, const wa_hpke_kem_t *kem,
                                   const uint8_t *public_key, const uint8_t *info, size_t info_length,
                                   const uint8_t *aad, size_t aad_length, const uint8_t *plaintext,
                                   size_t plaintext_length, uint8_t *enc, uint8_t *sealed);

/* Cipherdict {"kem_ciphertext": enc, "ciphertext": sealed} with empty info and AAD. */
wa_status_t wa_hpke_base_mode_seal_to_cipherdict(const wa_platform_hooks_t *platform_hooks, const wa_hpke_kem_t *kem,
                                                 const uint8_t *public_key, const uint8_t *plaintext,
                                                 size_t plaintext_length, wa_value_t **cipherdict_out);

#endif /* WA_HPKE_BASE_MODE_SEAL_H */
