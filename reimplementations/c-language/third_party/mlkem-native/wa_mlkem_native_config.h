/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* mlkem-native configuration (MLK_CONFIG_FILE) for the Mbed TLS backend of the flightbox encryptor: ML-KEM-768
 * only, portable C (no native backend), and the deterministic encapsulation alone, since every random input comes
 * from the platform random hook (design D5, D6). */

#ifndef WA_MLKEM_NATIVE_CONFIG_H
#define WA_MLKEM_NATIVE_CONFIG_H

#define MLK_CONFIG_PARAMETER_SET 768
#define MLK_CONFIG_NAMESPACE_PREFIX wa_mlkem

/* Only wa_mlkem_enc_derand() is used: no key generation, no decapsulation, no internal randomness */
#define MLK_CONFIG_NO_KEYPAIR_API
#define MLK_CONFIG_NO_DECAPS_API
#define MLK_CONFIG_NO_RANDOMIZED_API

/* Single compilation unit: internal functions stay private to it */
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static

#endif /* WA_MLKEM_NATIVE_CONFIG_H */
