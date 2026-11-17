/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Minimal Mbed TLS 3.6 configuration (MBEDTLS_CONFIG_FILE) for the flightbox C encryptor.
 *
 * Used by the host CMake build, and a reference for device integrators: on ESP-IDF, enable the same options in
 * menuconfig (see README.md). Only the legacy crypto API is used, without PSA nor any Mbed TLS RNG, since every
 * random input comes from the platform random hook. The adapter (src/backends/wa_crypto_backend_mbedtls.c)
 * checks each required option with #error. */

#ifndef WA_MBEDTLS_CONFIG_FOR_FLIGHTBOX_H
#define WA_MBEDTLS_CONFIG_FOR_FLIGHTBOX_H

/* System support */
#define MBEDTLS_HAVE_ASM

/* AES-256: bulk CBC (payload, CMAC/OMAC) and CTR (EAX) */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CTR

/* ChaCha20-Poly1305 (payload, HPKE AEAD) */
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C

/* Hashes and HMAC (OAEP, HPKE/HKDF) */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C

/* Raw RSA public operation; OAEP is encoded by the portable layer. MBEDTLS_RSA_C requires OID_C and a PKCS#1
 * version, though neither is used. */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_MPI_MAX_SIZE 1024 /* bytes: 8192-bit moduli at most (512 needed for 4096 bits) */

/* X25519 (HPKE DHKEM) */
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED

#endif /* WA_MBEDTLS_CONFIG_FOR_FLIGHTBOX_H */
