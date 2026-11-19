/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Minimal wolfSSL 5.8 user settings (WOLFSSL_USER_SETTINGS, included as "user_settings.h") for the flightbox C
 * encryptor: wolfCrypt only, with the primitives of the backend interface and nothing else.
 *
 * Used by the host CMake build, and a reference for device integrators. No wolfCrypt RNG is compiled
 * (WC_NO_RNG): every random input comes from the platform random hook. The adapter
 * (src/backends/wa_crypto_backend_wolfcrypt.c) checks each required option with #error.
 *
 * wolfCrypt allocates the working memory of RSA and ML-KEM with its own allocator, the malloc()/free() of the C
 * library here, and not with the platform hooks of the flightbox library. A device whose only heap is the one of
 * its hooks points wolfCrypt to that heap with XMALLOC_USER, wolfSSL_SetAllocators() or WOLFSSL_STATIC_MEMORY (see
 * README.md).
 *
 * WC_RSA_NO_PADDING is listed by wolfSSL among the options that weaken security: it exposes the raw RSA operation,
 * which the flightbox only uses inside its own OAEP encoding. */

#ifndef WA_WOLFSSL_USER_SETTINGS_FOR_FLIGHTBOX_H
#define WA_WOLFSSL_USER_SETTINGS_FOR_FLIGHTBOX_H

/* Platform */
#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define WOLFSSL_IGNORE_FILE_WARN
#define WC_NO_RNG
#define NO_ERROR_STRINGS

/* Windows hosts (MSYS2 MinGW-w64): with NO_FILESYSTEM, wolfSSL's MinGW branches use vsnprintf and size_t without
 * including their headers (C sources only: wolfSSL's assembly sources include the settings too) */
#if defined(__MINGW32__) && !defined(__ASSEMBLER__)
#include <stddef.h>
#include <stdio.h>
#endif

/* AES-256: bulk CBC (payload, CMAC/OMAC) and CTR (EAX) */
#define HAVE_AES_CBC
#define WOLFSSL_AES_COUNTER
#define NO_AES_128
#define NO_AES_192
#define WOLFSSL_AES_256

/* ChaCha20-Poly1305 */
#define HAVE_CHACHA
#define HAVE_POLY1305

/* Hashes and HMAC */
#define WOLFSSL_SHA512
#define NO_SHA
#define NO_MD5
#define NO_MD4

/* Raw RSA public operation from raw (n, e), up to 4096-bit moduli */
#define WC_RSA_NO_PADDING
#define WOLFSSL_RSA_PUBLIC_ONLY
#define WOLFSSL_SP_MATH_ALL
#define SP_INT_BITS 4096

/* X25519 */
#define HAVE_CURVE25519
/* No blinding: wolfCrypt's blinded wc_curve25519_generic() would create its own OS-seeded WC_RNG, a second source
 * of randomness (design D6). Only single-use HPKE ephemeral scalars are multiplied, on a constant-time ladder. */
#define NO_CURVE25519_BLINDING

/* ML-KEM-768, encapsulation only */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_NO_ML_KEM_512
#define WOLFSSL_NO_ML_KEM_1024
#define WOLFSSL_MLKEM_NO_MAKE_KEY
#define WOLFSSL_MLKEM_NO_DECAPSULATE
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* Everything else off */
#define NO_DSA
#define NO_DH
#define NO_DES3
#define NO_RC4
#define NO_PSK
#define NO_OLD_TLS
#define NO_PWDBASED
#define NO_SESSION_CACHE
#define NO_SIG_WRAPPER

#endif /* WA_WOLFSSL_USER_SETTINGS_FOR_FLIGHTBOX_H */
