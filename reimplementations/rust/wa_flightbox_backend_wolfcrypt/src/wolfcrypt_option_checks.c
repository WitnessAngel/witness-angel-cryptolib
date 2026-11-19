/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Compiled first by build.rs, with the wolfSSL settings of the build: each wolfCrypt option that the backend needs
 * is checked here, so that a missing one stops the build by its name instead of a link error. Same list as the C
 * adapter (reimplementations/c-language/src/backends/wa_crypto_backend_wolfcrypt.c). */

#include "wolfssl/wolfcrypt/settings.h" /* Includes user_settings.h, with WOLFSSL_USER_SETTINGS */

#if defined(NO_AES) || !defined(HAVE_AES_CBC)
#error "The flightbox wolfCrypt backend requires AES with HAVE_AES_CBC"
#endif
#if !defined(WOLFSSL_AES_COUNTER)
#error "The flightbox wolfCrypt backend requires WOLFSSL_AES_COUNTER"
#endif
#if !defined(WOLFSSL_AES_256)
#error "The flightbox wolfCrypt backend requires WOLFSSL_AES_256"
#endif
#if !defined(HAVE_CHACHA) || !defined(HAVE_POLY1305)
#error "The flightbox wolfCrypt backend requires HAVE_CHACHA and HAVE_POLY1305"
#endif
#if defined(NO_SHA256)
#error "The flightbox wolfCrypt backend requires SHA-256: undefine NO_SHA256"
#endif
#if !defined(WOLFSSL_SHA512)
#error "The flightbox wolfCrypt backend requires WOLFSSL_SHA512"
#endif
#if defined(NO_HMAC)
#error "The flightbox wolfCrypt backend requires HMAC: undefine NO_HMAC"
#endif
#if defined(NO_RSA) || !defined(WC_RSA_NO_PADDING)
#error "The flightbox wolfCrypt backend requires RSA with WC_RSA_NO_PADDING (raw public operation)"
#endif
#if !defined(HAVE_CURVE25519)
#error "The flightbox wolfCrypt backend requires HAVE_CURVE25519"
#endif
#if defined(WOLFSSL_CURVE25519_BLINDING)
#error "The flightbox wolfCrypt backend needs wc_curve25519_generic() without its internal RNG: define NO_CURVE25519_BLINDING"
#endif
#if !defined(WOLFSSL_HAVE_MLKEM) || !defined(WOLFSSL_WC_MLKEM)
#error "The flightbox wolfCrypt backend requires WOLFSSL_HAVE_MLKEM and WOLFSSL_WC_MLKEM (ML-KEM-768 encapsulation)"
#endif
#if defined(WOLFSSL_NO_ML_KEM_768) || defined(WOLFSSL_MLKEM_NO_ENCAPSULATE)
#error "The flightbox wolfCrypt backend requires ML-KEM-768 encapsulation"
#endif
#if !defined(SP_INT_BITS) || SP_INT_BITS < 4096
#error "The flightbox wolfCrypt backend requires SP_INT_BITS >= 4096, for 4096-bit RSA moduli"
#endif

/* ISO C forbids an empty translation unit */
typedef int wa_flightbox_wolfcrypt_option_checks_t;
