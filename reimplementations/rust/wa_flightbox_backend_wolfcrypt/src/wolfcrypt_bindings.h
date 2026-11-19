/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* The wolfCrypt headers that bindgen reads, with the wolfSSL settings of the build: the structures get the layout
 * of the C code actually compiled. build.rs lists the functions, types and constants that are bound. */

#include "wolfssl/wolfcrypt/settings.h" /* Includes user_settings.h, with WOLFSSL_USER_SETTINGS */

#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/chacha.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/mlkem.h"
#include "wolfssl/wolfcrypt/poly1305.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/wc_mlkem.h"

/* Macros and enumerators that the adapter needs, as constants of a known type */
enum {
    WA_WOLFCRYPT_INVALID_DEVID = INVALID_DEVID,
    WA_WOLFCRYPT_AES_ENCRYPTION = AES_ENCRYPTION,
    WA_WOLFCRYPT_HMAC_SHA256 = WC_SHA256,
    WA_WOLFCRYPT_ML_KEM_768 = WC_ML_KEM_768,
    WA_WOLFCRYPT_RSA_PUBLIC_ENCRYPT = RSA_PUBLIC_ENCRYPT,
    WA_WOLFCRYPT_SP_INT_BITS = SP_INT_BITS
};
