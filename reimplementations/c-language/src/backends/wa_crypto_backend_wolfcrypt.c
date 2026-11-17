/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Crypto backend adapter for wolfCrypt 5.8 (wolfSSL without TLS), ML-KEM-768 included. */

#if defined(WA_CRYPTO_BACKEND_MBEDTLS) && defined(WA_CRYPTO_BACKEND_WOLFCRYPT)
#error "Select exactly one crypto backend: define WA_CRYPTO_BACKEND_MBEDTLS or WA_CRYPTO_BACKEND_WOLFCRYPT, not both"
#endif
#if !defined(WA_CRYPTO_BACKEND_MBEDTLS) && !defined(WA_CRYPTO_BACKEND_WOLFCRYPT)
#error "No crypto backend selected: define WA_CRYPTO_BACKEND_WOLFCRYPT (compile this file) or WA_CRYPTO_BACKEND_MBEDTLS (compile wa_crypto_backend_mbedtls.c instead), e.g. with cmake -DWA_CRYPTO_BACKEND=WOLFCRYPT"
#endif

#if defined(WA_CRYPTO_BACKEND_WOLFCRYPT)

#include "backends/wa_crypto_backend.h"

#include <string.h>

#include "wolfssl/wolfcrypt/settings.h" /* Includes user_settings.h, with WOLFSSL_USER_SETTINGS */

/* Required wolfCrypt options (see config/wa_wolfssl_user_settings_for_flightbox.h and README.md) */
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

#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/chacha20_poly1305.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/mlkem.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/wc_mlkem.h"

#include "core/wa_platform_hooks_calls.h"
#include "primitives/wa_secure_memory_wipe.h"
#include "wa_flightbox/wa_flightbox_config.h"

#if SP_INT_BITS < WA_MAX_RSA_MODULUS_BITS
#error "SP_INT_BITS is too small for WA_MAX_RSA_MODULUS_BITS"
#endif

/* wolfCrypt takes word32 lengths: longer inputs are processed in chunks */
#define WA_WOLFCRYPT_MAXIMUM_CHUNK ((size_t)0x40000000u)

static size_t wa_wolfcrypt_chunk_length(size_t remaining)
{
    return remaining < WA_WOLFCRYPT_MAXIMUM_CHUNK ? remaining : WA_WOLFCRYPT_MAXIMUM_CHUNK;
}

/* AES-256: aes->reg is the CBC chaining value and the CTR counter alike, so it is loaded before each call and read
 * back after it; whole blocks only, so no keystream is ever left over in aes->tmp. */

struct wa_crypto_backend_aes_256 {
    const wa_platform_hooks_t *platform_hooks;
    Aes aes;
};

wa_status_t wa_crypto_backend_aes_256_create(const wa_platform_hooks_t *platform_hooks,
                                             const uint8_t key[WA_AES_256_KEY_SIZE],
                                             wa_crypto_backend_aes_256_t **context_out)
{
    wa_crypto_backend_aes_256_t *context;
    *context_out = NULL;
    context = (wa_crypto_backend_aes_256_t *)wa_allocate_memory(platform_hooks, sizeof(*context));
    if (context == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    context->platform_hooks = platform_hooks;
    if (wc_AesInit(&context->aes, NULL, INVALID_DEVID) != 0) {
        wa_release_secret_memory(platform_hooks, context, sizeof(*context));
        return WA_STATUS_CRYPTO_BACKEND_FAILURE;
    }
    if (wc_AesSetKey(&context->aes, key, WA_AES_256_KEY_SIZE, NULL, AES_ENCRYPTION) != 0) {
        wa_crypto_backend_aes_256_destroy(context);
        return WA_STATUS_CRYPTO_BACKEND_FAILURE;
    }
    *context_out = context;
    return WA_STATUS_OK;
}

wa_status_t wa_crypto_backend_aes_256_encrypt_cbc_blocks(wa_crypto_backend_aes_256_t *context,
                                                         uint8_t chaining_value[WA_AES_BLOCK_SIZE],
                                                         const uint8_t *input, uint8_t *output, size_t length)
{
    if (length % WA_AES_BLOCK_SIZE != 0) {
        return WA_STATUS_INTERNAL_ERROR;
    }
    if (length == 0) {
        return WA_STATUS_OK;
    }
    if (wc_AesSetIV(&context->aes, chaining_value) != 0) {
        return WA_STATUS_CRYPTO_BACKEND_FAILURE;
    }
    while (length != 0) {
        /* The chunk length stays a multiple of the block size */
        word32 chunk = (word32)wa_wolfcrypt_chunk_length(length);
        if (wc_AesCbcEncrypt(&context->aes, output, input, chunk) != 0) {
            return WA_STATUS_CRYPTO_BACKEND_FAILURE;
        }
        input += chunk;
        output += chunk;
        length -= chunk;
    }
    memcpy(chaining_value, context->aes.reg, WA_AES_BLOCK_SIZE);
    return WA_STATUS_OK;
}

wa_status_t wa_crypto_backend_aes_256_encrypt_ctr_blocks(wa_crypto_backend_aes_256_t *context,
                                                         uint8_t counter_block[WA_AES_BLOCK_SIZE],
                                                         const uint8_t *input, uint8_t *output, size_t length)
{
    if (length % WA_AES_BLOCK_SIZE != 0) {
        return WA_STATUS_INTERNAL_ERROR;
    }
    if (length == 0) {
        return WA_STATUS_OK;
    }
    /* wc_AesSetIV() also discards any leftover keystream (aes->left = 0) */
    if (wc_AesSetIV(&context->aes, counter_block) != 0) {
        return WA_STATUS_CRYPTO_BACKEND_FAILURE;
    }
    while (length != 0) {
        word32 chunk = (word32)wa_wolfcrypt_chunk_length(length);
        if (wc_AesCtrEncrypt(&context->aes, output, input, chunk) != 0) {
            return WA_STATUS_CRYPTO_BACKEND_FAILURE;
        }
        input += chunk;
        output += chunk;
        length -= chunk;
    }
    /* Incremented as a 128-bit big-endian integer by wolfCrypt's IncrementAesCounter() */
    memcpy(counter_block, context->aes.reg, WA_AES_BLOCK_SIZE);
    return WA_STATUS_OK;
}

void wa_crypto_backend_aes_256_destroy(wa_crypto_backend_aes_256_t *context_or_null)
{
    if (context_or_null != NULL) {
        wc_AesFree(&context_or_null->aes);
        wa_release_secret_memory(context_or_null->platform_hooks, context_or_null, sizeof(*context_or_null));
    }
}

/* CHACHA20-POLY1305 */

struct wa_crypto_backend_chacha20_poly1305 {
    const wa_platform_hooks_t *platform_hooks;
    ChaChaPoly_Aead aead;
};

wa_status_t wa_crypto_backend_chacha20_poly1305_create(const wa_platform_hooks_t *platform_hooks,
                                                       const uint8_t key[WA_CHACHA20_POLY1305_KEY_SIZE],
                                                       const uint8_t nonce[WA_CHACHA20_POLY1305_NONCE_SIZE],
                                                       const uint8_t *associated_data, size_t associated_data_length,
                                                       wa_crypto_backend_chacha20_poly1305_t **context_out)
{
    wa_crypto_backend_chacha20_poly1305_t *context;
    int result;
    *context_out = NULL;
    if (associated_data_length > WA_WOLFCRYPT_MAXIMUM_CHUNK) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    context = (wa_crypto_backend_chacha20_poly1305_t *)wa_allocate_memory(platform_hooks, sizeof(*context));
    if (context == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    context->platform_hooks = platform_hooks;
    result = wc_ChaCha20Poly1305_Init(&context->aead, key, nonce, CHACHA20_POLY1305_AEAD_ENCRYPT);
    if (result == 0 && associated_data_length != 0) {
        result = wc_ChaCha20Poly1305_UpdateAad(&context->aead, associated_data, (word32)associated_data_length);
    }
    if (result != 0) {
        wa_crypto_backend_chacha20_poly1305_destroy(context);
        return WA_STATUS_CRYPTO_BACKEND_FAILURE;
    }
    *context_out = context;
    return WA_STATUS_OK;
}

wa_status_t wa_crypto_backend_chacha20_poly1305_encrypt(wa_crypto_backend_chacha20_poly1305_t *context,
                                                        const uint8_t *input, uint8_t *output, size_t length)
{
    while (length != 0) {
        word32 chunk = (word32)wa_wolfcrypt_chunk_length(length);
        if (wc_ChaCha20Poly1305_UpdateData(&context->aead, input, output, chunk) != 0) {
            return WA_STATUS_CRYPTO_BACKEND_FAILURE;
        }
        input += chunk;
        output += chunk;
        length -= chunk;
    }
    return WA_STATUS_OK;
}

wa_status_t wa_crypto_backend_chacha20_poly1305_finish(wa_crypto_backend_chacha20_poly1305_t *context,
                                                       uint8_t tag[WA_AEAD_TAG_SIZE])
{
    /* wc_ChaCha20Poly1305_Final() refuses the READY state, left when neither associated data nor data was given;
     * with both empty, the AAD state is equivalent (its padding is a no-op), and gives the RFC 8439 tag */
    if (context->aead.state == CHACHA20_POLY1305_STATE_READY) {
        context->aead.state = CHACHA20_POLY1305_STATE_AAD;
    }
    return wc_ChaCha20Poly1305_Final(&context->aead, tag) == 0 ? WA_STATUS_OK : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

void wa_crypto_backend_chacha20_poly1305_destroy(wa_crypto_backend_chacha20_poly1305_t *context_or_null)
{
    if (context_or_null != NULL) {
        wa_release_secret_memory(context_or_null->platform_hooks, context_or_null, sizeof(*context_or_null));
    }
}

/* HASHES AND HMAC (contexts live on the stack: no allocation) */

wa_status_t wa_crypto_backend_compute_sha256(const wa_byte_span_t *parts, size_t part_count,
                                             uint8_t digest[WA_SHA256_DIGEST_SIZE])
{
    wc_Sha256 sha256;
    size_t index;
    int result = wc_InitSha256_ex(&sha256, NULL, INVALID_DEVID);
    if (result != 0) {
        return WA_STATUS_CRYPTO_BACKEND_FAILURE;
    }
    for (index = 0; index < part_count && result == 0; index++) {
        const uint8_t *bytes = parts[index].bytes;
        size_t remaining = parts[index].length;
        while (remaining != 0 && result == 0) {
            word32 chunk = (word32)wa_wolfcrypt_chunk_length(remaining);
            result = wc_Sha256Update(&sha256, bytes, chunk);
            bytes += chunk;
            remaining -= chunk;
        }
    }
    if (result == 0) {
        result = wc_Sha256Final(&sha256, digest);
    }
    wc_Sha256Free(&sha256);
    wa_secure_memory_wipe(&sha256, sizeof(sha256));
    return result == 0 ? WA_STATUS_OK : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

wa_status_t wa_crypto_backend_compute_sha512(const wa_byte_span_t *parts, size_t part_count,
                                             uint8_t digest[WA_SHA512_DIGEST_SIZE])
{
    wc_Sha512 sha512;
    size_t index;
    int result = wc_InitSha512_ex(&sha512, NULL, INVALID_DEVID);
    if (result != 0) {
        return WA_STATUS_CRYPTO_BACKEND_FAILURE;
    }
    for (index = 0; index < part_count && result == 0; index++) {
        const uint8_t *bytes = parts[index].bytes;
        size_t remaining = parts[index].length;
        while (remaining != 0 && result == 0) {
            word32 chunk = (word32)wa_wolfcrypt_chunk_length(remaining);
            result = wc_Sha512Update(&sha512, bytes, chunk);
            bytes += chunk;
            remaining -= chunk;
        }
    }
    if (result == 0) {
        result = wc_Sha512Final(&sha512, digest);
    }
    wc_Sha512Free(&sha512);
    wa_secure_memory_wipe(&sha512, sizeof(sha512));
    return result == 0 ? WA_STATUS_OK : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

wa_status_t wa_crypto_backend_compute_hmac_sha256(const uint8_t *key, size_t key_length, const wa_byte_span_t *parts,
                                                  size_t part_count, uint8_t mac[WA_SHA256_DIGEST_SIZE])
{
    Hmac hmac;
    size_t index;
    int result;
    if (key_length > WA_WOLFCRYPT_MAXIMUM_CHUNK) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    result = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (result != 0) {
        return WA_STATUS_CRYPTO_BACKEND_FAILURE;
    }
    result = wc_HmacSetKey(&hmac, WC_SHA256, key, (word32)key_length);
    for (index = 0; index < part_count && result == 0; index++) {
        const uint8_t *bytes = parts[index].bytes;
        size_t remaining = parts[index].length;
        while (remaining != 0 && result == 0) {
            word32 chunk = (word32)wa_wolfcrypt_chunk_length(remaining);
            result = wc_HmacUpdate(&hmac, bytes, chunk);
            bytes += chunk;
            remaining -= chunk;
        }
    }
    if (result == 0) {
        result = wc_HmacFinal(&hmac, mac);
    }
    wc_HmacFree(&hmac);
    wa_secure_memory_wipe(&hmac, sizeof(hmac)); /* The pads hold the key */
    return result == 0 ? WA_STATUS_OK : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

/* X25519: wc_curve25519_generic() requires a clamped scalar, so the adapter clamps it first */

static wa_status_t wa_x25519_multiply(const uint8_t private_scalar[WA_X25519_KEY_SIZE],
                                      const uint8_t point[WA_X25519_KEY_SIZE], uint8_t output[WA_X25519_KEY_SIZE])
{
    uint8_t clamped_scalar[WA_X25519_KEY_SIZE];
    uint8_t masked_point[WA_X25519_KEY_SIZE];
    int result;
    memcpy(clamped_scalar, private_scalar, sizeof(clamped_scalar));
    clamped_scalar[0] = (uint8_t)(clamped_scalar[0] & 248u);
    clamped_scalar[31] = (uint8_t)((clamped_scalar[31] & 127u) | 64u);
    memcpy(masked_point, point, sizeof(masked_point));
    masked_point[31] = (uint8_t)(masked_point[31] & 127u);
    result = wc_curve25519_generic(WA_X25519_KEY_SIZE, output, WA_X25519_KEY_SIZE, clamped_scalar,
                                   WA_X25519_KEY_SIZE, masked_point);
    wa_secure_memory_wipe(clamped_scalar, sizeof(clamped_scalar));
    return result == 0 ? WA_STATUS_OK : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

wa_status_t wa_crypto_backend_x25519_compute_public_key(const uint8_t private_scalar[WA_X25519_KEY_SIZE],
                                                        uint8_t public_key[WA_X25519_KEY_SIZE])
{
    static const uint8_t base_point[WA_X25519_KEY_SIZE] = {9};
    return wa_x25519_multiply(private_scalar, base_point, public_key);
}

wa_status_t wa_crypto_backend_x25519_compute_shared_secret(const uint8_t private_scalar[WA_X25519_KEY_SIZE],
                                                           const uint8_t peer_public_key[WA_X25519_KEY_SIZE],
                                                           uint8_t shared_secret[WA_X25519_KEY_SIZE])
{
    return wa_x25519_multiply(private_scalar, peer_public_key, shared_secret);
}

/* RAW RSA (RsaKey is large: allocated through the hooks) */

wa_status_t wa_crypto_backend_rsa_compute_public_operation(const wa_platform_hooks_t *platform_hooks,
                                                           const uint8_t *modulus, size_t modulus_length,
                                                           const uint8_t *public_exponent,
                                                           size_t public_exponent_length, const uint8_t *input,
                                                           uint8_t *output)
{
    RsaKey *rsa_key;
    word32 output_length = (word32)modulus_length;
    int result;
    if (modulus_length > WA_MAX_RSA_MODULUS_BITS / 8 || public_exponent_length > modulus_length) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    /* wc_RsaDirect() doesn't check that the input is below the modulus: refused here, as mbedtls_rsa_public() does
     * (big-endian byte strings of the same length compare like the integers) */
    if (memcmp(input, modulus, modulus_length) >= 0) {
        return WA_STATUS_CRYPTO_BACKEND_FAILURE;
    }
    rsa_key = (RsaKey *)wa_allocate_memory(platform_hooks, sizeof(*rsa_key));
    if (rsa_key == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    result = wc_InitRsaKey_ex(rsa_key, NULL, INVALID_DEVID);
    if (result != 0) {
        wa_release_memory(platform_hooks, rsa_key, sizeof(*rsa_key));
        return WA_STATUS_CRYPTO_BACKEND_FAILURE;
    }
    result = wc_RsaPublicKeyDecodeRaw(modulus, (word32)modulus_length, public_exponent,
                                      (word32)public_exponent_length, rsa_key);
    if (result == 0 && wc_RsaEncryptSize(rsa_key) != (int)modulus_length) {
        result = -1;
    }
    if (result == 0) {
        result = wc_RsaDirect(input, (word32)modulus_length, output, &output_length, rsa_key, RSA_PUBLIC_ENCRYPT,
                              NULL);
        result = (result == (int)modulus_length && output_length == (word32)modulus_length) ? 0 : -1;
    }
    wc_FreeRsaKey(rsa_key);
    wa_release_memory(platform_hooks, rsa_key, sizeof(*rsa_key)); /* Public material only */
    return result == 0 ? WA_STATUS_OK : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

/* ML-KEM-768 (MlKemKey is large: allocated through the hooks) */

wa_status_t wa_crypto_backend_ml_kem_768_encapsulate_derandomized(
    const wa_platform_hooks_t *platform_hooks, const uint8_t public_key[WA_ML_KEM_768_PUBLIC_KEY_SIZE],
    const uint8_t coins[WA_ML_KEM_768_COINS_SIZE], uint8_t ciphertext[WA_ML_KEM_768_CIPHERTEXT_SIZE],
    uint8_t shared_secret[WA_ML_KEM_768_SHARED_SECRET_SIZE])
{
    MlKemKey *ml_kem_key;
    int result;
    ml_kem_key = (MlKemKey *)wa_allocate_memory(platform_hooks, sizeof(*ml_kem_key));
    if (ml_kem_key == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    result = wc_MlKemKey_Init(ml_kem_key, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (result != 0) {
        wa_release_memory(platform_hooks, ml_kem_key, sizeof(*ml_kem_key));
        return WA_STATUS_CRYPTO_BACKEND_FAILURE;
    }
    result = wc_MlKemKey_DecodePublicKey(ml_kem_key, public_key, WA_ML_KEM_768_PUBLIC_KEY_SIZE);
    if (result == 0) {
        result = wc_MlKemKey_EncapsulateWithRandom(ml_kem_key, ciphertext, shared_secret, coins,
                                                   (int)WA_ML_KEM_768_COINS_SIZE);
    }
    wc_MlKemKey_Free(ml_kem_key);
    wa_release_secret_memory(platform_hooks, ml_kem_key, sizeof(*ml_kem_key));
    return result == 0 ? WA_STATUS_OK : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

#endif /* WA_CRYPTO_BACKEND_WOLFCRYPT */
