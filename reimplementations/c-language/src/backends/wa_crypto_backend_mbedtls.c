/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Crypto backend adapter for Mbed TLS 3.6 (legacy crypto API), plus the vendored mlkem-native for ML-KEM-768. */

#if defined(WA_CRYPTO_BACKEND_MBEDTLS) && defined(WA_CRYPTO_BACKEND_WOLFCRYPT)
#error "Select exactly one crypto backend: define WA_CRYPTO_BACKEND_MBEDTLS or WA_CRYPTO_BACKEND_WOLFCRYPT, not both"
#endif
#if !defined(WA_CRYPTO_BACKEND_MBEDTLS) && !defined(WA_CRYPTO_BACKEND_WOLFCRYPT)
#error "No crypto backend selected: define WA_CRYPTO_BACKEND_MBEDTLS (compile this file) or WA_CRYPTO_BACKEND_WOLFCRYPT (compile wa_crypto_backend_wolfcrypt.c instead), e.g. with cmake -DWA_CRYPTO_BACKEND=MBEDTLS"
#endif

#if defined(WA_CRYPTO_BACKEND_MBEDTLS)

#include "backends/wa_crypto_backend.h"

#include <string.h>

#include "mbedtls/build_info.h"

/* Required Mbed TLS options (see config/wa_mbedtls_config_for_flightbox.h and README.md) */
#if !defined(MBEDTLS_AES_C)
#error "The flightbox Mbed TLS backend requires MBEDTLS_AES_C"
#endif
#if defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
#error "The flightbox Mbed TLS backend requires AES-256: undefine MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH"
#endif
#if !defined(MBEDTLS_CIPHER_MODE_CBC)
#error "The flightbox Mbed TLS backend requires MBEDTLS_CIPHER_MODE_CBC"
#endif
#if !defined(MBEDTLS_CIPHER_MODE_CTR)
#error "The flightbox Mbed TLS backend requires MBEDTLS_CIPHER_MODE_CTR"
#endif
#if !defined(MBEDTLS_CHACHAPOLY_C)
#error "The flightbox Mbed TLS backend requires MBEDTLS_CHACHAPOLY_C (with MBEDTLS_CHACHA20_C and MBEDTLS_POLY1305_C)"
#endif
#if !defined(MBEDTLS_CHACHA20_C)
#error "The flightbox Mbed TLS backend requires MBEDTLS_CHACHA20_C"
#endif
#if !defined(MBEDTLS_POLY1305_C)
#error "The flightbox Mbed TLS backend requires MBEDTLS_POLY1305_C"
#endif
#if !defined(MBEDTLS_SHA256_C)
#error "The flightbox Mbed TLS backend requires MBEDTLS_SHA256_C"
#endif
#if !defined(MBEDTLS_SHA512_C)
#error "The flightbox Mbed TLS backend requires MBEDTLS_SHA512_C"
#endif
#if !defined(MBEDTLS_MD_C)
#error "The flightbox Mbed TLS backend requires MBEDTLS_MD_C"
#endif
#if !defined(MBEDTLS_BIGNUM_C)
#error "The flightbox Mbed TLS backend requires MBEDTLS_BIGNUM_C"
#endif
#if !defined(MBEDTLS_RSA_C)
#error "The flightbox Mbed TLS backend requires MBEDTLS_RSA_C"
#endif
#if !defined(MBEDTLS_ECP_C)
#error "The flightbox Mbed TLS backend requires MBEDTLS_ECP_C"
#endif
#if !defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
#error "The flightbox Mbed TLS backend requires MBEDTLS_ECP_DP_CURVE25519_ENABLED"
#endif
#if MBEDTLS_MPI_MAX_SIZE < 512
#error "The flightbox Mbed TLS backend requires MBEDTLS_MPI_MAX_SIZE >= 512 (bytes), for 4096-bit RSA moduli"
#endif
#if MBEDTLS_MPI_MAX_SIZE * 8 < WA_MAX_RSA_MODULUS_BITS
#error "MBEDTLS_MPI_MAX_SIZE is too small for WA_MAX_RSA_MODULUS_BITS"
#endif

#include "mbedtls/aes.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#include "core/wa_platform_hooks_calls.h"
#include "mlkem/mlkem_native.h"
#include "wa_flightbox/wa_flightbox_config.h"

/* AES-256 */

struct wa_crypto_backend_aes_256 {
    const wa_platform_hooks_t *platform_hooks;
    mbedtls_aes_context aes;
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
    mbedtls_aes_init(&context->aes);
    if (mbedtls_aes_setkey_enc(&context->aes, key, 256) != 0) {
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
    /* mbedtls_aes_crypt_cbc() leaves the last ciphertext block in the IV buffer */
    if (mbedtls_aes_crypt_cbc(&context->aes, MBEDTLS_AES_ENCRYPT, length, chaining_value, input, output) != 0) {
        return WA_STATUS_CRYPTO_BACKEND_FAILURE;
    }
    return WA_STATUS_OK;
}

wa_status_t wa_crypto_backend_aes_256_encrypt_ctr_blocks(wa_crypto_backend_aes_256_t *context,
                                                         uint8_t counter_block[WA_AES_BLOCK_SIZE],
                                                         const uint8_t *input, uint8_t *output, size_t length)
{
    unsigned char stream_block[WA_AES_BLOCK_SIZE];
    size_t stream_offset = 0;
    int result;
    if (length % WA_AES_BLOCK_SIZE != 0) {
        return WA_STATUS_INTERNAL_ERROR;
    }
    if (length == 0) {
        return WA_STATUS_OK;
    }
    /* Whole blocks: the offset stays 0, and the counter (incremented as a 128-bit big-endian integer) is updated */
    result = mbedtls_aes_crypt_ctr(&context->aes, length, &stream_offset, counter_block, stream_block, input, output);
    mbedtls_platform_zeroize(stream_block, sizeof(stream_block));
    return result == 0 ? WA_STATUS_OK : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

void wa_crypto_backend_aes_256_destroy(wa_crypto_backend_aes_256_t *context_or_null)
{
    if (context_or_null != NULL) {
        mbedtls_aes_free(&context_or_null->aes);
        wa_release_secret_memory(context_or_null->platform_hooks, context_or_null, sizeof(*context_or_null));
    }
}

/* CHACHA20-POLY1305 */

struct wa_crypto_backend_chacha20_poly1305 {
    const wa_platform_hooks_t *platform_hooks;
    mbedtls_chachapoly_context chachapoly;
};

wa_status_t wa_crypto_backend_chacha20_poly1305_create(const wa_platform_hooks_t *platform_hooks,
                                                       const uint8_t key[WA_CHACHA20_POLY1305_KEY_SIZE],
                                                       const uint8_t nonce[WA_CHACHA20_POLY1305_NONCE_SIZE],
                                                       const uint8_t *associated_data, size_t associated_data_length,
                                                       wa_crypto_backend_chacha20_poly1305_t **context_out)
{
    wa_crypto_backend_chacha20_poly1305_t *context;
    *context_out = NULL;
    context = (wa_crypto_backend_chacha20_poly1305_t *)wa_allocate_memory(platform_hooks, sizeof(*context));
    if (context == NULL) {
        return WA_STATUS_OUT_OF_MEMORY;
    }
    context->platform_hooks = platform_hooks;
    mbedtls_chachapoly_init(&context->chachapoly);
    if (mbedtls_chachapoly_setkey(&context->chachapoly, key) != 0 ||
        mbedtls_chachapoly_starts(&context->chachapoly, nonce, MBEDTLS_CHACHAPOLY_ENCRYPT) != 0 ||
        (associated_data_length != 0 &&
         mbedtls_chachapoly_update_aad(&context->chachapoly, associated_data, associated_data_length) != 0)) {
        wa_crypto_backend_chacha20_poly1305_destroy(context);
        return WA_STATUS_CRYPTO_BACKEND_FAILURE;
    }
    *context_out = context;
    return WA_STATUS_OK;
}

wa_status_t wa_crypto_backend_chacha20_poly1305_encrypt(wa_crypto_backend_chacha20_poly1305_t *context,
                                                        const uint8_t *input, uint8_t *output, size_t length)
{
    if (length == 0) {
        return WA_STATUS_OK;
    }
    return mbedtls_chachapoly_update(&context->chachapoly, length, input, output) == 0
               ? WA_STATUS_OK
               : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

wa_status_t wa_crypto_backend_chacha20_poly1305_finish(wa_crypto_backend_chacha20_poly1305_t *context,
                                                       uint8_t tag[WA_AEAD_TAG_SIZE])
{
    return mbedtls_chachapoly_finish(&context->chachapoly, tag) == 0 ? WA_STATUS_OK
                                                                      : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

void wa_crypto_backend_chacha20_poly1305_destroy(wa_crypto_backend_chacha20_poly1305_t *context_or_null)
{
    if (context_or_null != NULL) {
        mbedtls_chachapoly_free(&context_or_null->chachapoly);
        wa_release_secret_memory(context_or_null->platform_hooks, context_or_null, sizeof(*context_or_null));
    }
}

/* HASHES AND HMAC (sha256/sha512 contexts live on the stack: no allocation) */

wa_status_t wa_crypto_backend_compute_sha256(const wa_byte_span_t *parts, size_t part_count,
                                             uint8_t digest[WA_SHA256_DIGEST_SIZE])
{
    mbedtls_sha256_context sha256;
    size_t index;
    int result;
    mbedtls_sha256_init(&sha256);
    result = mbedtls_sha256_starts(&sha256, 0);
    for (index = 0; index < part_count && result == 0; index++) {
        result = mbedtls_sha256_update(&sha256, parts[index].bytes, parts[index].length);
    }
    if (result == 0) {
        result = mbedtls_sha256_finish(&sha256, digest);
    }
    mbedtls_sha256_free(&sha256);
    return result == 0 ? WA_STATUS_OK : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

wa_status_t wa_crypto_backend_compute_sha512(const wa_byte_span_t *parts, size_t part_count,
                                             uint8_t digest[WA_SHA512_DIGEST_SIZE])
{
    mbedtls_sha512_context sha512;
    size_t index;
    int result;
    mbedtls_sha512_init(&sha512);
    result = mbedtls_sha512_starts(&sha512, 0);
    for (index = 0; index < part_count && result == 0; index++) {
        result = mbedtls_sha512_update(&sha512, parts[index].bytes, parts[index].length);
    }
    if (result == 0) {
        result = mbedtls_sha512_finish(&sha512, digest);
    }
    mbedtls_sha512_free(&sha512);
    return result == 0 ? WA_STATUS_OK : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

wa_status_t wa_crypto_backend_compute_hmac_sha256(const uint8_t *key, size_t key_length, const wa_byte_span_t *parts,
                                                  size_t part_count, uint8_t mac[WA_SHA256_DIGEST_SIZE])
{
    mbedtls_md_context_t md;
    size_t index;
    int result;
    mbedtls_md_init(&md);
    result = mbedtls_md_setup(&md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (result == 0) {
        result = mbedtls_md_hmac_starts(&md, key, key_length);
    }
    for (index = 0; index < part_count && result == 0; index++) {
        result = mbedtls_md_hmac_update(&md, parts[index].bytes, parts[index].length);
    }
    if (result == 0) {
        result = mbedtls_md_hmac_finish(&md, mac);
    }
    mbedtls_md_free(&md); /* Zeroizes the HMAC pads */
    return result == 0 ? WA_STATUS_OK : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

/* X25519
 *
 * mbedtls_ecp_mul() requires an RNG for the blinding of its Montgomery ladder. To keep a single source of
 * randomness (design D6), the blinding bytes are derived from the private scalar and the input point, by
 * SHA-256 in counter mode: they stay unpredictable to an attacker who doesn't know the scalar, and outputs don't
 * depend on them. Mbed TLS rejects low-order input points itself (an error, where wolfCrypt outputs zeros). */

typedef struct wa_x25519_blinding_generator {
    uint8_t seed[2 * WA_X25519_KEY_SIZE];
    uint32_t counter;
} wa_x25519_blinding_generator_t;

static int wa_x25519_generate_blinding_bytes(void *generator_context, unsigned char *output, size_t length)
{
    wa_x25519_blinding_generator_t *generator = (wa_x25519_blinding_generator_t *)generator_context;
    uint8_t block[WA_SHA256_DIGEST_SIZE];
    while (length != 0) {
        uint8_t counter_bytes[4];
        wa_byte_span_t parts[2];
        size_t copied = length < sizeof(block) ? length : sizeof(block);
        counter_bytes[0] = (uint8_t)(generator->counter >> 24);
        counter_bytes[1] = (uint8_t)(generator->counter >> 16);
        counter_bytes[2] = (uint8_t)(generator->counter >> 8);
        counter_bytes[3] = (uint8_t)generator->counter;
        generator->counter++;
        parts[0].bytes = generator->seed;
        parts[0].length = sizeof(generator->seed);
        parts[1].bytes = counter_bytes;
        parts[1].length = sizeof(counter_bytes);
        if (wa_crypto_backend_compute_sha256(parts, 2, block) != WA_STATUS_OK) {
            mbedtls_platform_zeroize(block, sizeof(block));
            return -1;
        }
        memcpy(output, block, copied);
        output += copied;
        length -= copied;
    }
    mbedtls_platform_zeroize(block, sizeof(block));
    return 0;
}

static wa_status_t wa_x25519_multiply(const uint8_t private_scalar[WA_X25519_KEY_SIZE],
                                      const uint8_t point_bytes[WA_X25519_KEY_SIZE],
                                      uint8_t output[WA_X25519_KEY_SIZE])
{
    mbedtls_ecp_group group;
    mbedtls_ecp_point point;
    mbedtls_ecp_point result_point;
    mbedtls_mpi scalar;
    wa_x25519_blinding_generator_t generator;
    uint8_t clamped_scalar[WA_X25519_KEY_SIZE];
    uint8_t masked_point[WA_X25519_KEY_SIZE];
    size_t output_length = 0;
    int result;

    memcpy(clamped_scalar, private_scalar, sizeof(clamped_scalar));
    clamped_scalar[0] = (uint8_t)(clamped_scalar[0] & 248u);
    clamped_scalar[31] = (uint8_t)((clamped_scalar[31] & 127u) | 64u);
    memcpy(masked_point, point_bytes, sizeof(masked_point));
    masked_point[31] = (uint8_t)(masked_point[31] & 127u);

    memcpy(generator.seed, clamped_scalar, WA_X25519_KEY_SIZE);
    memcpy(generator.seed + WA_X25519_KEY_SIZE, masked_point, WA_X25519_KEY_SIZE);
    generator.counter = 0;

    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&point);
    mbedtls_ecp_point_init(&result_point);
    mbedtls_mpi_init(&scalar);

    result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_CURVE25519);
    if (result == 0) {
        result = mbedtls_mpi_read_binary_le(&scalar, clamped_scalar, sizeof(clamped_scalar));
    }
    if (result == 0) {
        /* Montgomery curves: little-endian u-coordinate, Z set to 1 */
        result = mbedtls_ecp_point_read_binary(&group, &point, masked_point, sizeof(masked_point));
    }
    if (result == 0) {
        result = mbedtls_ecp_mul(&group, &result_point, &scalar, &point, wa_x25519_generate_blinding_bytes,
                                 &generator);
    }
    if (result == 0) {
        result = mbedtls_ecp_point_write_binary(&group, &result_point, MBEDTLS_ECP_PF_UNCOMPRESSED, &output_length,
                                                output, WA_X25519_KEY_SIZE);
    }
    if (result == 0 && output_length != WA_X25519_KEY_SIZE) {
        result = -1;
    }

    mbedtls_mpi_free(&scalar);
    mbedtls_ecp_point_free(&result_point);
    mbedtls_ecp_point_free(&point);
    mbedtls_ecp_group_free(&group);
    mbedtls_platform_zeroize(clamped_scalar, sizeof(clamped_scalar));
    mbedtls_platform_zeroize(&generator, sizeof(generator));
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

/* RAW RSA */

wa_status_t wa_crypto_backend_rsa_compute_public_operation(const wa_platform_hooks_t *platform_hooks,
                                                           const uint8_t *modulus, size_t modulus_length,
                                                           const uint8_t *public_exponent,
                                                           size_t public_exponent_length, const uint8_t *input,
                                                           uint8_t *output)
{
    mbedtls_rsa_context rsa;
    int result;
    (void)platform_hooks;
    mbedtls_rsa_init(&rsa);
    result = mbedtls_rsa_import_raw(&rsa, modulus, modulus_length, NULL, 0, NULL, 0, NULL, 0, public_exponent,
                                    public_exponent_length);
    if (result == 0) {
        result = mbedtls_rsa_complete(&rsa);
    }
    if (result == 0 && mbedtls_rsa_get_len(&rsa) != modulus_length) {
        result = -1;
    }
    if (result == 0) {
        result = mbedtls_rsa_public(&rsa, input, output);
    }
    mbedtls_rsa_free(&rsa);
    return result == 0 ? WA_STATUS_OK : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

/* ML-KEM-768 (mlkem-native) */

wa_status_t wa_crypto_backend_ml_kem_768_encapsulate_derandomized(
    const wa_platform_hooks_t *platform_hooks, const uint8_t public_key[WA_ML_KEM_768_PUBLIC_KEY_SIZE],
    const uint8_t coins[WA_ML_KEM_768_COINS_SIZE], uint8_t ciphertext[WA_ML_KEM_768_CIPHERTEXT_SIZE],
    uint8_t shared_secret[WA_ML_KEM_768_SHARED_SECRET_SIZE])
{
    (void)platform_hooks;
    return wa_mlkem_enc_derand(ciphertext, shared_secret, public_key, coins) == 0 ? WA_STATUS_OK
                                                                                  : WA_STATUS_CRYPTO_BACKEND_FAILURE;
}

#endif /* WA_CRYPTO_BACKEND_MBEDTLS */
