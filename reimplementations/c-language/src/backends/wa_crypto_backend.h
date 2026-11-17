/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Internal crypto backend interface (design D3): bulk or costly primitives with no parameter ambiguity, fully
 * determined by their inputs. Every random input is drawn by portable code from the platform random hook and passed
 * in (design D6). Exactly one adapter implements it: wa_crypto_backend_mbedtls.c (Mbed TLS 3.6 + mlkem-native) or
 * wa_crypto_backend_wolfcrypt.c, selected with WA_CRYPTO_BACKEND_MBEDTLS / WA_CRYPTO_BACKEND_WOLFCRYPT.
 *
 * Contexts are opaque, allocated with the platform hooks, and wiped when destroyed. Backend errors map to
 * WA_STATUS_CRYPTO_BACKEND_FAILURE, allocation failures to WA_STATUS_OUT_OF_MEMORY. This header includes no
 * backend library header. */

#ifndef WA_CRYPTO_BACKEND_H
#define WA_CRYPTO_BACKEND_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_platform_hooks.h"
#include "wa_flightbox/wa_status_codes.h"

#define WA_AES_256_KEY_SIZE 32u
#define WA_AES_BLOCK_SIZE 16u
#define WA_CHACHA20_POLY1305_KEY_SIZE 32u
#define WA_CHACHA20_POLY1305_NONCE_SIZE 12u
#define WA_AEAD_TAG_SIZE 16u
#define WA_SHA256_DIGEST_SIZE 32u
#define WA_SHA512_DIGEST_SIZE 64u
#define WA_X25519_KEY_SIZE 32u
#define WA_ML_KEM_768_PUBLIC_KEY_SIZE 1184u
#define WA_ML_KEM_768_CIPHERTEXT_SIZE 1088u
#define WA_ML_KEM_768_SHARED_SECRET_SIZE 32u
#define WA_ML_KEM_768_COINS_SIZE 32u

/* A piece of input, for multi-part hashing without concatenation buffers. */
typedef struct wa_byte_span {
    const uint8_t *bytes;
    size_t length;
} wa_byte_span_t;

/* AES-256 (encryption direction only) */

typedef struct wa_crypto_backend_aes_256 wa_crypto_backend_aes_256_t;

wa_status_t wa_crypto_backend_aes_256_create(const wa_platform_hooks_t *platform_hooks,
                                             const uint8_t key[WA_AES_256_KEY_SIZE],
                                             wa_crypto_backend_aes_256_t **context_out);

/* CBC encryption of `length` bytes, a multiple of 16 (0 allowed). `chaining_value` holds the IV on input, and the
 * last ciphertext block on output, so that successive calls continue the same CBC stream. In-place allowed. */
wa_status_t wa_crypto_backend_aes_256_encrypt_cbc_blocks(wa_crypto_backend_aes_256_t *context,
                                                         uint8_t chaining_value[WA_AES_BLOCK_SIZE],
                                                         const uint8_t *input, uint8_t *output, size_t length);

/* CTR encryption of `length` bytes, a multiple of 16 (0 allowed). `counter_block` holds the initial counter on input,
 * and the next one on output, incremented as a 128-bit big-endian integer per block (as pycryptodome's EAX).
 * In-place allowed. */
wa_status_t wa_crypto_backend_aes_256_encrypt_ctr_blocks(wa_crypto_backend_aes_256_t *context,
                                                         uint8_t counter_block[WA_AES_BLOCK_SIZE],
                                                         const uint8_t *input, uint8_t *output, size_t length);

void wa_crypto_backend_aes_256_destroy(wa_crypto_backend_aes_256_t *context_or_null);

/* ChaCha20-Poly1305 (RFC 8439) streaming encryption */

typedef struct wa_crypto_backend_chacha20_poly1305 wa_crypto_backend_chacha20_poly1305_t;

/* Start an encryption, with its whole associated data (empty in cryptainers). */
wa_status_t wa_crypto_backend_chacha20_poly1305_create(const wa_platform_hooks_t *platform_hooks,
                                                       const uint8_t key[WA_CHACHA20_POLY1305_KEY_SIZE],
                                                       const uint8_t nonce[WA_CHACHA20_POLY1305_NONCE_SIZE],
                                                       const uint8_t *associated_data, size_t associated_data_length,
                                                       wa_crypto_backend_chacha20_poly1305_t **context_out);

/* Encrypt the next `length` bytes, any length (0 allowed). In-place allowed. */
wa_status_t wa_crypto_backend_chacha20_poly1305_encrypt(wa_crypto_backend_chacha20_poly1305_t *context,
                                                        const uint8_t *input, uint8_t *output, size_t length);

/* End the encryption and output the tag; the context only accepts destroy afterwards. */
wa_status_t wa_crypto_backend_chacha20_poly1305_finish(wa_crypto_backend_chacha20_poly1305_t *context,
                                                       uint8_t tag[WA_AEAD_TAG_SIZE]);

void wa_crypto_backend_chacha20_poly1305_destroy(wa_crypto_backend_chacha20_poly1305_t *context_or_null);

/* Hashes and HMAC (one shot over several parts) */

wa_status_t wa_crypto_backend_compute_sha256(const wa_byte_span_t *parts, size_t part_count,
                                             uint8_t digest[WA_SHA256_DIGEST_SIZE]);
wa_status_t wa_crypto_backend_compute_sha512(const wa_byte_span_t *parts, size_t part_count,
                                             uint8_t digest[WA_SHA512_DIGEST_SIZE]);
wa_status_t wa_crypto_backend_compute_hmac_sha256(const uint8_t *key, size_t key_length, const wa_byte_span_t *parts,
                                                  size_t part_count, uint8_t mac[WA_SHA256_DIGEST_SIZE]);

/* X25519 (RFC 7748): little-endian scalars and u-coordinates. The scalar is clamped and the top bit of u masked,
 * as RFC 7748 requires. A low-order input gives an all-zero output or a backend failure, depending on the backend:
 * callers check for zeros (profile loading rejects low-order public keys beforehand anyway). */

wa_status_t wa_crypto_backend_x25519_compute_public_key(const uint8_t private_scalar[WA_X25519_KEY_SIZE],
                                                        uint8_t public_key[WA_X25519_KEY_SIZE]);
wa_status_t wa_crypto_backend_x25519_compute_shared_secret(const uint8_t private_scalar[WA_X25519_KEY_SIZE],
                                                           const uint8_t peer_public_key[WA_X25519_KEY_SIZE],
                                                           uint8_t shared_secret[WA_X25519_KEY_SIZE]);

/* Raw RSA public operation output = input^e mod n, on big-endian byte strings of exactly `modulus_length` bytes;
 * `input` must be below the modulus. Only used inside the portable OAEP encoding. */
wa_status_t wa_crypto_backend_rsa_compute_public_operation(const wa_platform_hooks_t *platform_hooks,
                                                           const uint8_t *modulus, size_t modulus_length,
                                                           const uint8_t *public_exponent,
                                                           size_t public_exponent_length, const uint8_t *input,
                                                           uint8_t *output);

/* ML-KEM-768 deterministic encapsulation (FIPS 203 ML-KEM.Encaps_internal with the given 32 coins). The FIPS 203
 * modulus check of the public key is done by the portable profile loader (wa_public_key_constraints.c): adapters may
 * repeat it (mlkem-native does) or not (wolfCrypt doesn't). */
wa_status_t wa_crypto_backend_ml_kem_768_encapsulate_derandomized(
    const wa_platform_hooks_t *platform_hooks, const uint8_t public_key[WA_ML_KEM_768_PUBLIC_KEY_SIZE],
    const uint8_t coins[WA_ML_KEM_768_COINS_SIZE], uint8_t ciphertext[WA_ML_KEM_768_CIPHERTEXT_SIZE],
    uint8_t shared_secret[WA_ML_KEM_768_SHARED_SECRET_SIZE]);

#endif /* WA_CRYPTO_BACKEND_H */
