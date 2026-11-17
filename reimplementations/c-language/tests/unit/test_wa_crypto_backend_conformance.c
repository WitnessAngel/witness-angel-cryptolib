/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Crypto backend conformance test (tasks 4.2 and 4.3): the same file runs unchanged against each adapter, with the
 * published vectors of SP 800-38A, RFC 8439, FIPS 180-4, RFC 4231 and RFC 7748, raw RSA known values and an
 * ML-KEM-768 deterministic encapsulation computed with pycryptodome (see generate_backend_conformance_vectors.py). */

/* Included first: the backend interface compiles standalone (task 4.1) */
#include "backends/wa_crypto_backend.h"

#include <stdlib.h>
#include <string.h>

#include "wa_backend_conformance_vectors.h"
#include "wa_minimal_test_harness.h"
#include "wa_test_support.h"

#define WA_ARRAY_LENGTH(array) (sizeof(array) / sizeof((array)[0]))

static uint8_t *decode(const char *hex, size_t *length_out)
{
    uint8_t *bytes = wa_test_decode_hex(hex, length_out);
    if (bytes == NULL) {
        abort(); /* Malformed vector: a bug of the generator */
    }
    return bytes;
}

/* AES-256 */

static void check_cbc_split(wa_crypto_backend_aes_256_t *context, const uint8_t *plaintext,
                            const uint8_t *expected_ciphertext, const size_t *split_lengths, size_t split_count)
{
    uint8_t chaining_value[WA_AES_BLOCK_SIZE];
    uint8_t output[64];
    size_t offset = 0;
    size_t index;
    memcpy(chaining_value, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);
    for (index = 0; index < split_count; ++index) {
        WA_CHECK_STATUS(wa_crypto_backend_aes_256_encrypt_cbc_blocks(context, chaining_value, plaintext + offset,
                                                                     output + offset, split_lengths[index]),
                        WA_STATUS_OK);
        offset += split_lengths[index];
        if (offset != 0) { /* The chaining value is the last ciphertext block */
            WA_CHECK_BYTES(chaining_value, WA_AES_BLOCK_SIZE, output + offset - 16, WA_AES_BLOCK_SIZE);
        }
    }
    WA_CHECK_SIZE(offset, 64);
    WA_CHECK_BYTES(output, 64, expected_ciphertext, 64);
}

static void test_aes_256_cbc(void)
{
    static const size_t one_call[] = {64};
    static const size_t streamed[] = {16, 0, 32, 16};
    wa_test_platform_t *platform = wa_test_platform_create(1);
    wa_crypto_backend_aes_256_t *context = NULL;
    size_t key_length, plaintext_length, iv_length, ciphertext_length;
    uint8_t *key = decode(WA_SP800_38A_KEY_HEX, &key_length);
    uint8_t *plaintext = decode(WA_SP800_38A_PLAINTEXT_HEX, &plaintext_length);
    uint8_t *iv = decode(WA_SP800_38A_CBC_IV_HEX, &iv_length);
    uint8_t *ciphertext = decode(WA_SP800_38A_CBC_CIPHERTEXT_HEX, &ciphertext_length);
    uint8_t in_place[64];
    uint8_t chaining_value[WA_AES_BLOCK_SIZE];
    WA_REQUIRE(key_length == 32 && plaintext_length == 64 && iv_length == 16 && ciphertext_length == 64);
    /* The key must not survive in released memory */
    wa_test_allocator_register_secret_pattern(&platform->allocator, key, key_length);

    WA_REQUIRE_STATUS(wa_crypto_backend_aes_256_create(&platform->hooks, key, &context), WA_STATUS_OK);
    check_cbc_split(context, plaintext, ciphertext, one_call, WA_ARRAY_LENGTH(one_call));
    check_cbc_split(context, plaintext, ciphertext, streamed, WA_ARRAY_LENGTH(streamed));

    /* In place */
    memcpy(in_place, plaintext, 64);
    memcpy(chaining_value, iv, 16);
    WA_CHECK_STATUS(wa_crypto_backend_aes_256_encrypt_cbc_blocks(context, chaining_value, in_place, in_place, 64),
                    WA_STATUS_OK);
    WA_CHECK_BYTES(in_place, 64, ciphertext, 64);

    /* Partial blocks are a caller bug */
    WA_CHECK_STATUS(wa_crypto_backend_aes_256_encrypt_cbc_blocks(context, chaining_value, plaintext, in_place, 15),
                    WA_STATUS_INTERNAL_ERROR);

    wa_crypto_backend_aes_256_destroy(context);
    wa_crypto_backend_aes_256_destroy(NULL);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
    free(key);
    free(plaintext);
    free(iv);
    free(ciphertext);
    wa_test_platform_destroy(platform);
}

static void check_ctr(const char *key_hex, const char *counter_hex, const char *plaintext_hex,
                      const char *ciphertext_hex, const char *next_counter_hex_or_null)
{
    static const size_t streamed[] = {16, 0, 32, 16}; /* Stops once the plaintext is covered */
    wa_test_platform_t *platform = wa_test_platform_create(2);
    wa_crypto_backend_aes_256_t *context = NULL;
    size_t key_length, counter_length, plaintext_length, ciphertext_length, offset, index;
    uint8_t *key = decode(key_hex, &key_length);
    uint8_t *counter = decode(counter_hex, &counter_length);
    uint8_t *plaintext = decode(plaintext_hex, &plaintext_length);
    uint8_t *ciphertext = decode(ciphertext_hex, &ciphertext_length);
    uint8_t counter_block[WA_AES_BLOCK_SIZE];
    uint8_t output[64];
    WA_REQUIRE(key_length == 32 && counter_length == 16 && plaintext_length == ciphertext_length &&
               plaintext_length <= sizeof(output) && plaintext_length % 16 == 0);
    WA_REQUIRE_STATUS(wa_crypto_backend_aes_256_create(&platform->hooks, key, &context), WA_STATUS_OK);

    /* One call */
    memcpy(counter_block, counter, 16);
    WA_CHECK_STATUS(
        wa_crypto_backend_aes_256_encrypt_ctr_blocks(context, counter_block, plaintext, output, plaintext_length),
        WA_STATUS_OK);
    WA_CHECK_BYTES(output, plaintext_length, ciphertext, ciphertext_length);
    if (next_counter_hex_or_null != NULL) {
        WA_CHECK_HEX(counter_block, 16, next_counter_hex_or_null);
    }

    /* Streamed over several calls, in place, the counter carried over */
    memcpy(counter_block, counter, 16);
    memcpy(output, plaintext, plaintext_length);
    offset = 0;
    for (index = 0; index < WA_ARRAY_LENGTH(streamed) && offset < plaintext_length; ++index) {
        WA_CHECK_STATUS(wa_crypto_backend_aes_256_encrypt_ctr_blocks(context, counter_block, output + offset,
                                                                     output + offset, streamed[index]),
                        WA_STATUS_OK);
        offset += streamed[index];
    }
    WA_CHECK_SIZE(offset, plaintext_length);
    WA_CHECK_BYTES(output, plaintext_length, ciphertext, ciphertext_length);
    if (next_counter_hex_or_null != NULL) {
        WA_CHECK_HEX(counter_block, 16, next_counter_hex_or_null);
    }

    WA_CHECK_STATUS(wa_crypto_backend_aes_256_encrypt_ctr_blocks(context, counter_block, plaintext, output, 17),
                    WA_STATUS_INTERNAL_ERROR);
    wa_crypto_backend_aes_256_destroy(context);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    free(key);
    free(counter);
    free(plaintext);
    free(ciphertext);
    wa_test_platform_destroy(platform);
}

static void test_aes_256_ctr(void)
{
    /* SP 800-38A F.5.5: the next counter is the initial one + 4 */
    check_ctr(WA_SP800_38A_KEY_HEX, WA_SP800_38A_CTR_COUNTER_HEX, WA_SP800_38A_PLAINTEXT_HEX,
              WA_SP800_38A_CTR_CIPHERTEXT_HEX, "f0f1f2f3f4f5f6f7f8f9fafbfcfdff03");
    /* The counter is incremented on all 128 bits, wrapping around to zero */
    check_ctr(WA_CTR_WRAP_KEY_HEX, WA_CTR_WRAP_COUNTER_HEX, WA_CTR_WRAP_PLAINTEXT_HEX, WA_CTR_WRAP_CIPHERTEXT_HEX,
              WA_CTR_WRAP_NEXT_COUNTER_HEX);
}

static void test_aes_256_out_of_memory(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(3);
    wa_crypto_backend_aes_256_t *context = (wa_crypto_backend_aes_256_t *)platform; /* Must be reset to NULL */
    static const uint8_t key[WA_AES_256_KEY_SIZE] = {0};
    platform->allocator.fail_at_attempt_index = 0;
    WA_CHECK_STATUS(wa_crypto_backend_aes_256_create(&platform->hooks, key, &context), WA_STATUS_OUT_OF_MEMORY);
    WA_CHECK(context == NULL);
    WA_CHECK(platform->allocator.failure_was_injected);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

/* CHACHA20-POLY1305 */

static void check_chacha20_poly1305_split(const wa_test_platform_t *platform, const uint8_t *key,
                                          const uint8_t *nonce, const uint8_t *aad, size_t aad_length,
                                          const uint8_t *plaintext, size_t plaintext_length,
                                          const uint8_t *expected_ciphertext, const uint8_t *expected_tag,
                                          const size_t *split_lengths, size_t split_count, int in_place)
{
    wa_crypto_backend_chacha20_poly1305_t *context = NULL;
    uint8_t output[256];
    uint8_t tag[WA_AEAD_TAG_SIZE];
    size_t offset = 0;
    size_t index;
    WA_REQUIRE(plaintext_length <= sizeof(output));
    WA_REQUIRE_STATUS(
        wa_crypto_backend_chacha20_poly1305_create(&platform->hooks, key, nonce, aad, aad_length, &context),
        WA_STATUS_OK);
    if (in_place) {
        memcpy(output, plaintext, plaintext_length);
    }
    for (index = 0; index < split_count; ++index) {
        size_t length = split_lengths[index];
        if (offset + length > plaintext_length) {
            length = plaintext_length - offset;
        }
        WA_CHECK_STATUS(wa_crypto_backend_chacha20_poly1305_encrypt(
                            context, in_place ? output + offset : plaintext + offset, output + offset, length),
                        WA_STATUS_OK);
        offset += length;
    }
    WA_CHECK_SIZE(offset, plaintext_length);
    WA_CHECK_STATUS(wa_crypto_backend_chacha20_poly1305_finish(context, tag), WA_STATUS_OK);
    WA_CHECK_BYTES(output, plaintext_length, expected_ciphertext, plaintext_length);
    WA_CHECK_BYTES(tag, WA_AEAD_TAG_SIZE, expected_tag, WA_AEAD_TAG_SIZE);
    wa_crypto_backend_chacha20_poly1305_destroy(context);
}

static void test_chacha20_poly1305(void)
{
    static const size_t one_call[] = {1000};
    /* Odd sizes crossing the 64-byte ChaCha20 blocks and the 16-byte Poly1305 blocks, with empty updates */
    static const size_t streamed[] = {1, 0, 63, 50, 0, 7, 1000};
    wa_test_platform_t *platform = wa_test_platform_create(4);
    size_t key_length, nonce_length, aad_length, ciphertext_length, tag_length;
    uint8_t *key = decode(WA_RFC8439_KEY_HEX, &key_length);
    uint8_t *nonce = decode(WA_RFC8439_NONCE_HEX, &nonce_length);
    uint8_t *aad = decode(WA_RFC8439_AAD_HEX, &aad_length);
    uint8_t *ciphertext = decode(WA_RFC8439_CIPHERTEXT_HEX, &ciphertext_length);
    uint8_t *tag = decode(WA_RFC8439_TAG_HEX, &tag_length);
    const uint8_t *plaintext = (const uint8_t *)WA_RFC8439_PLAINTEXT;
    size_t plaintext_length = strlen(WA_RFC8439_PLAINTEXT);
    wa_crypto_backend_chacha20_poly1305_t *context = NULL;
    uint8_t empty_tag[WA_AEAD_TAG_SIZE];
    WA_REQUIRE(key_length == 32 && nonce_length == 12 && tag_length == 16 && ciphertext_length == plaintext_length);
    wa_test_allocator_register_secret_pattern(&platform->allocator, key, key_length);

    check_chacha20_poly1305_split(platform, key, nonce, aad, aad_length, plaintext, plaintext_length, ciphertext, tag,
                                  one_call, WA_ARRAY_LENGTH(one_call), 0);
    check_chacha20_poly1305_split(platform, key, nonce, aad, aad_length, plaintext, plaintext_length, ciphertext, tag,
                                  streamed, WA_ARRAY_LENGTH(streamed), 0);
    check_chacha20_poly1305_split(platform, key, nonce, aad, aad_length, plaintext, plaintext_length, ciphertext, tag,
                                  streamed, WA_ARRAY_LENGTH(streamed), 1);

    /* Empty associated data and plaintext (as in cryptainers, for the AAD): the tag only depends on the key */
    WA_REQUIRE_STATUS(wa_crypto_backend_chacha20_poly1305_create(&platform->hooks, key, nonce, NULL, 0, &context),
                      WA_STATUS_OK);
    WA_CHECK_STATUS(wa_crypto_backend_chacha20_poly1305_finish(context, empty_tag), WA_STATUS_OK);
    wa_crypto_backend_chacha20_poly1305_destroy(context);
    wa_crypto_backend_chacha20_poly1305_destroy(NULL);
    WA_CHECK_HEX(empty_tag, WA_AEAD_TAG_SIZE, WA_RFC8439_KEY_AND_NONCE_EMPTY_MESSAGE_TAG_HEX);

    platform->allocator.fail_at_attempt_index = platform->allocator.attempted_allocation_count;
    context = (wa_crypto_backend_chacha20_poly1305_t *)platform;
    WA_CHECK_STATUS(wa_crypto_backend_chacha20_poly1305_create(&platform->hooks, key, nonce, NULL, 0, &context),
                    WA_STATUS_OUT_OF_MEMORY);
    WA_CHECK(context == NULL);

    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
    free(key);
    free(nonce);
    free(aad);
    free(ciphertext);
    free(tag);
    wa_test_platform_destroy(platform);
}

/* HASHES AND HMAC */

/* Split `data` into 3 parts (the middle one possibly empty) */
static void split_in_three(const uint8_t *data, size_t length, wa_byte_span_t parts[3])
{
    size_t first = length / 3;
    size_t second = length / 2 - first / 2;
    if (first + second > length) {
        second = length - first;
    }
    parts[0].bytes = data;
    parts[0].length = first;
    parts[1].bytes = data + first;
    parts[1].length = second;
    parts[2].bytes = data + first + second;
    parts[2].length = length - first - second;
}

static void test_sha256_and_sha512(void)
{
    size_t index;
    for (index = 0; index < WA_ARRAY_LENGTH(wa_sha_vectors); ++index) {
        const uint8_t *message = (const uint8_t *)wa_sha_vectors[index].message;
        size_t length = strlen(wa_sha_vectors[index].message);
        wa_byte_span_t whole = {message, length};
        wa_byte_span_t parts[3];
        uint8_t digest256[WA_SHA256_DIGEST_SIZE];
        uint8_t digest512[WA_SHA512_DIGEST_SIZE];
        split_in_three(message, length, parts);

        WA_CHECK_STATUS(wa_crypto_backend_compute_sha256(&whole, 1, digest256), WA_STATUS_OK);
        WA_CHECK_HEX(digest256, sizeof(digest256), wa_sha_vectors[index].sha256_hex);
        WA_CHECK_STATUS(wa_crypto_backend_compute_sha256(parts, 3, digest256), WA_STATUS_OK);
        WA_CHECK_HEX(digest256, sizeof(digest256), wa_sha_vectors[index].sha256_hex);
        WA_CHECK_STATUS(wa_crypto_backend_compute_sha512(&whole, 1, digest512), WA_STATUS_OK);
        WA_CHECK_HEX(digest512, sizeof(digest512), wa_sha_vectors[index].sha512_hex);
        WA_CHECK_STATUS(wa_crypto_backend_compute_sha512(parts, 3, digest512), WA_STATUS_OK);
        WA_CHECK_HEX(digest512, sizeof(digest512), wa_sha_vectors[index].sha512_hex);
        if (length == 0) { /* No part at all is the empty message too */
            WA_CHECK_STATUS(wa_crypto_backend_compute_sha256(NULL, 0, digest256), WA_STATUS_OK);
            WA_CHECK_HEX(digest256, sizeof(digest256), wa_sha_vectors[index].sha256_hex);
            WA_CHECK_STATUS(wa_crypto_backend_compute_sha512(NULL, 0, digest512), WA_STATUS_OK);
            WA_CHECK_HEX(digest512, sizeof(digest512), wa_sha_vectors[index].sha512_hex);
        }
    }
}

static void test_hmac_sha256(void)
{
    size_t index;
    for (index = 0; index < WA_ARRAY_LENGTH(wa_hmac_vectors); ++index) {
        size_t key_length;
        uint8_t *key = decode(wa_hmac_vectors[index].key_hex, &key_length);
        const uint8_t *data = (const uint8_t *)wa_hmac_vectors[index].data;
        size_t data_length = strlen(wa_hmac_vectors[index].data);
        wa_byte_span_t whole = {data, data_length};
        wa_byte_span_t parts[3];
        uint8_t mac[WA_SHA256_DIGEST_SIZE];
        split_in_three(data, data_length, parts);
        WA_CHECK_STATUS(wa_crypto_backend_compute_hmac_sha256(key, key_length, &whole, 1, mac), WA_STATUS_OK);
        WA_CHECK_HEX(mac, sizeof(mac), wa_hmac_vectors[index].mac_hex);
        WA_CHECK_STATUS(wa_crypto_backend_compute_hmac_sha256(key, key_length, parts, 3, mac), WA_STATUS_OK);
        WA_CHECK_HEX(mac, sizeof(mac), wa_hmac_vectors[index].mac_hex);
        free(key);
    }
}

/* X25519 */

static void test_x25519(void)
{
    size_t length;
    uint8_t *scalar = decode(WA_RFC7748_SCALAR_HEX, &length);
    uint8_t *u = decode(WA_RFC7748_U_HEX, &length);
    uint8_t *alice_private = decode(WA_RFC7748_ALICE_PRIVATE_HEX, &length);
    uint8_t *bob_public = decode(WA_RFC7748_BOB_PUBLIC_HEX, &length);
    uint8_t output[WA_X25519_KEY_SIZE];
    uint8_t masked_u[WA_X25519_KEY_SIZE];
    static const uint8_t zero_point[WA_X25519_KEY_SIZE] = {0};
    static const uint8_t all_zeros[WA_X25519_KEY_SIZE] = {0};
    wa_status_t status;

    /* RFC 7748 5.2: the scalar is clamped by the primitive */
    WA_CHECK_STATUS(wa_crypto_backend_x25519_compute_shared_secret(scalar, u, output), WA_STATUS_OK);
    WA_CHECK_HEX(output, sizeof(output), WA_RFC7748_OUTPUT_HEX);
    /* The top bit of u is masked: setting it gives the same output */
    memcpy(masked_u, u, sizeof(masked_u));
    masked_u[31] ^= 0x80;
    WA_CHECK_STATUS(wa_crypto_backend_x25519_compute_shared_secret(scalar, masked_u, output), WA_STATUS_OK);
    WA_CHECK_HEX(output, sizeof(output), WA_RFC7748_OUTPUT_HEX);

    /* RFC 7748 6.1 */
    WA_CHECK_STATUS(wa_crypto_backend_x25519_compute_public_key(alice_private, output), WA_STATUS_OK);
    WA_CHECK_HEX(output, sizeof(output), WA_RFC7748_ALICE_PUBLIC_HEX);
    WA_CHECK_STATUS(wa_crypto_backend_x25519_compute_shared_secret(alice_private, bob_public, output), WA_STATUS_OK);
    WA_CHECK_HEX(output, sizeof(output), WA_RFC7748_SHARED_HEX);

    /* A low-order point gives zeros or a backend failure, as documented */
    memset(output, 0x55, sizeof(output));
    status = wa_crypto_backend_x25519_compute_shared_secret(alice_private, zero_point, output);
    WA_CHECK(status == WA_STATUS_CRYPTO_BACKEND_FAILURE ||
             (status == WA_STATUS_OK && memcmp(output, all_zeros, sizeof(output)) == 0));

    free(scalar);
    free(u);
    free(alice_private);
    free(bob_public);
}

/* RAW RSA */

static void test_raw_rsa_public_operation(void)
{
    size_t index;
    for (index = 0; index < WA_ARRAY_LENGTH(wa_raw_rsa_vectors); ++index) {
        wa_test_platform_t *platform = wa_test_platform_create(5);
        size_t modulus_length, exponent_length, input_length, output_length;
        uint8_t *modulus = decode(wa_raw_rsa_vectors[index].modulus_hex, &modulus_length);
        uint8_t *exponent = decode(wa_raw_rsa_vectors[index].public_exponent_hex, &exponent_length);
        uint8_t *input = decode(wa_raw_rsa_vectors[index].input_hex, &input_length);
        uint8_t *expected = decode(wa_raw_rsa_vectors[index].output_hex, &output_length);
        uint8_t *output = (uint8_t *)malloc(modulus_length);
        WA_REQUIRE(output != NULL && input_length == modulus_length && output_length == modulus_length);
        WA_CHECK_STATUS(wa_crypto_backend_rsa_compute_public_operation(&platform->hooks, modulus, modulus_length,
                                                                       exponent, exponent_length, input, output),
                        WA_STATUS_OK);
        WA_CHECK_BYTES(output, modulus_length, expected, modulus_length);
        /* An input equal to the modulus is refused */
        WA_CHECK_STATUS(wa_crypto_backend_rsa_compute_public_operation(&platform->hooks, modulus, modulus_length,
                                                                       exponent, exponent_length, modulus, output),
                        WA_STATUS_CRYPTO_BACKEND_FAILURE);
        WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
        free(modulus);
        free(exponent);
        free(input);
        free(expected);
        free(output);
        wa_test_platform_destroy(platform);
    }
    WA_CHECK_SIZE(index, 2);
}

/* ML-KEM-768 */

static void test_ml_kem_768_encapsulation(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(6);
    size_t public_key_length, coins_length, ciphertext_length, shared_secret_length;
    uint8_t *public_key = decode(wa_ml_kem_768_public_key_hex, &public_key_length);
    uint8_t *coins = decode(wa_ml_kem_768_coins_hex, &coins_length);
    uint8_t *expected_ciphertext = decode(wa_ml_kem_768_ciphertext_hex, &ciphertext_length);
    uint8_t *expected_shared_secret = decode(wa_ml_kem_768_shared_secret_hex, &shared_secret_length);
    uint8_t *ciphertext = (uint8_t *)malloc(WA_ML_KEM_768_CIPHERTEXT_SIZE);
    uint8_t shared_secret[WA_ML_KEM_768_SHARED_SECRET_SIZE];
    WA_REQUIRE(ciphertext != NULL);
    WA_REQUIRE(public_key_length == WA_ML_KEM_768_PUBLIC_KEY_SIZE && coins_length == WA_ML_KEM_768_COINS_SIZE &&
               ciphertext_length == WA_ML_KEM_768_CIPHERTEXT_SIZE &&
               shared_secret_length == WA_ML_KEM_768_SHARED_SECRET_SIZE);
    WA_CHECK_STATUS(wa_crypto_backend_ml_kem_768_encapsulate_derandomized(&platform->hooks, public_key, coins,
                                                                          ciphertext, shared_secret),
                    WA_STATUS_OK);
    WA_CHECK_BYTES(ciphertext, WA_ML_KEM_768_CIPHERTEXT_SIZE, expected_ciphertext, ciphertext_length);
    WA_CHECK_BYTES(shared_secret, sizeof(shared_secret), expected_shared_secret, shared_secret_length);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    free(public_key);
    free(coins);
    free(expected_ciphertext);
    free(expected_shared_secret);
    free(ciphertext);
    wa_test_platform_destroy(platform);
}

int main(void)
{
    WA_RUN_TEST(test_aes_256_cbc);
    WA_RUN_TEST(test_aes_256_ctr);
    WA_RUN_TEST(test_aes_256_out_of_memory);
    WA_RUN_TEST(test_chacha20_poly1305);
    WA_RUN_TEST(test_sha256_and_sha512);
    WA_RUN_TEST(test_hmac_sha256);
    WA_RUN_TEST(test_x25519);
    WA_RUN_TEST(test_raw_rsa_public_operation);
    WA_RUN_TEST(test_ml_kem_768_encapsulation);
    return wa_test_finish();
}
