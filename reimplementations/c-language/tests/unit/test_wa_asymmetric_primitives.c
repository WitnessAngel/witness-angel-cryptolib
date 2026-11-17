/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Unit tests of the asymmetric primitives (tasks 5.4, 5.5 and 5.8): RSA-OAEP-SHA512 encoding and chunking against
 * pycryptodome with a replayed seed, HKDF-SHA256 (RFC 5869), HPKE Base mode (RFC 9180 A.2.1, and pycryptodome
 * outputs for both KEMs with replayed randomness), and asymmetric key wrapping of key structs in both document
 * formats, on each backend. */

#include <stdlib.h>
#include <string.h>

#include "encoding/wa_document_serialization.h"
#include "encoding/wa_value_tree_internal.h"
#include "primitives/wa_asymmetric_key_wrapping.h"
#include "primitives/wa_hkdf_sha256.h"
#include "primitives/wa_hpke_base_mode_seal.h"
#include "primitives/wa_hpke_kem_dhkem_x25519.h"
#include "primitives/wa_hpke_kem_ml_kem_768.h"
#include "primitives/wa_rsa_oaep_chunked_encryption.h"
#include "primitives/wa_rsa_oaep_sha512_padding.h"
#include "primitives/wa_symmetric_key_generation.h"
#include "wa_minimal_test_harness.h"
#include "wa_primitive_vectors.h"
#include "wa_test_support.h"

#define WA_ARRAY_LENGTH(array) (sizeof(array) / sizeof((array)[0]))

static uint8_t *decode(const char *hex, size_t *length_out)
{
    uint8_t *bytes = wa_test_decode_hex(hex, length_out);
    if (bytes == NULL) {
        abort();
    }
    return bytes;
}

/* Replace the platform's random hook by the replay of `bytes` */
static void use_replayed_random(wa_test_platform_t *platform, wa_test_replayed_random_t *replayed_random,
                                const uint8_t *bytes, size_t length)
{
    wa_test_replayed_random_initialize(replayed_random, bytes, length);
    platform->hooks.fill_random = wa_test_fill_replayed_random;
    platform->hooks.random_context = replayed_random;
}

static const uint8_t *get_bytes_entry(const wa_value_t *map, const char *key, size_t *length_out)
{
    const uint8_t *bytes = NULL;
    *length_out = 0;
    if (wa_value_get_bytes(wa_value_find_map_value(map, key), &bytes, length_out) != 0) {
        return NULL;
    }
    return bytes;
}

/* RSA-OAEP */

static void test_oaep_encoding_against_pycryptodome(void)
{
    size_t modulus_length, message_length, seed_length, expected_length;
    uint8_t *modulus = decode(wa_oaep_modulus_hex, &modulus_length);
    uint8_t *message = decode(wa_oaep_message_hex, &message_length);
    uint8_t *seed = decode(wa_oaep_seed_hex, &seed_length);
    uint8_t *expected = decode(wa_oaep_encoded_message_hex, &expected_length);
    uint8_t encoded_message[512];
    WA_REQUIRE(seed_length == WA_RSA_OAEP_SEED_SIZE && modulus_length == 256 && expected_length == 256);
    WA_REQUIRE_STATUS(wa_rsa_oaep_sha512_encode_padding(message, message_length, seed, encoded_message, 256),
                      WA_STATUS_OK);
    WA_CHECK_BYTES(encoded_message, 256, expected, expected_length);
    /* Longest message: k - 130 = 126 bytes for RSA-2048 */
    {
        uint8_t long_message[127] = {0};
        WA_CHECK_STATUS(wa_rsa_oaep_sha512_encode_padding(long_message, 126, seed, encoded_message, 256),
                        WA_STATUS_OK);
        WA_CHECK(encoded_message[0] == 0);
        WA_CHECK_STATUS(wa_rsa_oaep_sha512_encode_padding(long_message, 127, seed, encoded_message, 256),
                        WA_STATUS_INVALID_ARGUMENT);
        WA_CHECK_STATUS(wa_rsa_oaep_sha512_encode_padding(long_message, 0, seed, encoded_message, 129),
                        WA_STATUS_INVALID_ARGUMENT);
        WA_CHECK_STATUS(wa_rsa_oaep_sha512_encode_padding(NULL, 0, seed, encoded_message, 130), WA_STATUS_OK);
    }
    free(modulus);
    free(message);
    free(seed);
    free(expected);
}

static void test_oaep_ciphertext_against_pycryptodome(void)
{
    size_t modulus_length, exponent_length, message_length, seed_length, chunk_length;
    uint8_t *modulus = decode(wa_oaep_modulus_hex, &modulus_length);
    uint8_t *exponent = decode(wa_oaep_public_exponent_hex, &exponent_length);
    uint8_t *message = decode(wa_oaep_message_hex, &message_length);
    uint8_t *seed = decode(wa_oaep_seed_hex, &seed_length);
    wa_test_platform_t *platform = wa_test_platform_create(1);
    wa_test_replayed_random_t replayed_random;
    wa_value_t *cipherdict = NULL;
    const wa_value_t *chunks;
    const uint8_t *chunk;
    use_replayed_random(platform, &replayed_random, seed, seed_length);
    WA_REQUIRE_STATUS(wa_rsa_oaep_encrypt_into_chunks(&platform->hooks, modulus, modulus_length, exponent,
                                                      exponent_length, message, message_length, &cipherdict),
                      WA_STATUS_OK);
    WA_CHECK_SIZE(wa_value_get_item_count(cipherdict), 1);
    chunks = wa_value_find_map_value(cipherdict, "ciphertext_chunks");
    WA_REQUIRE(chunks != NULL && wa_value_get_type(chunks) == WA_VALUE_TYPE_ARRAY);
    WA_REQUIRE(wa_value_get_item_count(chunks) == 1);
    WA_REQUIRE(wa_value_get_bytes(wa_value_get_array_item(chunks, 0), &chunk, &chunk_length) == 0);
    WA_CHECK_HEX(chunk, chunk_length, wa_oaep_ciphertext_hex);
    wa_value_destroy(cipherdict);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
    free(modulus);
    free(exponent);
    free(message);
    free(seed);
}

static void test_oaep_chunk_counts(void)
{
    static const size_t plaintext_lengths[] = {0, 1, 59, 60, 61, 120, 121, 300};
    static const size_t expected_chunk_counts[] = {0, 1, 1, 1, 2, 2, 3, 5};
    size_t modulus_length, exponent_length;
    uint8_t *modulus = decode(wa_oaep_modulus_hex, &modulus_length);
    uint8_t *exponent = decode(wa_oaep_public_exponent_hex, &exponent_length);
    uint8_t plaintext[300];
    size_t index;
    memset(plaintext, 0xab, sizeof(plaintext)); /* Identical chunks, all encrypted differently */
    for (index = 0; index < WA_ARRAY_LENGTH(plaintext_lengths); ++index) {
        wa_test_platform_t *platform = wa_test_platform_create(20 + index);
        wa_value_t *cipherdict = NULL;
        const wa_value_t *chunks;
        size_t chunk_index;
        WA_REQUIRE_STATUS(wa_rsa_oaep_encrypt_into_chunks(&platform->hooks, modulus, modulus_length, exponent,
                                                          exponent_length, plaintext, plaintext_lengths[index],
                                                          &cipherdict),
                          WA_STATUS_OK);
        chunks = wa_value_find_map_value(cipherdict, "ciphertext_chunks");
        WA_REQUIRE(chunks != NULL && wa_value_get_type(chunks) == WA_VALUE_TYPE_ARRAY);
        WA_CHECK_SIZE(wa_value_get_item_count(chunks), expected_chunk_counts[index]);
        WA_CHECK_SIZE(platform->random_generator.call_count, expected_chunk_counts[index]);
        for (chunk_index = 0; chunk_index < wa_value_get_item_count(chunks); ++chunk_index) {
            const uint8_t *chunk = NULL;
            size_t chunk_length = 0;
            WA_CHECK(wa_value_get_bytes(wa_value_get_array_item(chunks, chunk_index), &chunk, &chunk_length) == 0);
            WA_CHECK_SIZE(chunk_length, 256);
            if (chunk_index > 0) {
                const uint8_t *previous_chunk = NULL;
                size_t previous_length = 0;
                WA_CHECK(wa_value_get_bytes(wa_value_get_array_item(chunks, chunk_index - 1), &previous_chunk,
                                            &previous_length) == 0);
                WA_CHECK(memcmp(chunk, previous_chunk, 256) != 0);
            }
        }
        wa_value_destroy(cipherdict);
        WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
        WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
        wa_test_platform_destroy(platform);
    }
    free(modulus);
    free(exponent);
}

static void test_oaep_failures(void)
{
    size_t modulus_length, exponent_length;
    uint8_t *modulus = decode(wa_oaep_modulus_hex, &modulus_length);
    uint8_t *exponent = decode(wa_oaep_public_exponent_hex, &exponent_length);
    uint8_t plaintext[130] = {1};
    size_t attempt_index;
    int completed = 0;
    /* Allocation failures at each attempt, then random failures at each call */
    for (attempt_index = 0; !completed; ++attempt_index) {
        wa_test_platform_t *platform = wa_test_platform_create(30);
        wa_value_t *cipherdict = NULL;
        wa_status_t status;
        platform->allocator.fail_at_attempt_index = attempt_index;
        status = wa_rsa_oaep_encrypt_into_chunks(&platform->hooks, modulus, modulus_length, exponent,
                                                 exponent_length, plaintext, sizeof(plaintext), &cipherdict);
        if (platform->allocator.failure_was_injected) {
            WA_CHECK_STATUS(status, WA_STATUS_OUT_OF_MEMORY);
            WA_CHECK(cipherdict == NULL);
        } else {
            WA_CHECK_STATUS(status, WA_STATUS_OK);
            completed = 1;
        }
        wa_value_destroy(cipherdict);
        WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
        WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
        wa_test_platform_destroy(platform);
    }
    for (attempt_index = 0; attempt_index < 3; ++attempt_index) {
        wa_test_platform_t *platform = wa_test_platform_create(31);
        wa_value_t *cipherdict = NULL;
        platform->random_generator.fail_at_call_index = attempt_index;
        WA_CHECK_STATUS(wa_rsa_oaep_encrypt_into_chunks(&platform->hooks, modulus, modulus_length, exponent,
                                                        exponent_length, plaintext, sizeof(plaintext), &cipherdict),
                        WA_STATUS_RANDOMNESS_FAILURE);
        WA_CHECK(cipherdict == NULL);
        WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
        WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
        wa_test_platform_destroy(platform);
    }
    /* A modulus too short for a 60-byte chunk, or with a leading zero byte */
    {
        wa_test_platform_t *platform = wa_test_platform_create(32);
        wa_value_t *cipherdict = NULL;
        WA_CHECK_STATUS(wa_rsa_oaep_encrypt_into_chunks(&platform->hooks, modulus, 189, exponent, exponent_length,
                                                        plaintext, 1, &cipherdict),
                        WA_STATUS_INVALID_ARGUMENT);
        modulus[0] = 0;
        WA_CHECK_STATUS(wa_rsa_oaep_encrypt_into_chunks(&platform->hooks, modulus, modulus_length, exponent,
                                                        exponent_length, plaintext, 1, &cipherdict),
                        WA_STATUS_INVALID_ARGUMENT);
        WA_CHECK(cipherdict == NULL);
        wa_test_platform_destroy(platform);
    }
    free(modulus);
    free(exponent);
}

/* HKDF */

static void test_hkdf_rfc5869(void)
{
    size_t index;
    for (index = 0; index < WA_ARRAY_LENGTH(wa_hkdf_vectors); ++index) {
        size_t ikm_length, salt_length, info_length;
        uint8_t *ikm = decode(wa_hkdf_vectors[index].ikm_hex, &ikm_length);
        uint8_t *salt = decode(wa_hkdf_vectors[index].salt_hex, &salt_length);
        uint8_t *info = decode(wa_hkdf_vectors[index].info_hex, &info_length);
        uint8_t prk[WA_HKDF_SHA256_PRK_SIZE];
        uint8_t okm[128];
        wa_byte_span_t ikm_parts[3];
        wa_byte_span_t info_parts[2];
        size_t okm_length = wa_hkdf_vectors[index].length;
        WA_REQUIRE(okm_length <= sizeof(okm));
        /* Whole inputs */
        ikm_parts[0].bytes = ikm;
        ikm_parts[0].length = ikm_length;
        info_parts[0].bytes = info;
        info_parts[0].length = info_length;
        WA_REQUIRE_STATUS(wa_hkdf_sha256_extract(salt, salt_length, ikm_parts, 1, prk), WA_STATUS_OK);
        WA_CHECK_HEX(prk, sizeof(prk), wa_hkdf_vectors[index].prk_hex);
        WA_REQUIRE_STATUS(wa_hkdf_sha256_expand(prk, info_parts, 1, okm, okm_length), WA_STATUS_OK);
        WA_CHECK_HEX(okm, okm_length, wa_hkdf_vectors[index].okm_hex);
        /* Split inputs, and the info as no part at all when empty */
        ikm_parts[0].length = ikm_length / 2;
        ikm_parts[1].bytes = ikm + ikm_length / 2;
        ikm_parts[1].length = 0;
        ikm_parts[2].bytes = ikm + ikm_length / 2;
        ikm_parts[2].length = ikm_length - ikm_length / 2;
        info_parts[0].length = info_length / 3;
        info_parts[1].bytes = info + info_length / 3;
        info_parts[1].length = info_length - info_length / 3;
        memset(prk, 0, sizeof(prk));
        memset(okm, 0, sizeof(okm));
        WA_REQUIRE_STATUS(wa_hkdf_sha256_extract(salt, salt_length, ikm_parts, 3, prk), WA_STATUS_OK);
        WA_CHECK_HEX(prk, sizeof(prk), wa_hkdf_vectors[index].prk_hex);
        WA_REQUIRE_STATUS(wa_hkdf_sha256_expand(prk, info_parts, info_length == 0 ? 0 : 2, okm, okm_length),
                          WA_STATUS_OK);
        WA_CHECK_HEX(okm, okm_length, wa_hkdf_vectors[index].okm_hex);
        free(ikm);
        free(salt);
        free(info);
    }
    {
        uint8_t prk[WA_HKDF_SHA256_PRK_SIZE] = {0};
        uint8_t okm[1];
        WA_CHECK_STATUS(wa_hkdf_sha256_expand(prk, NULL, 0, okm, 0), WA_STATUS_INVALID_ARGUMENT);
        WA_CHECK_STATUS(wa_hkdf_sha256_expand(prk, NULL, 0, okm, 255 * 32 + 1), WA_STATUS_INVALID_ARGUMENT);
    }
}

/* HPKE */

static void test_hpke_rfc9180_base_mode(void)
{
    size_t info_length, skem_length, pkrm_length, shared_secret_length, plaintext_length, aad_length;
    uint8_t *info = decode(WA_RFC9180_INFO_HEX, &info_length);
    uint8_t *skem = decode(WA_RFC9180_SKEM_HEX, &skem_length);
    uint8_t *pkrm = decode(WA_RFC9180_PKRM_HEX, &pkrm_length);
    uint8_t *shared_secret = decode(WA_RFC9180_SHARED_SECRET_HEX, &shared_secret_length);
    uint8_t *plaintext = decode(WA_RFC9180_PLAINTEXT_HEX, &plaintext_length);
    uint8_t *aad = decode(WA_RFC9180_AAD_HEX, &aad_length);
    wa_test_platform_t *platform = wa_test_platform_create(2);
    wa_test_replayed_random_t replayed_random;
    uint8_t key[WA_HPKE_KEY_SIZE];
    uint8_t base_nonce[WA_HPKE_NONCE_SIZE];
    uint8_t enc[WA_X25519_KEY_SIZE];
    uint8_t computed_shared_secret[WA_HPKE_SHARED_SECRET_SIZE];
    uint8_t sealed[128];
    WA_REQUIRE(plaintext_length + WA_AEAD_TAG_SIZE <= sizeof(sealed));
    /* Key schedule */
    WA_REQUIRE_STATUS(wa_hpke_base_mode_key_schedule(WA_HPKE_KEM_ID_DHKEM_X25519, shared_secret, info, info_length,
                                                     key, base_nonce),
                      WA_STATUS_OK);
    WA_CHECK_HEX(key, sizeof(key), WA_RFC9180_KEY_HEX);
    WA_CHECK_HEX(base_nonce, sizeof(base_nonce), WA_RFC9180_BASE_NONCE_HEX);
    /* Encapsulation with skEm as ephemeral scalar */
    use_replayed_random(platform, &replayed_random, skem, skem_length);
    WA_REQUIRE_STATUS(wa_hpke_kem_dhkem_x25519.encapsulate(&platform->hooks, pkrm, enc, computed_shared_secret),
                      WA_STATUS_OK);
    WA_CHECK_HEX(enc, sizeof(enc), WA_RFC9180_ENC_HEX);
    WA_CHECK_BYTES(computed_shared_secret, sizeof(computed_shared_secret), shared_secret, shared_secret_length);
    /* Seal at sequence number 0, with the vector's info and AAD */
    use_replayed_random(platform, &replayed_random, skem, skem_length);
    WA_REQUIRE_STATUS(wa_hpke_base_mode_seal(&platform->hooks, &wa_hpke_kem_dhkem_x25519, pkrm, info, info_length,
                                             aad, aad_length, plaintext, plaintext_length, enc, sealed),
                      WA_STATUS_OK);
    WA_CHECK_HEX(enc, sizeof(enc), WA_RFC9180_ENC_HEX);
    WA_CHECK_HEX(sealed, plaintext_length + WA_AEAD_TAG_SIZE, WA_RFC9180_CIPHERTEXT_HEX);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
    free(info);
    free(skem);
    free(pkrm);
    free(shared_secret);
    free(plaintext);
    free(aad);
}

/* Seal to a cipherdict with replayed randomness, and compare with pycryptodome's outputs */
static void check_hpke_cipherdict(const wa_hpke_kem_t *kem, const char *public_key_hex, const char *randomness_hex,
                                  const char *plaintext_hex, const char *enc_hex, const char *sealed_hex)
{
    size_t public_key_length, randomness_length, plaintext_length, length;
    uint8_t *public_key = decode(public_key_hex, &public_key_length);
    uint8_t *randomness = decode(randomness_hex, &randomness_length);
    uint8_t *plaintext = decode(plaintext_hex, &plaintext_length);
    wa_test_platform_t *platform = wa_test_platform_create(3);
    wa_test_replayed_random_t replayed_random;
    wa_value_t *cipherdict = NULL;
    const uint8_t *bytes;
    WA_REQUIRE(public_key_length == kem->public_key_length);
    use_replayed_random(platform, &replayed_random, randomness, randomness_length);
    WA_REQUIRE_STATUS(wa_hpke_base_mode_seal_to_cipherdict(&platform->hooks, kem, public_key, plaintext,
                                                           plaintext_length, &cipherdict),
                      WA_STATUS_OK);
    WA_CHECK_SIZE(replayed_random.offset, randomness_length);
    WA_CHECK_SIZE(wa_value_get_item_count(cipherdict), 2);
    bytes = get_bytes_entry(cipherdict, "kem_ciphertext", &length);
    WA_CHECK_SIZE(length, kem->enc_length);
    WA_CHECK_HEX(bytes, length, enc_hex);
    bytes = get_bytes_entry(cipherdict, "ciphertext", &length);
    WA_CHECK_SIZE(length, plaintext_length + WA_AEAD_TAG_SIZE);
    WA_CHECK_HEX(bytes, length, sealed_hex);
    wa_value_destroy(cipherdict);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
    free(public_key);
    free(randomness);
    free(plaintext);
}

static void test_hpke_x25519_against_pycryptodome(void)
{
    check_hpke_cipherdict(&wa_hpke_kem_dhkem_x25519, WA_HPKE_X25519_PUBLIC_KEY_HEX,
                          WA_HPKE_X25519_EPHEMERAL_SCALAR_HEX, WA_HPKE_X25519_PLAINTEXT_HEX, WA_HPKE_X25519_ENC_HEX,
                          WA_HPKE_X25519_SEALED_HEX);
}

static void test_hpke_ml_kem_768_against_pycryptodome(void)
{
    check_hpke_cipherdict(&wa_hpke_kem_ml_kem_768, wa_hpke_ml_kem_768_public_key_hex, wa_hpke_ml_kem_768_coins_hex,
                          wa_hpke_ml_kem_768_plaintext_hex, wa_hpke_ml_kem_768_enc_hex,
                          wa_hpke_ml_kem_768_sealed_hex);
}

static void test_hpke_low_order_x25519_key(void)
{
    static const uint8_t zero_public_key[WA_X25519_KEY_SIZE] = {0};
    wa_test_platform_t *platform = wa_test_platform_create(4);
    wa_value_t *cipherdict = NULL;
    wa_status_t status = wa_hpke_base_mode_seal_to_cipherdict(&platform->hooks, &wa_hpke_kem_dhkem_x25519,
                                                              zero_public_key, (const uint8_t *)"key", 3, &cipherdict);
    /* All-zero DH output, or a backend refusing the point beforehand */
    WA_CHECK(status == WA_STATUS_KEY_CONSTRAINT_VIOLATION || status == WA_STATUS_CRYPTO_BACKEND_FAILURE);
    WA_CHECK(cipherdict == NULL);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
    wa_test_platform_destroy(platform);
}

static void test_hpke_failures(void)
{
    const wa_hpke_kem_t *const kems[] = {&wa_hpke_kem_dhkem_x25519, &wa_hpke_kem_ml_kem_768};
    const char *const public_key_hexes[] = {WA_HPKE_X25519_PUBLIC_KEY_HEX, wa_hpke_ml_kem_768_public_key_hex};
    size_t kem_index;
    for (kem_index = 0; kem_index < WA_ARRAY_LENGTH(kems); ++kem_index) {
        size_t public_key_length;
        uint8_t *public_key = decode(public_key_hexes[kem_index], &public_key_length);
        uint8_t plaintext[100];
        size_t attempt_index;
        int completed = 0;
        memset(plaintext, 0x5c, sizeof(plaintext));
        for (attempt_index = 0; !completed; ++attempt_index) {
            wa_test_platform_t *platform = wa_test_platform_create(40);
            wa_value_t *cipherdict = NULL;
            wa_status_t status;
            platform->allocator.fail_at_attempt_index = attempt_index;
            status = wa_hpke_base_mode_seal_to_cipherdict(&platform->hooks, kems[kem_index], public_key, plaintext,
                                                          sizeof(plaintext), &cipherdict);
            if (platform->allocator.failure_was_injected) {
                WA_CHECK_STATUS(status, WA_STATUS_OUT_OF_MEMORY);
                WA_CHECK(cipherdict == NULL);
            } else {
                WA_CHECK_STATUS(status, WA_STATUS_OK);
                completed = 1;
            }
            wa_value_destroy(cipherdict);
            WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
            WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
            wa_test_platform_destroy(platform);
        }
        {
            wa_test_platform_t *platform = wa_test_platform_create(41);
            wa_value_t *cipherdict = NULL;
            platform->random_generator.fail_at_call_index = 0;
            WA_CHECK_STATUS(wa_hpke_base_mode_seal_to_cipherdict(&platform->hooks, kems[kem_index], public_key,
                                                                 plaintext, sizeof(plaintext), &cipherdict),
                            WA_STATUS_RANDOMNESS_FAILURE);
            WA_CHECK(cipherdict == NULL);
            WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
            wa_test_platform_destroy(platform);
        }
        free(public_key);
    }
}

/* ASYMMETRIC KEY WRAPPING */

/* {"SOME_METADATA": 2726562425242, "b": [true, null, "x"]} */
static wa_value_t *build_metadata(const wa_platform_hooks_t *platform_hooks)
{
    wa_value_t *metadata = NULL;
    wa_value_t *value = NULL;
    wa_value_t *array = NULL;
    if (wa_value_create_map(platform_hooks, &metadata) != WA_STATUS_OK ||
        wa_value_create_integer(platform_hooks, 2726562425242, &value) != WA_STATUS_OK ||
        wa_value_map_add_consuming(metadata, "SOME_METADATA", value) != WA_STATUS_OK ||
        wa_value_create_array(platform_hooks, &array) != WA_STATUS_OK ||
        wa_value_create_boolean(platform_hooks, 1, &value) != WA_STATUS_OK ||
        wa_value_array_append(array, value) != WA_STATUS_OK ||
        wa_value_create_null(platform_hooks, &value) != WA_STATUS_OK ||
        wa_value_array_append(array, value) != WA_STATUS_OK ||
        wa_value_create_text(platform_hooks, "x", 1, &value) != WA_STATUS_OK ||
        wa_value_array_append(array, value) != WA_STATUS_OK ||
        wa_value_map_add_consuming(metadata, "b", array) != WA_STATUS_OK) {
        abort();
    }
    return metadata;
}

/* The serialized AES_CBC symkey {"key": b"k" * 32, "iv": b"i" * 16} */
static void serialize_test_symkey(const wa_platform_hooks_t *platform_hooks, wa_document_format_t format,
                                  wa_growable_byte_buffer_t *buffer)
{
    wa_symkey_t symkey;
    wa_value_t *tree = NULL;
    memset(&symkey, 0, sizeof(symkey));
    symkey.cipher_algo = WA_SYMMETRIC_CIPHER_AES_CBC;
    memset(symkey.key, 'k', sizeof(symkey.key));
    memset(symkey.iv_or_nonce, 'i', 16);
    symkey.iv_or_nonce_length = 16;
    WA_REQUIRE_STATUS(wa_symkey_build_tree(platform_hooks, &symkey, &tree), WA_STATUS_OK);
    WA_REQUIRE_STATUS(wa_document_serialize_to_buffer(tree, format, buffer), WA_STATUS_OK);
    wa_value_destroy(tree);
}

static void test_asymmetric_cipher_algo_names(void)
{
    wa_asymmetric_cipher_algo_t algo = WA_ASYMMETRIC_CIPHER_RSA_OAEP;
    WA_CHECK(wa_asymmetric_cipher_algo_from_name("ECIES_X25519", 12, &algo) &&
             algo == WA_ASYMMETRIC_CIPHER_ECIES_X25519);
    WA_CHECK(wa_asymmetric_cipher_algo_from_name("ML_KEM_768", 10, &algo) && algo == WA_ASYMMETRIC_CIPHER_ML_KEM_768);
    WA_CHECK(wa_asymmetric_cipher_algo_from_name("RSA_OAEP", 8, &algo) && algo == WA_ASYMMETRIC_CIPHER_RSA_OAEP);
    WA_CHECK(!wa_asymmetric_cipher_algo_from_name("RSA_OAE", 7, &algo));
    WA_CHECK(!wa_asymmetric_cipher_algo_from_name("AES_CBC", 7, &algo));
    WA_CHECK(strcmp(wa_asymmetric_cipher_algo_get_name(WA_ASYMMETRIC_CIPHER_ML_KEM_768), "ML_KEM_768") == 0);
    WA_CHECK(wa_asymmetric_cipher_algo_get_name((wa_asymmetric_cipher_algo_t)0) == NULL);
}

static void test_key_struct_wrapping(void)
{
    /* Key struct sizes of dump_to_json_bytes() / dump_to_cbor_bytes(), without and with metadata */
    static const struct {
        wa_document_format_t format;
        size_t symkey_length;
        size_t key_struct_lengths[2];
    } formats[] = {{WA_DOCUMENT_FORMAT_JSON, 173, {320, 372}}, {WA_DOCUMENT_FORMAT_CBOR, 59, {93, 123}}};
    size_t modulus_length, exponent_length, x25519_key_length, ml_kem_key_length;
    uint8_t *modulus = decode(wa_oaep_modulus_hex, &modulus_length);
    uint8_t *exponent = decode(wa_oaep_public_exponent_hex, &exponent_length);
    uint8_t *x25519_key = decode(WA_HPKE_X25519_PUBLIC_KEY_HEX, &x25519_key_length);
    uint8_t *ml_kem_key = decode(wa_hpke_ml_kem_768_public_key_hex, &ml_kem_key_length);
    wa_asymmetric_public_key_t public_keys[3];
    size_t format_index;
    memset(public_keys, 0, sizeof(public_keys));
    public_keys[0].cipher_algo = WA_ASYMMETRIC_CIPHER_RSA_OAEP;
    public_keys[0].modulus = modulus;
    public_keys[0].modulus_length = modulus_length;
    public_keys[0].public_exponent = exponent;
    public_keys[0].public_exponent_length = exponent_length;
    public_keys[1].cipher_algo = WA_ASYMMETRIC_CIPHER_ECIES_X25519;
    public_keys[1].key_bytes = x25519_key;
    public_keys[1].key_bytes_length = x25519_key_length;
    public_keys[2].cipher_algo = WA_ASYMMETRIC_CIPHER_ML_KEM_768;
    public_keys[2].key_bytes = ml_kem_key;
    public_keys[2].key_bytes_length = ml_kem_key_length;
    for (format_index = 0; format_index < WA_ARRAY_LENGTH(formats); ++format_index) {
        size_t metadata_index;
        if (!wa_document_format_is_enabled(formats[format_index].format)) {
            continue;
        }
        for (metadata_index = 0; metadata_index < 2; ++metadata_index) {
            size_t key_index;
            for (key_index = 0; key_index < WA_ARRAY_LENGTH(public_keys); ++key_index) {
                wa_test_platform_t *platform = wa_test_platform_create(50 + key_index);
                wa_growable_byte_buffer_t symkey_bytes;
                wa_value_t *metadata = metadata_index ? build_metadata(&platform->hooks) : NULL;
                wa_value_t *cipherdict = NULL;
                size_t key_struct_length = formats[format_index].key_struct_lengths[metadata_index];
                uint8_t key_pattern[WA_TEST_SECRET_PATTERN_LENGTH];
                /* The symkey must not survive in any released block */
                memset(key_pattern, 'k', sizeof(key_pattern));
                wa_test_allocator_register_secret_pattern(&platform->allocator, key_pattern, sizeof(key_pattern));
                wa_growable_byte_buffer_initialize(&symkey_bytes, &platform->hooks, 1);
                serialize_test_symkey(&platform->hooks, formats[format_index].format, &symkey_bytes);
                WA_CHECK_SIZE(symkey_bytes.length, formats[format_index].symkey_length);
                WA_REQUIRE_STATUS(wa_asymmetric_wrap_key_struct(&platform->hooks, &public_keys[key_index],
                                                                formats[format_index].format, symkey_bytes.data,
                                                                symkey_bytes.length, metadata, &cipherdict),
                                  WA_STATUS_OK);
                if (public_keys[key_index].cipher_algo == WA_ASYMMETRIC_CIPHER_RSA_OAEP) {
                    const wa_value_t *chunks = wa_value_find_map_value(cipherdict, "ciphertext_chunks");
                    size_t chunk_index;
                    WA_CHECK_SIZE(wa_value_get_item_count(cipherdict), 1);
                    WA_REQUIRE(chunks != NULL);
                    WA_CHECK_SIZE(wa_value_get_item_count(chunks), (key_struct_length + 59) / 60);
                    for (chunk_index = 0; chunk_index < wa_value_get_item_count(chunks); ++chunk_index) {
                        const uint8_t *chunk = NULL;
                        size_t chunk_length = 0;
                        WA_CHECK(wa_value_get_bytes(wa_value_get_array_item(chunks, chunk_index), &chunk,
                                                    &chunk_length) == 0);
                        WA_CHECK_SIZE(chunk_length, 256);
                    }
                } else {
                    size_t length;
                    WA_CHECK_SIZE(wa_value_get_item_count(cipherdict), 2);
                    WA_CHECK(get_bytes_entry(cipherdict, "kem_ciphertext", &length) != NULL);
                    WA_CHECK_SIZE(length, public_keys[key_index].cipher_algo == WA_ASYMMETRIC_CIPHER_ECIES_X25519
                                              ? WA_X25519_KEY_SIZE
                                              : WA_ML_KEM_768_CIPHERTEXT_SIZE);
                    WA_CHECK(get_bytes_entry(cipherdict, "ciphertext", &length) != NULL);
                    WA_CHECK_SIZE(length, key_struct_length + WA_AEAD_TAG_SIZE);
                }
                wa_value_destroy(cipherdict);
                wa_value_destroy(metadata);
                wa_growable_byte_buffer_release(&symkey_bytes);
                WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
                WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
                wa_test_platform_destroy(platform);
            }
        }
    }
    free(modulus);
    free(exponent);
    free(x25519_key);
    free(ml_kem_key);
}

static void test_key_struct_wrapping_failures(void)
{
    size_t x25519_key_length;
    uint8_t *x25519_key = decode(WA_HPKE_X25519_PUBLIC_KEY_HEX, &x25519_key_length);
    wa_asymmetric_public_key_t public_key;
    wa_document_format_t format = wa_document_format_is_enabled(WA_DOCUMENT_FORMAT_CBOR) ? WA_DOCUMENT_FORMAT_CBOR
                                                                                         : WA_DOCUMENT_FORMAT_JSON;
    static const uint8_t key_bytes[40] = {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
    size_t attempt_index;
    int completed = 0;
    memset(&public_key, 0, sizeof(public_key));
    public_key.cipher_algo = WA_ASYMMETRIC_CIPHER_ECIES_X25519;
    public_key.key_bytes = x25519_key;
    public_key.key_bytes_length = x25519_key_length;
    {
        wa_test_platform_t *platform = wa_test_platform_create(60);
        wa_value_t *not_a_map = NULL;
        wa_value_t *cipherdict = NULL;
        WA_REQUIRE_STATUS(wa_value_create_null(&platform->hooks, &not_a_map), WA_STATUS_OK);
        WA_CHECK_STATUS(wa_asymmetric_wrap_key_struct(&platform->hooks, &public_key, format, key_bytes,
                                                      sizeof(key_bytes), not_a_map, &cipherdict),
                        WA_STATUS_INVALID_ARGUMENT);
        public_key.key_bytes_length = 31;
        WA_CHECK_STATUS(wa_asymmetric_wrap_key_struct(&platform->hooks, &public_key, format, key_bytes,
                                                      sizeof(key_bytes), NULL, &cipherdict),
                        WA_STATUS_INVALID_ARGUMENT);
        public_key.key_bytes_length = x25519_key_length;
        public_key.cipher_algo = (wa_asymmetric_cipher_algo_t)9;
        WA_CHECK_STATUS(wa_asymmetric_wrap_key_struct(&platform->hooks, &public_key, format, key_bytes,
                                                      sizeof(key_bytes), NULL, &cipherdict),
                        WA_STATUS_INVALID_ARGUMENT);
        public_key.cipher_algo = WA_ASYMMETRIC_CIPHER_ECIES_X25519;
        WA_CHECK(cipherdict == NULL);
        wa_value_destroy(not_a_map);
        WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
        wa_test_platform_destroy(platform);
    }
    /* Allocation failures at each attempt after the metadata is built: nothing leaks, the key struct is wiped */
    for (attempt_index = 0; !completed; ++attempt_index) {
        wa_test_platform_t *platform = wa_test_platform_create(61);
        wa_value_t *metadata = build_metadata(&platform->hooks);
        wa_value_t *cipherdict = NULL;
        wa_status_t status;
        wa_test_allocator_register_secret_pattern(&platform->allocator, key_bytes, WA_TEST_SECRET_PATTERN_LENGTH);
        platform->allocator.fail_at_attempt_index = platform->allocator.attempted_allocation_count + attempt_index;
        status = wa_asymmetric_wrap_key_struct(&platform->hooks, &public_key, format, key_bytes, sizeof(key_bytes),
                                               metadata, &cipherdict);
        if (platform->allocator.failure_was_injected) {
            WA_CHECK_STATUS(status, WA_STATUS_OUT_OF_MEMORY);
            WA_CHECK(cipherdict == NULL);
        } else {
            WA_CHECK_STATUS(status, WA_STATUS_OK);
            completed = 1;
        }
        wa_value_destroy(cipherdict);
        wa_value_destroy(metadata);
        WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
        WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
        wa_test_platform_destroy(platform);
    }
    free(x25519_key);
}

int main(void)
{
    WA_RUN_TEST(test_oaep_encoding_against_pycryptodome);
    WA_RUN_TEST(test_oaep_ciphertext_against_pycryptodome);
    WA_RUN_TEST(test_oaep_chunk_counts);
    WA_RUN_TEST(test_oaep_failures);
    WA_RUN_TEST(test_hkdf_rfc5869);
    WA_RUN_TEST(test_hpke_rfc9180_base_mode);
    WA_RUN_TEST(test_hpke_x25519_against_pycryptodome);
    WA_RUN_TEST(test_hpke_ml_kem_768_against_pycryptodome);
    WA_RUN_TEST(test_hpke_low_order_x25519_key);
    WA_RUN_TEST(test_hpke_failures);
    WA_RUN_TEST(test_asymmetric_cipher_algo_names);
    WA_RUN_TEST(test_key_struct_wrapping);
    WA_RUN_TEST(test_key_struct_wrapping_failures);
    return wa_test_finish();
}
