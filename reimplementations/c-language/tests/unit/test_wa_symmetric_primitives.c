/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Unit tests of the symmetric primitives (tasks 5.1, 5.2 and 5.3): symkey generation, PKCS#7, AES-256 CMAC (SP
 * 800-38B examples), AES-256 EAX (over the EAX paper messages, see generate_primitive_vectors.py), cipher streams and
 * one-shot cipherdicts against wacryptolib, chunked and one-shot alike, on each backend. */

#include <stdlib.h>
#include <string.h>

#include "encoding/wa_value_tree_internal.h"
#include "primitives/wa_aes_cbc_pkcs7_padding.h"
#include "primitives/wa_aes_cmac_omac1.h"
#include "primitives/wa_aes_eax_mode.h"
#include "primitives/wa_secure_memory_wipe.h"
#include "primitives/wa_symmetric_cipher_streams.h"
#include "primitives/wa_symmetric_key_generation.h"
#include "wa_minimal_test_harness.h"
#include "wa_primitive_vectors.h"
#include "wa_test_support.h"

#define WA_ARRAY_LENGTH(array) (sizeof(array) / sizeof((array)[0]))

/* Chunk sizes of the chunked equivalence checks, used in turn */
static const size_t wa_chunk_patterns[][4] = {{1, 1, 1, 1}, {15, 15, 15, 15}, {16, 16, 16, 16}, {17, 17, 17, 17},
                                               {1, 15, 16, 17}, {0, 17, 0, 15}};

static uint8_t *decode(const char *hex, size_t *length_out)
{
    uint8_t *bytes = wa_test_decode_hex(hex, length_out);
    if (bytes == NULL) {
        abort();
    }
    return bytes;
}

/* SYMKEY GENERATION */

static void test_symmetric_cipher_algo_names(void)
{
    wa_symmetric_cipher_algo_t algo = WA_SYMMETRIC_CIPHER_AES_CBC;
    WA_CHECK(wa_symmetric_cipher_algo_from_name("AES_EAX", 7, &algo) && algo == WA_SYMMETRIC_CIPHER_AES_EAX);
    WA_CHECK(wa_symmetric_cipher_algo_from_name("CHACHA20_POLY1305", 17, &algo) &&
             algo == WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305);
    WA_CHECK(wa_symmetric_cipher_algo_from_name("AES_CBC", 7, &algo) && algo == WA_SYMMETRIC_CIPHER_AES_CBC);
    WA_CHECK(!wa_symmetric_cipher_algo_from_name("AES_CB", 6, &algo));
    WA_CHECK(!wa_symmetric_cipher_algo_from_name("aes_cbc", 7, &algo));
    WA_CHECK(!wa_symmetric_cipher_algo_from_name("RSA_OAEP", 8, &algo));
    WA_CHECK(strcmp(wa_symmetric_cipher_algo_get_iv_or_nonce_field_name(WA_SYMMETRIC_CIPHER_AES_CBC), "iv") == 0);
    WA_CHECK(strcmp(wa_symmetric_cipher_algo_get_iv_or_nonce_field_name(WA_SYMMETRIC_CIPHER_AES_EAX), "nonce") == 0);
    WA_CHECK(wa_symmetric_cipher_algo_get_name((wa_symmetric_cipher_algo_t)9) == NULL);
    WA_CHECK(!wa_symmetric_cipher_algo_has_tag(WA_SYMMETRIC_CIPHER_AES_CBC));
    WA_CHECK(wa_symmetric_cipher_algo_has_tag(WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305));
}

static void test_symkey_generation(void)
{
    static const struct {
        wa_symmetric_cipher_algo_t algo;
        const char *field_name;
        size_t iv_or_nonce_length;
    } cases[] = {{WA_SYMMETRIC_CIPHER_AES_CBC, "iv", 16},
                 {WA_SYMMETRIC_CIPHER_AES_EAX, "nonce", 16},
                 {WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305, "nonce", 12}};
    size_t index;
    for (index = 0; index < WA_ARRAY_LENGTH(cases); ++index) {
        wa_test_platform_t *platform = wa_test_platform_create(10 + index);
        wa_test_random_generator_t twin_generator;
        uint8_t expected_key[32];
        uint8_t expected_iv_or_nonce[16];
        wa_symkey_t symkey;
        wa_value_t *tree = NULL;
        const uint8_t *bytes;
        size_t length;
        wa_test_random_generator_initialize(&twin_generator, 10 + index);
        WA_REQUIRE(wa_test_fill_random(&twin_generator, expected_key, 32) == 0);
        WA_REQUIRE(wa_test_fill_random(&twin_generator, expected_iv_or_nonce, cases[index].iv_or_nonce_length) == 0);

        WA_CHECK_STATUS(wa_symkey_generate(&platform->hooks, cases[index].algo, &symkey), WA_STATUS_OK);
        /* The key is drawn first, then the IV or nonce */
        WA_CHECK_BYTES(symkey.key, 32, expected_key, 32);
        WA_CHECK_BYTES(symkey.iv_or_nonce, symkey.iv_or_nonce_length, expected_iv_or_nonce,
                       cases[index].iv_or_nonce_length);
        WA_CHECK_SIZE(platform->random_generator.call_count, 2);

        WA_CHECK_STATUS(wa_symkey_build_tree(&platform->hooks, &symkey, &tree), WA_STATUS_OK);
        WA_REQUIRE(tree != NULL);
        WA_CHECK_SIZE(wa_value_get_item_count(tree), 2);
        WA_CHECK(wa_value_get_bytes(wa_value_find_map_value(tree, "key"), &bytes, &length) == 0 && length == 32 &&
                 memcmp(bytes, expected_key, 32) == 0);
        WA_CHECK(wa_value_get_bytes(wa_value_find_map_value(tree, cases[index].field_name), &bytes, &length) == 0 &&
                 length == cases[index].iv_or_nonce_length);
        wa_value_destroy(tree);
        wa_symkey_wipe(&symkey);

        /* A failing random hook leaves a wiped symkey */
        platform->random_generator.fail_at_call_index = platform->random_generator.call_count + 1;
        WA_CHECK_STATUS(wa_symkey_generate(&platform->hooks, cases[index].algo, &symkey), WA_STATUS_RANDOMNESS_FAILURE);
        WA_CHECK(wa_constant_time_is_all_zero((const uint8_t *)&symkey, sizeof(symkey)));

        WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
        WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
        wa_test_platform_destroy(platform);
    }
}

/* PKCS#7 */

static void test_pkcs7_padding(void)
{
    uint8_t block[16];
    WA_CHECK_SIZE(wa_pkcs7_get_padding_length(0), 16);
    WA_CHECK_SIZE(wa_pkcs7_get_padding_length(1), 15);
    WA_CHECK_SIZE(wa_pkcs7_get_padding_length(15), 1);
    WA_CHECK_SIZE(wa_pkcs7_get_padding_length(16), 16);
    WA_CHECK_SIZE(wa_pkcs7_get_padding_length(33), 15);
    memset(block, 0xaa, sizeof(block));
    wa_pkcs7_pad_final_block(block, 13);
    WA_CHECK_HEX(block, 16, "aaaaaaaaaaaaaaaaaaaaaaaaaa030303");
    wa_pkcs7_pad_final_block(block, 0);
    WA_CHECK_HEX(block, 16, "10101010101010101010101010101010");
}

/* CMAC */

static void compute_chunked_cmac(wa_crypto_backend_aes_256_t *aes, const uint8_t *message, size_t length,
                                 const size_t pattern[4], uint8_t mac[16])
{
    wa_aes_cmac_t cmac;
    size_t offset = 0;
    size_t step = 0;
    WA_REQUIRE_STATUS(wa_aes_cmac_start(&cmac, aes), WA_STATUS_OK);
    while (offset < length) {
        size_t chunk = pattern[step++ % 4];
        if (chunk > length - offset) {
            chunk = length - offset;
        }
        WA_CHECK_STATUS(wa_aes_cmac_update(&cmac, message + offset, chunk), WA_STATUS_OK);
        offset += chunk;
    }
    WA_CHECK_STATUS(wa_aes_cmac_finish(&cmac, mac), WA_STATUS_OK);
}

static void test_aes_cmac(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(20);
    wa_crypto_backend_aes_256_t *aes = NULL;
    size_t key_length, message_length, index, pattern_index;
    uint8_t *key = decode(WA_CMAC_KEY_HEX, &key_length);
    uint8_t *message = decode(WA_CMAC_FULL_MESSAGE_HEX, &message_length);
    wa_aes_cmac_t cmac;
    uint8_t mac[16];
    WA_REQUIRE_STATUS(wa_crypto_backend_aes_256_create(&platform->hooks, key, &aes), WA_STATUS_OK);

    WA_REQUIRE_STATUS(wa_aes_cmac_start(&cmac, aes), WA_STATUS_OK);
    WA_CHECK_HEX(cmac.subkey_1, 16, WA_CMAC_SUBKEY_1_HEX);
    WA_CHECK_HEX(cmac.subkey_2, 16, WA_CMAC_SUBKEY_2_HEX);
    wa_aes_cmac_wipe(&cmac);

    for (index = 0; index < WA_ARRAY_LENGTH(wa_cmac_vectors); ++index) {
        size_t length = wa_cmac_vectors[index].message_length;
        WA_REQUIRE_STATUS(wa_aes_cmac_start(&cmac, aes), WA_STATUS_OK);
        WA_CHECK_STATUS(wa_aes_cmac_update(&cmac, message, length), WA_STATUS_OK);
        WA_CHECK_STATUS(wa_aes_cmac_finish(&cmac, mac), WA_STATUS_OK);
        WA_CHECK_HEX(mac, 16, wa_cmac_vectors[index].mac_hex);
        for (pattern_index = 0; pattern_index < WA_ARRAY_LENGTH(wa_chunk_patterns); ++pattern_index) {
            compute_chunked_cmac(aes, message, length, wa_chunk_patterns[pattern_index], mac);
            WA_CHECK_HEX(mac, 16, wa_cmac_vectors[index].mac_hex);
        }
    }
    wa_crypto_backend_aes_256_destroy(aes);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    free(key);
    free(message);
    wa_test_platform_destroy(platform);
}

/* EAX */

static void check_eax(const wa_test_platform_t *platform, const uint8_t *key, const uint8_t *nonce, size_t nonce_length,
                      const uint8_t *message, size_t message_length, const uint8_t *expected_ciphertext,
                      const uint8_t *expected_tag, const size_t pattern[4], int in_place)
{
    wa_aes_eax_encryption_t encryption;
    uint8_t *output = (uint8_t *)malloc(message_length + 1);
    uint8_t tag[16];
    size_t offset = 0;
    size_t step = 0;
    WA_REQUIRE(output != NULL);
    if (in_place && message_length > 0) {
        memcpy(output, message, message_length);
    }
    WA_REQUIRE_STATUS(wa_aes_eax_encryption_start(&platform->hooks, key, nonce, nonce_length, &encryption),
                      WA_STATUS_OK);
    while (offset < message_length || (pattern == NULL && step == 0)) {
        size_t chunk = pattern != NULL ? pattern[step % 4] : message_length;
        ++step;
        if (chunk > message_length - offset) {
            chunk = message_length - offset;
        }
        WA_CHECK_STATUS(wa_aes_eax_encryption_update(&encryption, in_place ? output + offset : message + offset,
                                                     output + offset, chunk),
                        WA_STATUS_OK);
        offset += chunk;
    }
    WA_CHECK_STATUS(wa_aes_eax_encryption_finish(&encryption, tag), WA_STATUS_OK);
    wa_aes_eax_encryption_release(&encryption);
    WA_CHECK_BYTES(output, message_length, expected_ciphertext, message_length);
    WA_CHECK_BYTES(tag, 16, expected_tag, 16);
    free(output);
}

static void test_aes_eax(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(21);
    size_t index, pattern_index;
    for (index = 0; index < WA_ARRAY_LENGTH(wa_eax_vectors); ++index) {
        size_t key_length, nonce_length, message_length, ciphertext_length, tag_length;
        uint8_t *key = decode(wa_eax_vectors[index].key_hex, &key_length);
        uint8_t *nonce = decode(wa_eax_vectors[index].nonce_hex, &nonce_length);
        uint8_t *message = decode(wa_eax_vectors[index].message_hex, &message_length);
        uint8_t *ciphertext = decode(wa_eax_vectors[index].ciphertext_hex, &ciphertext_length);
        uint8_t *tag = decode(wa_eax_vectors[index].tag_hex, &tag_length);
        WA_REQUIRE(key_length == 32 && ciphertext_length == message_length && tag_length == 16);
        check_eax(platform, key, nonce, nonce_length, message, message_length, ciphertext, tag, NULL, 0);
        for (pattern_index = 0; pattern_index < WA_ARRAY_LENGTH(wa_chunk_patterns); ++pattern_index) {
            check_eax(platform, key, nonce, nonce_length, message, message_length, ciphertext, tag,
                      wa_chunk_patterns[pattern_index], (int)(pattern_index % 2));
        }
        free(key);
        free(nonce);
        free(message);
        free(ciphertext);
        free(tag);
    }
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

/* CIPHER STREAMS AND CIPHERDICTS */

static int load_symkey(size_t vector_index, wa_symkey_t *symkey)
{
    size_t key_length, nonce_length;
    uint8_t *key = decode(wa_symmetric_cipherdict_vectors[vector_index].key_hex, &key_length);
    uint8_t *nonce = decode(wa_symmetric_cipherdict_vectors[vector_index].iv_or_nonce_hex, &nonce_length);
    const char *algo_name = wa_symmetric_cipherdict_vectors[vector_index].cipher_algo;
    int is_valid = wa_symmetric_cipher_algo_from_name(algo_name, strlen(algo_name), &symkey->cipher_algo) &&
                   key_length == 32 && nonce_length <= 16;
    if (is_valid) {
        memcpy(symkey->key, key, 32);
        memcpy(symkey->iv_or_nonce, nonce, nonce_length);
        symkey->iv_or_nonce_length = nonce_length;
    }
    free(key);
    free(nonce);
    return is_valid;
}

static void check_stream(const wa_test_platform_t *platform, const wa_symkey_t *symkey, const uint8_t *plaintext,
                         size_t plaintext_length, const uint8_t *expected_ciphertext, size_t expected_length,
                         const char *expected_tag_hex, const size_t pattern[4])
{
    wa_symmetric_cipher_stream_t stream;
    uint8_t *output = (uint8_t *)malloc(plaintext_length + 32);
    uint8_t tag[16];
    size_t output_length = 0;
    size_t written, tag_length;
    size_t offset = 0;
    size_t step = 0;
    WA_REQUIRE(output != NULL);
    WA_REQUIRE_STATUS(wa_symmetric_cipher_stream_start(&platform->hooks, symkey, &stream), WA_STATUS_OK);
    while (offset < plaintext_length) {
        size_t chunk = pattern[step++ % 4];
        if (chunk > plaintext_length - offset) {
            chunk = plaintext_length - offset;
        }
        /* An empty input, even NULL, is a no-op at any point of the stream */
        written = 99;
        WA_CHECK_STATUS(wa_symmetric_cipher_stream_encrypt(&stream, NULL, 0, output + output_length, &written),
                        WA_STATUS_OK);
        WA_CHECK_SIZE(written, 0);
        WA_CHECK_STATUS(
            wa_symmetric_cipher_stream_encrypt(&stream, plaintext + offset, chunk, output + output_length, &written),
            WA_STATUS_OK);
        WA_CHECK(written <= chunk + 15);
        if (symkey->cipher_algo == WA_SYMMETRIC_CIPHER_AES_CBC) {
            WA_CHECK(written % 16 == 0);
        } else {
            WA_CHECK_SIZE(written, chunk);
        }
        output_length += written;
        offset += chunk;
    }
    written = 99;
    WA_CHECK_STATUS(wa_symmetric_cipher_stream_encrypt(&stream, NULL, 0, output + output_length, &written),
                    WA_STATUS_OK);
    WA_CHECK_SIZE(written, 0);
    WA_CHECK_STATUS(wa_symmetric_cipher_stream_finish(&stream, output + output_length, &written, tag, &tag_length),
                    WA_STATUS_OK);
    output_length += written;
    wa_symmetric_cipher_stream_release(&platform->hooks, &stream);
    WA_CHECK_BYTES(output, output_length, expected_ciphertext, expected_length);
    WA_CHECK_HEX(tag, tag_length, expected_tag_hex);
    free(output);
}

static void test_cipher_streams_and_cipherdicts(void)
{
    size_t index, pattern_index;
    WA_CHECK(WA_ARRAY_LENGTH(wa_symmetric_cipherdict_vectors) == 15);
    for (index = 0; index < WA_ARRAY_LENGTH(wa_symmetric_cipherdict_vectors); ++index) {
        wa_test_platform_t *platform = wa_test_platform_create(30 + index);
        size_t plaintext_length, ciphertext_length;
        uint8_t *plaintext = decode(wa_symmetric_cipherdict_vectors[index].plaintext_hex, &plaintext_length);
        uint8_t *ciphertext = decode(wa_symmetric_cipherdict_vectors[index].ciphertext_hex, &ciphertext_length);
        const char *tag_hex = wa_symmetric_cipherdict_vectors[index].tag_hex;
        wa_symkey_t symkey;
        wa_value_t *cipherdict = NULL;
        const uint8_t *bytes;
        size_t length;
        WA_REQUIRE(load_symkey(index, &symkey));
        wa_test_allocator_register_secret_pattern(&platform->allocator, symkey.key, 32);

        /* One-shot cipherdict: exactly the keys of section 3.4 */
        WA_CHECK_STATUS(wa_symmetric_encrypt_to_cipherdict(&platform->hooks, &symkey, plaintext, plaintext_length,
                                                           &cipherdict),
                        WA_STATUS_OK);
        WA_REQUIRE(cipherdict != NULL);
        WA_CHECK(wa_value_get_bytes(wa_value_find_map_value(cipherdict, "ciphertext"), &bytes, &length) == 0);
        WA_CHECK_BYTES(bytes, length, ciphertext, ciphertext_length);
        if (symkey.cipher_algo == WA_SYMMETRIC_CIPHER_AES_CBC) {
            WA_CHECK_SIZE(wa_value_get_item_count(cipherdict), 1);
            WA_CHECK_SIZE(length, plaintext_length + wa_pkcs7_get_padding_length(plaintext_length));
        } else {
            WA_CHECK_SIZE(wa_value_get_item_count(cipherdict), 2);
            WA_CHECK(wa_value_get_bytes(wa_value_find_map_value(cipherdict, "tag"), &bytes, &length) == 0);
            WA_CHECK_SIZE(length, 16);
            WA_CHECK_HEX(bytes, length, tag_hex);
        }
        wa_value_destroy(cipherdict);

        /* Streamed in chunks of 1, 15, 16, 17... bytes: the same ciphertext and tag */
        for (pattern_index = 0; pattern_index < WA_ARRAY_LENGTH(wa_chunk_patterns); ++pattern_index) {
            check_stream(platform, &symkey, plaintext, plaintext_length, ciphertext, ciphertext_length, tag_hex,
                         wa_chunk_patterns[pattern_index]);
        }

        WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
        WA_CHECK_SIZE(platform->allocator.unwiped_secret_release_count, 0);
        free(plaintext);
        free(ciphertext);
        wa_test_platform_destroy(platform);
    }
}

static void test_cipherdict_out_of_memory(void)
{
    size_t vector_index;
    for (vector_index = 0; vector_index < WA_ARRAY_LENGTH(wa_symmetric_cipherdict_vectors); vector_index += 4) {
        size_t attempt;
        wa_symkey_t symkey;
        WA_REQUIRE(load_symkey(vector_index, &symkey));
        for (attempt = 0;; ++attempt) {
            wa_test_platform_t *platform = wa_test_platform_create(40);
            wa_value_t *cipherdict = NULL;
            wa_status_t status;
            platform->allocator.fail_at_attempt_index = attempt;
            status = wa_symmetric_encrypt_to_cipherdict(&platform->hooks, &symkey, (const uint8_t *)"0123456789", 10,
                                                        &cipherdict);
            wa_value_destroy(cipherdict);
            WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
            if (!platform->allocator.failure_was_injected) {
                WA_CHECK_STATUS(status, WA_STATUS_OK);
                wa_test_platform_destroy(platform);
                break;
            }
            WA_CHECK_STATUS(status, WA_STATUS_OUT_OF_MEMORY);
            WA_CHECK(cipherdict == NULL);
            wa_test_platform_destroy(platform);
            WA_REQUIRE(attempt < 100);
        }
    }
}

static void test_payload_macs(void)
{
    wa_test_platform_t *platform = wa_test_platform_create(50);
    static const uint8_t tag[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    wa_value_t *payload_macs = NULL;
    const uint8_t *bytes;
    size_t length;
    WA_CHECK_STATUS(wa_symmetric_build_payload_macs(&platform->hooks, WA_SYMMETRIC_CIPHER_AES_CBC, NULL, 0,
                                                    &payload_macs),
                    WA_STATUS_OK);
    WA_CHECK(payload_macs != NULL && wa_value_get_type(payload_macs) == WA_VALUE_TYPE_MAP);
    WA_CHECK_SIZE(wa_value_get_item_count(payload_macs), 0);
    wa_value_destroy(payload_macs);
    WA_CHECK_STATUS(wa_symmetric_build_payload_macs(&platform->hooks, WA_SYMMETRIC_CIPHER_AES_EAX, tag, 16,
                                                    &payload_macs),
                    WA_STATUS_OK);
    WA_CHECK_SIZE(wa_value_get_item_count(payload_macs), 1);
    WA_CHECK(wa_value_get_bytes(wa_value_find_map_value(payload_macs, "tag"), &bytes, &length) == 0 && length == 16 &&
             memcmp(bytes, tag, 16) == 0);
    wa_value_destroy(payload_macs);
    WA_CHECK_STATUS(wa_symmetric_build_payload_macs(&platform->hooks, WA_SYMMETRIC_CIPHER_CHACHA20_POLY1305, tag, 0,
                                                    &payload_macs),
                    WA_STATUS_INVALID_ARGUMENT);
    WA_CHECK(payload_macs == NULL);
    WA_CHECK(wa_test_allocator_is_clean(&platform->allocator));
    wa_test_platform_destroy(platform);
}

int main(void)
{
    WA_RUN_TEST(test_symmetric_cipher_algo_names);
    WA_RUN_TEST(test_symkey_generation);
    WA_RUN_TEST(test_pkcs7_padding);
    WA_RUN_TEST(test_aes_cmac);
    WA_RUN_TEST(test_aes_eax);
    WA_RUN_TEST(test_cipher_streams_and_cipherdicts);
    WA_RUN_TEST(test_cipherdict_out_of_memory);
    WA_RUN_TEST(test_payload_macs);
    return wa_test_finish();
}
