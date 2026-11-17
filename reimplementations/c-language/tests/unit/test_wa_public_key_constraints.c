/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Unit tests of the public key constraints (task 5.7, device profile specification section 5): every accepted and
 * rejected case for RSA, X25519 and ML-KEM-768 keys. The X25519 low-order list is cross-checked with the backend:
 * each of its points gives an all-zero shared secret (or a backend refusal). */

#include <stdlib.h>
#include <string.h>

#include "backends/wa_crypto_backend.h"
#include "primitives/wa_public_key_constraints.h"
#include "wa_minimal_test_harness.h"
#include "wa_primitive_vectors.h"
#include "wa_test_support.h"

#define WA_VIOLATION WA_STATUS_KEY_CONSTRAINT_VIOLATION

static uint8_t *decode(const char *hex, size_t *length_out)
{
    uint8_t *bytes = wa_test_decode_hex(hex, length_out);
    if (bytes == NULL) {
        abort();
    }
    return bytes;
}

/* RSA */

static void test_rsa_constraints(void)
{
    size_t modulus_length, exponent_length;
    uint8_t *modulus = decode(wa_oaep_modulus_hex, &modulus_length);
    uint8_t *exponent = decode(wa_oaep_public_exponent_hex, &exponent_length);
    uint8_t big_modulus[WA_MAX_RSA_MODULUS_BITS / 8 + 1];
    uint8_t big_exponent[WA_MAX_RSA_MODULUS_BITS / 8 + 1];
    uint8_t small_exponent[1];
    uint8_t padded_exponent[2] = {0x00, 0x03};
    WA_REQUIRE(modulus_length == 256);
    /* A wacryptolib RSA-2048 key, and small odd exponents */
    WA_CHECK_STATUS(wa_public_key_check_rsa(modulus, modulus_length, exponent, exponent_length), WA_STATUS_OK);
    small_exponent[0] = 3;
    WA_CHECK_STATUS(wa_public_key_check_rsa(modulus, modulus_length, small_exponent, 1), WA_STATUS_OK);
    /* e = 1, e = 2, e even, e with a leading zero, empty e */
    small_exponent[0] = 1;
    WA_CHECK_STATUS(wa_public_key_check_rsa(modulus, modulus_length, small_exponent, 1), WA_VIOLATION);
    small_exponent[0] = 2;
    WA_CHECK_STATUS(wa_public_key_check_rsa(modulus, modulus_length, small_exponent, 1), WA_VIOLATION);
    small_exponent[0] = 0x10;
    WA_CHECK_STATUS(wa_public_key_check_rsa(modulus, modulus_length, small_exponent, 1), WA_VIOLATION);
    WA_CHECK_STATUS(wa_public_key_check_rsa(modulus, modulus_length, padded_exponent, 2), WA_VIOLATION);
    WA_CHECK_STATUS(wa_public_key_check_rsa(modulus, modulus_length, small_exponent, 0), WA_VIOLATION);
    /* e = n (odd), e = n - 2 (largest odd e below n), e > n */
    WA_CHECK_STATUS(wa_public_key_check_rsa(modulus, modulus_length, modulus, modulus_length), WA_VIOLATION);
    memcpy(big_exponent, modulus, modulus_length);
    big_exponent[modulus_length - 1] = (uint8_t)(big_exponent[modulus_length - 1] - 2u); /* n ends in an odd byte >= 3 */
    WA_REQUIRE(modulus[modulus_length - 1] >= 3);
    WA_CHECK_STATUS(wa_public_key_check_rsa(modulus, modulus_length, big_exponent, modulus_length), WA_STATUS_OK);
    big_exponent[modulus_length - 1] = (uint8_t)(big_exponent[modulus_length - 1] + 4u);
    WA_REQUIRE(modulus[modulus_length - 1] <= 0xfd);
    WA_CHECK_STATUS(wa_public_key_check_rsa(modulus, modulus_length, big_exponent, modulus_length), WA_VIOLATION);
    big_exponent[0] = 0x01;
    big_exponent[modulus_length] = 0x01; /* Odd, one byte longer than n */
    WA_CHECK_STATUS(wa_public_key_check_rsa(modulus, modulus_length, big_exponent, modulus_length + 1),
                    WA_VIOLATION);
    /* Even modulus, modulus with a leading zero, empty modulus */
    modulus[modulus_length - 1] ^= 1u;
    WA_CHECK_STATUS(wa_public_key_check_rsa(modulus, modulus_length, exponent, exponent_length), WA_VIOLATION);
    modulus[modulus_length - 1] ^= 1u;
    big_modulus[0] = 0;
    memcpy(big_modulus + 1, modulus, modulus_length);
    WA_CHECK_STATUS(wa_public_key_check_rsa(big_modulus, modulus_length + 1, exponent, exponent_length),
                    WA_VIOLATION);
    WA_CHECK_STATUS(wa_public_key_check_rsa(modulus, 0, exponent, exponent_length), WA_VIOLATION);
    /* Sizes: 2047 bits rejected, 2048 bits accepted, 1024 bits rejected */
    memset(big_modulus, 0xff, sizeof(big_modulus));
    big_modulus[0] = 0x7f;
    WA_CHECK_STATUS(wa_public_key_check_rsa(big_modulus, 256, exponent, exponent_length), WA_VIOLATION);
    big_modulus[0] = 0x80;
    WA_CHECK_STATUS(wa_public_key_check_rsa(big_modulus, 256, exponent, exponent_length), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_public_key_check_rsa(big_modulus, 128, exponent, exponent_length), WA_VIOLATION);
    /* The maximum (4096 bits by default) accepted, one more byte rejected */
    WA_CHECK_STATUS(wa_public_key_check_rsa(big_modulus, WA_MAX_RSA_MODULUS_BITS / 8, exponent, exponent_length),
                    WA_STATUS_OK);
    big_modulus[0] = 0x01;
    WA_CHECK_STATUS(
        wa_public_key_check_rsa(big_modulus, WA_MAX_RSA_MODULUS_BITS / 8 + 1, exponent, exponent_length),
        WA_VIOLATION);
    free(modulus);
    free(exponent);
}

/* X25519 */

static void test_x25519_constraints(void)
{
    /* p - 2, the largest canonical u-coordinate not in the low-order list */
    uint8_t key[WA_X25519_KEY_SIZE];
    size_t pycryptodome_key_length;
    uint8_t *pycryptodome_key = decode(WA_HPKE_X25519_PUBLIC_KEY_HEX, &pycryptodome_key_length);
    size_t rfc9180_key_length;
    uint8_t *rfc9180_key = decode(WA_RFC9180_PKRM_HEX, &rfc9180_key_length);
    WA_CHECK_STATUS(wa_public_key_check_x25519(pycryptodome_key, pycryptodome_key_length), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_public_key_check_x25519(rfc9180_key, rfc9180_key_length), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_public_key_check_x25519(rfc9180_key, 31), WA_VIOLATION);
    WA_CHECK_STATUS(wa_public_key_check_x25519(rfc9180_key, 33), WA_VIOLATION);
    /* Most significant bit set */
    memcpy(key, rfc9180_key, sizeof(key));
    key[31] |= 0x80u;
    WA_CHECK_STATUS(wa_public_key_check_x25519(key, sizeof(key)), WA_VIOLATION);
    /* p - 2 accepted; p - 1 (low order), p, p + 1 and 2^255 - 1 rejected */
    memset(key, 0xff, sizeof(key));
    key[31] = 0x7f;
    key[0] = 0xeb;
    WA_CHECK_STATUS(wa_public_key_check_x25519(key, sizeof(key)), WA_STATUS_OK);
    key[0] = 0xec;
    WA_CHECK_STATUS(wa_public_key_check_x25519(key, sizeof(key)), WA_VIOLATION);
    key[0] = 0xed;
    WA_CHECK_STATUS(wa_public_key_check_x25519(key, sizeof(key)), WA_VIOLATION);
    key[0] = 0xee;
    WA_CHECK_STATUS(wa_public_key_check_x25519(key, sizeof(key)), WA_VIOLATION);
    key[0] = 0xff;
    WA_CHECK_STATUS(wa_public_key_check_x25519(key, sizeof(key)), WA_VIOLATION);
    /* Below p by a middle byte: accepted */
    key[0] = 0xff;
    key[15] = 0xfe;
    WA_CHECK_STATUS(wa_public_key_check_x25519(key, sizeof(key)), WA_STATUS_OK);
    /* 0, 1 rejected; 2 and 9 (the base point) accepted */
    memset(key, 0, sizeof(key));
    WA_CHECK_STATUS(wa_public_key_check_x25519(key, sizeof(key)), WA_VIOLATION);
    key[0] = 1;
    WA_CHECK_STATUS(wa_public_key_check_x25519(key, sizeof(key)), WA_VIOLATION);
    key[0] = 2;
    WA_CHECK_STATUS(wa_public_key_check_x25519(key, sizeof(key)), WA_STATUS_OK);
    key[0] = 9;
    WA_CHECK_STATUS(wa_public_key_check_x25519(key, sizeof(key)), WA_STATUS_OK);
    free(pycryptodome_key);
    free(rfc9180_key);
}

static void test_x25519_low_order_points_give_zero_secrets(void)
{
    static const char *const low_order_hexes[] = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"};
    uint8_t scalar[WA_X25519_KEY_SIZE];
    size_t index;
    for (index = 0; index < sizeof(scalar); ++index) {
        scalar[index] = (uint8_t)(0x31 * index + 7);
    }
    for (index = 0; index < sizeof(low_order_hexes) / sizeof(low_order_hexes[0]); ++index) {
        size_t point_length;
        uint8_t *point = decode(low_order_hexes[index], &point_length);
        uint8_t shared_secret[WA_X25519_KEY_SIZE];
        wa_status_t status;
        WA_CHECK_STATUS(wa_public_key_check_x25519(point, point_length), WA_VIOLATION);
        memset(shared_secret, 0x55, sizeof(shared_secret));
        status = wa_crypto_backend_x25519_compute_shared_secret(scalar, point, shared_secret);
        if (status == WA_STATUS_OK) {
            static const uint8_t zeros[WA_X25519_KEY_SIZE] = {0};
            WA_CHECK_BYTES(shared_secret, sizeof(shared_secret), zeros, sizeof(zeros));
        } else {
            WA_CHECK_STATUS(status, WA_STATUS_CRYPTO_BACKEND_FAILURE);
        }
        free(point);
    }
}

/* ML-KEM-768 */

static void set_coefficient(uint8_t *public_key, size_t coefficient_index, unsigned int value)
{
    uint8_t *triple = public_key + (coefficient_index / 2) * 3;
    if (coefficient_index % 2 == 0) {
        triple[0] = (uint8_t)value;
        triple[1] = (uint8_t)((triple[1] & 0xf0u) | ((value >> 8) & 0x0fu));
    } else {
        triple[1] = (uint8_t)((triple[1] & 0x0fu) | ((value & 0x0fu) << 4));
        triple[2] = (uint8_t)(value >> 4);
    }
}

static void test_ml_kem_768_constraints(void)
{
    static const size_t coefficient_indices[] = {0, 1, 254, 255, 256, 511, 766, 767};
    size_t key_length;
    uint8_t *key = decode(wa_hpke_ml_kem_768_public_key_hex, &key_length);
    uint8_t *modified_key = (uint8_t *)malloc(key_length);
    size_t index;
    WA_REQUIRE(key_length == WA_ML_KEM_768_PUBLIC_KEY_SIZE && modified_key != NULL);
    WA_CHECK_STATUS(wa_public_key_check_ml_kem_768(key, key_length), WA_STATUS_OK);
    WA_CHECK_STATUS(wa_public_key_check_ml_kem_768(key, key_length - 1), WA_VIOLATION);
    WA_CHECK_STATUS(wa_public_key_check_ml_kem_768(key, 800), WA_VIOLATION); /* An ML-KEM-512 size */
    for (index = 0; index < sizeof(coefficient_indices) / sizeof(coefficient_indices[0]); ++index) {
        static const unsigned int rejected_values[] = {3329, 3330, 4095};
        size_t value_index;
        memcpy(modified_key, key, key_length);
        set_coefficient(modified_key, coefficient_indices[index], 3328);
        WA_CHECK_STATUS(wa_public_key_check_ml_kem_768(modified_key, key_length), WA_STATUS_OK);
        set_coefficient(modified_key, coefficient_indices[index], 0);
        WA_CHECK_STATUS(wa_public_key_check_ml_kem_768(modified_key, key_length), WA_STATUS_OK);
        for (value_index = 0; value_index < 3; ++value_index) {
            set_coefficient(modified_key, coefficient_indices[index], rejected_values[value_index]);
            WA_CHECK_STATUS(wa_public_key_check_ml_kem_768(modified_key, key_length), WA_VIOLATION);
        }
    }
    /* The seed rho (last 32 bytes) is not made of coefficients: any value is accepted */
    memcpy(modified_key, key, key_length);
    memset(modified_key + key_length - 32, 0xff, 32);
    WA_CHECK_STATUS(wa_public_key_check_ml_kem_768(modified_key, key_length), WA_STATUS_OK);
    free(key);
    free(modified_key);
}

int main(void)
{
    WA_RUN_TEST(test_rsa_constraints);
    WA_RUN_TEST(test_x25519_constraints);
    WA_RUN_TEST(test_x25519_low_order_points_give_zero_secrets);
    WA_RUN_TEST(test_ml_kem_768_constraints);
    return wa_test_finish();
}
