/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "primitives/wa_asymmetric_key_wrapping.h"

#include <string.h>

#include "encoding/wa_document_serialization.h"
#include "encoding/wa_growable_byte_buffer.h"
#include "encoding/wa_value_tree_internal.h"
#include "primitives/wa_hpke_base_mode_seal.h"
#include "primitives/wa_hpke_kem_dhkem_x25519.h"
#include "primitives/wa_hpke_kem_ml_kem_768.h"
#include "primitives/wa_rsa_oaep_chunked_encryption.h"

static const char *const wa_asymmetric_cipher_algo_names[] = {"RSA_OAEP", "ECIES_X25519", "ML_KEM_768"};

int wa_asymmetric_cipher_algo_from_name(const char *name, size_t name_length, wa_asymmetric_cipher_algo_t *algo_out)
{
    size_t index;
    for (index = 0; index < sizeof(wa_asymmetric_cipher_algo_names) / sizeof(wa_asymmetric_cipher_algo_names[0]);
         ++index) {
        const char *candidate = wa_asymmetric_cipher_algo_names[index];
        if (strlen(candidate) == name_length && memcmp(candidate, name, name_length) == 0) {
            *algo_out = (wa_asymmetric_cipher_algo_t)(index + 1u);
            return 1;
        }
    }
    return 0;
}

const char *wa_asymmetric_cipher_algo_get_name(wa_asymmetric_cipher_algo_t cipher_algo)
{
    if (cipher_algo < WA_ASYMMETRIC_CIPHER_RSA_OAEP || cipher_algo > WA_ASYMMETRIC_CIPHER_ML_KEM_768) {
        return NULL;
    }
    return wa_asymmetric_cipher_algo_names[cipher_algo - 1];
}

wa_status_t wa_asymmetric_encrypt_to_cipherdict(const wa_platform_hooks_t *platform_hooks,
                                                const wa_asymmetric_public_key_t *public_key,
                                                const uint8_t *plaintext, size_t plaintext_length,
                                                wa_value_t **cipherdict_out)
{
    const wa_hpke_kem_t *kem;
    *cipherdict_out = NULL;
    switch (public_key->cipher_algo) {
    case WA_ASYMMETRIC_CIPHER_RSA_OAEP:
        return wa_rsa_oaep_encrypt_into_chunks(platform_hooks, public_key->modulus, public_key->modulus_length,
                                               public_key->public_exponent, public_key->public_exponent_length,
                                               plaintext, plaintext_length, cipherdict_out);
    case WA_ASYMMETRIC_CIPHER_ECIES_X25519:
        kem = &wa_hpke_kem_dhkem_x25519;
        break;
    case WA_ASYMMETRIC_CIPHER_ML_KEM_768:
        kem = &wa_hpke_kem_ml_kem_768;
        break;
    default:
        return WA_STATUS_INVALID_ARGUMENT;
    }
    if (public_key->key_bytes_length != kem->public_key_length) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    return wa_hpke_base_mode_seal_to_cipherdict(platform_hooks, kem, public_key->key_bytes, plaintext,
                                                plaintext_length, cipherdict_out);
}

wa_status_t wa_asymmetric_serialize_key_struct(const wa_platform_hooks_t *platform_hooks,
                                               wa_document_format_t resolved_format, const uint8_t *key_bytes,
                                               size_t key_bytes_length,
                                               const wa_value_t *cryptainer_metadata_or_null,
                                               wa_growable_byte_buffer_t *serialized_out)
{
    /* Borrowed nodes around the data of the caller: no allocation but the serialization buffer */
    wa_value_t key_struct;
    wa_value_t key_bytes_node;
    wa_value_t null_node;
    wa_value_map_entry_t entries[2];
    wa_status_t status;
    wa_growable_byte_buffer_initialize(serialized_out, platform_hooks, 1);
    if (cryptainer_metadata_or_null != NULL && wa_value_get_type(cryptainer_metadata_or_null) != WA_VALUE_TYPE_MAP) {
        return WA_STATUS_INVALID_ARGUMENT;
    }
    wa_value_initialize_borrowed_bytes(&key_bytes_node, key_bytes, key_bytes_length);
    wa_value_initialize_borrowed_null(&null_node);
    wa_value_initialize_borrowed_map_entry(&entries[0], "key_bytes", &key_bytes_node);
    wa_value_initialize_borrowed_map_entry(&entries[1], "cryptainer_metadata",
                                           cryptainer_metadata_or_null != NULL ? cryptainer_metadata_or_null
                                                                               : &null_node);
    wa_value_initialize_borrowed_map(&key_struct, entries, 2);
    status = wa_document_serialize_to_buffer(&key_struct, resolved_format, serialized_out);
    if (status != WA_STATUS_OK) {
        wa_growable_byte_buffer_release(serialized_out);
    }
    return status;
}

wa_status_t wa_asymmetric_wrap_key_struct(const wa_platform_hooks_t *platform_hooks,
                                          const wa_asymmetric_public_key_t *public_key,
                                          wa_document_format_t resolved_format, const uint8_t *key_bytes,
                                          size_t key_bytes_length, const wa_value_t *cryptainer_metadata_or_null,
                                          wa_value_t **cipherdict_out)
{
    wa_growable_byte_buffer_t serialized_key_struct;
    wa_status_t status;
    *cipherdict_out = NULL;
    status = wa_asymmetric_serialize_key_struct(platform_hooks, resolved_format, key_bytes, key_bytes_length,
                                                cryptainer_metadata_or_null, &serialized_key_struct);
    if (status != WA_STATUS_OK) {
        return status;
    }
    status = wa_asymmetric_encrypt_to_cipherdict(platform_hooks, public_key, serialized_key_struct.data,
                                                 serialized_key_struct.length, cipherdict_out);
    wa_growable_byte_buffer_release(&serialized_key_struct);
    return status;
}
