/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Cryptoconf validation (design D10): a mirror of wacryptolib's CRYPTOCONF_SCHEMA_PYTHON
 * (src/wacryptolib/cryptainer/_validation.py), plus the rules of the C encryptor.
 *
 * Mirrored rules: closed maps per node type (unknown keys rejected, so the output fields key_ciphertext,
 * key_ciphertext_format and payload_macs too), algorithm names, trustee grammar, UUID and integer types, non-empty
 * payload_cipher_layers and key_cipher_layers lists, 1 <= key_shared_secret_threshold <= len(shards), the legacy
 * payload_signatures alias (one of the two keys, never both) and the signature conf grammar.
 * C rules: a mandatory root keychain_uid (WA_STATUS_INVALID_PROFILE), non-empty signature lists
 * (WA_STATUS_UNSUPPORTED_SIGNATURE, once their items are found well-formed), and the key cipher nesting depth
 * (WA_STATUS_NESTING_TOO_DEEP beyond WA_MAX_KEY_CIPHER_NESTING_DEPTH, a payload layer's key_cipher_layers list
 * being level 1, each shard or symmetric key layer holding key_cipher_layers adding one level).
 * Other violations give WA_STATUS_INVALID_PROFILE. On error, `location` names the faulty item (a missing key is
 * named as if it were present). Resolving asymmetric layers to public keys is the device profile's job. */

#ifndef WA_CRYPTOCONF_VALIDATION_H
#define WA_CRYPTOCONF_VALIDATION_H

#include "core/wa_error_location_path.h"
#include "wa_flightbox/wa_status_codes.h"
#include "wa_flightbox/wa_value_tree.h"

#define WA_SHARED_SECRET_ALGO_MARKER "[SHARED_SECRET]"

/* Validate a cryptoconf, `location` holding the path of the cryptoconf itself (e.g. "cryptoconf"). */
wa_status_t wa_cryptoconf_validate(const wa_value_t *cryptoconf, wa_error_location_path_t *location);

/* Validate a trustee map: {"trustee_type": "local_keyfactory"}, {"trustee_type": "authenticator", "keystore_uid":
 * UUID, optional "keystore_owner": text}, or {"trustee_type": "jsonrpc_api", "jsonrpc_url": text}. */
wa_status_t wa_cryptoconf_validate_trustee(const wa_value_t *trustee, wa_error_location_path_t *location);

/* 1 if two valid trustees have the same identity: trustee_type, plus keystore_uid for authenticators and
 * jsonrpc_url for JSON-RPC APIs (keystore_owner never counts), else 0. */
int wa_trustee_identities_are_equal(const wa_value_t *trustee_a, const wa_value_t *trustee_b);

#endif /* WA_CRYPTOCONF_VALIDATION_H */
