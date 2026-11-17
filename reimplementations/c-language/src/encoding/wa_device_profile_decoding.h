/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Internals of device profiles (design D9): the loaded profile keeps its decoded tree, and its public key entries
 * borrow their trustee, keychain uid and raw key bytes from it. Profiles are immutable once loaded. */

#ifndef WA_DEVICE_PROFILE_DECODING_H
#define WA_DEVICE_PROFILE_DECODING_H

#include <stddef.h>
#include <stdint.h>

#include "primitives/wa_asymmetric_key_wrapping.h"
#include "wa_flightbox/wa_device_profile.h"
#include "wa_flightbox/wa_value_tree.h"

#define WA_DEVICE_PROFILE_FORMAT "flightbox_device_profile_1.0"
#define WA_X25519_PUBLIC_KEY_SIZE 32u
#define WA_ML_KEM_768_PUBLIC_KEY_SIZE 1184u

typedef struct wa_device_profile_key_entry {
    const wa_value_t *trustee;    /* Trustee map, borrowed from the profile tree */
    const uint8_t *keychain_uid;  /* WA_UUID_SIZE bytes, borrowed from the profile tree */
    wa_asymmetric_public_key_t public_key; /* Raw key material, borrowed from the profile tree */
} wa_device_profile_key_entry_t;

struct wa_device_profile {
    const wa_platform_hooks_t *platform_hooks;
    wa_value_t *document;         /* The whole decoded profile */
    const wa_value_t *cryptoconf; /* Validated cryptoconf, inside `document` */
    const uint8_t *root_keychain_uid;
    wa_device_profile_key_entry_t *key_entries;
    size_t key_entry_capacity; /* Allocated entries */
    size_t key_entry_count;    /* Decoded entries (fewer after a failed load) */
};

/* The public key of an (already validated) asymmetric key cipher layer: same trustee identity, same keychain uid
 * (the layer's own, or else the root one) and same algorithm. WA_STATUS_MISSING_PUBLIC_KEY if no entry matches. */
wa_status_t wa_device_profile_find_layer_public_key(const wa_device_profile_t *device_profile,
                                                    const wa_value_t *key_cipher_layer,
                                                    const wa_asymmetric_public_key_t **public_key_out);

#endif /* WA_DEVICE_PROFILE_DECODING_H */
