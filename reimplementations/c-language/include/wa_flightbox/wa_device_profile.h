/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Device profiles: a WA-CBOR document holding a cryptoconf and the raw public keys of its trustees
 * (docs/flightbox_specifications/flightbox_device_profile_specification.md). A loaded profile is immutable, and
 * may be shared by any number of encryptors. */

#ifndef WA_DEVICE_PROFILE_H
#define WA_DEVICE_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#include "wa_platform_hooks.h"
#include "wa_status_codes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wa_device_profile wa_device_profile_t;

/* Decode and fully validate a device profile: WA-CBOR sub-profile, root structure and format string, cryptoconf
 * rules (mirroring wacryptolib's schema, plus a mandatory root keychain uid, no signatures and the nesting limits),
 * public key entries and their constraints, and the resolution of every asymmetric layer to one entry.
 *
 * On failure, `*device_profile_out` is NULL, and when a buffer is given, it receives the NUL-terminated location
 * of the faulty item (e.g. "cryptoconf.payload_cipher_layers[0].key_cipher_layers[1]", possibly truncated), or an
 * empty string when there is none. A location is printable ASCII without spaces, whatever the profile holds: in an
 * unexpected key, the bytes other than printable ASCII characters, and the space, '.', '[', ']' and backslash
 * characters, are written as \xNN (two uppercase hexadecimal digits). */
wa_status_t wa_device_profile_load_from_cbor(const uint8_t *cbor, size_t cbor_length,
                                             const wa_platform_hooks_t *platform_hooks,
                                             wa_device_profile_t **device_profile_out,
                                             char *error_location_buffer_or_null,
                                             size_t error_location_buffer_size);

/* Release a profile. NULL is a no-op. */
void wa_device_profile_destroy(wa_device_profile_t *device_profile_or_null);

#ifdef __cplusplus
}
#endif

#endif /* WA_DEVICE_PROFILE_H */
