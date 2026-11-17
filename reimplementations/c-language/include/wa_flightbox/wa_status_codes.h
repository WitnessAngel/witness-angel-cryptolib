/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Status codes returned by every library function that can fail. */

#ifndef WA_STATUS_CODES_H
#define WA_STATUS_CODES_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wa_status {
    WA_STATUS_OK = 0,
    WA_STATUS_INVALID_ARGUMENT,          /* NULL pointer, bad option value... (caller bug) */
    WA_STATUS_UNSUPPORTED_FORMAT,        /* unknown or missing device_profile_format */
    WA_STATUS_DECODING_ERROR,            /* bytes that are not a WA-CBOR document */
    WA_STATUS_INVALID_PROFILE,           /* validation error of a profile, cryptoconf or metadata tree */
    WA_STATUS_UNSUPPORTED_TYPE,          /* valid WA-CBOR item outside the device profile sub-profile */
    WA_STATUS_UNSUPPORTED_FEATURE,       /* feature not compiled in, e.g. a disabled document format */
    WA_STATUS_UNSUPPORTED_SIGNATURE,     /* signature confs, not supported by this encryptor */
    WA_STATUS_UNSUPPORTED_ALGORITHM,     /* algorithm unknown to this build */
    WA_STATUS_MISSING_PUBLIC_KEY,        /* an asymmetric layer has no matching public key entry */
    WA_STATUS_KEY_CONSTRAINT_VIOLATION,  /* a public key fails its sanity constraints */
    WA_STATUS_NESTING_TOO_DEEP,          /* key cipher layers or CBOR items nested beyond the limits */
    WA_STATUS_OUT_OF_MEMORY,             /* the allocator hook returned NULL */
    WA_STATUS_RANDOMNESS_FAILURE,        /* the random hook failed */
    WA_STATUS_CRYPTO_BACKEND_FAILURE,    /* the crypto backend reported an error */
    WA_STATUS_SINK_WRITE_FAILURE,        /* an output sink reported an error */
    WA_STATUS_WRONG_STATE,               /* call made in the wrong encryptor state */
    WA_STATUS_INTERNAL_ERROR             /* broken internal invariant, should never happen */
} wa_status_t;

/* Return a static, human-readable English description of a status (never NULL). */
const char *wa_status_get_description(wa_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* WA_STATUS_CODES_H */
