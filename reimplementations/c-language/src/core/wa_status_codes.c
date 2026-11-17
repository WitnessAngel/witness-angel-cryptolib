/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wa_flightbox/wa_status_codes.h"

const char *wa_status_get_description(wa_status_t status)
{
    switch (status) {
    case WA_STATUS_OK:
        return "success";
    case WA_STATUS_INVALID_ARGUMENT:
        return "invalid argument";
    case WA_STATUS_UNSUPPORTED_FORMAT:
        return "unsupported or missing device profile format";
    case WA_STATUS_DECODING_ERROR:
        return "invalid WA-CBOR data";
    case WA_STATUS_INVALID_PROFILE:
        return "invalid device profile, cryptoconf or metadata";
    case WA_STATUS_UNSUPPORTED_TYPE:
        return "unsupported WA-CBOR item (float, datetime, bignum, decimal, indefinite length, tag 55799 or "
               "integer outside int64)";
    case WA_STATUS_UNSUPPORTED_FEATURE:
        return "unsupported feature (e.g. a document format not compiled in)";
    case WA_STATUS_UNSUPPORTED_SIGNATURE:
        return "signatures are not supported by this encryptor";
    case WA_STATUS_UNSUPPORTED_ALGORITHM:
        return "unsupported algorithm";
    case WA_STATUS_MISSING_PUBLIC_KEY:
        return "no public key entry matches a key cipher layer";
    case WA_STATUS_KEY_CONSTRAINT_VIOLATION:
        return "a public key violates its constraints";
    case WA_STATUS_NESTING_TOO_DEEP:
        return "nesting too deep";
    case WA_STATUS_OUT_OF_MEMORY:
        return "out of memory";
    case WA_STATUS_RANDOMNESS_FAILURE:
        return "the random generator failed";
    case WA_STATUS_CRYPTO_BACKEND_FAILURE:
        return "the crypto backend failed";
    case WA_STATUS_SINK_WRITE_FAILURE:
        return "an output sink failed";
    case WA_STATUS_WRONG_STATE:
        return "call made in the wrong encryptor state";
    case WA_STATUS_INTERNAL_ERROR:
        return "internal error";
    }
    return "unknown status";
}
