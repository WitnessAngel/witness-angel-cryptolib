/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Compiles the umbrella header alone, with strict warnings: the public API must be self-contained C99. */

#include "wa_flightbox/wa_flightbox.h"

int main(void)
{
    wa_cryptainer_encryptor_options_t options;
    options.platform_hooks = NULL;
    options.document_format = WA_DOCUMENT_FORMAT_BUILD_DEFAULT;
    options.ciphertext_location = WA_CIPHERTEXT_LOCATION_OFFLOADED;
    options.payload_ciphertext_sink = NULL;
    (void)options;
    return (int)WA_STATUS_OK;
}
