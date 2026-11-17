/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Symmetric ciphers of the encryptor specification, section 3.4: AES_CBC (PKCS#7), AES_EAX and CHACHA20_POLY1305,
 * no associated data. Streaming contexts (payload cipher layers) and one-shot cipherdicts (symmetric key layers),
 * the latter running the former, so both give exactly the same ciphertext and tag. */

#ifndef WA_SYMMETRIC_CIPHER_STREAMS_H
#define WA_SYMMETRIC_CIPHER_STREAMS_H

#include <stddef.h>
#include <stdint.h>

#include "backends/wa_crypto_backend.h"
#include "primitives/wa_aes_eax_mode.h"
#include "primitives/wa_symmetric_key_generation.h"
#include "wa_flightbox/wa_value_tree.h"

/* An encrypt call outputs at most `length` + 15 bytes, and finish at most 16 bytes (the AES_CBC padding block). */
#define WA_SYMMETRIC_CIPHER_STREAM_MAXIMUM_EXTRA_OUTPUT 16u

typedef struct wa_symmetric_cipher_stream {
    wa_symmetric_cipher_algo_t cipher_algo;
    union {
        struct {
            wa_crypto_backend_aes_256_t *aes;
            uint8_t chaining_value[WA_AES_BLOCK_SIZE];
            uint8_t pending_block[WA_AES_BLOCK_SIZE];
            size_t pending_length; /* 0..15 */
        } aes_cbc;
        wa_aes_eax_encryption_t aes_eax;
        wa_crypto_backend_chacha20_poly1305_t *chacha20_poly1305;
    } state;
} wa_symmetric_cipher_stream_t;

wa_status_t wa_symmetric_cipher_stream_start(const wa_platform_hooks_t *platform_hooks, const wa_symkey_t *symkey,
                                             wa_symmetric_cipher_stream_t *stream);

/* Encrypt the next `length` bytes into `output` (capacity `length` + 15 at least, not overlapping `input`), which
 * receives `*output_length` bytes: as many for AES_EAX and CHACHA20_POLY1305, whole blocks for AES_CBC. */
wa_status_t wa_symmetric_cipher_stream_encrypt(wa_symmetric_cipher_stream_t *stream, const uint8_t *input,
                                               size_t length, uint8_t *output, size_t *output_length);

/* End the encryption: AES_CBC outputs its final padded block in `final_output` (16 bytes) and no tag; the others
 * output nothing there and a 16-byte tag. `tag_length_out` receives 0 or 16. */
wa_status_t wa_symmetric_cipher_stream_finish(wa_symmetric_cipher_stream_t *stream,
                                              uint8_t final_output[WA_AES_BLOCK_SIZE], size_t *final_output_length,
                                              uint8_t tag[WA_SYMMETRIC_TAG_SIZE], size_t *tag_length_out);

/* Release the contexts and wipe the stream (also after errors; a zeroed stream is accepted). */
void wa_symmetric_cipher_stream_release(const wa_platform_hooks_t *platform_hooks, wa_symmetric_cipher_stream_t *stream);

/* One-shot cipherdict: {"ciphertext": bytes} for AES_CBC, {"ciphertext": bytes, "tag": bytes(16)} otherwise. */
wa_status_t wa_symmetric_encrypt_to_cipherdict(const wa_platform_hooks_t *platform_hooks, const wa_symkey_t *symkey,
                                               const uint8_t *plaintext, size_t plaintext_length,
                                               wa_value_t **cipherdict_out);

/* Payload MACs of a payload cipher layer (section 3.4): {} for AES_CBC, {"tag": bytes(16)} otherwise. */
wa_status_t wa_symmetric_build_payload_macs(const wa_platform_hooks_t *platform_hooks,
                                            wa_symmetric_cipher_algo_t cipher_algo, const uint8_t *tag,
                                            size_t tag_length, wa_value_t **payload_macs_out);

#endif /* WA_SYMMETRIC_CIPHER_STREAMS_H */
