# Flightbox C encryptor

A portable C99 library creating Witness Angel cryptainers on microcontrollers, interoperable with wacryptolib: the
cryptainers it writes are decrypted by wacryptolib, its trustees (local keyfactory, authenticators, JSON-RPC
servers) and the Authenticator app, unchanged.

It implements steps 1 to 3 of the
[flightbox encryptor specification](../../docs/flightbox_specifications/flightbox_encryptor_specification.md)
(its "C profile" is described in §10.2 there). Its input is a **device profile**, a WA-CBOR document holding a
cryptoconf and the raw public keys of its trustees
([device profile specification](../../docs/flightbox_specifications/flightbox_device_profile_specification.md)),
exported on a computer by `scripts/flightbox/export_device_profile.py`.

Supported:

- payload ciphers `AES_CBC`, `AES_EAX` and `CHACHA20_POLY1305`, inline or offloaded, fed by chunks of any size;
- key cipher layers: asymmetric `RSA_OAEP`, `ECIES_X25519` and `ML_KEM_768`, symmetric `AES_CBC`, `AES_EAX` and
  `CHACHA20_POLY1305`, and Shamir shared secrets, nested up to `WA_MAX_KEY_CIPHER_NESTING_DEPTH` levels;
- trustees `local_keyfactory`, `authenticator` and `jsonrpc_api`, with keys found in the profile;
- cryptainers in relaxed Extended JSON and/or WA-CBOR, chosen at compile time, with one format per cryptainer (for
  the cryptainer itself and for every structure encrypted into its key ciphertexts);
- metadata given as a value tree, built in C or decoded from WA-CBOR.

Not supported, by design: signatures (signature confs are rejected with `WA_STATUS_UNSUPPORTED_SIGNATURE`),
payload digests, cryptoconfs without a root `keychain_uid` (the device can't fetch keys), decryption, and key
generation.

## Layout and naming

```
reimplementations/c-language/
  include/wa_flightbox/     public API; include only wa_flightbox.h
  src/core/                 the algorithm of the specification (validation, key cipher layers, pipeline, finalization)
  src/primitives/           AES modes, CMAC/EAX, HKDF, HPKE, RSA-OAEP encoding, Shamir over GF(2^128), wiping
  src/encoding/             value trees, WA-CBOR sub-profile decoder, Extended JSON and WA-CBOR writers
  src/backends/             the crypto backend interface, and its Mbed TLS and wolfCrypt adapters
  config/                   minimal Mbed TLS and wolfSSL configurations (also references for device builds)
  cmake/                    the arm-none-eabi Cortex-M4 toolchain file
  third_party/mlkem-native/ vendored mlkem-native v2.0.0 (ML-KEM-768 encapsulation, Mbed TLS backend only)
  tools/                    host CLI, test driver for pytest, host platform hooks
  tests/unit/               C unit tests (CTest), and the Python generators of their vectors
  tests/fuzz/               libFuzzer targets (WA-CBOR decoder, device profile loader)
  tests/interop/            pytest suites comparing with wacryptolib
  build_and_test_all_backends.sh
```

Every symbol is prefixed with `wa_`. Functions are named `wa_<module>_<verb>_<object>()`, compile-time limits
`WA_MAX_...`, and a source file holds one concept, named after it. Core files carry references to the sections of
the specification, to be audited against `src/wacryptolib/cryptainer/_flightbox.py`.

## API walkthrough

1. Provide the platform hooks (allocator, random generator, optional clock), see below.
2. Load the device profile once with `wa_device_profile_load_from_cbor()`; it is fully validated there (WA-CBOR
   sub-profile, cryptoconf rules, key constraints, every asymmetric layer resolved to a key), and may then serve
   any number of cryptainers.
3. For each cryptainer: `wa_cryptainer_encryptor_create()` (step 1: every key ciphertext is produced here),
   `wa_cryptainer_encryptor_encrypt_payload_chunk()` as often as needed (step 2),
   `wa_cryptainer_encryptor_finalize()` (step 3), `wa_cryptainer_encryptor_write_cryptainer()`, then
   `wa_cryptainer_encryptor_destroy()`, which wipes every secret. `wa_cryptainer_encrypt_payload_in_one_call()`
   does it all for a payload in memory.
4. Name files with `wa_document_format_get_cryptainer_suffix()`: `<basename>.crypt.json` or
   `<basename>.crypt.cbor`, and `<cryptainer file name>.payload` for an offloaded payload ciphertext.

Every function returns a `wa_status_t`, described by `wa_status_get_description()`. After any error, an encryptor
only accepts `wa_cryptainer_encryptor_destroy()`, and the caller should delete the partial output files.

The minimal example below (compiled and run by the `test_wa_readme_minimal_example` unit test, which extracts it
from this file) encrypts a recording into an offloaded cryptainer:

<!-- minimal-example-begin -->
```c
#include <stdio.h>
#include <string.h>

#include "wa_flightbox/wa_flightbox.h"

static wa_status_t example_write_to_file(void *sink_context, const uint8_t *bytes, size_t length)
{
    return fwrite(bytes, 1, length, (FILE *)sink_context) == length ? WA_STATUS_OK : WA_STATUS_SINK_WRITE_FAILURE;
}

/* Encrypt everything readable from `recording` into "<basename>.crypt.cbor" (or ".crypt.json"), its payload
 * ciphertext being offloaded into "<basename>.crypt.cbor.payload". Return 0 on success. */
int example_encrypt_recording(const wa_platform_hooks_t *hooks, const uint8_t *profile_cbor, size_t profile_length,
                              const char *basename, FILE *recording)
{
    /* The format of the build: the only one compiled in, or Extended JSON when both are */
    const wa_document_format_t document_format = WA_DOCUMENT_FORMAT_BUILD_DEFAULT;
    const char *suffix = wa_document_format_get_cryptainer_suffix(document_format);
    char error_location[128];
    char cryptainer_path[256];
    char payload_path[sizeof(cryptainer_path) + sizeof(".payload")];
    uint8_t chunk[512];
    size_t chunk_length;
    wa_device_profile_t *profile = NULL;
    wa_value_t *metadata = NULL;
    wa_value_t *device_name = NULL;
    wa_cryptainer_encryptor_t *encryptor = NULL;
    wa_cryptainer_encryptor_options_t options;
    wa_output_sink_t payload_sink;
    wa_output_sink_t cryptainer_sink;
    FILE *payload_file = NULL;
    FILE *cryptainer_file = NULL;
    wa_status_t status = WA_STATUS_OK;

    if (strlen(basename) + strlen(suffix) >= sizeof(cryptainer_path)) {
        return -1;
    }
    snprintf(cryptainer_path, sizeof(cryptainer_path), "%s%s", basename, suffix);
    snprintf(payload_path, sizeof(payload_path), "%s.payload", cryptainer_path);

    /* Load and validate the device profile (in a real device, once at startup) */
    status = wa_device_profile_load_from_cbor(profile_cbor, profile_length, hooks, &profile, error_location,
                                              sizeof(error_location));
    if (status != WA_STATUS_OK) {
        fprintf(stderr, "Invalid device profile (%s) at '%s'\n", wa_status_get_description(status), error_location);
        return -1;
    }

    /* Optional metadata, a map stored in clear in the cryptainer */
    status = wa_value_create_map(hooks, &metadata);
    if (status == WA_STATUS_OK) {
        status = wa_value_create_text(hooks, "camera-1", strlen("camera-1"), &device_name);
    }
    if (status == WA_STATUS_OK) {
        status = wa_value_map_add(metadata, "device_name", strlen("device_name"), device_name);
        if (status == WA_STATUS_OK) {
            device_name = NULL; /* now owned by the map */
        }
    }

    if (status == WA_STATUS_OK) {
        payload_file = fopen(payload_path, "wb");
        cryptainer_file = fopen(cryptainer_path, "wb");
        if (payload_file == NULL || cryptainer_file == NULL) {
            status = WA_STATUS_SINK_WRITE_FAILURE;
        }
    }

    /* Step 1: the cryptainer base and its key ciphertexts */
    if (status == WA_STATUS_OK) {
        payload_sink.write = example_write_to_file;
        payload_sink.sink_context = payload_file;
        memset(&options, 0, sizeof(options));
        options.platform_hooks = hooks;
        options.document_format = document_format;
        options.ciphertext_location = WA_CIPHERTEXT_LOCATION_OFFLOADED;
        options.payload_ciphertext_sink = &payload_sink;
        status = wa_cryptainer_encryptor_create(profile, metadata, &options, &encryptor);
    }

    /* Step 2: the payload, streamed in chunks of any size */
    while (status == WA_STATUS_OK && (chunk_length = fread(chunk, 1, sizeof(chunk), recording)) > 0) {
        status = wa_cryptainer_encryptor_encrypt_payload_chunk(encryptor, chunk, chunk_length);
    }
    if (status == WA_STATUS_OK && ferror(recording)) {
        status = WA_STATUS_INVALID_ARGUMENT;
    }

    /* Step 3, then the cryptainer document, small since the payload ciphertext is in its sibling file */
    if (status == WA_STATUS_OK) {
        status = wa_cryptainer_encryptor_finalize(encryptor);
    }
    if (status == WA_STATUS_OK) {
        cryptainer_sink.write = example_write_to_file;
        cryptainer_sink.sink_context = cryptainer_file;
        status = wa_cryptainer_encryptor_write_cryptainer(encryptor, &cryptainer_sink);
    }

    wa_cryptainer_encryptor_destroy(encryptor); /* wipes every secret */
    wa_value_destroy(device_name);
    wa_value_destroy(metadata);
    wa_device_profile_destroy(profile);
    if (payload_file != NULL && fclose(payload_file) != 0) {
        status = WA_STATUS_SINK_WRITE_FAILURE;
    }
    if (cryptainer_file != NULL && fclose(cryptainer_file) != 0) {
        status = WA_STATUS_SINK_WRITE_FAILURE;
    }
    if (status != WA_STATUS_OK) {
        fprintf(stderr, "Encryption failed: %s\n", wa_status_get_description(status));
        remove(payload_path);
        remove(cryptainer_path);
        return -1;
    }
    return 0;
}
```
<!-- minimal-example-end -->

## Platform hooks

The library makes no operating system call and has no global state. It reaches memory, randomness and time only
through a `wa_platform_hooks_t` given to each call (it must outlive every object created with it), and writes only
to the `wa_output_sink_t` it is given (a file, flash, a socket, a buffer). `tools/wa_host_platform_hooks.c` is the
host implementation (`malloc`, `getrandom`/`/dev/urandom` or `BCryptGenRandom`, the system clock).

- **`allocate` / `release`**: blocks of any size, aligned for any type; `release` receives the requested size,
  which suits pool allocators. Blocks that held secrets are wiped before release. Returning NULL gives
  `WA_STATUS_OUT_OF_MEMORY` and a clean failure (tested by out-of-memory sweeps). One exception: the crypto library
  allocates by itself, with its own allocator and not with this hook, the working memory of some primitives (see
  "The allocator of the crypto library" below).
- **`fill_random`**: MUST be a cryptographically secure generator. Every secret comes from it: symmetric keys, IVs
  and nonces, Shamir coefficients, HPKE ephemeral keys, ML-KEM encapsulation randomness, OAEP seeds and the random
  bits of UUIDs; neither backend uses a generator of its own. A non-zero return aborts the operation
  (`WA_STATUS_RANDOMNESS_FAILURE`); there is no fallback. The library can't check the entropy of its input, so
  wire it carefully (§5 of the [embedded crypto libraries audit](../../docs/audits/embedded_crypto_libraries_for_flightbox.md)):
  - **ESP32 / ESP32-S3**: `esp_fill_random()` is truly random only while Wi-Fi or Bluetooth is on, while the SAR
    ADC entropy source is enabled by `bootloader_random_enable()`, or in the second-stage bootloader; otherwise it
    is pseudo-random. Keep the radio or the ADC source on while encrypting, or seed an Mbed TLS CTR_DRBG or
    HMAC_DRBG from it while the source is on and wrap that DRBG as the hook. The ADC source must be disabled with
    `bootloader_random_disable()` before starting Wi-Fi/BT, the ADC or (on the original ESP32) I2S.
  - **RP2040**: no TRNG (its ring oscillator bit "does not meet the requirements of randomness for security
    systems"); add a secure element (e.g. ATECC608C) or avoid this chip.
  - **RP2350**: read the TRNG into a DRBG. Never use the Pico SDK's `pico_rand`, a xoroshiro128** generator.
  - In every case, a DRBG must be seeded from a hardware TRNG, never from a seedable PRNG (§3.1 of the
    specification).
- **`get_unix_time_in_ten_thousandths_of_second`**: optional, used for the time prefix of UUID0s. Without a clock
  (NULL, or a non-zero return), those prefixes are zero, which only loses their ordering.

## Compile-time configuration

Limits, in `include/wa_flightbox/wa_flightbox_config.h`, each overridable with `-D` (identically for the library
and the code including its headers):

| Macro | Default | Meaning |
|---|---|---|
| `WA_MAX_KEY_CIPHER_NESTING_DEPTH` | 8 (1 to 64) | Nesting levels of key cipher layers (shared secrets and symmetric layers containing layers); bounds the core recursion |
| `WA_MAX_CBOR_NESTING_DEPTH` | 64 (8 to 64) | Nesting of CBOR arrays and maps in profiles and metadata (metadata gets one level less); lower it to save stack |
| `WA_MAX_RSA_MODULUS_BITS` | 4096 (2048 to 8192) | Largest RSA trustee key |
| `WA_PAYLOAD_PROCESSING_SLICE_SIZE` | 4096 (multiple of 16) | Slice size of payload processing, which bounds memory use whatever the chunk size |

Document formats: `WA_DOCUMENT_FORMAT_JSON_ENABLED` and `WA_DOCUMENT_FORMAT_CBOR_ENABLED` (0 or 1, both 1 by
default; CMake sets them from `-DWA_DOCUMENT_FORMATS=JSON;CBOR`, `JSON` or `CBOR`). The writer of a disabled
format, and the base64 encoder in CBOR-only builds, are not compiled at all (a CTest symbol check verifies it);
requesting a disabled format gives `WA_STATUS_UNSUPPORTED_FEATURE`. Device profiles are WA-CBOR in every build.

- **Big chips** (ESP32-S3 with PSRAM...): Extended JSON, readable everywhere; keeping both formats costs little.
- **Small chips**: WA-CBOR only, which is more compact on disk and in RAM (no base64 expansion of the key
  ciphertexts nested inside each other): with the 5-level `nested_all_layer_kinds` profile, the peak heap use is
  about 21 KB in WA-CBOR against 82 KB in Extended JSON.

### Measured footprint

Cortex-M4 (`arm-none-eabi-gcc` 13.2.1, `-mcpu=cortex-m4 -mthumb -Os -ffunction-sections -fdata-sections`, Mbed
TLS backend), totals of `arm-none-eabi-size` over each static archive, before the linker's garbage collection
(a firmware only links what it calls):

| Build | `wa_flightbox` (text) | `wa_mlkem_native` (text) | `mbedcrypto` (minimal config of `config/`) |
|---|---|---|---|
| CBOR-only | 22,879 B | 8,042 B | 40,326 B text, 8,754 B bss |
| JSON-only | 23,549 B | 8,042 B | same |

Most of the Mbed TLS bss is its AES tables: `MBEDTLS_AES_ROM_TABLES` moves them to flash.

Peak heap use (counting allocator of the unit tests, offloaded payload, 64-bit host; the peak is the same for a
4 KiB payload, a 1 MiB payload fed in 4 KiB chunks, and a 1 MiB payload fed in one chunk):

| Device profile | Extended JSON | WA-CBOR |
|---|---|---|
| `corpus_2026_cbor_key_ciphertexts_05` (RSA-OAEP and X25519 trustees) | 19.6 KB | 15.4 KB |
| `nested_all_layer_kinds` (5 nested layer kinds, every asymmetric algorithm) | 81.8 KB | 20.5 KB |

Stack (`-fstack-usage`, Cortex-M4, `-Os`): the largest frame is `wa_rsa_values_are_coprime` (1,048 B), which
checks that the RSA exponent and modulus of each trustee key are coprime when the profile is loaded, on two
`WA_MAX_RSA_MODULUS_BITS`-bit buffers (half of it with a 2048-bit maximum); then come `wa_device_profile_load_from_cbor`
(376 B), `wa_x25519_multiply` (320 B) and `wa_cmac_process_blocks` (296 B). The recursive functions, and their
bounds:

| Function | Frame | Recursion bound |
|---|---|---|
| `wa_cbor_decode_item` (the array, map and tag decoders are inlined into it) | 112 B | `WA_MAX_CBOR_NESTING_DEPTH` (64 levels: about 7 KiB) |
| `wa_cbor_write_node` / `wa_json_write_node` | 48 B / 64 B | depth of the cryptainer tree |
| `wa_document_tree_check_node` | 24 B | `WA_MAX_CBOR_NESTING_DEPTH` |
| `wa_value_deep_copy` / `wa_value_destroy` | 64 B / 24 B | depth of the tree |
| `wa_key_cipher_layers_encrypt_key` | 208 B | `WA_MAX_KEY_CIPHER_NESTING_DEPTH` (8 levels) |
| `wa_validate_key_cipher_layers` / `wa_resolve_key_cipher_layers` | 96 B / 64 B | `WA_MAX_KEY_CIPHER_NESTING_DEPTH` |

Lowering `WA_MAX_CBOR_NESTING_DEPTH` (to 16, for instance, which still leaves room for metadata) reduces the worst
case of the decoder to under 2 KiB.

## Crypto backends

Exactly one backend is compiled, by defining `WA_CRYPTO_BACKEND_MBEDTLS` or `WA_CRYPTO_BACKEND_WOLFCRYPT` (CMake:
`-DWA_CRYPTO_BACKEND=MBEDTLS|WOLFCRYPT`). Both produce byte-identical cryptainers for identical random inputs
(tested). Each adapter checks the options it needs with `#error`, so a misconfigured build fails at compile time,
naming the missing option.

Both backends enforce the RFC 8439 limit of a ChaCha20-Poly1305 message, 2^32 - 1 blocks of 64 bytes (about
256 GiB, `WA_CHACHA20_POLY1305_MAXIMUM_DATA_LENGTH`): encrypting more data with one key gives
`WA_STATUS_INVALID_ARGUMENT` rather than a reused keystream. The wolfCrypt adapter composes the AEAD from
`wc_Chacha_*` and `wc_Poly1305*` calls, with 64-bit lengths, since wolfCrypt's own streaming ChaCha20-Poly1305
counts the data length in 32 bits, which would break payloads beyond 4 GiB.

### Mbed TLS 3.6 (default)

`config/wa_mbedtls_config_for_flightbox.h` is the minimal configuration (legacy crypto API, no PSA, no Mbed TLS
RNG). Required: `MBEDTLS_AES_C` (without `MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH`), `MBEDTLS_CIPHER_MODE_CBC`,
`MBEDTLS_CIPHER_MODE_CTR`, `MBEDTLS_CHACHA20_C`, `MBEDTLS_POLY1305_C`, `MBEDTLS_CHACHAPOLY_C`, `MBEDTLS_MD_C`,
`MBEDTLS_SHA256_C`, `MBEDTLS_SHA512_C`, `MBEDTLS_BIGNUM_C`, `MBEDTLS_RSA_C` (which needs `MBEDTLS_OID_C` and
`MBEDTLS_PKCS1_V21`), `MBEDTLS_ECP_C` and `MBEDTLS_ECP_DP_CURVE25519_ENABLED`, with `MBEDTLS_MPI_MAX_SIZE` of at
least `WA_MAX_RSA_MODULUS_BITS / 8` bytes.

On **ESP-IDF**, enable the same options in `idf.py menuconfig`, under Component config > mbedTLS: in particular
`CONFIG_MBEDTLS_CHACHA20_C`, `CONFIG_MBEDTLS_POLY1305_C` and `CONFIG_MBEDTLS_CHACHAPOLY_C` (off by default in
ESP-IDF 5.x), `CONFIG_MBEDTLS_SHA512_C`, `CONFIG_MBEDTLS_RSA_C`, `CONFIG_MBEDTLS_ECP_C` and
`CONFIG_MBEDTLS_ECP_DP_CURVE25519_ENABLED`; keep the hardware AES, SHA and MPI accelerators on. The backend calls
CBC and CTR in bulk, so the AES accelerator is taken once per slice, not once per block.

ML-KEM-768 comes from the vendored **mlkem-native** v2.0.0 (`third_party/mlkem-native/`, unmodified sources,
pure C99, only the deterministic encapsulation compiled in, symbols prefixed `wa_mlkem_`; see its
`VENDORED_VERSION.md`), since Mbed TLS 3.6 has no ML-KEM. It is the release line embedded in pycryptodome, whose
output the interop tests compare byte for byte.

### wolfCrypt 5.8

`config/wa_wolfssl_user_settings_for_flightbox.h` is the minimal `user_settings.h` (`WOLFSSL_USER_SETTINGS`).
Required: AES (not `NO_AES`) with `HAVE_AES_CBC`, `WOLFSSL_AES_COUNTER` and `WOLFSSL_AES_256`; `HAVE_CHACHA` and
`HAVE_POLY1305`; SHA-256 (not `NO_SHA256`) and `WOLFSSL_SHA512`; HMAC (not `NO_HMAC`); RSA (not `NO_RSA`) with
`WC_RSA_NO_PADDING`; `HAVE_CURVE25519` with `NO_CURVE25519_BLINDING`; `WOLFSSL_HAVE_MLKEM` and `WOLFSSL_WC_MLKEM`
(without `WOLFSSL_NO_ML_KEM_768` nor `WOLFSSL_MLKEM_NO_ENCAPSULATE`); and `SP_INT_BITS` of at least 4096 and at
least `WA_MAX_RSA_MODULUS_BITS`. wolfCrypt's own ML-KEM is used.

`NO_CURVE25519_BLINDING` is safe here: blinding protects the private scalar of a long-lived key, while the library
only multiplies fresh ephemeral scalars, used once.

### The allocator of the crypto library

The contexts of the backend adapters are allocated with the `allocate`/`release` platform hooks, but both crypto
libraries allocate by themselves the working memory of some primitives, with their own allocator, which is the one
of the C library by default:

- Mbed TLS: the HMAC pads, the big numbers of X25519 and those of the RSA public operation (`calloc`/`free`);
- wolfCrypt: the big numbers of the RSA public operation (about 4 KB for a 4096-bit key) and the polynomials of
  the ML-KEM-768 encapsulation (10.5 KB), with the reference configuration (`malloc`/`free`).

The platform hooks neither see nor bound these blocks, and the peak heap figures above don't count them. Each
library has a single allocator per process, whose functions get neither a context nor the size of the blocks they
release, so the flightbox library can't route it to hooks given per call. If the heap of the hooks is the only one
of the device, point the crypto library to it in its own configuration: `MBEDTLS_PLATFORM_C` and
`MBEDTLS_PLATFORM_MEMORY`, then `MBEDTLS_PLATFORM_CALLOC_MACRO`/`MBEDTLS_PLATFORM_FREE_MACRO` or a call to
`mbedtls_platform_set_calloc_free()` at startup (on ESP-IDF, the `CONFIG_MBEDTLS_MEM_ALLOC_MODE` options choose the
heap of Mbed TLS); `XMALLOC_USER`, `wolfSSL_SetAllocators()` or `WOLFSSL_STATIC_MEMORY` for wolfCrypt. A failure of
these allocators gives `WA_STATUS_OUT_OF_MEMORY` like one of the hooks, except in the RSA operation of wolfCrypt,
which reports it like any other failure of its modular exponentiation (`WA_STATUS_CRYPTO_BACKEND_FAILURE`).

### The raw RSA note

Both backends are only asked for the raw RSA public operation (`mbedtls_rsa_public()`, and `wc_RsaDirect()` which
`WC_RSA_NO_PADDING` enables); the OAEP padding (SHA-512, as wacryptolib uses) is encoded by the portable code
(`src/primitives/wa_rsa_oaep_sha512_padding.c`), tested against fixed-seed vectors. wolfSSL lists
`WC_RSA_NO_PADDING` among the options that "weaken security", because raw RSA is insecure when misused: here it is
only ever applied to an OAEP-encoded block, and the library exposes no raw RSA function.

## Licences

The C tree is GPL-2.0-or-later, like the rest of wacryptolib.

- Mbed TLS: Apache-2.0 OR GPL-2.0-or-later, compatible.
- mlkem-native: Apache-2.0 OR ISC OR MIT (`third_party/mlkem-native/LICENSE`), compatible.
- **wolfCrypt is GPL-3.0-or-later** (or commercial): a firmware built with the wolfCrypt backend is, as a whole,
  distributed under GPL-3.0-or-later, with its source-availability and installation-information obligations, unless
  a commercial wolfSSL licence is bought. Mbed TLS remains the default for this reason.

## Inline vs offloaded ciphertexts

- **Inline** (`WA_CIPHERTEXT_LOCATION_INLINE`): the whole payload ciphertext stays in RAM and is embedded in the
  cryptainer. Meant for small payloads (a few KB); memory grows with the payload.
- **Offloaded** (`WA_CIPHERTEXT_LOCATION_OFFLOADED`): the ciphertext is written progressively to
  `payload_ciphertext_sink`, to be stored as `<cryptainer file name>.payload`, and the cryptainer only holds the
  offloaded marker. Memory use is bounded and independent of the payload size (see the peaks above). This is the
  mode for recordings.

## Building and testing

Requirements: CMake 3.16+, a C99 compiler (GCC or Clang), and network access at configure time to fetch the
pinned Mbed TLS 3.6.8 or wolfSSL 5.8.4 archives (or `-DWA_USE_SYSTEM_CRYPTO_LIBRARIES=ON` to use installed ones).
Supported hosts: Linux and macOS, and Windows through MSYS2 MinGW-w64 GCC or Clang. MSVC is not supported.

```sh
cmake -S reimplementations/c-language -B build_mbedtls -DWA_CRYPTO_BACKEND=MBEDTLS -DWA_ENABLE_SANITIZERS=ON
cmake --build build_mbedtls
ctest --test-dir build_mbedtls --output-on-failure
```

On Windows, from an MSYS2 UCRT64 shell with `mingw-w64-ucrt-x86_64-{gcc,cmake,ninja}` installed, the same commands
work (add `-G Ninja`, and drop the sanitizers, which MinGW lacks); the config headers enable what Mbed TLS and
wolfSSL need under MinGW. The interop tests then run with the Windows Python, `WA_FLIGHTBOX_C_BUILD_DIR` being
`;`-separated there, which exercises the Windows file handling of the CLI.

CMake options: `WA_CRYPTO_BACKEND` (`MBEDTLS` or `WOLFCRYPT`, required), `WA_DOCUMENT_FORMATS` (`JSON;CBOR`,
`JSON` or `CBOR`), `WA_ENABLE_SANITIZERS` (ASan/UBSan), `WA_BUILD_TOOLS` (CLI and test driver, ON),
`WA_BUILD_FUZZERS` (Clang, libFuzzer), `WA_LIBRARY_ONLY` (cross-compilation checks), `WA_USE_SYSTEM_CRYPTO_LIBRARIES`.

Host CLI (encrypts a file with the operating system's randomness):

```sh
build_mbedtls/wa_flightbox_encrypt_file_cli -p device_profile.cbor --format cbor recording.bin
# -> recording.bin.crypt.cbor and recording.bin.crypt.cbor.payload
```

The CLI never overwrites an existing file unless `--force` is given, and then only replaces the old outputs once
the new ones are complete (written to `<output>.tmp-NNN` files, renamed at the end): a failed run leaves the
previous recording intact, and deletes whatever it created. An output that is one of the inputs (the same file
under another path, or a hard link to it) is refused, stdin (`-`) can be only one of the input file, the profile
and the metadata, and `--chunk-size` takes a decimal number of bytes, up to 1 GiB.

Trustees decrypt these cryptainers like any other (with test cryptoconfs whose private keys are local,
`flightbox cryptainer decrypt recording.bin.crypt.cbor` does it).

Device profiles are exported from a cryptoconf and the keystore pool holding its trustees' public keys:

```sh
python scripts/flightbox/export_device_profile.py my_cryptoconf.json my_keystore_pool/ -o device_profile.cbor
```

Interop tests (pytest, from the repository root, with wacryptolib installed), against one or more builds made with
the tools:

```sh
WA_FLIGHTBOX_C_BUILD_DIR=build_mbedtls:build_wolfcrypt pytest reimplementations/c-language/tests/interop
```

Besides decrypting the C cryptainers (and the metadata of the key structs inside their key ciphertexts) with
wacryptolib, they compare the C validation with wacryptolib's on seeded random mutations of the corpus
cryptoconfs (whatever the C loader accepts, wacryptolib must accept), and check the CLI's file handling.

Fuzzing (Clang): configure with `-DWA_BUILD_FUZZERS=ON -DBUILD_TESTING=OFF -DWA_BUILD_TOOLS=OFF`, generate the
seeds with `python reimplementations/c-language/tests/fuzz/generate_fuzz_seed_corpora.py SEED_DIR`, then run
`wa_fuzz_wacbor_subprofile_decoder` or `wa_fuzz_device_profile_loader` with `SEED_DIR/<target name without
wa_fuzz_>` as a corpus.

Cortex-M4 compile check:

```sh
cmake -S reimplementations/c-language -B build_cortex_m4 \
    -DCMAKE_TOOLCHAIN_FILE=cmake/wa_arm_cortex_m4_toolchain.cmake \
    -DWA_CRYPTO_BACKEND=MBEDTLS -DWA_LIBRARY_ONLY=ON -DWA_DOCUMENT_FORMATS=CBOR
cmake --build build_cortex_m4 --target wa_flightbox mbedcrypto wa_mlkem_native
```

`build_and_test_all_backends.sh` runs everything (Linux or WSL, with Clang and `arm-none-eabi-gcc` installed):
both backends with both formats, JSON-only and CBOR-only builds, sanitizers, a Clang build, unit tests, 60 s of
fuzzing per target and the Cortex-M4 builds. `tox -e c_flightbox` runs it, then the interop tests.
