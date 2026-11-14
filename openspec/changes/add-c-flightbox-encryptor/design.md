## Context

See proposal.md for the motivation. The algorithm is fully specified by `docs/flightbox_specifications/flightbox_encryptor_specification.md` (referred to below as "the spec", with section numbers). The portable Python core (`src/wacryptolib/cryptainer/_flightbox.py`) already separates the algorithm from a platform layer (`FlightboxUtilities`, spec §10), and this C port keeps that split. Library and hardware facts come from `docs/audits/embedded_crypto_libraries_for_flightbox.md`. The CBOR input follows `docs/audits/flightbox_cryptoconf_storage_format.md`.

Constraints that shape the design:

- Neither Mbed TLS nor wolfCrypt provides our HPKE suite: Mbed TLS has no HPKE, and wolfCrypt's HPKE only has AES-GCM. Mbed TLS also has no AES-EAX and no ML-KEM. Both libraries do provide RSA-OAEP with SHA-512, but wolfCrypt's draws its seed from its own DRBG.
- The cryptainer copies the whole cryptoconf tree and adds fields to it at several depths (spec §6.6, §9.1). `payload_macs` are only known after the last payload byte.
- Targets range from a Linux/macOS/Windows host (tests, CLI) to ESP32 under ESP-IDF 5.x, which bundles Mbed TLS 3.6, and later to Cortex-M parts. Hardware acceleration is optional.
- The `compatibility/` corpus provides:
  - symmetric cipherdict fixtures, each tied to one plaintext, with key and IV/nonce;
  - keystore pools with private keys and sidecar passphrases (`2026_post_quantum/pq_pool` covers all three asymmetric algorithms);
  - cryptoconfs, of which only a few are signature-free with a root `keychain_uid`, and none uses an `AES_CBC` payload layer or `ML_KEM_768` without signatures.

  Asymmetric outputs are randomized, so they are checked by having wacryptolib decrypt them, or by byte comparison under fixed randomness where the reference allows it.
- The repository's CI is GitHub Actions running tox (`.github/workflows/ci.yml`, `tox.ini`), and pytest only collects `tests/` (`testpaths`).

## Goals / Non-Goals

**Goals:**
- One portable core whose behaviour is identical on both backends, so that each backend adapter is a thin, auditable mapping onto a handful of primitives.
- The same RNG path, and the same deterministic test mode, on both backends.
- Small, readable source files, one concept per file, named after what they implement.
- A public API usable from bare-metal C: no OS, no globals, caller-owned memory policy, memory bounded independently of payload and chunk sizes.

**Non-Goals:**
- Using every backend-native construction where one exists (wolfCrypt's native EAX, both libraries' OAEP): uniformity, a single RNG and deterministic tests come first.
- Mbed TLS 4.x / PSA-only builds, Mbed TLS 2.x, MSVC, or any third backend. The backend interface makes them possible later.
- Decryption, key generation, signatures, digests, JSON-RPC key fetching, device profile signing (COSE_Sign1), the STARTED "savegame" serialization (spec §7.2, optional), and ESP-IDF/Pico example firmwares or component manifests.
- Byte-exact cryptainers compared with CPython. Key order and separators match CPython, but randomness differs, and the spec does not require byte-exactness. Intermediate structures are byte-identical by construction, which the tests check.

## Decisions

### D1. Source layout and naming

```
reimplementations/c-language/
  CMakeLists.txt                     host build; option WA_CRYPTO_BACKEND=MBEDTLS|WOLFCRYPT
  README.md                          integration guide (sources list, defines, hooks, configs)
  include/wa_flightbox/              public API only
    wa_flightbox.h                   umbrella header
    wa_status_codes.h                wa_status_t + wa_status_get_description()
    wa_platform_hooks.h              allocator, random, clock, output sink types
    wa_value_tree.h                  metadata data model + builder functions + CBOR decoding entry
    wa_device_profile.h              load/validate/destroy a CBOR device profile
    wa_cryptainer_encryptor.h        create / encrypt chunk / finalize / write JSON / destroy
    wa_flightbox_config.h            compile-time limits, each overridable with -D
  src/
    core/                            the flightbox algorithm (spec §6-§9), no crypto code
      wa_cryptainer_encryptor.c          public API, lifecycle and state machine
      wa_cryptainer_base_generation.c    step 1: deep copy, payload layer loop (spec §6.1)
      wa_key_cipher_layers_encryption.c  §6.2-§6.5: chain, single layer, shards, key struct
      wa_payload_encryption_pipeline.c   step 2: streaming nodes (spec §7.2), internal slicing
      wa_cryptainer_finalization.c       step 3: payload_macs, FINISHED (spec §8 minus signing)
      wa_cryptoconf_validation.c         mirror of CRYPTOCONF_SCHEMA_PYTHON + C-specific rules
      wa_error_location_path.c           builds "cryptoconf.payload_cipher_layers[0]..." paths
    encoding/
      wa_value_tree.c                    tree nodes, deep copy, lookups
      wa_cbor_strict_decoder.c           CBOR subset -> value tree
      wa_device_profile_decoding.c       profile structure, key entries, key constraints
      wa_extended_json_writer.c          value tree -> relaxed Extended JSON (spec §2)
      wa_base64_encoder.c
      wa_growable_byte_buffer.c          secret-aware buffer (wipes on growth and release)
    primitives/                      composite constructions, portable, on top of the backend
      wa_symmetric_key_generation.c      spec §3.3
      wa_symmetric_cipher_streams.c      AES_CBC/AES_EAX/CHACHA20_POLY1305 streaming + one-shot
      wa_aes_cbc_pkcs7_padding.c
      wa_aes_cmac_omac1.c                OMAC1/CMAC over the backend's bulk AES-CBC
      wa_aes_eax_mode.c                  EAX = backend bulk AES-CTR + OMAC (wa_aes_cmac_omac1)
      wa_rsa_oaep_sha512_padding.c       EME-OAEP encoding, SHA-512 + MGF1-SHA-512
      wa_rsa_oaep_chunked_encryption.c   60-byte chunking (spec §3.5)
      wa_hkdf_sha256.c                   RFC 5869 over HMAC-SHA256
      wa_hpke_base_mode_seal.c           RFC 9180 key schedule + single-shot seal, KEM-agnostic
      wa_hpke_kem_dhkem_x25519.c         KEM 0x0020 encapsulation (+ all-zero DH check)
      wa_hpke_kem_ml_kem_768.c           KEM 0x0041 encapsulation
      wa_public_key_constraints.c        RSA bounds, canonical/low-order X25519, ML-KEM modulus check
      wa_asymmetric_key_wrapping.c       RSA_OAEP / ECIES_X25519 / ML_KEM_768 dispatch -> cipherdict
      wa_shamir_secret_sharing_gf128.c   spec §3.7
      wa_uuid0_generation.c              spec §3.2
      wa_secure_memory_wipe.c
    backends/
      wa_crypto_backend.h                internal primitive interface (D3)
      wa_crypto_backend_mbedtls.c        Mbed TLS 3.6 legacy API + mlkem-native
      wa_crypto_backend_wolfcrypt.c
  config/
    wa_mbedtls_config_for_flightbox.h         minimal MBEDTLS_CONFIG_FILE for host builds
    wa_wolfssl_user_settings_for_flightbox.h  minimal user_settings.h for host builds
  third_party/mlkem-native/          vendored, pinned, ML-KEM-768-only build (Mbed TLS backend only)
  tools/
    wa_flightbox_encrypt_file_cli.c  host CLI (OS randomness, files)
    wa_flightbox_test_driver.c       host-only primitives exposure for pytest (D13)
    wa_host_platform_hooks.c         OS RNG (getrandom / BCryptGenRandom), clock, stdlib malloc
  tests/
    unit/                            test_wa_<module>.c + wa_minimal_test_harness.h, run by CTest
    fuzz/                            libFuzzer targets (CBOR decoder, profile loader)
    interop/                         pytest: conftest.py, device_profile_test_helpers.py,
                                     test_c_flightbox_<topic>.py
  build_and_test_all_backends.sh
scripts/flightbox/export_device_profile.py   CPython -> CBOR device profile
docs/flightbox_specifications/flightbox_device_profile_specification.md   format + CDDL
```

Naming: every public and internal symbol is prefixed with `wa_`. Function names follow `wa_<module>_<verb>_<object>`, for example `wa_shamir_split_secret_into_shards()`, `wa_hpke_base_mode_seal()`, `wa_rsa_oaep_sha512_encode_padding()`, `wa_cryptainer_encryptor_encrypt_payload_chunk()`. Compile-time limits are `WA_MAX_...` macros. A source file holds one concept and is named after it. Core files carry spec section references in comments so they can be audited against the Python `_flightbox.py` line by line. Abbreviations are kept to those of the spec (`symkey`, `cipherdict`, `uid`).

Alternative considered: mirroring the Python module names (`_flightbox.c`, `_encryptor.c`). Rejected: those names reflect Python history, not concepts, and the user asked for self-explanatory names.

### D2. Layering

```
 public API (include/)  ──>  core/  ──>  primitives/  ──>  backends/wa_crypto_backend.h
        │                     │  │            │                 ├─ mbedtls (+ mlkem-native)
        │                     │  └─ encoding/ │                 └─ wolfcrypt
        └──────── platform hooks (allocator, random, clock, sinks) used by every layer
```

`core/` never calls a backend directly and contains no cryptographic arithmetic, so it is a straight transcription of the spec. `primitives/` holds every composite construction once, for both backends. Only `backends/` includes Mbed TLS or wolfSSL headers.

### D3. Minimal backend interface, compile-time selection

The backend provides only bulk or costly primitives with no parameter ambiguity, all fully determined by their inputs:

| Primitive | Mbed TLS 3.6 | wolfCrypt |
|---|---|---|
| AES-256-CBC encryption over whole blocks, streaming (also serves CMAC) | `mbedtls_aes_crypt_cbc` | `wc_AesCbcEncrypt` |
| AES-256-CTR encryption, streaming (for EAX) | `mbedtls_aes_crypt_ctr` | `wc_AesCtrEncrypt` |
| ChaCha20-Poly1305 streaming encryption (start/update/finish) | `mbedtls_chachapoly_*` | `wc_ChaCha20Poly1305_Init/UpdateData/Final` |
| SHA-256, SHA-512 (one-shot) and HMAC-SHA256 | `mbedtls_md` / `mbedtls_md_hmac` | `wc_Sha256*`, `wc_Sha512*`, `wc_Hmac*` |
| X25519: public key from private scalar; shared secret | `mbedtls_ecp_*` on `MBEDTLS_ECP_DP_CURVE25519` | `wc_curve25519_*` (little-endian import/export) |
| RSA raw public operation `m^e mod n` from raw (n, e) | `mbedtls_rsa_import_raw` + `mbedtls_rsa_public` | `wc_RsaPublicKeyDecodeRaw` + raw public encryption |
| ML-KEM-768 deterministic encapsulation (32-byte coins) | mlkem-native `crypto_kem_enc_derand` | `wc_MlKemKey_EncapsulateWithRandom` |

Required configuration, checked by `#if`/`#error` at the top of each adapter. These are the expected names, to be confirmed against the pinned versions in task 4:
- Mbed TLS: `MBEDTLS_AES_C`, `MBEDTLS_CIPHER_MODE_CBC`, `MBEDTLS_CIPHER_MODE_CTR`, `MBEDTLS_CHACHAPOLY_C` (with `_CHACHA20_C`, `_POLY1305_C`), `MBEDTLS_SHA256_C`, `MBEDTLS_SHA512_C`, `MBEDTLS_MD_C`, `MBEDTLS_RSA_C`, `MBEDTLS_BIGNUM_C`, `MBEDTLS_ECP_C`, `MBEDTLS_ECP_DP_CURVE25519_ENABLED`, and **not** `MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH`. `MBEDTLS_MPI_MAX_SIZE` must be at least 512 bytes, for 4096-bit moduli.
- wolfCrypt: `HAVE_AES_CBC`, `WOLFSSL_AES_COUNTER`, `HAVE_CHACHA`, `HAVE_POLY1305`, `WOLFSSL_SHA512`, HMAC enabled, RSA enabled with `WC_RSA_NO_PADDING` (and `WC_RSA_DIRECT` if the pinned version requires it), `HAVE_CURVE25519`, `WOLFSSL_HAVE_MLKEM` (which brings `WOLFSSL_SHA3`/`SHAKE128`/`SHAKE256`), and RSA maximum size at least 4096 bits. Raw RSA is listed by wolfSSL among "options that weaken security": it is only used inside our own OAEP encoding (D4), and the README says so.

Selection: exactly one of `WA_CRYPTO_BACKEND_MBEDTLS` / `WA_CRYPTO_BACKEND_WOLFCRYPT` must be defined. CMake sets it from `WA_CRYPTO_BACKEND`, and device builds define it themselves. A misconfigured ESP-IDF menuconfig thus becomes a build error, not a runtime failure. Bulk CBC and CTR calls also mean that, on ESP32, the AES accelerator is taken once per slice, not once per 16-byte block.

Alternative considered: letting each backend implement whole algorithms (OAEP, EAX, HPKE). Rejected: two implementations of each composite to keep in sync, more and harder tests, and wolfCrypt's OAEP would bring a second source of randomness (D6).

### D4. Composite constructions in portable C

- **HPKE** (`wa_hpke_base_mode_seal.c`): `LabeledExtract`/`LabeledExpand`, `KeySchedule` for mode Base (`psk` and `psk_id` empty), then a single ChaCha20-Poly1305 seal with sequence number 0. It is parameterised by a small KEM descriptor (KEM id, `enc` length, encapsulate function), and info/AAD are internal parameters, empty in cryptainers but settable by tests for RFC 9180 A.2.1. The KDF is HKDF-SHA256 for both KEMs.
  - DHKEM(X25519) (`0x0020`): the ephemeral scalar comes from the random hook. It implements `ExtractAndExpand` with the `eae_prk`/`shared_secret` labels and `kem_context = enc || pkR`, and rejects an all-zero DH output.
  - ML-KEM-768 (`0x0041`): the ML-KEM shared secret is used directly, and `enc` is the ML-KEM ciphertext. This matches pycryptodome 4.2's `Crypto.Protocol.HPKE` (`_encap_pq`, draft-ietf-hpke-pq), checked locally. Interop tests against pycryptodome remain the acceptance gate, since the KEM id comes from a draft.
- **AES-EAX** (`wa_aes_eax_mode.c`): N = OMAC0(nonce), H = OMAC1(empty header), ciphertext = backend AES-CTR keyed from N, and OMAC2 updated incrementally over the ciphertext; tag = N ⊕ H ⊕ C.
  - OMAC/CMAC (`wa_aes_cmac_omac1.c`) runs the backend's bulk CBC with a zero IV, keeps the last block, and derives its subkeys from E_K(0^128), obtained the same way. Mbed TLS's CMAC module (`MBEDTLS_CMAC_C`, off by default in ESP-IDF) is therefore not required.
  - Streaming keeps at most one partial block each for CTR and for OMAC.
- **RSA-OAEP**: EME-OAEP (RFC 8017 §7.1.1) with SHA-512, MGF1-SHA-512 and an empty label, the seed taken from the random hook, then the backend's raw public operation, which is the costly part. This is a deliberate trade-off rather than a library gap. Both libraries offer OAEP-SHA-512, but owning the encoding gives one RNG path (D6), deterministic tests and identical behaviour on both backends, for about 60 lines checked against a pycryptodome reference with a fixed seed.
- **Shamir over GF(2^128)**: big-endian 16-byte field elements, reduction polynomial x^128 + x^7 + x^2 + x + 1, constant-time shift-and-xor multiplication (no tables), per-chunk random coefficients, PKCS#7 pre-padding. Polynomials are evaluated with Horner's rule at x = 1..n.
- **UUID0**, **PKCS#7**, **base64**: small, standalone files.

### D5. ML-KEM-768 source per backend

The Mbed TLS backend links a vendored mlkem-native, pinned to the release line embedded in pycryptodome (2.x). It is built as a single compilation unit with `MLK_CONFIG_PARAMETER_SET=768`, its own FIPS 202 code, a `wa_mlkem_` namespace prefix, and its randomized API disabled: only `_derand` is used, coins come from our hook. The wolfCrypt backend uses wolfCrypt's native ML-KEM. Both are wrapped behind the same deterministic encapsulation primitive, so the HPKE layer and the tests don't differ.

Alternative considered: an in-tree ML-KEM. Rejected: mlkem-native is C90, memory-safety-proven with CBMC, and is the code pycryptodome itself runs.

### D6. A single source of randomness

All randomness is drawn by portable code from the platform random hook and passed down explicitly: symkeys, IVs/nonces, Shamir coefficients, UUID random bits, HPKE X25519 ephemeral scalars, ML-KEM coins and OAEP seeds. The backends are only called with fully determined inputs: raw RSA, a given X25519 scalar, derandomized ML-KEM. Neither backend needs its own DRBG, which gives three properties:
- one place to wire the hardware TRNG/DRBG (on ESP32: `esp_fill_random` with the entropy conditions of audit §5, or an Mbed TLS CTR_DRBG wrapped as the hook);
- byte-identical outputs on both backends under a deterministic test hook, which makes the cross-backend and chunking tests exact;
- no hidden fallback to a weak source. A hook failure is fatal.

If a future wolfCrypt configuration requires an RNG for X25519 blinding (`WOLFSSL_CURVE25519_BLINDING`), the adapter will feed a `WC_RNG` seeded from the same hook (`wc_SetSeed_Cb`, `WC_RNG_SEED_CB`). This changes nothing outside the adapter. The blinding values don't affect the outputs, so determinism is kept.

The clock hook returns Unix time in units of 1/10000 s as a `uint64_t`, which UUID0 truncates to its low 48 bits, or reports that no clock is available.

### D7. Value tree as the data model

The cryptoconf, metadata and cryptainer are held in a small generic tree: null, bool, int64, text, bytes, UUID, array, insertion-ordered map. Nodes are allocated through the allocator hook.
- The CBOR decoder builds the tree.
- Step 1 deep-copies the cryptoconf subtree into the cryptainer, with a fresh copy per node, so there is no aliasing, which satisfies spec §6.6 by construction.
- The core then adds fields (`key_ciphertext`, `payload_macs`...) in place.
- The JSON writer serializes the tree with keys sorted at write time.
- Bytes nodes may be flagged secret, so they are wiped on release.

Alternative considered: a single-pass writer emitting the cryptainer while walking the input (audit "single-pass C design"). Rejected: `payload_macs` arrive last and would need placeholders or a second section, it complicates every layer type, and a cryptainer tree without payload weighs a few KB.

### D8. Strict in-house CBOR decoder

The decoder handles only the needed subset: definite-length maps, arrays, byte and text strings, major types 0/1 within int64, `true`/`false`/`null`, and tag 37 over 16 bytes. It also checks UTF-8 validity, rejects duplicate map keys, enforces `WA_MAX_CBOR_NESTING_DEPTH` (default 64) and bounds every length against the remaining input. Anything else (floats, other tags, indefinite lengths, undefined and simple values) gives a typed error. Profile semantics (D9) are checked in a second pass over the tree.

The two depth limits are separate because a single Shamir layer already costs about 11 CBOR levels: the corpus profiles reach 11 to 13 levels, measured during review.
- `WA_MAX_CBOR_NESTING_DEPTH` protects the decoder's stack.
- `WA_MAX_KEY_CIPHER_NESTING_DEPTH` (default 8, unit defined in the spec) bounds the recursion of the core.

Alternatives considered: TinyCBOR (ESP-IDF component), QCBOR, zcbor (CDDL code generation). All are viable, but they would be a third-party dependency on every target, for about 400 lines of decoding that must produce our tree anyway. zcbor's generated decoders don't fit well with a recursive grammar of unbounded shape and arbitrary metadata maps. The decoder is fuzz-tested to compensate for being in-house.

### D9. Device profile semantics and key lookup

`wa_device_profile_load_from_cbor()` runs these steps:
- decode the CBOR;
- validate the cryptoconf (D10) and the key entries;
- check key constraints (`wa_public_key_constraints.c`);
- resolve every asymmetric layer to its entry, through its own `keychain_uid` or else the mandatory root one.

The result is an immutable, reusable object: loaded once at boot, shared by every cryptainer.

Lookups compare the trustee identity (`trustee_type` + `keystore_uid` | `jsonrpc_url`, `keystore_owner` ignored), the keychain uid and the algorithm. Unused entries are accepted and ignored, so a provisioning tool may ship a shared key bundle. Raw RSA key bytes stay in the profile and are imported into the backend at each wrap. A per-key backend context cache is a possible later optimisation.

Key constraints are deliberately stricter than CPython's where backends could diverge:
- RSA modulus at most `WA_MAX_RSA_MODULUS_BITS` (default 4096, wolfSSL's default maximum);
- X25519 keys must be canonical (bit 255 clear, u < p), so the backends' different handling of non-canonical inputs never matters.

The exporter only produces canonical keys, so this rejects nothing legitimate.

The root `keychain_uid` is mandatory. Without it, Python generates one at encryption time, which no provisioned key can match, and the cryptainer's mandatory root `keychain_uid` would need a fresh UUID0 per cryptainer, a case with no use on a device.

### D10. Validation in C

`wa_cryptoconf_validation.c` mirrors `CRYPTOCONF_SCHEMA_PYTHON` (`src/wacryptolib/cryptainer/_validation.py`):
- allowed keys per node type, algorithm enums, non-empty lists, threshold bounds and UUID types;
- the legacy `payload_signatures` alias, normalized at copy time like spec §6.1 step 8;
- rejection of layers carrying both alias keys, since the Python schema is an `Or` of two closed schemas.

On top of that come the C-specific rules: mandatory root keychain uid, non-empty signature lists rejected as unsupported, the depth limits, and every asymmetric layer resolving to a key. Validation errors carry an error location path (`wa_error_location_path.c`).

Negative tests can't come from the export script, which validates its input first. Tests instead use `device_profile_test_helpers.py`:
- a raw cryptoconf → CBOR converter with no validation, which adds a root keychain uid and the needed keys, so that only the targeted rule can fire;
- profile mutators for text UUIDs, indefinite lengths, unknown or duplicate keys, wrong key sizes, low-order and non-canonical points, and short or long RSA keys.

The invalid cryptoconfs of `compatibility/cryptoconfs/*/invalid/` go through the converter, each with an expected status, and C unit tests call cryptoconf validation directly on hand-built trees.

### D11. Public API and lifecycle

```c
wa_status_t wa_device_profile_load_from_cbor(const uint8_t *cbor, size_t cbor_length,
                                             const wa_platform_hooks_t *platform_hooks,
                                             wa_device_profile_t **device_profile_out,      /* NULL on failure */
                                             char *error_location_buffer_or_null,
                                             size_t error_location_buffer_size);
void        wa_device_profile_destroy(wa_device_profile_t *device_profile_or_null);

wa_status_t wa_value_tree_decode_from_cbor(const uint8_t *cbor, size_t cbor_length,
                                           const wa_platform_hooks_t *platform_hooks,
                                           wa_value_t **value_out);                          /* metadata */

wa_status_t wa_cryptainer_encryptor_create(const wa_device_profile_t *device_profile,
                                           const wa_value_t *cryptainer_metadata_or_null,
                                           const wa_cryptainer_encryptor_options_t *options,
                                           wa_cryptainer_encryptor_t **encryptor_out);   /* step 1; NULL on failure */
wa_status_t wa_cryptainer_encryptor_encrypt_payload_chunk(wa_cryptainer_encryptor_t *encryptor,
                                                          const uint8_t *chunk, size_t chunk_length);
wa_status_t wa_cryptainer_encryptor_finalize(wa_cryptainer_encryptor_t *encryptor);       /* step 2 end + step 3 */
wa_status_t wa_cryptainer_encryptor_write_cryptainer_json(const wa_cryptainer_encryptor_t *encryptor,
                                                          const wa_output_sink_t *cryptainer_json_sink);
void        wa_cryptainer_encryptor_destroy(wa_cryptainer_encryptor_t *encryptor_or_null); /* wipes secrets */
```

- `options` holds the platform hooks, the ciphertext location (`WA_CIPHERTEXT_LOCATION_INLINE` / `_OFFLOADED`) and, when offloaded, the payload ciphertext sink.
- States: `CREATED → STREAMING → FINISHED`, plus `FAILED`, which only accepts destroy. Writing the JSON is only allowed in `FINISHED`.
- A one-shot convenience, `wa_cryptainer_encrypt_payload_in_one_call()`, wraps the sequence.
- Metadata is built with the public value tree builder, or decoded from CBOR.
- Sinks are `{write(context, bytes, length) -> wa_status_t, context}`, so the caller decides whether output goes to a file, flash, a socket or a buffer.

### D12. Memory policy

Every allocation goes through `platform_hooks->allocate(context, size)` / `release(context, pointer, size)`. Passing the size lets fixed-pool allocators work. The library has no reallocation hook: `wa_growable_byte_buffer` grows by allocate, copy, wipe the old block, then release it, so secrets never survive in freed heap.

The pipeline cuts every input chunk into internal slices of at most `WA_PAYLOAD_PROCESSING_SLICE_SIZE` bytes (default 4096). Per-layer state is a 16-byte CBC remainder, the EAX partial blocks, and one scratch buffer of slice size plus 16 bytes per layer. Offloaded memory therefore depends neither on the payload length nor on the caller's chunk size: a 1 MiB chunk costs the same as a 4 KiB one. Inline mode accumulates the ciphertext in a growable buffer, documented as meant for small payloads. Tests use a counting and fault-injecting allocator to check leaks, out-of-memory paths, wiping and peak usage.

### D13. Build, test and CI

- **CMake** (≥ 3.16) for host builds. Mbed TLS (v3.6.x LTS tag) and wolfSSL (v5.8.x tag) are fetched at pinned tags with `FetchContent`, or found via `WA_USE_SYSTEM_CRYPTO_LIBRARIES=ON`. They are compiled with the minimal config headers in `config/`, which also serve as references for device integrators.
- **Toolchains**: GCC and Clang, with `-std=c99 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror`; ASan/UBSan builds on Linux. Host platforms are Linux and macOS, plus Windows through MSYS2 MinGW-w64 GCC or Clang. MSVC is not supported.
- **C unit tests**: a dependency-free harness (`wa_minimal_test_harness.h`) and one test executable per module, registered with CTest. They cover:
  - the encodings: base64, JSON escaping and key order, CBOR valid/invalid/depth;
  - UUID0;
  - Shamir: split, then a test-only Lagrange recombination, with k = 1 and k = n;
  - backend conformance: FIPS 197/SP 800-38A AES vectors, RFC 4493 CMAC, the EAX paper vectors, RFC 8439, RFC 7748 X25519, the RFC 9180 A.2.1 vector, ML-KEM derand known-answer vectors, OAEP encoding with a fixed seed;
  - the state machine, out-of-memory sweeps and wiping.
- **Fuzzing**: libFuzzer targets for the CBOR decoder and profile loader (Clang), 60 s per target in CI, longer runs locally.
- **Interop tests** (pytest, `reimplementations/c-language/tests/interop/`, outside `testpaths`, run explicitly). They drive `wa_flightbox_test_driver` and the CLI from the build directory given by `WA_FLIGHTBOX_C_BUILD_DIR`, and are skipped when it is absent:
  - symmetric cipherdict fixtures, each against its own plaintext, byte-for-byte;
  - asymmetric wraps decrypted by wacryptolib; ML-KEM KEM output compared byte-for-byte with pycryptodome's `MLKEMKey._encaps(coins)` under the same coins; RFC 9180 vector through the driver;
  - cryptainers decrypted by wacryptolib using the corpus keystore pools and sidecar passphrases. Profiles come from three sources:
    - the corpus cryptoconfs that are signature-free and have a root keychain uid;
    - signature-stripped variants of `2026_current/03`, `04`, `06` and `2026_post_quantum/07_pq_hybrid`;
    - synthetic cryptoconfs, for `AES_CBC` payloads, every algo, nested symmetric layers, nested shared secrets, and so on.
  - shard subsets tested by withholding one trustee key at a time, asserting only the expected "key not found"-type entries;
  - backend parity: the same deterministic hook gives identical output from both builds.
- **Cross-compilation check**: an `arm-none-eabi-gcc` Cortex-M4 compile of the library, the Mbed TLS backend and mlkem-native (no link, no tests).
- **Entry points**: `reimplementations/c-language/build_and_test_all_backends.sh` runs both backends, unit tests, fuzz smoke and cross-compile. A new tox env, `c_flightbox`, runs that script then the interop pytest. A new `c-flightbox` job in `.github/workflows/ci.yml` (ubuntu-latest, with `arm-none-eabi-gcc` and Clang installed) runs `tox -e c_flightbox`.

### D14. Device profile export script

`scripts/flightbox/export_device_profile.py`:
- loads an Extended JSON cryptoconf with wacryptolib, validates it, and requires a root keychain uid;
- walks its asymmetric layers to collect every (trustee, keychain uid, algo), rejecting `jsonrpc_api` trustees;
- fetches public keys from a `FilesystemKeystorePool`, and converts PEMs to raw form: RSA `n`/`e` big-endian bytes, X25519 raw 32 bytes, ML-KEM-768 raw 1184 bytes (pycryptodome, so the ML-KEM tests are marked `requires_pycryptodome`);
- writes CBOR with `cbor2`, where UUIDs become tag 37 natively.

`cbor2` goes to the dev dependency group, and `pip_requirements_export.txt` is regenerated so that tox environments install it. The CDDL in the device profile specification is normative, and the script and the C decoder are tested against the same sample files.

## Risks / Trade-offs

- [In-house composites (HPKE, EAX/CMAC, OAEP encoding, Shamir) are custom crypto code] → Each one is small, exactly specified, checked against RFC/paper vectors where they exist, and validated end to end by wacryptolib decryption on every test run. Shamir's non-GCM encoding has its own split/recombine tests and a comparison with pycryptodome under injected coefficients.
- [ML-KEM's HPKE KEM id 0x0041 and its key schedule come from an IETF draft that may change] → pycryptodome is the reference, so the interop tests fail loudly if either side moves. The KEM descriptor isolates the change to one file.
- [Mbed TLS X25519 byte-order and clamping conventions differ from wolfCrypt's] → RFC 7748 vectors are tested through the backend interface on both backends, the adapter is the only place that converts, and non-canonical keys are rejected upfront.
- [Expected backend option and function names (D3) may differ in the pinned versions] → Task 4 confirms them and updates the `#error` checks and README together.
- [ESP-IDF menuconfig may lack options (ChaCha20-Poly1305 is off by default in ESP-IDF 5.x)] → Compile-time `#error` checks name each missing option, and the README lists the menuconfig entries to enable.
- [The wolfCrypt licence (GPL-3.0-or-later) applies to firmwares built with it] → Documented in the README and proposal. Mbed TLS (Apache-2.0 OR GPL-2.0-or-later) remains the default backend.
- [Inline ciphertext keeps the whole payload in RAM] → Documented. Offloaded mode is the default in the CLI and the recommended device mode.
- [Recursive layers on small stacks] → Both depth limits are enforced at profile load. The stack use per level is measured on host (`-fstack-usage`) and documented.
- [Device profiles are not authenticated: a swapped profile means a swapped trustee key] → Out of scope here and stated in the profile specification. COSE_Sign1 is the planned follow-up, and the format string allows a later version to require it.
- [The random hook on ESP32 is only truly random under conditions, and Pico's `pico_rand` is not a CSPRNG] → The README states the hook contract and points to audit §5. The library cannot check entropy itself.
- [The interop tests live outside `testpaths`, so a plain `pytest` run skips them] → The dedicated tox env and CI job run them on every push.

## Migration Plan

Purely additive: a new directory, a new script, a new doc, a dev dependency, a tox env and a CI job. No wacryptolib behaviour, wire format or API changes, so there is no rollback concern beyond reverting the commits. The sibling `witness-angel-cryptolib-c` skeleton can be archived once this port runs on a device. That is outside this change.

## Open Questions

- Licence of the new C tree. By default it inherits the repository's GPL-2.0-or-later, which is compatible with both backends (with wolfCrypt the combined firmware becomes GPL-3.0-or-later). A more permissive licence (e.g. Apache-2.0) for device makers would only change the licence headers and a LICENSE file, not the specs or tasks.
- Which exact patch versions to pin (latest Mbed TLS 3.6.x, wolfSSL 5.8.x and mlkem-native 2.x at implementation time).
- Whether to ship an ESP-IDF component manifest in a follow-up, once a target board is chosen (audit §8).
