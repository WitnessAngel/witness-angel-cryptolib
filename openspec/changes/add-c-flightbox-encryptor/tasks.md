## 0. Prerequisite

- [x] 0.1 Check that `add-cbor-key-ciphertexts` is implemented and archived (in `openspec/changes/archive/2026-11-17-add-cbor-key-ciphertexts/`; wacryptolib decrypts WA-CBOR key ciphertexts; the `key-ciphertext-format` main spec and the `2026_cbor_key_ciphertexts` corpus generation exist), and verify `openspec list` no longer shows it as active

## 1. Device profile format, export script and test helpers

- [x] 1.1 Write `docs/flightbox_specifications/flightbox_device_profile_specification.md` and verify the CDDL parses with a CDDL tool (e.g. the `cddl` gem or `cddlc`), or record the tool used. Contents:
  - purpose, and the reference to the WA-CBOR specification for every rule not restricted;
  - the sub-profile (allowed items; WA-CBOR items rejected as unsupported; the 64-level depth);
  - the root map, UUIDs as tag 37, and the raw key encodings;
  - trustee identity, the `local_keyfactory` meaning, the mandatory root keychain uid, and unused entries;
  - key constraints, with the configurable RSA maximum and canonical X25519;
  - the `.cbor` file naming, and the no-integrity warning;
  - the full CDDL.

  Update §9 of `docs/specifications/wa_cbor_document_format.md` if the sub-profile's definition there differs
- [x] 1.2 Write `scripts/flightbox/export_device_profile.py`, and verify that it:
  - exports `compatibility/cryptoconfs/2026_current/05_shamir_authenticators.cryptoconf` with `classic_pool`;
  - gives byte-identical profiles from `2026_cbor_pairs/01_single_layer.cryptoconf.json` and `.cbor`;
  - fails cleanly on a pool missing a key, on a cryptoconf without root keychain uid, and on an existing output.

  The script must:
  - load the cryptoconf with `load_from_document_file()`, in either format, validate it, and require a root keychain uid;
  - reject `jsonrpc_api` trustees, collect the asymmetric layers, and fetch keys from a `FilesystemKeystorePool`;
  - convert PEM to raw RSA n/e, X25519 and ML-KEM-768, with unique entries;
  - encode with `dump_to_cbor_bytes()`;
  - write a `.cbor` output (any letter case, lowercased) by exclusive creation, or overwrite it with `--force`;
  - exit non-zero without writing on any error.
- [x] 1.3 Write `reimplementations/c-language/tests/interop/device_profile_test_helpers.py`:
  - a raw cryptoconf → profile converter with no validation, encoding with `dump_to_cbor_bytes()`, adding a root keychain uid and the keys required, so that only the targeted rule fires;
  - profile mutators for text UUIDs, unknown and duplicate keys, Extended JSON keyword maps, indefinite lengths, floats and other tags, wrong key sizes, low-order and non-canonical X25519, and short or long RSA keys (byte-level, or through `cbor2` for non-WA-CBOR encodings);
  - a byte-level splicer placing an arbitrary CBOR item as the profile's `cryptoconf` value;
  - a signature-stripping helper.

  Verify that each mutator's output differs from its input only as intended: decode valid outputs with `load_from_cbor_bytes()`, and the others with `cbor2`
- [x] 1.4 Add `tests/test_flightbox_device_profile_export.py`. It checks that exported profiles load with `load_from_cbor_bytes()`, equal their own `dump_to_cbor_bytes()` re-encoding, and follow the CDDL rules (keys, tag 37, sizes, uniqueness, root keychain uid), for:
  - every corpus cryptoconf that is signature-free with a root keychain uid (`2026_current/01` and `05`, `2026_cbor_pairs/01_single_layer`, and the five of `2026_cbor_key_ciphertexts`), the WA-CBOR pairs from each of their two formats, with byte-identical profiles for both;
  - the signature-stripped variants of `2026_current/03`, `04`, `06` and `2026_post_quantum/07_pq_hybrid`.

  ML-KEM cases are marked `requires_pycryptodome`. Verify that it passes with `tox -e py` and is deselected as intended in the fallback env

## 2. C project skeleton and build

- [x] 2.1 Create the `reimplementations/c-language/` tree of design D1 with the public headers holding the API of design D11:
  - `wa_status_codes.h`, `wa_platform_hooks.h`, `wa_value_tree.h`, `wa_device_profile.h`, `wa_document_formats.h`, `wa_cryptainer_encryptor.h`, and the umbrella `wa_flightbox.h`;
  - `wa_flightbox_config.h`, with `WA_MAX_KEY_CIPHER_NESTING_DEPTH`, `WA_MAX_CBOR_NESTING_DEPTH` (`#error` above 64), `WA_MAX_RSA_MODULUS_BITS`, `WA_PAYLOAD_PROCESSING_SLICE_SIZE`, and `WA_DOCUMENT_FORMAT_JSON_ENABLED` / `WA_DOCUMENT_FORMAT_CBOR_ENABLED` (`#error` if neither).

  Verify that a test file including only `wa_flightbox.h` compiles with `-std=c99 -Wall -Wextra -Wpedantic -Werror`, and that compilation fails with an explicit message with both formats disabled, or with a CBOR depth of 65
- [ ] 2.2 Write `CMakeLists.txt` with:
  - `WA_CRYPTO_BACKEND=MBEDTLS|WOLFCRYPT`, and `WA_DOCUMENT_FORMATS` (default `JSON;CBOR`, which also selects the writer sources);
  - FetchContent of pinned Mbed TLS 3.6.x and wolfSSL 5.8.x tags, or `WA_USE_SYSTEM_CRYPTO_LIBRARIES=ON`;
  - strict warning flags, an ASan/UBSan option and CTest.

  Verify that an empty library builds with each backend value on Linux and with MSYS2 MinGW-w64 on Windows, and that an unset or invalid backend or format value stops configuration with a clear message
- [x] 2.3 Write `config/wa_mbedtls_config_for_flightbox.h` and `config/wa_wolfssl_user_settings_for_flightbox.h` (options of design D3, confirmed against the pinned versions), and verify both crypto libraries build with them through CMake
- [x] 2.4 Vendor mlkem-native (pinned 2.x release, licence files, ML-KEM-768-only single-unit build, `wa_mlkem_` namespace, randomized API disabled), record version and source hash in `third_party/mlkem-native/VENDORED_VERSION.md`, and verify it compiles in the Mbed TLS build with no warnings
- [x] 2.5 Add `tests/unit/wa_minimal_test_harness.h` plus test support code: a counting, fault-injecting, wipe-checking and peak-measuring test allocator, and a deterministic test random hook. Verify a sample test registered in CTest passes, and that a deliberately failing assertion makes `ctest` fail

## 3. Encoding layer

- [x] 3.1 Implement `wa_secure_memory_wipe.c` and `wa_growable_byte_buffer.c` (growth by allocate/copy/wipe/release, secret flag), and verify unit tests show old blocks are zeroed on growth and release
- [x] 3.2 Implement `wa_value_tree.c` (node types of design D7, insertion-ordered maps, deep copy without aliasing, lookups, public builder functions, secret bytes nodes wiped on release) and `wa_document_tree_constraints.c` (Extended JSON keyword maps, nesting depth with the metadata limit of design D8). Verify unit tests including a shared-subtree deep copy where modifying one copy leaves the other unchanged, and keyword-map and depth rejections
- [x] 3.3 Implement `wa_base64_encoder.c` (standard alphabet, padding, streaming to a sink), and verify RFC 4648 §10 vectors and chunked-streaming equivalence
- [x] 3.4 Implement `wa_extended_json_writer.c`, verified by unit tests whose expected strings are generated by wacryptolib's `dump_to_json_bytes()` for symkeys, key structs, nested cipherdicts, shard tuples, `"Café ☕"` (written `"Caf\u00e9 \u2615"`) and a non-BMP character (surrogate pair). The writer must handle:
  - relaxed mode, with keys sorted by code point (UTF-8 byte order) and `", "`/`": "` separators;
  - ASCII-only output, with lowercase `\uXXXX` escapes and surrogate pairs;
  - `$binary` with subType `"00"` and `$uuid` in lowercase hex;
  - streaming to a sink.
- [x] 3.5 Implement `wa_wacbor_deterministic_writer.c` (shortest heads, definite lengths, map keys sorted by encoded bytes, tag 37 UUIDs, streaming to a sink), verified by unit tests whose expected bytes are generated by wacryptolib's `dump_to_cbor_bytes()` for the same structures as task 3.4, and by the deterministic in-sub-profile vectors of §10 of the WA-CBOR specification
- [x] 3.6 Implement `wa_document_serialization.c` (dispatch by `wa_document_format_t`, to a buffer or a sink, unsupported-feature status for disabled formats). Verify a unit test in each single-format build, and a symbol check that a CBOR-only library has no `wa_extended_json_` nor `wa_base64_` symbol, and a JSON-only one no `wa_wacbor_deterministic_writer_` symbol
- [x] 3.7 Implement `wa_wacbor_subprofile_decoder.c` (accepted, unsupported and invalid classes of design D8, UTF-8 check, duplicate-key and keyword-map rejection, `WA_MAX_CBOR_NESTING_DEPTH`, bounds checks, typed errors) and `wa_value_tree_decode_from_cbor()`. Verify unit tests covering:
  - every accepted type, including non-shortest heads and unsorted keys;
  - each unsupported class: floats, tags 0/2/3/4, indefinite lengths, tag 55799, integers outside int64;
  - each invalid case: other tags, non-text and duplicate keys, keyword maps, truncated input, oversize lengths, invalid UTF-8, trailing bytes, too deep;
  - every test vector of §10 of the WA-CBOR specification, embedded in the test.
- [x] 3.8 Add libFuzzer targets in `tests/fuzz/` for the CBOR decoder and the profile loader, seeded with the WA-CBOR test vectors and the corpus profiles, and verify each runs 10 minutes on host under ASan/UBSan with no finding

## 4. Crypto backend interface and adapters

- [x] 4.1 Write `backends/wa_crypto_backend.h` (the primitives of design D3: bulk AES-256-CBC and AES-256-CTR, ChaCha20-Poly1305 streaming, SHA-256/512, HMAC-SHA256, X25519, raw RSA public, ML-KEM-768 derand; plus status mapping and opaque context types allocated through the allocator hook, a fixed-pool allocator giving static use as everywhere else in the library), and verify the header compiles standalone
- [x] 4.2 Write a shared backend conformance test: SP 800-38A AES-256 CBC and CTR including multi-call streaming, RFC 8439 ChaCha20-Poly1305 including multi-update streaming, FIPS 180-4 SHA-256/512, RFC 4231 HMAC, RFC 7748 X25519, a raw-RSA known value with a 4096-bit modulus, and an ML-KEM-768 derand known-answer test. Implement `wa_crypto_backend_mbedtls.c` with `#error` checks for every required `MBEDTLS_*` option, and verify the conformance test passes
- [x] 4.3 Implement `wa_crypto_backend_wolfcrypt.c` with `#error` checks for every required wolfSSL option (exact names confirmed against the pinned version, design D3 updated if they differ), and verify the same conformance test passes unchanged
- [x] 4.4 Verify the missing-option checks: build once with `MBEDTLS_CHACHAPOLY_C` undefined and once with `WOLFSSL_AES_COUNTER` undefined, and confirm each build fails with an error naming the option

## 5. Portable primitives

- [x] 5.1 Implement `wa_uuid0_generation.c` (spec §3.2, clock hook in 1/10000 s units, optional) and `wa_symmetric_key_generation.c` (spec §3.3), and verify layout unit tests with a fixed clock and deterministic randomness, including the zero time prefix without a clock
- [x] 5.2 Implement `wa_aes_cbc_pkcs7_padding.c`, `wa_aes_cmac_omac1.c` (CBC-MAC over bulk CBC, subkeys from E_K(0)) and `wa_aes_eax_mode.c` (backend CTR + OMAC, streaming). Verify the AES-256 CMAC examples of SP 800-38B (subkeys and the 0/16/40/64-byte messages; the RFC 4493 vectors are AES-128, which the AES-256-only backend interface cannot run), the EAX paper messages and nonces under an AES-256 key with pycryptodome outputs (the paper vectors themselves, AES-128, being checked against pycryptodome by the generator), and one-shot vs 1/15/16/17-byte chunked equivalence
- [x] 5.3 Implement `wa_symmetric_cipher_streams.c` (AES_CBC, AES_EAX and CHACHA20_POLY1305 streaming contexts, and one-shot cipherdict builders), and verify unit tests on both backends for cipherdict shapes and tag sizes
- [x] 5.4 Implement `wa_rsa_oaep_sha512_padding.c` and `wa_rsa_oaep_chunked_encryption.c` (empty label, seed from the hook, 60-byte chunks, empty plaintext gives zero chunks). Verify an OAEP encoding test with a fixed seed against a pycryptodome reference, and chunk counts for 0, 60, 61 and 121-byte inputs
- [x] 5.5 Implement `wa_hkdf_sha256.c`, `wa_hpke_base_mode_seal.c`, `wa_hpke_kem_dhkem_x25519.c` (all-zero DH check) and `wa_hpke_kem_ml_kem_768.c`. Verify the RFC 5869 HKDF vectors and the RFC 9180 A.2.1 base-mode vector (enc, key, base_nonce, sequence-0 ciphertext) on both backends
- [x] 5.6 Implement `wa_shamir_secret_sharing_gf128.c` (spec §3.7, constant-time GF(2^128) multiply), and verify unit tests that:
  - recombine with a test-only Lagrange interpolation for k = 1, k = n and k < n;
  - check shard lengths and indices;
  - compare one split with injected coefficients against pycryptodome's `Shamir.split` output.
- [x] 5.7 Implement `wa_public_key_constraints.c` (RSA 2048..`WA_MAX_RSA_MODULUS_BITS`, odd modulus, `3 <= e < n` with e odd; canonical, non-low-order X25519; ML-KEM-768 modulus check), and verify unit tests for each accepted and rejected case of the profile spec
- [x] 5.8 Implement `wa_asymmetric_key_wrapping.c` (key struct serialization in the cryptainer's document format, dispatch to RSA_OAEP / ECIES_X25519 / ML_KEM_768, cipherdict shapes of spec §3.5), and verify unit tests on cipherdict keys and sizes for each algorithm and each format, including 2 RSA-OAEP chunks for a WA-CBOR `AES_CBC` key struct without metadata, against 6 in Extended JSON

## 6. Device profile loading and cryptoconf validation

- [x] 6.1 Implement `wa_cryptoconf_validation.c` and `wa_error_location_path.c` (mirror of `CRYPTOCONF_SCHEMA_PYTHON`, output fields rejected, legacy alias, both-keys rejection, mandatory root keychain uid, key cipher nesting depth, signature rejection, error paths). Verify C unit tests on hand-built trees for each rule, with expected status and location path
- [x] 6.2 Implement `wa_device_profile_decoding.c` and `wa_device_profile_load_from_cbor()` (top-level map, root keys, format string, entries, trustee identity, uniqueness, unused entries, key constraints, layer-to-key resolution, NULL output on failure). Verify unit tests for each scenario of the `flightbox-device-profile` spec, using CBOR samples produced by the export script and by the helpers of task 1.3

## 7. Flightbox core (steps 1, 2, 3)

- [x] 7.1 Implement `wa_key_cipher_layers_encryption.c` (spec §6.2–§6.5: chain with a `key_bytes != initial` check, shared secret recursion, symmetric sub-key with in-place `key_ciphertext` and, in WA-CBOR, `key_ciphertext_format`, asymmetric key struct; every serialization through `wa_document_serialization`). Verify, in each format, unit tests that a nested sample produces the nesting of spec §6.7, decoded back with a test-only reader
- [x] 7.2 Implement `wa_cryptainer_base_generation.c` (spec §6.1: fresh uid, root keychain uid, deep copy, legacy rename, `payload_macs` null, `key_ciphertext_format` in WA-CBOR only, root fields, in-memory secrets), and verify unit tests that check every root and layer field after creation, in each format, including the legacy `payload_signatures: []` rename
- [x] 7.3 Implement `wa_payload_encryption_pipeline.c` (internal slicing by `WA_PAYLOAD_PROCESSING_SLICE_SIZE`, per-layer streaming nodes, CBC remainder, final flush order of spec §7.2, offloaded sink or inline buffer), and verify unit tests that chunked and one-shot outputs are identical for 1–3 layers of mixed algorithms
- [x] 7.4 Implement `wa_cryptainer_finalization.c` (payload_macs `{}` / `{"tag": ...}`, ciphertext struct, FINISHED) and `wa_cryptainer_encryptor.c`:
  - document format option, defaulting to the build default, and unsupported-feature status for a disabled one;
  - metadata checked against the document tree constraints;
  - state machine with a FAILED state, NULL on failed creation, and `destroy(NULL)` as a no-op;
  - cryptainer writing only when FINISHED, the one-shot helper, and destroy wiping everything;
  - `wa_document_format_get_cryptainer_suffix()`.

  Verify state-machine unit tests, including wrong-state calls and a disabled format
- [x] 7.5 Verify robustness:
  - an out-of-memory sweep failing each allocation index in turn, across a full nested profile load and cryptainer creation, in each format, with no leak, the correct status and no instance each time;
  - a random-hook failure test, with nothing written to the sinks;
  - a check that every released secret block was zeroed.

## 8. Host tools

- [x] 8.1 Implement `tools/wa_host_platform_hooks.c` (getrandom or `/dev/urandom` on POSIX, BCryptGenRandom on Windows, clock in 1/10000 s, stdlib allocation), and verify that the random hook returns distinct buffers and fails cleanly when the source is unavailable (simulated)
- [x] 8.2 Implement `tools/wa_flightbox_encrypt_file_cli.c` and verify, by a manual run on a corpus-derived profile, that it produces both files in each format, normalizes `Clip.CRYPT`, and refuses an existing output without `--force`. The tool must handle:
  - the profile, the payload, optional WA-CBOR metadata, `--format json|cbor` among the build's formats, inline/offloaded, and the chunk size;
  - output naming of design D14 (typed suffix stripped in any letter case, lowercase suffix appended);
  - exclusive creation, or `--force`, with the payload written first and the cryptainer last;
  - cleanup of the created files on failure, and a non-zero exit printing the status description and error location.
- [x] 8.3 Implement `tools/wa_flightbox_test_driver.c`, and verify each subcommand on one sample input. Subcommands:
  - symmetric encryption with given key material;
  - HPKE seal with a given ephemeral key and info/AAD;
  - ML-KEM derand encapsulation printing the KEM ciphertext and shared secret;
  - CBOR decoding of a document, printing it back through each enabled writer, or the status;
  - serialization of a given intermediate structure in a given format;
  - cryptainer creation with a deterministic seed and clock, in a given format.

## 9. Interoperability tests (pytest)

- [x] 9.1 Write `reimplementations/c-language/tests/interop/conftest.py` (locate builds through `WA_FLIGHTBOX_C_BUILD_DIR`, skip when absent, parametrize over the available backends and their enabled document formats, corpus helpers reusing `tests/_compatibility_corpus.py`, `check_key_ciphertext_formats()` included), and verify tests are skipped cleanly with no build and collected with one
- [x] 9.2 Write `test_c_flightbox_wacbor_conformance.py`, and verify it passes on both backends:
  - the test vectors of §10 of the WA-CBOR specification, parsed from the document like wacryptolib's own test does, classified as in design D8;
  - accepted deterministic vectors re-encoded to exactly `cbor_hex` and written as exactly `extjson`;
  - every `2026_cbor_pairs/invalid/*.cryptoconf.cbor` document rejected through the splicer;
  - a differential test over the helper mutations and vectors: every input the C decoder accepts loads with `load_from_cbor_bytes()` to the same tree.
- [x] 9.3 Write `test_c_flightbox_symmetric_vectors.py` (every symmetric cipherdict fixture of `compatibility/cipherdicts/`, against its own plaintext, byte-for-byte), and verify it passes on both backends
- [x] 9.4 Write `test_c_flightbox_asymmetric_interop.py`, and verify it passes on both backends:
  - RSA_OAEP, ECIES_X25519 and ML_KEM_768 wraps by the C driver, in each format, decrypted with wacryptolib private keys from `2026_post_quantum/pq_pool`;
  - intermediate structures byte-identical to `dump_to_json_bytes()` / `dump_to_cbor_bytes()` of the same trees;
  - the ML-KEM KEM ciphertext and shared secret compared byte-for-byte with pycryptodome's `MLKEMKey._encaps(coins)` (`requires_pycryptodome`);
  - the RFC 9180 vector through the driver.
- [x] 9.5 Write `test_c_flightbox_cryptainer_interop.py`, and verify it passes on both backends.
  - Profiles:
    - corpus cryptoconfs that are signature-free with a root keychain uid: `2026_current/01` and `05`, `2026_cbor_pairs/01_single_layer`, and `2026_cbor_key_ciphertexts/01`–`05` with `cbor_key_ciphertexts_pool` (authenticator passphrases from its sidecar);
    - signature-stripped `03`, `04`, `06` and `07_pq_hybrid`;
    - synthetic ones covering what the corpus lacks among `AES_CBC`, `AES_EAX` and `CHACHA20_POLY1305` payloads, multiple payload layers, nested symmetric layers, and nested shared secrets with thresholds 1 and n.
  - Variations: both document formats; metadata null, non-null and non-ASCII; payload sizes 0/1/15/16/17/4099/65539/1048579; inline and offloaded; odd chunk sizes.
  - Each cryptainer must:
    - be loaded from the filesystem (`.crypt.json` / `.crypt.cbor` names), and pass strict cryptainer validation;
    - equal its re-encoding by wacryptolib's default writer of its format, with `key_ciphertext_format: "cbor"` on every payload and symmetric key layer in WA-CBOR, and none in Extended JSON, as checked by `check_key_ciphertext_formats()`;
    - have the same tree shape as the cryptainer wacryptolib makes from the same cryptoconf with `key_ciphertext_format` set to its format (byte strings, UUIDs and timestamps aside);
    - be decrypted by wacryptolib with the pool's sidecar passphrases, with no report error.
  - A sample of them is converted with `flightbox convert-format` to the other format and decrypted again.
  - For one 2-of-3 profile, each trustee key is withheld in turn, and only the expected missing-key entries may appear.
- [x] 9.6 Write `test_c_flightbox_rejections.py`, and verify it passes on both backends. Each case uses the task 1.3 helpers and expects a given status and location, with no output file:
  - signature confs;
  - missing keys;
  - missing root keychain uid;
  - bad thresholds;
  - both alias keys;
  - output fields such as `key_ciphertext_format` in the cryptoconf;
  - excessive key cipher nesting;
  - the mutated profiles;
  - float, datetime, keyword-map and too-deep metadata;
  - every `compatibility/cryptoconfs/*/invalid/` file.
- [x] 9.7 Write `test_c_flightbox_backend_parity.py`, and verify it passes when both builds are present: the same deterministic seed and clock give byte-identical cryptainers, in each format, from the Mbed TLS and wolfCrypt builds; and one-shot vs chunked encryption give identical payload ciphertext

## 10. Portability, CI and documentation

- [x] 10.1 Add `arm-none-eabi-gcc` Cortex-M4 compile-only targets for the library with the Mbed TLS backend and mlkem-native, one CBOR-only and one JSON-only, and verify both compile with `-Werror`. Record in the README the code size of each (`arm-none-eabi-size`) and the per-function stack usage (`-fstack-usage`) of the recursive core functions
- [x] 10.2 Measure peak library allocation for 4 KiB and 1 MiB offloaded payloads, fed in 4 KiB chunks and in one 1 MiB chunk, with the counting allocator. Verify all three peaks are within a small fixed margin of each other
- [ ] 10.3 Write `reimplementations/c-language/build_and_test_all_backends.sh` (the build matrix of design D13, sanitizers, unit tests, 60 s fuzz smoke per target, cross-compiles), add a `c_flightbox` tox env running it and then `pytest reimplementations/c-language/tests/interop`, and add a `c-flightbox` job to `.github/workflows/ci.yml` (ubuntu-latest, installing CMake, Clang and `arm-none-eabi-gcc`). Verify `tox -e c_flightbox` runs green locally (Linux or WSL) and the CI job passes on a pushed branch
- [x] 10.4 Write `reimplementations/c-language/README.md`, and verify the minimal example in it compiles as part of the build. Contents:
  - layout and naming;
  - an API walkthrough with a minimal example, including file naming with `wa_document_format_get_cryptainer_suffix()`;
  - the platform hook contracts, with the RNG warnings of audit §5;
  - the configurable limits, and the document format macros, with guidance (Extended JSON on big chips, WA-CBOR only on small ones) and the measured code sizes;
  - the required Mbed TLS / ESP-IDF menuconfig and wolfSSL options, and the raw-RSA note;
  - the mlkem-native note and licences, including the wolfCrypt GPL-3.0 warning;
  - inline vs offloaded, supported host toolchains, and how to run the tests.
- [x] 10.5 Add a "C profile" subsection to section 10 of `docs/flightbox_specifications/flightbox_encryptor_specification.md` next to the JSON-only MicroPython profile of §10.1 (supported algorithms, WA-CBOR device profile input, mandatory root keychain uid, no signatures, backends, compile-time document formats with one format per cryptainer, as §2 allows single-serialization devices), with a link to the device profile specification, and verify `tox -e doc` still builds
- [x] 10.6 Run `openspec validate add-c-flightbox-encryptor --strict`, `tox -e py` and `tox -e c_flightbox`, and verify everything passes before marking the change complete
