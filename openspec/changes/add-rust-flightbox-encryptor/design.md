## Context

See proposal.md for the motivation. The algorithm is specified by `docs/flightbox_specifications/flightbox_encryptor_specification.md` ("the spec" below, with section numbers), the input by `docs/flightbox_specifications/flightbox_device_profile_specification.md`, and the documents by `docs/specifications/wa_cbor_document_format.md`. The C library of `reimplementations/c-language/` (change `add-c-flightbox-encryptor`, whose design decisions are cited below as "C-D1" to "C-D15") is a working implementation of the same feature set, with a layering that this port keeps: an algorithmic core, portable composite constructions, and a thin backend of primitives. The library choice comes from `audits/rust_crypto_backend_options_2026-11-17.md`.

Constraints that shape the design:

- The targets are STM32U3 and STM32U5 (Cortex-M33, Rust target `thumbv8m.main-none-eabihf`, stable toolchain). MSP430 is not a Rust target for this library (16-bit pointers, 64 KB address space) and stays with the C library.
- The encryptor only performs public-key operations: RSA public exponentiation, X25519 with a single-use ephemeral scalar, ML-KEM encapsulation. The known timing weaknesses of Rust RSA code concern private-key operations.
- RustCrypto moved to a new generation of its traits in 2026 (`digest` 0.11, `cipher` 0.5), but its `rsa` crate has no stable release on that generation, and its `chacha20poly1305` crate only encrypts whole buffers.
- wolfSSL publishes Rust wrappers implementing the RustCrypto traits. Whether they expose the low-level functions the C adapter relies on (raw RSA, ML-KEM encapsulation with given randomness, streaming ChaCha20-Poly1305) has not been established.
- The C test driver and CLI are plain executables with a documented command-line protocol and JSON outputs, and the pytest interop suite (`reimplementations/c-language/tests/interop/`) finds them in build directories listed in `WA_FLIGHTBOX_C_BUILD_DIR`, asking each for its `build-info`.
- Spec §6.8 fixes an order of random draws, which the C library follows, all its randomness coming from one hook (C-D6).
- The development machine is Windows with the MSVC Rust toolchain; the C tree needs Linux, WSL or MSYS2. CI is GitHub Actions running tox.

## Goals / Non-Goals

**Goals:**
- Memory safety by construction for everything that parses or builds data: no `unsafe` in the core crate nor in the default backend.
- One portable core, identical on both backends and in both document formats, with the same observable behaviour as the C library, down to the bytes under deterministic randomness.
- A backend interface that an integrator can implement for a hardware accelerator.
- A default configuration that builds and tests with `cargo` alone, on Windows, Linux and macOS.
- Reuse of the C change's assets (specifications, vector generators, interop suite) instead of a second copy.

**Non-Goals:**
- A C API (static library and header) over the Rust library, and chip-specific hardware backends. The design keeps both possible; each is a later change.
- An Mbed TLS backend. The trait allows it; RustCrypto covers the pure-software case and wolfCrypt the validated-library case.
- Using the RustCrypto composites where they exist (`eax`, `cmac`, `hkdf`, `hpke`, `rsa`'s OAEP): the composites are written once over the backend trait, as in C-D4, so that both backends share them and one source of randomness.
- A heap-free build. The RSA arithmetic and the document trees need an allocator.
- Recovering from every allocation failure (D8).
- Decryption, key generation, signatures, digests, device profile signing, the STARTED serialization of spec §7.2.

## Decisions

### D1. Workspace layout and naming

```
reimplementations/rust/
  Cargo.toml                         workspace, shared lints, release profile
  Cargo.lock                         committed
  rust-toolchain.toml                pinned stable toolchain, thumbv8m.main and thumbv7em targets
  deny.toml                          advisories and licences policy (D12)
  README.md                          integration guide
  wa_flightbox/                      core crate: no_std + alloc, forbid(unsafe_code), no crypto dependency
    src/
      lib.rs                         public API re-exports
      error.rs                       Error, ErrorKind, error location
      platform_hooks.rs              PlatformHooks and OutputSink traits
      limits.rs                      EncryptorLimits
      crypto_backend.rs              CryptoBackend trait (D3)
      core/                          the flightbox algorithm (spec §6-§9), no crypto code
        cryptainer_encryptor.rs          public API and typestate lifecycle (D7)
        cryptainer_base_generation.rs    step 1 (spec §6.1)
        key_cipher_layers_encryption.rs  spec §6.2-§6.5
        payload_encryption_pipeline.rs   step 2 (spec §7.2), internal slicing
        cryptainer_finalization.rs       step 3 (spec §8 minus signing)
        cryptoconf_validation.rs         mirror of CRYPTOCONF_SCHEMA_PYTHON + device rules
        error_location_path.rs
      encoding/
        value_tree.rs                    data model (D6)
        document_tree_constraints.rs     keyword maps, nesting depth
        wacbor_subprofile_decoder.rs     device profile sub-profile of WA-CBOR -> value tree
        device_profile.rs                profile structure, key entries, key lookup
        document_serialization.rs        the only dispatch point between writers
        wacbor_deterministic_writer.rs   [feature wa-cbor]
        extended_json_writer.rs          [feature extended-json]
        base64_encoder.rs                [feature extended-json]
        secret_byte_buffer.rs            wiping buffer that never reallocates in place (D9)
      primitives/                    composite constructions, generic over the backend
        symmetric_key_generation.rs, symmetric_cipher_streams.rs, aes_cbc_pkcs7_padding.rs,
        aes_cmac_omac1.rs, aes_eax_mode.rs, rsa_oaep_sha512_padding.rs,
        rsa_oaep_chunked_encryption.rs, hkdf_sha256.rs, hpke_base_mode_seal.rs,
        hpke_kem_dhkem_x25519.rs, hpke_kem_ml_kem_768.rs, public_key_constraints.rs,
        asymmetric_key_wrapping.rs, shamir_secret_sharing_gf128.rs, uuid0_generation.rs
  wa_flightbox_backend_rustcrypto/   default backend: no_std, forbid(unsafe_code)
  wa_flightbox_backend_wolfcrypt/    wolfCrypt backend: build.rs (cc + bindgen), FFI in one module
  wa_flightbox_backend_conformance/  backend test suite, generic over CryptoBackend (D10)
  wa_flightbox_host_tools/           std: wa_flightbox_encrypt_file_cli, wa_flightbox_test_driver, host hooks
  wa_flightbox_footprint_probe/      no_std staticlib calling the whole API, for cross-builds and sizes
  fuzz/                              cargo-fuzz targets (outside the workspace, nightly)
  test_vectors/                      generated JSON vectors + their generator script (D10)
  build_and_test_all_backends.sh
```

Module names are those of the C files without the `wa_` prefix, so that a reviewer can read both implementations side by side, and core modules carry the same spec section references. Crate names use the `wa_flightbox` prefix. Rust naming conventions apply inside (`CryptainerEncryptor::encrypt_payload_chunk()`).

Alternative considered: a single crate with a cargo feature per backend. Rejected: backends are mutually exclusive choices, which cargo features, being additive, express badly; separate crates also keep `unsafe` and the C build script out of the default dependency graph, and let one test binary run two backends side by side.

### D2. Layering and the safety boundary

```
 wa_flightbox:  public API --> core/ --> primitives/ --> trait CryptoBackend
                                 |                          ^            ^
                                 +--> encoding/             |            |
                                                 backend_rustcrypto   backend_wolfcrypt
                                                 (safe Rust)          (FFI, unsafe confined)
```

`#![forbid(unsafe_code)]` is set at the root of `wa_flightbox`, `wa_flightbox_backend_rustcrypto`, `wa_flightbox_backend_conformance` and `wa_flightbox_host_tools`. A device built with the default backend therefore runs no `unsafe` code of ours; what remains is the audited `unsafe` inside the RustCrypto crates and `alloc`. In `wa_flightbox_backend_wolfcrypt`, `unsafe` is denied by default and allowed in the single module that wraps the generated bindings behind safe functions taking slices.

The core crate has one dependency, `zeroize`. Arithmetic on public sizes uses checked operations; indexing of decoded input goes through slice methods returning `Option`, so that a decoder bug surfaces as an error, not a panic (D8).

### D3. The backend trait

`CryptoBackend` carries the primitives of C-D3, with associated types for the streaming states:

| Primitive | RustCrypto backend | wolfCrypt backend |
|---|---|---|
| AES-256-CBC encryption over whole blocks, streaming (also serves CMAC) | `aes` + `cbc` | `wc_AesCbcEncrypt` |
| AES-256-CTR, streaming (for EAX) | `aes` + `ctr` | `wc_AesCtrEncrypt` |
| ChaCha20-Poly1305 streaming encryption | `chacha20` + `poly1305`, composed per RFC 8439 in the adapter | `wc_ChaCha20Poly1305_Init/UpdateData/Final` |
| SHA-256, SHA-512, HMAC-SHA256 | `sha2`, `hmac` | `wc_Sha256*`, `wc_Sha512*`, `wc_Hmac*` |
| X25519: public key from scalar; shared secret | `x25519-dalek`'s bare `x25519()` function | `wc_curve25519_*` |
| RSA raw public operation from raw (n, e) | `crypto-bigint` Montgomery exponentiation | `wc_RsaDirect` |
| ML-KEM-768 encapsulation from 32 given bytes | `ml-kem` deterministic encapsulation | `wc_MlKemKey_EncapsulateWithRandom` |

The trait is implemented by zero-sized types and used as a type parameter (`CryptainerEncryptor<B: CryptoBackend, ...>`), so calls are statically dispatched and a firmware links one backend. Methods take no random generator: the backend is only given fully determined inputs (C-D6). Bulk CBC and CTR calls receive whole processing slices, so that a hardware backend takes its accelerator once per slice. The trait and its contract (input sizes, the raw RSA input being below the modulus, the empty-stream ChaCha20-Poly1305 case) are documented for integrators, and the conformance crate (D10) is the acceptance test of any implementation.

RSA: the default backend does not use the `rsa` crate. That crate is still in release candidates on the new trait generation, and its OAEP would draw its own seed. `crypto-bigint`, which `rsa` 0.10 itself builds on, gives a modular exponentiation that is constant-time in the base (the OAEP-encoded secret) and may be variable-time in the public exponent. The exact `crypto-bigint` and `ml-kem` APIs are confirmed against the versions locked at implementation time (task 4).

ChaCha20-Poly1305: composing the two RustCrypto primitives in the adapter is about 40 lines (Poly1305 key from block 0, padding to 16 bytes, length block), checked by the RFC 8439 vectors of the conformance suite, including multi-update streaming.

Alternatives considered:
- RustCrypto's `chacha20poly1305`, `eax` and `rsa` crates as whole algorithms. Rejected: no streaming for the first, and the composites would then differ between backends.
- A trait per primitive family. Rejected for now: one trait is simpler to implement and document; a hardware backend overriding only AES delegates the rest to the RustCrypto backend, which the "integrator-provided backend" test demonstrates.

### D4. The wolfCrypt backend goes through direct FFI

`wa_flightbox_backend_wolfcrypt` calls the same wolfCrypt functions as the C adapter (`wa_crypto_backend_wolfcrypt.c`), through bindings generated by `bindgen` at build time. Its `build.rs`:
- takes the wolfSSL source directory from `WA_WOLFSSL_SOURCE_DIR` (wolfSSL 5.8.x, the tag pinned by the C tree), and fails with an explicit message when it is unset;
- compiles the needed wolfCrypt sources with the `cc` crate, with `WOLFSSL_USER_SETTINGS` and the settings header of the C tree (`reimplementations/c-language/config/wa_wolfssl_user_settings_for_flightbox.h`), or another header given by `WA_WOLFSSL_USER_SETTINGS_DIR` for device builds;
- compiles a small C file of `#error` checks for every required option, the same list as the C adapter, so that a missing option stops the build by name;
- generates bindings for the functions and types the adapter uses only.

The two wolfCrypt behaviours evened out in the C adapter (C-D3: empty ChaCha20-Poly1305 streams, raw RSA inputs not below the modulus) are evened out the same way. `NO_CURVE25519_BLINDING` is required for the same reason as in C-D6.

This departs from the audit report, which expected wolfSSL's own Rust wrapper crate to make this backend nearly free. That crate targets the high-level RustCrypto traits, while this backend needs raw RSA, ML-KEM encapsulation with given randomness and streaming ChaCha20-Poly1305. Direct FFI is certain to work, shares its configuration with the C tree, and makes the Rust and C wolfCrypt builds run the very same C code. The wrapper crate can replace the bindings later if it exposes these functions.

Alternative considered: hand-written `extern "C"` declarations. Rejected: wolfCrypt's structures (`Aes`, `RsaKey`, `MlKemKey`) change size with the configuration, so their layout must come from the headers actually compiled.

### D5. Randomness, clock and parity with the C library

`PlatformHooks` is a trait with `fill_random(&mut self, &mut [u8]) -> Result<(), RandomFailure>` and `unix_time_in_ten_thousandths_of_second(&mut self) -> Option<u64>`. Portable code draws every random value and passes it down: symkeys, IVs and nonces, Shamir coefficients, UUID random bits, X25519 ephemeral scalars, ML-KEM coins, OAEP seeds. There is no dependency on `rand_core` nor `getrandom` in the library; the host tools implement the hook with `getrandom`.

Draws follow spec §6.8, with the sizes and the order of the C library inside each step (for instance key before IV, one 64-byte seed per OAEP chunk in chunk order). The Rust test driver reimplements the C driver's deterministic generator and incrementing clock (`--seed`, `--time`). Since every other step is deterministic and both writers are byte-exact, a Rust build and a C build then give the same cryptainer, which the parity test checks. This is the strongest available check that the two implementations read the specification the same way; where the C library made an unspecified choice that the comparison reveals, the Rust port follows it and a comment records it.

### D6. Value tree and codecs

The data model is an enum, `Value { Null, Bool, Integer(i64), Text, Bytes, Uuid([u8; 16]), Array(Vec<Value>), Map(Vec<(String, Value)>) }`, maps keeping insertion order, as in C-D7. Bytes values that hold secrets use the wiping buffer of D9. Step 1 clones the cryptoconf subtree, which gives the alias-free deep copy of spec §6.6 by construction.

The WA-CBOR sub-profile decoder is written in the crate, with the accepted, unsupported and invalid classes of C-D8 and the same typed errors, since it must match the C decoder's verdicts and enforce the WA-CBOR rules (duplicate keys, keyword maps, tag whitelist) that general CBOR crates do not. It recurses with an explicit depth counter checked against `EncryptorLimits`. Both writers stream to an `OutputSink` and sort keys at write time, each in its own order (C-D15).

Alternatives considered: `minicbor` or `ciborium` for decoding, `serde_json` for writing. Rejected: byte-exact output and WA-CBOR's extra rules would need as much code around them as the codecs themselves (about 400 lines of decoding in C), `serde_json` needs `std` or brings `alloc` formatting machinery, and the safety argument for hand-written parsing in C does not apply to safe Rust.

### D7. Public API and lifecycle

```rust
let limits = EncryptorLimits::default();                 // or ::new(...)?, refusing a CBOR depth above 64
let profile = DeviceProfile::load_from_cbor(profile_bytes, &limits)?;   // immutable, reusable

let encryptor = CryptainerEncryptor::<RustCryptoBackend, _, _>::create(
    &profile, metadata.as_ref(), options, hooks, payload_sink)?;        // step 1
encryptor.encrypt_payload_chunk(chunk)?;                                // step 2, any number of times
let finished = encryptor.finalize()?;                                   // end of step 2 + step 3, consumes self
finished.write_cryptainer(&mut cryptainer_sink)?;

DocumentFormat::Cbor.cryptainer_suffix();                               // ".crypt.cbor"
```

- `options` holds the document format (`BuildDefault`, `ExtendedJson`, `Cbor`), the ciphertext location and the processing slice size (default 4096, a multiple of 16).
- `finalize()` takes the encryptor by value and returns a `FinishedCryptainer`, so a chunk after finalization or a write before it does not compile; the wrong-state status of the C API has no equivalent. An error from `encrypt_payload_chunk()` puts the encryptor in a failed state, in which every call returns the failed-encryptor error.
- `DocumentFormat` always has both variants; requesting one whose feature is disabled fails at creation with the unsupported-feature error, as in C, which also keeps the tools' protocol identical.
- A one-shot convenience function wraps the sequence.
- `Drop` wipes every secret, on every path (D9).
- Profile loading needs no backend: the key constraints (RSA bounds, canonical and non-low-order X25519, ML-KEM modulus check) are portable code.

The limits are runtime values rather than compile-time constants: they cost a few bytes in the profile object, and avoid a second configuration mechanism beside cargo features.

### D8. Errors, panics and allocation failures

`Error` holds an `ErrorKind` (the categories of the spec, named after the C status codes so that the tools print the same status names) and, for profile errors, the location path as a `String`. It implements `Display`, and `core::error::Error`.

The library is written not to panic: no `unwrap()`/`expect()`/indexing on data derived from input, enforced by clippy lints (`unwrap_used`, `expect_used`, `indexing_slicing`, `arithmetic_side_effects`) denied in the core crate, with local, commented exceptions where a bound is established just above. Fuzzing (D10) checks the claim on the parsing code.

Memory: the library allocates through `alloc` and the firmware's global allocator. The C library's per-instance allocator hook has no stable Rust equivalent (the allocator API is unstable), and RustCrypto's big integers and ML-KEM code allocate on their own. Consequently:
- buffers whose size depends on caller input (decoded trees, the inline ciphertext) are grown with `try_reserve`, and report the out-of-memory error;
- other allocation failures reach Rust's allocation error handler, which a `no_std` firmware defines (usually a reset). The README says so, and gives the measured peak heap per profile, so that integrators size their heap.

Alternative considered: fallible allocation everywhere, as in the C library's out-of-memory sweep. Rejected: it cannot cover the dependencies, so the guarantee would be partial while costing a `Result` on every node construction.

### D9. Secret hygiene

Secrets are held in `zeroize::Zeroizing` arrays and in `SecretByteBuffer`, a buffer that grows by allocating a new block, copying, wiping the old block and releasing it (a `Vec` would leave an unwiped copy behind when it reallocates). Fixed-size secrets (symkeys, scalars, shared secrets, coefficients) are arrays, never `Vec`. Backend streaming states are wiped by the backend crates: the RustCrypto crates are built with their `zeroize` features, and the wolfCrypt adapter calls the library's free functions, then wipes its structures.

The test of the spec relies on determinism: a test binary installs a global allocator that scans every released block, the run uses the deterministic generator, and the test asserts that no released block contains the symkeys, sub-symkeys, shards or ephemeral scalars of that run, on success and on aborted creations.

### D10. Tests

- **Backend conformance** (`wa_flightbox_backend_conformance`): one generic function per primitive, instantiated for each backend by a one-line test, with the vectors of the C conformance test (SP 800-38A AES-256 CBC and CTR, RFC 8439, FIPS 180-4, RFC 4231, RFC 7748, a 4096-bit raw RSA value, an ML-KEM-768 known answer), including multi-call streaming and the two edge cases of D4.
- **Unit tests** in the core crate, run with the RustCrypto backend, and again with wolfCrypt where a backend is involved: codecs against bytes generated by wacryptolib, the sub-profile decoder against every vector of §10 of the WA-CBOR specification, the composites against SP 800-38B, the EAX and OAEP references, RFC 5869 and RFC 9180 A.2.1, Shamir with a test-only recombination and a pycryptodome comparison, key constraints, validation rules with their error locations, the pipeline's chunking equivalence, the failed state, wiping (D9) and peak allocation with a counting global allocator.
- **Test vectors**: `test_vectors/generate_rust_test_vectors.py` writes JSON files, committed, by calling the generator functions of `reimplementations/c-language/tests/unit/generate_*.py` where they exist, so both ports test against the same expected bytes. A pytest check regenerates them and fails on any difference.
- **Compile-time checks**: a `compile_fail` doctest for the chunk-after-finalization scenario; builds with each single document format feature, and with none (expected to fail with the explicit message).
- **Fuzzing**: `cargo-fuzz` targets for the sub-profile decoder and the profile loader, seeded like the C targets, 60 s each in CI on nightly. A target comparing the Rust decoder's verdicts with wacryptolib's is not needed: the interop suite's differential test covers it.
- **Interoperability**: the existing pytest suite, unchanged in its assertions, driven against Rust builds (D11).

### D11. Host tools and reuse of the interop suite

`wa_flightbox_host_tools` builds two binaries with the names, arguments, JSON outputs, exit codes and status names of the C tools: `wa_flightbox_encrypt_file_cli` and `wa_flightbox_test_driver`. The backend is a cargo feature of this crate only (`backend-rustcrypto`, default, or `backend-wolfcrypt`; a `compile_error!` refuses both or neither), since binaries have to pick one. `build-info` reports `"implementation": "rust"`, the backend (`RUSTCRYPTO` or `WOLFCRYPT`) and the enabled formats. Arguments are parsed by hand, as the C tools do, to avoid a dependency and keep the usage errors identical.

The interop suite stays in `reimplementations/c-language/tests/interop/`, and its support module is made implementation-aware:
- a build directory is any directory holding the two executables; `WA_FLIGHTBOX_C_BUILD_DIR` keeps its name and may list Rust tool directories beside CMake build directories;
- a build's identity becomes (implementation, backend), the implementation defaulting to `c` when `build-info` does not give it, so the C driver is not modified;
- the backend parity test compares every pair of builds given, which covers RustCrypto against wolfCrypt and Rust against C;
- tests about C-only build options are skipped for Rust builds, by name.

`reimplementations/rust/build_and_test_all_backends.sh` builds the tools once per backend into separate target directories, and the tox environment passes those directories, plus the C build directories when they exist, to the suite.

Alternative considered: moving the suite to a neutral `reimplementations/interop_tests/` directory and renaming the variable. Deferred (see Open Questions): it touches the tox environment, CI job and README of the C change for a cosmetic gain.

### D12. Build, CI and supply chain

- **Toolchain**: stable Rust pinned in `rust-toolchain.toml`, edition 2024, with the minimum supported version recorded in `Cargo.toml` as the highest one required by the locked dependencies. `cargo fmt --check` and `cargo clippy --workspace --all-targets -- -D warnings` are part of the checks.
- **Document formats**: features `extended-json` and `wa-cbor` of the core crate, both default, re-exported by the tools crate; `compile_error!` when neither is set. Writers and the base64 encoder are behind `#[cfg(feature = ...)]`.
- **Build matrix** of `build_and_test_all_backends.sh`:
  - RustCrypto backend, both formats: conformance, unit tests, tools;
  - wolfCrypt backend, both formats: the same (Linux, WSL or MSYS2; skipped with a message when `WA_WOLFSSL_SOURCE_DIR` is unset and no fetch is allowed);
  - CBOR-only and JSON-only: unit tests on the RustCrypto backend, plus a check with `nm` that a debug build of the driver has no symbol of the disabled writer's module nor, in CBOR-only builds, of the base64 encoder;
  - `wa_flightbox_footprint_probe` for `thumbv8m.main-none-eabihf` and `thumbv7em-none-eabihf`, CBOR-only and JSON-only, in release mode with `opt-level = "s"`, LTO and `panic = "abort"`; `arm-none-eabi-size` on the static library gives the code sizes recorded in the README, next to the C library's;
  - fuzz smoke runs, when a nightly toolchain is present;
  - `cargo deny check advisories licenses bans`.
- **wolfSSL source**: the script clones the pinned wolfSSL tag into the build directory when `WA_WOLFSSL_SOURCE_DIR` is unset, as CMake's FetchContent does for the C tree. `build.rs` itself never accesses the network.
- **Entry points**: a `rust_flightbox` tox environment runs the script, then the interop pytest with the Rust tool directories; a `rust-flightbox` job in `.github/workflows/ci.yml` (ubuntu-latest, Rust stable and nightly, the two embedded targets, Clang, `gcc-arm-none-eabi` for `arm-none-eabi-size`) runs `tox -e rust_flightbox`. On Windows, `cargo test` covers the RustCrypto backend natively.
- **Supply chain**: `Cargo.lock` is committed; `deny.toml` allows MIT, Apache-2.0, BSD and ISC-style licences (all compatible with GPL-2.0-or-later) and fails on RustSec advisories unless waived with a reason.

### D13. Documentation

- `reimplementations/rust/README.md`: layout, an API walkthrough with a minimal example compiled as a doctest, the hook contracts with the RNG warnings of the C README, how to write a backend (with the hardware AES case), features and limits, the allocator and panic notes of D8, the wolfCrypt build variables and licence, measured code sizes and heap peaks, how to run the tests.
- Encryptor specification, section 10: a "10.3 Rust profile" subsection after the C profile; the notes for new reimplementations become 10.4, their table gaining a "Rust choice" column and their mention of Rust as a future implementation being updated. References to §10.3 elsewhere in the repository are updated.
- `CHANGELOG` entry.

## Risks / Trade-offs

- [The pure-Rust crypto has no FIPS validation, and `ml-kem`'s independent audit status is unclear] → Stated in the README. The wolfCrypt backend is the answer where a validated library is required; ML-KEM output is compared byte for byte with pycryptodome under the same coins on every run.
- [`crypto-bigint` or `ml-kem` APIs differ from what D3 assumes, or `ml-kem` no longer exposes deterministic encapsulation] → Task 4 confirms them first; `libcrux-ml-kem`, whose encapsulation takes its randomness as an argument, is the fallback for ML-KEM, isolated in one function of the default backend.
- [Byte parity with the C library fails on an unspecified detail] → Each difference is either a bug in one port, which the test was meant to find, or an unspecified choice, aligned on the C library and recorded. The parity test is written early (task 8) so that this surfaces before the documentation.
- [Allocation failures abort instead of returning an error (D8)] → Documented, with measured heap peaks; caller-sized buffers do return the error.
- [Dependencies' own `unsafe` code and supply chain] → Locked versions, `cargo deny` in CI, a small dependency set limited to RustCrypto and `zeroize`.
- [`bindgen` needs libclang, and wolfSSL builds add a C toolchain] → Only for the optional backend; the default configuration needs neither.
- [The RustCrypto backend does not use hardware accelerators] → The trait is public and bulk-oriented; a chip-specific backend is a later change. Software AES on Cortex-M33 is measured only by code size here, not by throughput.
- [RustCrypto software AES on a microcontroller: table-based implementations leak through cache timing on larger cores] → The `aes` crate's portable implementation is constant-time (fixsliced), which the README notes; this is one reason not to pick a table-based one for speed.
- [The interop suite lives under the C tree and is shared] → A failure caused by the support changes shows in the C environment too, which the C tox environment detects; moving the suite is an open question.
- [Panics remain possible inside dependencies] → `panic = "abort"` on devices; the backend contract is restricted to validated inputs (key sizes and canonical forms are checked at profile load, before any backend call).

## Migration Plan

Purely additive: a new directory, a tox environment, a CI job and documentation, plus a backward-compatible extension of the interop support code. Nothing changes for wacryptolib nor for the C library, so rollback is a revert of the commits. Prerequisite: `add-c-flightbox-encryptor` is archived first.

## Open Questions

- Whether to move the interop suite to a neutral directory and rename `WA_FLIGHTBOX_C_BUILD_DIR`, once both implementations use it.
- The exact crate versions to lock, and the resulting minimum supported Rust version.
- Whether wolfSSL's own Rust wrapper crate can later replace the generated bindings (D4).
- Whether to publish the crates on crates.io, which would need final crate names and a versioning policy. Nothing in this change depends on it.
