## Why

The C flightbox encryptor (`reimplementations/c-language/`, change `add-c-flightbox-encryptor`) parses device profiles and metadata, builds trees and nests key ciphertexts in a memory-unsafe language, on devices that will be provisioned and fed from outside. A Rust implementation gives memory safety on exactly that code, and builds for the targeted STM32U3 and STM32U5 chips (Cortex-M33) with a plain `cargo build`, without a C toolchain. The audit report `audits/rust_crypto_backend_options_2026-11-17.md` settles the library question: the pure-Rust RustCrypto crates as primary crypto backend, wolfCrypt as an alternative one. The encryptor specification, the device profile specification, the test vectors and the pytest interoperability suite written for the C port can all be reused.

## What Changes

- Add a Rust workspace in `reimplementations/rust/` (currently an empty directory) that implements the whole flightbox **encryptor** workflow, steps 1 to 3 of the encryptor specification, from a device profile to a `FINISHED` cryptainer, with the same feature set as the C library:
  - payload and symmetric key ciphers `AES_CBC`, `AES_EAX` and `CHACHA20_POLY1305`; asymmetric key ciphers `RSA_OAEP`, `ECIES_X25519` and `ML_KEM_768`; Shamir shared secrets; nested key cipher layers;
  - payload streamed by chunks of any size, with an inline or offloaded ciphertext and bounded memory;
  - cryptainers in Extended JSON or WA-CBOR, one format per cryptainer, byte-identical to wacryptolib's default writers for the same tree;
  - no signatures, and a mandatory root `keychain_uid`, as in the C library.
- The input is the existing **device profile** (`flightbox-device-profile` capability), unchanged: the Rust loader applies the same WA-CBOR sub-profile, the same validation and the same key constraints as the C one.
- The core crate is `no_std` (with `alloc`), contains no `unsafe` code and no cryptographic dependency. It holds the algorithm, the document codecs and the composite constructions written once for every backend (HPKE Base-mode seal, AES-EAX and CMAC, the RSA-OAEP SHA-512 encoding and its 60-byte chunking, HKDF, Shamir over GF(2^128), UUID0), on top of a small **crypto backend trait**.
- Two backends implement that trait, each in its own crate, chosen by the integrator through the type system:
  - **RustCrypto** (default, pure Rust, `no_std`, no `unsafe`);
  - **wolfCrypt**, through FFI bindings to wolfSSL built with the same settings header as the C tree.

  Both give byte-identical output for identical random inputs. The trait is public, so that an integrator can later provide a hardware-accelerated backend (AES, SHA or PKA peripherals of an STM32, for instance) without changing the library.
- All randomness and the clock come from caller-provided platform hooks, drawn in the order of section 6.8 of the encryptor specification. With the test driver's deterministic generator, the Rust builds therefore produce the same cryptainer bytes as the C builds, which the tests check.
- Document formats are selected at compile time by cargo features; limits (nesting depths, RSA modulus size, processing slice size) are runtime options with the C library's defaults.
- Add host tools (a file encryption CLI and a test driver) that follow the command-line protocol of the C tools, so that the existing pytest interoperability suite runs against the Rust builds: wacryptolib decrypts Rust-made cryptainers in both formats, on both backends. The interop support code is made implementation-aware (C or Rust) for that purpose.
- Add Rust unit tests (backend conformance vectors, codecs, primitives, state machine, secret wiping, peak allocation), `cargo-fuzz` targets for the WA-CBOR decoder and the profile loader, `no_std` cross-builds for Cortex-M33 and Cortex-M4 with recorded code sizes, and dependency checks (RustSec advisories, licences).
- Add a `rust_flightbox` tox environment and a `rust-flightbox` CI job, a `README.md` integration guide, a "Rust profile" subsection in section 10 of the encryptor specification, and a CHANGELOG entry.

## Capabilities

### New Capabilities
- `rust-flightbox-encryptor`: the Rust flightbox encryptor: supported algorithms and their wire compatibility, the crypto backend trait and its two backends, memory-safety and `no_std` guarantees, document format features, streaming payload encryption, platform hooks and randomness, secret hygiene, error reporting, host tools, and interoperability with the wacryptolib decryptor and parity with the C encryptor.

### Modified Capabilities

(none: `flightbox-device-profile` is implemented a second time without any requirement change; `c-flightbox-encryptor`, `cbor-document-format`, `key-ciphertext-format`, `ecies-key-encapsulation`, `post-quantum-key-encapsulation` and `crypto-backends` are untouched. The CPython library's behaviour, API and wire formats do not change.)

## Impact

- Builds on `add-c-flightbox-encryptor`, which is to be completed and archived first: it brings the `flightbox-device-profile` and `c-flightbox-encryptor` main specs, the device profile specification and export script, the test vector generators and the interop suite that this change reuses.
- New tree `reimplementations/rust/`: a cargo workspace with the core crate, the two backend crates, a backend conformance test crate, the host tools, fuzz targets and a footprint probe; a committed `Cargo.lock` and a pinned toolchain.
- New dependencies, all for the Rust tree only: RustCrypto crates (`aes`, `cbc`, `ctr`, `chacha20`, `poly1305`, `sha2`, `hmac`, `x25519-dalek`, `ml-kem`, `crypto-bigint`) and `zeroize`, under MIT or Apache-2.0; `bindgen` and `cc` as build dependencies of the wolfCrypt backend. No runtime dependency is added to wacryptolib.
- The wolfCrypt backend compiles wolfSSL 5.8.x from a source directory given at build time, with `reimplementations/c-language/config/wa_wolfssl_user_settings_for_flightbox.h`. A firmware built with it falls under GPL-3.0-or-later or needs a wolfSSL commercial licence, as with the C library. The Rust code itself is GPL-2.0-or-later like the rest of the repository.
- `reimplementations/c-language/tests/interop/`: the support module and `conftest.py` learn to drive Rust builds beside C builds, and the backend parity test is extended to compare implementations. The C sources are not modified.
- `tox.ini` and `.github/workflows/ci.yml` gain a Rust environment and job, which need a Rust toolchain with the `thumbv8m.main-none-eabihf` and `thumbv7em-none-eabihf` targets, a nightly toolchain for fuzzing, Clang (for `bindgen`) and `arm-none-eabi-size`.
- `docs/flightbox_specifications/flightbox_encryptor_specification.md`: a new "Rust profile" subsection, the notes for new reimplementations being renumbered and their table extended with the Rust choices.
- Out of scope, left to later changes: a C API (static library and header) over the Rust library, hardware-accelerated backends for specific chips, an Mbed TLS backend, signatures, decryption, and MSP430 support, which stays with the C library (Rust's MSP430 target is limited to a 64 KB address space, see the audit report).
