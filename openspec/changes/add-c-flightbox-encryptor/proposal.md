## Why

Flightbox devices (ESP32-class microcontrollers, later others) must encrypt recordings into cryptainers that the existing wacryptolib decryptor accepts. The only device-side implementation today is the MicroPython port. It stops after step 1 of the encryptor specification, has no payload encryption, and runs its pure-Python RSA and X25519 in hundreds of milliseconds to seconds. The C prototype in the sibling `witness-angel-cryptolib-c` repository is still a skeleton built on outdated wire forms. The encryptor specification (`docs/flightbox_specifications/flightbox_encryptor_specification.md`) and the two embedded audits (`docs/audits/embedded_crypto_libraries_for_flightbox.md`, `docs/audits/flightbox_cryptoconf_storage_format.md`) now settle the algorithm, the libraries and the input format. A portable C encryptor can therefore be written in this repository, next to the reference implementation and its compatibility corpus.

## What Changes

- Add a portable C99 library in `reimplementations/c-language/` that implements the whole flightbox **encryptor** workflow, from a cryptoconf to a `FINISHED` cryptainer:
  - step 1: cryptainer base, symkey generation and key wrapping through recursive key cipher layers (asymmetric, symmetric sub-keys, Shamir shared secrets);
  - step 2: payload encryption through all payload cipher layers, streamed chunk by chunk, with the ciphertext either kept inline or offloaded to a separate payload sink;
  - step 3: payload MACs and state `FINISHED`; the cryptainer is written as Extended JSON.
- Support all three payload/symmetric ciphers (`AES_CBC`, `AES_EAX`, `CHACHA20_POLY1305`) and all three asymmetric key ciphers (`RSA_OAEP`, `ECIES_X25519`, `ML_KEM_768`).
- Select the cryptographic backend **at compilation time**: **Mbed TLS 3.6 LTS** (plus vendored **mlkem-native** for ML-KEM-768, which Mbed TLS lacks) or **wolfCrypt**. Some code is written once in portable C, on top of a small set of backend primitives:
  - what neither library provides with our parameters: HPKE Base-mode seal with ChaCha20-Poly1305, AES-EAX on Mbed TLS, the 60-byte RSA-OAEP chunking, Shamir over GF(2^128), UUID0 and the Extended JSON writer;
  - deliberately, the OAEP-SHA-512 encoding and AES-EAX on wolfCrypt, so that both backends share one source of randomness and behave identically, which makes tests deterministic.
- Hardware acceleration is not required. The library only uses the standard backend APIs, so a backend's own acceleration (e.g. ESP-IDF's Mbed TLS port) is used when it is present.
- Make the code embedded-portable: no OS calls in the library, all allocations through an injectable allocator, randomness and clock through injected platform hooks, bounded recursion depth, secrets wiped after use, no global mutable state. File and function names describe exactly what they do.
- Introduce the **flightbox device profile**: a CBOR (RFC 8949) document holding the cryptoconf and the raw public keys of its trustees, described by a CDDL schema. The device reads this instead of parsing Extended JSON. Its cryptoconf must carry a root `keychain_uid`, since keys are provisioned in advance. Add a CPython export script that builds a device profile from a cryptoconf and a keystore pool.
- **Signing is out of scope**: cryptoconfs with a non-empty `payload_plaintext_signatures` or `payload_ciphertext_signatures` list are rejected with a clear error, because an unsigned signature conf would make every decryption report a signature error. No digest computation is needed for now.
- Add C unit tests, fuzz targets, and pytest interoperability tests that drive a host build of the C encryptor: they check primitives against the `compatibility/` corpus and the RFC vectors, then decrypt C-made cryptainers with wacryptolib. Both backends are built and tested in a new tox environment and CI job.
- Document the C profile in the encryptor specification and in a `reimplementations/c-language/README.md` integration guide.

## Capabilities

### New Capabilities
- `flightbox-device-profile`: the CBOR device profile format (cryptoconf + trustee raw public keys), its CDDL schema, its decoding and validation rules, and its export from CPython.
- `c-flightbox-encryptor`: the portable C encryptor library: supported algorithms and their wire compatibility, compile-time backend selection, streaming payload encryption, cryptainer output, platform hooks, portability and secret-hygiene guarantees, and interoperability with the wacryptolib decryptor.

### Modified Capabilities

(none: the CPython library's behaviour and wire formats are unchanged; `crypto-backends`, `ecies-key-encapsulation` and `post-quantum-key-encapsulation` are only reimplemented, not modified)

## Impact

- New tree `reimplementations/c-language/`: public headers, portable core, two backend adapters, a host CLI and test driver, C unit tests, pytest interop tests, CMake build, backend configuration headers, and a vendored and pinned copy of mlkem-native (Apache-2.0 / ISC / MIT).
- Host builds fetch Mbed TLS 3.6.x and wolfSSL 5.8.x at pinned versions, or use installed ones. Device builds integrate the sources into their own toolchain (e.g. ESP-IDF's bundled Mbed TLS).
- Licensing:
  - the new C code inherits the repository's GPL-2.0-or-later unless decided otherwise (see design.md, Open Questions);
  - Mbed TLS (Apache-2.0 OR GPL-2.0-or-later) and mlkem-native are compatible with it;
  - a firmware built with the wolfCrypt backend falls under GPL-3.0-or-later, or needs a wolfSSL commercial licence.
- New script `scripts/flightbox/export_device_profile.py` and a new dev dependency, `cbor2` (also added to `pip_requirements_export.txt`). No runtime dependency is added to wacryptolib, and its API does not change.
- New tox environment `c_flightbox` and a new `c-flightbox` job in `.github/workflows/ci.yml`. They need CMake, GCC/Clang and `arm-none-eabi-gcc` on the CI runner.
- New document `docs/flightbox_specifications/flightbox_device_profile_specification.md` (CDDL). Section 10 of the encryptor specification gains a C profile.
- The sibling `witness-angel-cryptolib-c` skeleton is not reused. Integrity protection of device profiles (COSE_Sign1), signatures, digests, and ESP-IDF/Pico example firmwares are left to later changes.
