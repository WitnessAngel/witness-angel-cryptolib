## Why

Flightbox devices (ESP32-class microcontrollers, later others) must encrypt recordings into cryptainers that the existing wacryptolib decryptor accepts. The only device-side implementation today is the MicroPython port. It stops after step 1 of the encryptor specification, has no payload encryption, and runs its pure-Python RSA and X25519 in hundreds of milliseconds to seconds. The C prototype in the sibling `witness-angel-cryptolib-c` repository is still a skeleton built on outdated wire forms. The following documents now settle the algorithm, the libraries and the document formats:
- the encryptor specification (`docs/flightbox_specifications/flightbox_encryptor_specification.md`);
- the two embedded audits (`docs/audits/embedded_crypto_libraries_for_flightbox.md`, `docs/audits/flightbox_cryptoconf_storage_format.md`);
- the WA-CBOR document format (`docs/specifications/wa_cbor_document_format.md`, change `add-cbor-document-format`);
- the key ciphertext format field (change `add-cbor-key-ciphertexts`).

A portable C encryptor can therefore be written in this repository, next to the reference implementation and its compatibility corpus.

## What Changes

- Add a portable C99 library in `reimplementations/c-language/` that implements the whole flightbox **encryptor** workflow, from a device profile to a `FINISHED` cryptainer:
  - step 1: cryptainer base, symkey generation and key wrapping through recursive key cipher layers (asymmetric, symmetric sub-keys, Shamir shared secrets);
  - step 2: payload encryption through all payload cipher layers, streamed chunk by chunk, with the ciphertext either kept inline or offloaded to a separate payload sink;
  - step 3: payload MACs and state `FINISHED`. The cryptainer is then written to a caller-provided sink.
- **Document formats chosen at compile time**: each build enables Extended JSON, WA-CBOR, or both, through C macros. A cryptainer uses one format for both its key ciphertexts (`key_ciphertext_format`) and its file. Big chips can use Extended JSON. Small chips can ship a WA-CBOR-only build, without any JSON writer or base64 encoder, whose key ciphertexts are also smaller (2 RSA-OAEP chunks instead of 6 for a typical key struct). Both writers produce exactly the bytes of wacryptolib's default writers for the same tree.
- Support all three payload/symmetric ciphers (`AES_CBC`, `AES_EAX`, `CHACHA20_POLY1305`) and all three asymmetric key ciphers (`RSA_OAEP`, `ECIES_X25519`, `ML_KEM_768`).
- Select the cryptographic backend **at compile time**: **Mbed TLS 3.6 LTS** (plus vendored **mlkem-native** for ML-KEM-768, which Mbed TLS lacks) or **wolfCrypt**. Some code is written once in portable C, on top of a small set of backend primitives:
  - what neither library provides with our parameters: HPKE Base-mode seal with ChaCha20-Poly1305, AES-EAX on Mbed TLS, the 60-byte RSA-OAEP chunking, Shamir over GF(2^128), UUID0, and the document writers;
  - deliberately, the OAEP-SHA-512 encoding and AES-EAX on wolfCrypt, so that both backends share one source of randomness and behave identically, which makes tests deterministic.
- Hardware acceleration is not required. The library only uses the standard backend APIs, so a backend's own acceleration (e.g. ESP-IDF's Mbed TLS port) is used when it is present.
- Make the code embedded-portable: no OS calls in the library, all allocations through an injectable allocator, randomness and clock through injected platform hooks, bounded recursion depth, secrets wiped after use, no global mutable state. File and function names describe exactly what they do.
- Introduce the **flightbox device profile**: a WA-CBOR document holding the cryptoconf and the raw public keys of its trustees, restricted to a strict sub-profile (definite lengths, no floats, no tag other than 37) and described by a CDDL schema. The device reads it with a small decoder that accepts nothing that WA-CBOR rejects, instead of parsing Extended JSON. Its cryptoconf must carry a root `keychain_uid`, since keys are provisioned in advance. A CPython export script builds a device profile from an Extended JSON or WA-CBOR cryptoconf and a keystore pool, with wacryptolib's deterministic `dump_to_cbor_bytes()`.
- **Signing is out of scope**: cryptoconfs with a non-empty `payload_plaintext_signatures` or `payload_ciphertext_signatures` list are rejected with a clear error, because an unsigned signature conf would make every decryption report a signature error. No digest computation is needed for now.
- Add C unit tests, fuzz targets, and pytest interoperability tests that drive a host build of the C encryptor:
  - they check primitives against the `compatibility/` corpus and the RFC vectors, and the CBOR decoder and both writers against the WA-CBOR test vectors;
  - wacryptolib then decrypts C-made cryptainers in both formats.

  Both backends are built and tested in a new tox environment and CI job.
- Document the C profile in the encryptor specification and in a `reimplementations/c-language/README.md` integration guide.

## Capabilities

### New Capabilities
- `flightbox-device-profile`: the device profile format (a WA-CBOR sub-profile: cryptoconf + trustee raw public keys), its CDDL schema, its decoding and validation rules, and its export from CPython.
- `c-flightbox-encryptor`: the portable C encryptor library: supported algorithms and their wire compatibility, compile-time backend and document format selection, streaming payload encryption, cryptainer output in Extended JSON or WA-CBOR, platform hooks, portability and secret-hygiene guarantees, and interoperability with the wacryptolib decryptor.

### Modified Capabilities

(none: the CPython library's behaviour and wire formats are unchanged. `crypto-backends`, `ecies-key-encapsulation`, `post-quantum-key-encapsulation`, `cbor-document-format` and `key-ciphertext-format` are only reimplemented, not modified.)

## Impact

- Depends on `add-cbor-key-ciphertexts`, which must be implemented and archived first, so that wacryptolib decrypts the WA-CBOR key ciphertexts of CBOR builds.
- New tree `reimplementations/c-language/`: public headers, portable core, document codecs, two backend adapters, a host CLI and test driver, C unit tests, pytest interop tests, CMake build, backend configuration headers, and a vendored and pinned copy of mlkem-native (Apache-2.0 / ISC / MIT).
- Host builds fetch Mbed TLS 3.6.x and wolfSSL 5.8.x at pinned versions, or use installed ones. Device builds integrate the sources into their own toolchain (e.g. ESP-IDF's bundled Mbed TLS).
- Licensing:
  - the new C code inherits the repository's GPL-2.0-or-later unless decided otherwise (see design.md, Open Questions);
  - Mbed TLS (Apache-2.0 OR GPL-2.0-or-later) and mlkem-native are compatible with it;
  - a firmware built with the wolfCrypt backend falls under GPL-3.0-or-later, or needs a wolfSSL commercial licence.
- New script `scripts/flightbox/export_device_profile.py`. It needs no new dependency: `cbor2`, already a dev dependency since `add-cbor-document-format`, is only used by the test helpers that forge non-WA-CBOR inputs. No runtime dependency is added to wacryptolib, and its API does not change.
- New tox environment `c_flightbox` and a new `c-flightbox` job in `.github/workflows/ci.yml`. They need CMake, GCC/Clang and `arm-none-eabi-gcc` on the CI runner.
- New document `docs/flightbox_specifications/flightbox_device_profile_specification.md` (sub-profile of WA-CBOR, CDDL). Section 10 of the encryptor specification gains a C profile. Section 9 of the WA-CBOR specification is updated if the sub-profile's definition changes.
- The sibling `witness-angel-cryptolib-c` skeleton is not reused. Integrity protection of device profiles (COSE_Sign1), signatures, digests, and ESP-IDF/Pico example firmwares are left to later changes.
