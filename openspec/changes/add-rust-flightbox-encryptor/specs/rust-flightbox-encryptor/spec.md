## Purpose

Provides a memory-safe Rust implementation of the flightbox encryptor workflow for embedded devices. From a device profile, it turns a payload into a finished cryptainer, in Extended JSON or WA-CBOR, that the reference wacryptolib decryptor accepts unchanged, with a pluggable crypto backend.

## ADDED Requirements

### Requirement: End-to-end cryptainer creation
The Rust encryptor SHALL implement steps 1, 2 and 3 of the encryptor specification (`docs/flightbox_specifications/flightbox_encryptor_specification.md`), referred to below as "the encryptor specification". From a validated device profile and optional cryptainer metadata, it SHALL produce a cryptainer, in the document format chosen for it, with:
- state `FINISHED` and format `cryptainer_1.0`;
- a fresh `cryptainer_uid`;
- the cryptoconf's root `keychain_uid`;
- a `key_ciphertext` in every payload layer and in every symmetric key layer;
- `payload_macs` in every payload layer;
- a non-null `payload_ciphertext_struct`.

Given the trustees' private keys, the produced cryptainer SHALL pass wacryptolib's strict cryptainer validation, once loaded from the filesystem when its ciphertext is offloaded. wacryptolib's decryption SHALL recover the original payload with no error entry in the operation report.

#### Scenario: Single-layer cryptainer decrypted by wacryptolib
- **WHEN** the Rust encryptor encrypts a 4099-byte payload with a profile made of one `CHACHA20_POLY1305` payload layer wrapped by one `ECIES_X25519` layer for an authenticator trustee, once in each document format
- **THEN** wacryptolib decrypts both cryptainers with that authenticator's private key, returns the exact payload, and reports no error

#### Scenario: Nested key layers decrypted by wacryptolib
- **WHEN** the profile has two payload layers, and the key of one of them goes through `RSA_OAEP`, then a shared secret of threshold 2 out of 3 whose shards use `ECIES_X25519`, `ML_KEM_768` and an `AES_EAX` symmetric layer wrapped by `RSA_OAEP`
- **THEN** wacryptolib decrypts the cryptainer with all keys available
- **AND** for each of the three shards in turn, wacryptolib still decrypts it with that shard's private key withheld, with error entries only about the withheld key

#### Scenario: Fresh secrets for every cryptainer
- **WHEN** the same payload is encrypted twice with the same profile and operating-system randomness
- **THEN** the two cryptainers have different `cryptainer_uid`, different `key_ciphertext` values and different payload ciphertexts

### Requirement: Supported algorithms
The Rust encryptor SHALL support:
- `AES_CBC`, `AES_EAX` and `CHACHA20_POLY1305`, both as payload ciphers and as symmetric key cipher layers;
- `RSA_OAEP`, `ECIES_X25519` and `ML_KEM_768` as asymmetric key cipher layers;
- `[SHARED_SECRET]` layers.

Each algorithm SHALL produce the exact cipherdict shape, key sizes and parameters of sections 3.3 to 3.5 and 11.2 of the encryptor specification. Every build SHALL support all of these algorithms, whichever backend it uses. Sizes SHALL be:
- symmetric keys: 32 bytes;
- AES-CBC IVs: 16 bytes;
- AES-EAX nonces: 16 bytes;
- ChaCha20-Poly1305 nonces: 12 bytes;
- tags: 16 bytes.

#### Scenario: Symmetric vectors from the compatibility corpus
- **WHEN** the Rust symmetric ciphers encrypt the plaintext referenced by each symmetric cipherdict fixture of `compatibility/cipherdicts/`, with the key and IV/nonce of that fixture
- **THEN** the resulting ciphertext and tag are byte-identical to the fixture

#### Scenario: HPKE X25519 test vector
- **WHEN** the HPKE base-mode seal behind `ECIES_X25519` is run with the receiver public key, ephemeral private key, info, AAD (`Count-0`) and plaintext of RFC 9180 Appendix A.2.1 (sequence number 0)
- **THEN** the encapsulated key equals the RFC's `enc` and the sealed output equals the RFC's sequence-0 ciphertext, while cryptainer key wrapping itself always uses empty info and AAD

#### Scenario: RSA-OAEP chunking
- **WHEN** a 121-byte plaintext is wrapped with a 2048-bit `RSA_OAEP` key
- **THEN** the cipherdict is `{"ciphertext_chunks": [c1, c2, c3]}` with three 256-byte chunks covering 60, 60 and 1 plaintext bytes, and wacryptolib decrypts it with SHA-512 OAEP and MGF1-SHA-512

#### Scenario: ML-KEM-768 interoperability
- **WHEN** a key struct is wrapped with an `ML_KEM_768` public key exported from a wacryptolib keystore
- **THEN** `kem_ciphertext` is 1088 bytes, `ciphertext` is the plaintext length plus 16 bytes, and wacryptolib decrypts it with the matching private key
- **AND** with the same 32 bytes of encapsulation randomness, the KEM ciphertext and shared secret are byte-identical to the reference library's ML-KEM-768 encapsulation

### Requirement: Device profile input
The Rust encryptor SHALL take its cryptoconf and trustee public keys from a device profile, as defined by the `flightbox-device-profile` capability and by `docs/flightbox_specifications/flightbox_device_profile_specification.md`. Its loader SHALL apply every rule of that capability: the WA-CBOR sub-profile, the document structure, the trustee public key entries, the public key sanity constraints, and the cryptoconf validation with its mandatory root `keychain_uid`.

For any input bytes, the Rust loader and the C loader of the `c-flightbox-encryptor` capability, used with the same limits, SHALL agree on acceptance, and on the error category of a rejection. No input, however malformed, SHALL make the loader panic, abort, or read or write outside its buffers. A loaded profile SHALL be immutable and reusable for any number of cryptainers.

#### Scenario: Corpus profiles accepted
- **WHEN** profiles are exported by `scripts/flightbox/export_device_profile.py` from every corpus cryptoconf that is signature-free and has a root keychain uid
- **THEN** the Rust loader accepts each of them with the default limits

#### Scenario: Same verdicts as the C loader
- **WHEN** the valid and invalid test vectors of section 10 of the WA-CBOR specification, the invalid corpus cryptoconfs and the mutated profiles of the interoperability suite are given to both loaders
- **THEN** each input is accepted by both or rejected by both, with the same error category and the same error location

#### Scenario: Arbitrary bytes never crash the loader
- **WHEN** the profile loader and the metadata decoder are fuzzed with arbitrary and mutated inputs
- **THEN** every input ends in a loaded profile or an error value, never in a panic or an abort

### Requirement: Pluggable crypto backends
The encryptor SHALL obtain its cryptographic primitives from a crypto backend chosen by the integrator at build time, through a documented public interface that integrators can implement themselves. That interface SHALL be limited to primitives fully determined by their inputs: AES-256 in CBC and CTR modes over bulk data, ChaCha20-Poly1305 streaming encryption, SHA-256, SHA-512, HMAC-SHA256, X25519 scalar multiplication, the raw RSA public operation, and ML-KEM-768 encapsulation from given randomness. A backend SHALL NOT draw randomness of its own that affects the output.

Two backends SHALL be provided:
- a default backend written entirely in Rust, on the RustCrypto libraries, usable without any C toolchain;
- a wolfCrypt backend.

Both SHALL pass the same test suite, accept exactly the same device profiles, and produce byte-identical cryptainers for identical random inputs. A wolfCrypt configuration lacking a required feature SHALL make the build fail with a message naming that feature. Hardware acceleration SHALL NOT be required.

#### Scenario: Both backends pass the same tests
- **WHEN** the workspace is tested once with the RustCrypto backend and once with the wolfCrypt backend
- **THEN** both pass the whole backend conformance suite, the whole unit test suite and the whole interoperability suite

#### Scenario: Backend parity
- **WHEN** the same profile and payload are encrypted with the same deterministic random generator and fixed clock on each backend, in each document format
- **THEN** the cryptainers and payload ciphertexts are byte-identical

#### Scenario: Integrator-provided backend
- **WHEN** a backend defined outside the library delegates every primitive to the RustCrypto backend while counting the AES calls, and is used to create a cryptainer
- **THEN** the cryptainer is created without modifying the library, wacryptolib decrypts it, and the bulk AES primitives were called once per processing slice, not once per 16-byte block

#### Scenario: Missing wolfCrypt feature
- **WHEN** the wolfCrypt backend is built against a wolfSSL configuration without AES counter mode
- **THEN** the build stops with an error naming the missing wolfSSL option

### Requirement: Streaming payload encryption
The Rust encryptor SHALL accept the payload as a sequence of chunks of arbitrary sizes, including empty chunks and a zero-length payload, and SHALL pass it through all payload cipher layers in cryptoconf order. When the ciphertext is offloaded, its memory use SHALL depend neither on the payload size nor on the size of the chunks submitted by the caller. The resulting ciphertext and MAC tags SHALL be byte-identical to a one-shot encryption with the same symkeys, regardless of chunking. `AES_CBC` layers SHALL apply PKCS#7 padding once, at finalization.

#### Scenario: Chunking does not change the output
- **WHEN** the same payload is encrypted with deterministic test randomness, once in a single chunk and once in chunks of 1, 15, 16, 17 and 4099 bytes
- **THEN** both cryptainers have identical payload ciphertexts and `payload_macs`

#### Scenario: Empty payload
- **WHEN** a zero-length payload is encrypted through `AES_CBC` then `AES_EAX`
- **THEN** the cryptainer is `FINISHED`, and wacryptolib decrypts it to an empty payload

#### Scenario: Large offloaded payload in bounded memory
- **WHEN** a 1 MiB payload is encrypted with an offloaded ciphertext, once in 4 KiB chunks and once in a single 1 MiB chunk
- **THEN** in both cases the peak memory allocated by the library is the same as for a 4 KiB payload, within a small constant margin

### Requirement: Ciphertext location
When creating a cryptainer, the caller SHALL choose between an inline ciphertext and an offloaded one:
- inline: the cryptainer gets `{"ciphertext_location": "inline", "ciphertext_value": <bytes>}`, and the whole ciphertext is held in memory until serialization;
- offloaded: the cryptainer gets exactly `{"ciphertext_location": "offloaded"}`, and the raw final ciphertext bytes are delivered progressively to a caller-provided payload sink, to be stored as the `<cryptainer filename>.payload` sibling file.

The library SHALL provide the lowercase cryptainer suffix of each document format (`.crypt.json`, `.crypt.cbor`), so that integrators name files as section 9 of the encryptor specification requires.

#### Scenario: Offloaded cryptainer
- **WHEN** a payload is encrypted with an offloaded ciphertext in WA-CBOR, and the host tool writes `rec.crypt.cbor` and `rec.crypt.cbor.payload`
- **THEN** `rec.crypt.cbor` contains the offloaded marker only, and wacryptolib loads both files from the filesystem and decrypts the payload

#### Scenario: Inline cryptainer
- **WHEN** a 255-byte payload is encrypted with an inline ciphertext, once in each document format
- **THEN** the Extended JSON cryptainer embeds the ciphertext as a `$binary` value, the WA-CBOR one as a byte string, and wacryptolib decrypts both

### Requirement: Document formats
Each build SHALL enable the Extended JSON format, the WA-CBOR format, or both, through build-time options, both being enabled by default. A build with neither SHALL fail with an explicit message. The code of a disabled format, the base64 encoder included for Extended JSON, SHALL NOT be compiled. The caller SHALL choose one enabled format per cryptainer, the default being the only enabled format, or Extended JSON when both are. Requesting a format that is not enabled SHALL fail at creation with an unsupported-feature error. Device profiles SHALL be readable in every build.

The chosen format SHALL govern both:
- every structure serialized and then encrypted (symkeys, sub-symkeys, cipherdicts, shards, key structs), as defined by the `key-ciphertext-format` capability and by `S_F` in section 2 of the encryptor specification;
- the cryptainer document.

In WA-CBOR, every payload cipher layer and every symmetric key cipher layer SHALL get `key_ciphertext_format: "cbor"`. In Extended JSON, no `key_ciphertext_format` field SHALL be written. Shards SHALL NOT get the field, since their chains use the format of their enclosing chain.

Every serialized structure, intermediate or cryptainer, SHALL be byte-identical to the serialization of the same tree by wacryptolib's default writer of its format (`dump_to_json_bytes()` or `dump_to_cbor_bytes()`), which means relaxed Extended JSON as defined by section 2 of the encryptor specification, and the core deterministic encoding of the WA-CBOR specification (`docs/specifications/wa_cbor_document_format.md`). Every cryptainer SHALL be a valid WA-CBOR tree, so that `flightbox convert-format` converts it to the other format. Output SHALL be delivered progressively to a caller-provided sink, without requiring the whole document in memory.

#### Scenario: CBOR-only build
- **WHEN** the library is built with only the WA-CBOR format enabled
- **THEN** it contains no Extended JSON writer nor base64 encoder, its cryptainers carry `key_ciphertext_format: "cbor"` on every payload layer and symmetric key layer, and wacryptolib decrypts them

#### Scenario: No format enabled
- **WHEN** the library is built with both document formats disabled
- **THEN** the build stops with an error explaining how to enable one

#### Scenario: Disabled format requested
- **WHEN** a JSON-only build is asked to create a WA-CBOR cryptainer
- **THEN** creation fails with the unsupported-feature error, before any key is generated

#### Scenario: JSON mode matches the reference form
- **WHEN** a cryptainer is created in Extended JSON
- **THEN** it has no `key_ciphertext_format` field, and its bytes equal `dump_to_json_bytes(load_from_json_bytes(bytes))`

#### Scenario: CBOR mode matches the reference form
- **WHEN** a cryptainer is created in WA-CBOR
- **THEN** its bytes equal `dump_to_cbor_bytes(load_from_cbor_bytes(bytes))`

#### Scenario: Non-ASCII metadata
- **WHEN** cryptainer metadata contains the text `"Café ☕"`, in an Extended JSON cryptainer
- **THEN** the cryptainer file contains `"Caf\u00e9 \u2615"`, and wacryptolib reads the metadata back as `"Café ☕"`

#### Scenario: Same serialization as the reference for intermediate structures
- **WHEN** a symkey `{"key": K, "iv": IV}` with fixed bytes is serialized by the Rust library and by wacryptolib, in each format
- **THEN** both byte sequences are identical

#### Scenario: Conversion of Rust cryptainers
- **WHEN** a Rust-made cryptainer of either format, with an offloaded payload, is converted to the other format with `flightbox convert-format`
- **THEN** wacryptolib decrypts the converted cryptainer to the original payload

### Requirement: Cryptainer metadata
The caller SHALL be able to attach metadata to each cryptainer, or none. Metadata SHALL be a map of text keys whose values are null, booleans, signed 64-bit integers, text strings, byte strings, UUIDs, arrays or maps. When provided as CBOR, metadata SHALL be a WA-CBOR document within the sub-profile of the device profile capability. Whether built or decoded, metadata SHALL be checked before any key is generated:
- it SHALL be nested at most one level less than the configured CBOR nesting depth, since it sits at depth 2 in cryptainers and key structs;
- it SHALL contain no single-key map whose key is an Extended JSON keyword (`$binary`, `$uuid`, `$date`, `$numberInt`, `$numberLong`, `$numberDouble`, `$numberDecimal`, `$undefined`).

Metadata SHALL appear unencrypted in the cryptainer's `cryptainer_metadata` and in every key struct, as the encryptor specification requires. Floating-point numbers, datetimes, decimals and integers outside the signed 64-bit range SHALL be rejected with an unsupported-type error.

#### Scenario: Metadata copied into key structs
- **WHEN** a cryptainer is created with metadata `{"device_id": "fb-07", "sequence": 42}` and one `RSA_OAEP` layer
- **THEN** `cryptainer_metadata` equals that map, and the trustee-side decryption of the key struct exposes the same metadata

#### Scenario: Null metadata
- **WHEN** no metadata is given
- **THEN** `cryptainer_metadata` is `null` in the cryptainer and in every key struct

#### Scenario: Float metadata rejected
- **WHEN** CBOR metadata contains a floating-point value or a tag 0 datetime
- **THEN** cryptainer creation fails with an unsupported-type error before any key is generated

#### Scenario: Extended JSON keyword map rejected
- **WHEN** metadata built in memory contains the map `{"$uuid": "0123"}`
- **THEN** cryptainer creation fails with a validation error before any key is generated, since wacryptolib would read that map back as a UUID

### Requirement: Signatures are not supported yet
The Rust encryptor SHALL reject any cryptoconf that has a non-empty `payload_plaintext_signatures` list, or a non-empty `payload_ciphertext_signatures` (or legacy `payload_signatures`) list. The rejection SHALL happen when the profile is loaded, and the error SHALL state that signatures are unsupported. Absent or empty signature lists SHALL be accepted. An empty legacy `payload_signatures` list SHALL be written into the cryptainer as an empty `payload_ciphertext_signatures` list, as in section 6.1 of the encryptor specification.

#### Scenario: Cryptoconf with a ciphertext signature
- **WHEN** a profile's cryptoconf has a payload layer with one `RSA_PSS` signature conf
- **THEN** loading the profile fails with an unsupported-signature error

#### Scenario: Legacy empty signature list
- **WHEN** a payload layer has `payload_signatures: []` and no `payload_ciphertext_signatures`
- **THEN** the cryptainer's payload layer has `payload_ciphertext_signatures: []` and no `payload_signatures` key, and wacryptolib decrypts it without signature errors

### Requirement: Platform hooks and randomness
The library SHALL perform no operating-system call. Random byte generation and the wall clock SHALL be provided by the caller through platform hooks, given per encryptor.

All secrets SHALL come from the random hook:
- symmetric keys, IVs and nonces;
- Shamir coefficients;
- HPKE ephemeral keys and ML-KEM encapsulation randomness;
- RSA-OAEP seeds;
- UUID random bits.

That hook SHALL be documented as requiring a cryptographically secure generator. A failure of the random hook SHALL abort the operation with an error, never fall back to another source. Random values SHALL be drawn in the order of section 6.8 of the encryptor specification.

The clock hook SHALL return the Unix time in units of 1/10000 second, as an unsigned 64-bit integer, or report that no clock is available. Without a clock, UUID0 time prefixes SHALL be zero, and the 80 random bits SHALL be kept.

#### Scenario: Random hook failure
- **WHEN** the random hook reports a failure while a symkey is being generated
- **THEN** cryptainer creation fails with a randomness error, and nothing is written to the sinks

#### Scenario: Deterministic test randomness
- **WHEN** two encryptions are run with the same deterministic test random hook and fixed clock
- **THEN** they produce byte-identical cryptainers

#### Scenario: No clock
- **WHEN** a cryptainer is created with a clock hook reporting that no clock is available
- **THEN** the first 6 bytes of its `cryptainer_uid` are zero, and its other 10 bytes come from the random hook

### Requirement: Parity with the C encryptor
For the same device profile, payload, chunking, metadata, document format and ciphertext location, a Rust build and a C build of the `c-flightbox-encryptor` capability, both fed by the deterministic random generator and clock of their test drivers with the same seed and time, SHALL produce byte-identical cryptainers and payload ciphertexts. The Rust host tools SHALL follow the command-line protocol of the C host tools, so that one interoperability test suite drives both implementations.

#### Scenario: Same bytes as the C library
- **WHEN** the nested corpus profile `2026_cbor_key_ciphertexts/05_mixable` is used by the Rust test driver and by the C test driver with the same seed and time, in each document format, inline and offloaded
- **THEN** the cryptainers and payload ciphertexts of both implementations are byte-identical

#### Scenario: One suite for both implementations
- **WHEN** the interoperability suite is run with a C build and a Rust build
- **THEN** every test that does not concern a C-only build option runs against both, and passes

### Requirement: Memory safety and embedded portability
The core library and the RustCrypto backend SHALL contain no `unsafe` code, which their builds SHALL enforce. `unsafe` code SHALL be confined to the wolfCrypt backend, where calls into the C library require it. The core library and the RustCrypto backend SHALL build without the Rust standard library, needing only a memory allocator, for at least the Cortex-M33 hard-float target (STM32U3 and STM32U5) and the Cortex-M4 hard-float target. The workspace SHALL build without warnings under the lints enabled for it, and the library SHALL have no global mutable state of its own.

Three limits SHALL be options with the defaults of the C library, and inputs beyond them SHALL be rejected at profile load with an error rather than overflowing the stack:
- the key cipher nesting depth, default 8, counted as in the `c-flightbox-encryptor` capability;
- the CBOR item nesting depth, default 64, which applies to profiles and metadata, may be lowered, and SHALL be refused above 64, the maximum of WA-CBOR;
- the largest RSA modulus, default 4096 bits.

#### Scenario: Cross-compilation for Cortex-M33
- **WHEN** a program using the core library and the RustCrypto backend, without the standard library, is built for the Cortex-M33 hard-float target, once with only WA-CBOR and once with only Extended JSON enabled
- **THEN** both builds succeed

#### Scenario: Unsafe code refused
- **WHEN** an `unsafe` block is added to the core library or to the RustCrypto backend
- **THEN** its build fails

#### Scenario: Excessive key cipher nesting
- **WHEN** a profile nests shared secret layers so that the key cipher nesting depth is one above the configured maximum
- **THEN** profile loading fails with a nesting-depth error

#### Scenario: CBOR depth above the format maximum
- **WHEN** limits with a CBOR nesting depth of 65 are requested
- **THEN** they are refused before any profile is loaded

### Requirement: Secret hygiene
The following SHALL be overwritten with zeros before their memory is released or goes out of scope, on success and error paths alike, in a way that the compiler cannot optimize away:
- symkeys and sub-symkeys;
- Shamir shards and coefficients;
- HPKE ephemeral private keys and shared secrets;
- intermediate plaintext key structs.

Buffers holding secrets SHALL NOT leave an unwiped copy behind when they grow. Secrets SHALL never be written to the cryptainer or payload sinks.

#### Scenario: Secrets wiped after finalization
- **WHEN** a cryptainer is finalized, or creation is aborted midway, under deterministic randomness and a test allocator that inspects released blocks
- **THEN** no released block contains the bytes of a symkey, a sub-symkey, a shard or an HPKE ephemeral key of that run

### Requirement: Error reporting
Every fallible operation SHALL return an error value from a single documented set, never panic. Errors SHALL distinguish at least:
- unsupported format;
- decoding error;
- invalid profile or cryptoconf;
- unsupported algorithm, type or feature, including signatures;
- missing public key;
- key constraint violation;
- nesting too deep;
- out of memory;
- randomness failure;
- crypto backend failure;
- sink write failure;
- a call made on a failed encryptor.

A human-readable description SHALL be available for each error. Profile loading errors SHALL also carry the location of the faulty item in the profile, as a path such as `cryptoconf.payload_cipher_layers[0].key_cipher_layers[1]`.

Calls made in the wrong order (a payload chunk after finalization, a cryptainer written before finalization) SHALL be rejected at compile time. After a failed call, an encryptor SHALL refuse every further operation. Reserving memory for a buffer whose size depends on caller input (decoded documents, an inline ciphertext) SHALL report the out-of-memory error when the allocator refuses it.

#### Scenario: Error location
- **WHEN** a profile's second key cipher layer of the first payload layer references a trustee without public key
- **THEN** loading returns the missing-public-key error, with the location `cryptoconf.payload_cipher_layers[0].key_cipher_layers[1]`

#### Scenario: Chunk after finalization does not compile
- **WHEN** a program submits a payload chunk to an encryptor it has already finalized
- **THEN** the program is rejected by the compiler

#### Scenario: Failed encryptor
- **WHEN** the payload sink fails during a chunk, and another chunk is then submitted
- **THEN** the first call returns the sink write error, and the second the failed-encryptor error

#### Scenario: Inline ciphertext too large for the allocator
- **WHEN** an inline ciphertext grows beyond what a size-limited test allocator grants
- **THEN** the call returns the out-of-memory error, without panicking

### Requirement: Host command-line tools
The Rust workspace SHALL provide two host tools, built only for host targets, taking the same arguments, producing the same outputs and exit statuses, and reporting the same status names as the C tools of the `c-flightbox-encryptor` capability:
- a file encryption tool, using operating-system randomness, taking a device profile, a payload file, an optional WA-CBOR metadata file, an output basename, a document format among those of the build, an inline or offloaded choice and a chunk size;
- a test driver exposing the primitives, the codecs, profile loading and deterministic cryptainer creation to the interoperability suite, and reporting its implementation, crypto backend and enabled document formats.

The file encryption tool SHALL name its outputs like `flightbox encrypt`:
- a trailing `.crypt`, `.crypt.json` or `.crypt.cbor` suffix of the basename, in any letter case, is stripped;
- the lowercase suffix of the chosen format is then appended, plus a `.payload` file named after the cryptainer when offloaded.

It SHALL refuse to overwrite existing output files unless a `--force` option is given. It SHALL write the payload file before the cryptainer file. On error, it SHALL exit with a non-zero status, print the error description and error location, and leave no file it created behind.

#### Scenario: Encrypt a file from the command line
- **WHEN** the tool is run with a device profile exported from the compatibility corpus and a payload file, in offloaded mode with 4096-byte chunks, once per document format
- **THEN** it writes `<output>.crypt.json` and `<output>.crypt.json.payload`, or `<output>.crypt.cbor` and `<output>.crypt.cbor.payload`, exits with status 0, and wacryptolib decrypts each result with the corpus keystore pool and the passphrases documented in its sidecar

#### Scenario: Typed suffix normalized
- **WHEN** the tool is run with the output basename `Clip.CRYPT` and the WA-CBOR format
- **THEN** it writes `Clip.crypt.cbor`

#### Scenario: Existing output refused
- **WHEN** `<output>.crypt.json` already exists and the tool is run without `--force`
- **THEN** it exits with a non-zero status before encrypting anything, and leaves the existing file unchanged

#### Scenario: Driver identifies its build
- **WHEN** the test driver of a Rust build is asked for its build information
- **THEN** it reports the Rust implementation, its crypto backend and its enabled document formats

### Requirement: Dependency hygiene
The exact versions of every dependency of the Rust workspace SHALL be locked in the repository. The automated checks SHALL fail when a locked dependency has a known security advisory that is not explicitly waived with a written reason, or a licence incompatible with GPL-2.0-or-later.

#### Scenario: Advisory on a dependency
- **WHEN** the dependency check runs while a locked dependency has a published security advisory that is not waived
- **THEN** the check fails, naming the dependency and the advisory
