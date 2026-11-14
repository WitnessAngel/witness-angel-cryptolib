## Purpose

Provides a portable C implementation of the flightbox encryptor workflow for embedded devices. From a device profile, it turns a payload into a finished cryptainer that the reference wacryptolib decryptor accepts unchanged.

## ADDED Requirements

### Requirement: End-to-end cryptainer creation
The C encryptor SHALL implement steps 1, 2 and 3 of the encryptor specification (`docs/flightbox_specifications/flightbox_encryptor_specification.md`), referred to below as "the encryptor specification". From a validated device profile and optional cryptainer metadata, it SHALL produce a cryptainer with:
- state `FINISHED` and format `cryptainer_1.0`;
- a fresh `cryptainer_uid`;
- the cryptoconf's root `keychain_uid`;
- a `key_ciphertext` in every payload layer and in every symmetric key layer;
- `payload_macs` in every payload layer;
- a non-null `payload_ciphertext_struct`.

Given the trustees' private keys, the produced cryptainer SHALL pass wacryptolib's strict cryptainer validation, once loaded from the filesystem when its ciphertext is offloaded. wacryptolib's decryption SHALL recover the original payload with no error entry in the operation report.

#### Scenario: Single-layer cryptainer decrypted by wacryptolib
- **WHEN** the C encryptor encrypts a 4099-byte payload with a profile made of one `CHACHA20_POLY1305` payload layer wrapped by one `ECIES_X25519` layer for an authenticator trustee
- **THEN** wacryptolib decrypts the cryptainer with that authenticator's private key, returns the exact payload, and reports no error

#### Scenario: Nested key layers decrypted by wacryptolib
- **WHEN** the profile has two payload layers, and the key of one of them goes through `RSA_OAEP`, then a shared secret of threshold 2 out of 3 whose shards use `ECIES_X25519`, `ML_KEM_768` and an `AES_EAX` symmetric layer wrapped by `RSA_OAEP`
- **THEN** wacryptolib decrypts the cryptainer with all keys available
- **AND** for each of the three shards in turn, wacryptolib still decrypts it with that shard's private key withheld, with error entries only about the withheld key

#### Scenario: Fresh secrets for every cryptainer
- **WHEN** the same payload is encrypted twice with the same profile
- **THEN** the two cryptainers have different `cryptainer_uid`, different `key_ciphertext` values and different payload ciphertexts

### Requirement: Supported algorithms
The C encryptor SHALL support:
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
- **WHEN** the C symmetric ciphers encrypt the plaintext referenced by each symmetric cipherdict fixture of `compatibility/cipherdicts/`, with the key and IV/nonce of that fixture
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

### Requirement: Compile-time crypto backend selection
The library SHALL be buildable against exactly one cryptographic backend, chosen at compilation time:
- Mbed TLS 3.6 LTS, with a vendored ML-KEM-768 implementation since Mbed TLS has none;
- or wolfCrypt.

Compilation SHALL fail with an explicit message in each of these cases:
- zero or two backends are selected;
- the selected backend's configuration lacks a required feature (the message names that feature).

Both backend builds SHALL pass the same test suite and accept exactly the same device profiles. Hardware acceleration SHALL NOT be required. A backend's own accelerated implementations SHALL be used transparently when its configuration enables them.

#### Scenario: Both backends pass the same tests
- **WHEN** the library is built once with the Mbed TLS backend and once with the wolfCrypt backend
- **THEN** both builds pass the whole C unit test suite and the whole interoperability test suite

#### Scenario: No backend selected
- **WHEN** the library is compiled without selecting a backend
- **THEN** compilation stops with an error explaining how to select one

#### Scenario: Missing backend feature
- **WHEN** the library is compiled against an Mbed TLS configuration without ChaCha20-Poly1305 support
- **THEN** compilation stops with an error naming the missing Mbed TLS option

### Requirement: Streaming payload encryption
The C encryptor SHALL accept the payload as a sequence of chunks of arbitrary sizes, including empty chunks and a zero-length payload, and SHALL pass it through all payload cipher layers in cryptoconf order. When the ciphertext is offloaded, its memory use SHALL depend neither on the payload size nor on the size of the chunks submitted by the caller. The resulting ciphertext and MAC tags SHALL be byte-identical to a one-shot encryption with the same symkeys, regardless of chunking. `AES_CBC` layers SHALL apply PKCS#7 padding once, at finalization.

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

#### Scenario: Offloaded cryptainer
- **WHEN** a payload is encrypted with an offloaded ciphertext, and the host tool writes `rec.crypt` and `rec.crypt.payload`
- **THEN** `rec.crypt` contains the offloaded marker only, and wacryptolib loads both files from the filesystem and decrypts the payload

#### Scenario: Inline cryptainer
- **WHEN** a 255-byte payload is encrypted with an inline ciphertext
- **THEN** the cryptainer embeds the ciphertext as an Extended JSON `$binary` value, and wacryptolib decrypts it

### Requirement: Cryptainer serialization
The cryptainer SHALL be written as UTF-8 Extended JSON in relaxed mode, as defined by section 2 of the encryptor specification:
- bytes as `{"$binary": {"base64": ..., "subType": "00"}}`, UUIDs as `{"$uuid": "<32 lowercase hex>"}`, integers as plain numbers;
- keys sorted, separators `", "` and `": "`;
- ASCII-only output, with `\uXXXX` escapes (surrogate pairs beyond the BMP).

Every intermediate structure that gets encrypted (symkeys, key structs, cipherdicts, shards) SHALL use the same serialization, and SHALL be byte-identical to the reference library's serialization of the same structure. Output SHALL be delivered progressively to a caller-provided sink, without requiring the whole JSON text in memory.

#### Scenario: Non-ASCII metadata
- **WHEN** cryptainer metadata contains the text `"Café ☕"`
- **THEN** the cryptainer file contains `"Café ☕"`, and wacryptolib reads the metadata back as `"Café ☕"`

#### Scenario: Same serialization as the reference for intermediate structures
- **WHEN** a symkey `{"key": K, "iv": IV}` with fixed bytes is serialized by the C library and by wacryptolib
- **THEN** both byte sequences are identical

### Requirement: Cryptainer metadata
The caller SHALL be able to attach metadata to each cryptainer, or none. Metadata SHALL be a map of text keys whose values are null, booleans, signed 64-bit integers, text strings, byte strings, UUIDs, arrays or maps, within the configured CBOR nesting depth. When provided as CBOR, metadata SHALL use the encodings of the device profile capability. Metadata SHALL appear unencrypted in the cryptainer's `cryptainer_metadata` and in every key struct, as the encryptor specification requires. Floating-point numbers and dates SHALL be rejected with an unsupported-type error.

#### Scenario: Metadata copied into key structs
- **WHEN** a cryptainer is created with metadata `{"device_id": "fb-07", "sequence": 42}` and one `RSA_OAEP` layer
- **THEN** `cryptainer_metadata` equals that map, and the trustee-side decryption of the key struct exposes the same metadata

#### Scenario: Null metadata
- **WHEN** no metadata is given
- **THEN** `cryptainer_metadata` is `null` in the cryptainer and in every key struct

#### Scenario: Float metadata rejected
- **WHEN** CBOR metadata contains a floating-point value
- **THEN** cryptainer creation fails with an unsupported-type error before any key is generated

### Requirement: Signatures are not supported yet
The C encryptor SHALL reject any cryptoconf that has a non-empty `payload_plaintext_signatures` list, or a non-empty `payload_ciphertext_signatures` (or legacy `payload_signatures`) list. The rejection SHALL happen when the profile is loaded, and the error SHALL state that signatures are unsupported. Absent or empty signature lists SHALL be accepted. An empty legacy `payload_signatures` list SHALL be written into the cryptainer as an empty `payload_ciphertext_signatures` list, as in section 6.1 of the encryptor specification.

#### Scenario: Cryptoconf with a ciphertext signature
- **WHEN** a profile's cryptoconf has a payload layer with one `RSA_PSS` signature conf
- **THEN** loading the profile fails with an unsupported-signature error

#### Scenario: Empty signature lists
- **WHEN** a payload layer has `payload_ciphertext_signatures: []`
- **THEN** the cryptainer keeps `payload_ciphertext_signatures: []` and is decrypted by wacryptolib without signature errors

#### Scenario: Legacy empty signature list
- **WHEN** a payload layer has `payload_signatures: []` and no `payload_ciphertext_signatures`
- **THEN** the cryptainer's payload layer has `payload_ciphertext_signatures: []` and no `payload_signatures` key

### Requirement: Platform hooks and randomness
The library SHALL perform no operating-system call. Memory allocation, random byte generation and the wall clock SHALL be provided by the caller through platform hooks, given per instance.

All secrets SHALL come from the random hook:
- symmetric keys, IVs and nonces;
- Shamir coefficients;
- HPKE ephemeral keys and ML-KEM encapsulation randomness;
- RSA-OAEP seeds;
- UUID random bits.

That hook SHALL be documented as requiring a cryptographically secure generator. A failure of the random hook SHALL abort the operation with an error, never fall back to another source.

The clock hook SHALL return the Unix time in units of 1/10000 second, as an unsigned 64-bit integer, or report that no clock is available. Without a clock, UUID0 time prefixes SHALL be zero, and the 80 random bits SHALL be kept.

#### Scenario: Random hook failure
- **WHEN** the random hook reports a failure while a symkey is being generated
- **THEN** cryptainer creation fails with a randomness error, and nothing is written to the sinks

#### Scenario: Deterministic test randomness
- **WHEN** two encryptions are run with the same deterministic test random hook and fixed clock
- **THEN** they produce byte-identical cryptainers, on either backend

### Requirement: Embedded portability
The library SHALL be written in ISO C99. Its sources SHALL use only freestanding-compatible headers plus `string.h`. It SHALL avoid variable-length arrays, unaligned memory access, byte-order assumptions, and global mutable state of its own. It SHALL compile without warnings at high warning levels on GCC and Clang, for host targets and for at least one 32-bit ARM Cortex-M target.

Two compile-time configurable limits SHALL bound recursion, and deeper inputs SHALL be rejected at profile load with a nesting-depth error rather than overflowing the stack:
- the key cipher nesting depth, default 8: a payload layer's `key_cipher_layers` list is level 1, and each shard or symmetric key layer containing `key_cipher_layers` adds one level;
- the CBOR item nesting depth, default 64, which applies to profiles and metadata.

Public identifiers SHALL share a single library prefix. File and function names SHALL describe their role explicitly.

#### Scenario: Cross-compilation for Cortex-M
- **WHEN** the library and its Mbed TLS backend are compiled for a Cortex-M4 target with warnings treated as errors
- **THEN** compilation succeeds

#### Scenario: Excessive key cipher nesting
- **WHEN** a profile nests shared secret layers so that the key cipher nesting depth is one above the configured maximum
- **THEN** profile loading fails with a nesting-depth error

#### Scenario: Corpus-sized nesting accepted
- **WHEN** a profile is exported from `compatibility/cryptoconfs/2026_current/05_shamir_authenticators.cryptoconf`
- **THEN** it is accepted with the default limits

### Requirement: Secret hygiene
The following SHALL be overwritten with zeros before their memory is released or goes out of scope, on success and error paths alike, in a way that the compiler cannot optimize away:
- symkeys and sub-symkeys;
- Shamir shards and coefficients;
- HPKE ephemeral private keys and shared secrets;
- intermediate plaintext key structs.

Secrets SHALL never be written to the cryptainer or payload sinks.

#### Scenario: Secrets wiped after finalization
- **WHEN** a cryptainer is finalized, or creation is aborted midway, with a test allocator that records released blocks
- **THEN** every released block that held secret material contains only zeros at release time

### Requirement: Error reporting
Every public library function that can fail SHALL return a status code from a single documented enumeration. Errors SHALL distinguish at least:
- unsupported format;
- invalid profile or cryptoconf;
- unsupported algorithm, type or feature, including signatures;
- missing public key;
- key constraint violation;
- nesting too deep;
- out of memory;
- randomness failure;
- crypto backend failure;
- sink write failure;
- a call made in the wrong encryptor state.

A human-readable description SHALL be available for each status. Profile loading errors SHALL also report the location of the faulty item in the profile, as a path such as `cryptoconf.payload_cipher_layers[0].key_cipher_layers[1]`, written into an optional caller-provided buffer.

A failed creation SHALL return no instance, and destroying a null instance SHALL be a no-op. After an error, an existing encryptor instance SHALL only accept being destroyed.

#### Scenario: Out of memory
- **WHEN** the allocator hook returns no memory at any allocation of a profile load or cryptainer creation, tested for each allocation index in turn
- **THEN** the call returns the out-of-memory status, provides no instance, and leaks nothing

#### Scenario: Error location
- **WHEN** a profile's second key cipher layer of the first payload layer references a trustee without public key
- **THEN** loading returns the missing-public-key status, and the location buffer holds `cryptoconf.payload_cipher_layers[0].key_cipher_layers[1]`

#### Scenario: Wrong state
- **WHEN** a payload chunk is submitted after finalization
- **THEN** the call returns the wrong-state status, and the instance can only be destroyed

### Requirement: Host command-line tool
The C tree SHALL provide a host command-line tool, built only for host targets, using operating-system randomness. It SHALL take:
- a device profile file and a payload file;
- optional CBOR metadata;
- an inline or offloaded choice and a chunk size.

It SHALL write a `.crypt` file, plus its `.payload` sibling when offloaded. On error, it SHALL exit with a non-zero status and print the status description and error location.

#### Scenario: Encrypt a file from the command line
- **WHEN** the tool is run with a device profile exported from the compatibility corpus and a payload file, in offloaded mode with 4096-byte chunks
- **THEN** it writes `<output>.crypt` and `<output>.crypt.payload`, exits with status 0, and wacryptolib decrypts the result with the corpus keystore pool and the passphrases documented in its sidecar
