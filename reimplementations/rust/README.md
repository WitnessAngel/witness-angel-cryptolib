# Flightbox Rust encryptor

A memory-safe Rust library creating Witness Angel cryptainers on microcontrollers and hosts, interoperable with
wacryptolib: the cryptainers it writes are decrypted by wacryptolib, its trustees (local keyfactory, authenticators,
JSON-RPC servers) and the Authenticator app, unchanged.

It implements steps 1 to 3 of the
[flightbox encryptor specification](../../docs/flightbox_specifications/flightbox_encryptor_specification.md)
(its "Rust profile" is described in §10.3 there), with the feature set of the
[C library](../c-language/README.md). Its input is a **device profile**, a WA-CBOR document holding a cryptoconf
and the raw public keys of its trustees
([device profile specification](../../docs/flightbox_specifications/flightbox_device_profile_specification.md)),
exported on a computer by `scripts/flightbox/export_device_profile.py`.

Supported:

- payload ciphers `AES_CBC`, `AES_EAX` and `CHACHA20_POLY1305`, inline or offloaded, fed by chunks of any size;
- key cipher layers: asymmetric `RSA_OAEP`, `ECIES_X25519` and `ML_KEM_768`, symmetric `AES_CBC`, `AES_EAX` and
  `CHACHA20_POLY1305`, and Shamir shared secrets, nested up to a configurable depth (8 by default);
- trustees `local_keyfactory`, `authenticator` and `jsonrpc_api`, with keys found in the profile;
- cryptainers in relaxed Extended JSON and/or WA-CBOR, chosen by cargo features, with one format per cryptainer
  (for the cryptainer itself and for every structure encrypted into its key ciphertexts);
- metadata given as a value tree, built in Rust or decoded from WA-CBOR.

Not supported, by design: signatures (signature confs are rejected with `ErrorKind::UnsupportedSignature`),
payload digests, cryptoconfs without a root `keychain_uid` (the device can't fetch keys), decryption, and key
generation.

With the same random bytes and clock, a Rust build and a C build write the same cryptainer, byte for byte. The
interoperability tests check it between every pair of builds they are given.

## Layout and naming

A cargo workspace. File and item names follow those of the C library, so that both can be read side by side.

| Crate | Content |
|---|---|
| `wa_flightbox` | The library: `no_std` with `alloc`, `#![forbid(unsafe_code)]`, one dependency (`zeroize`). `core/` is the flightbox algorithm, `encoding/` the value tree, the WA-CBOR decoder of profiles and both writers, `primitives/` the composite constructions (PKCS#7, CMAC, EAX, OAEP, HKDF, HPKE, Shamir, UUID0), written once over the backend trait |
| `wa_flightbox_backend_rustcrypto` | Default crypto backend, pure Rust: `no_std`, `#![forbid(unsafe_code)]` |
| `wa_flightbox_backend_wolfcrypt` | wolfCrypt 5.8 backend through FFI bindings, `unsafe` confined to one module |
| `wa_flightbox_backend_conformance` | The acceptance tests of a backend, generic over the trait, and test helpers |
| `wa_flightbox_host_tools` | `wa_flightbox_encrypt_file_cli` and `wa_flightbox_test_driver`, with the arguments and outputs of the C tools |
| `wa_flightbox_footprint_probe` | A bare-metal static library calling the whole API, for cross-builds and code sizes |
| `fuzz/` | `cargo-fuzz` targets (its own workspace, nightly toolchain) |
| `test_vectors/` | Expected values as JSON files, generated from wacryptolib and pycryptodome by `generate_rust_test_vectors.py`; `tests/test_rust_flightbox_test_vectors.py` checks that they are up to date |

## API walkthrough

```rust
use wa_flightbox::{
    CryptainerEncryptor, DeviceProfile, EncryptorLimits, EncryptorOptions, PlatformHooks, RandomFailure,
};
use wa_flightbox_backend_rustcrypto::RustCryptoBackend;

/// Randomness and time of the platform: here a host. See "Platform hooks" for devices.
struct HostHooks;

impl PlatformHooks for HostHooks {
    fn fill_random(&mut self, buffer: &mut [u8]) -> Result<(), RandomFailure> {
        getrandom::fill(buffer).map_err(|_| RandomFailure)
    }

    fn unix_time_in_ten_thousandths_of_second(&mut self) -> Option<u64> {
        let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?;
        u64::try_from(elapsed.as_micros() / 100).ok()
    }
}

/// Returns the cryptainer, and its payload ciphertext to store as `<cryptainer file name>.payload`.
fn create_cryptainer(profile_bytes: &[u8], recording: &[u8]) -> wa_flightbox::Result<(Vec<u8>, Vec<u8>)> {
    // Once per profile: decoded and fully validated, then immutable and reusable for any number of cryptainers
    let profile = DeviceProfile::load_from_cbor(profile_bytes, &EncryptorLimits::default())?;
    let options = EncryptorOptions::default();
    let mut hooks = HostHooks;
    // Any `OutputSink`: a file, flash, a socket. `Vec<u8>` is one.
    let mut payload_file = Vec::new();
    let mut cryptainer_file = Vec::new();

    // Step 1: the keys are generated and wrapped for the trustees of the profile
    let mut encryptor = CryptainerEncryptor::<RustCryptoBackend, _>::create_offloaded(
        &profile,
        None, // No metadata
        &options,
        &mut hooks,
        &mut payload_file,
    )?;
    // Step 2: any number of chunks, of any size
    for chunk in recording.chunks(1000) {
        encryptor.encrypt_payload_chunk(chunk)?;
    }
    // End of step 2 and step 3: the encryptor is consumed, so that no chunk can follow
    let finished = encryptor.finalize()?;
    finished.write_cryptainer(&mut cryptainer_file)?;
    Ok((cryptainer_file, payload_file))
}
```

- `CryptainerEncryptor::create()` keeps the payload ciphertext in memory and embeds it in the cryptainer;
  `create_offloaded()` streams it to a sink. `encrypt_payload_in_one_call()` does everything for a small payload.
- **Errors** are `wa_flightbox::Error`: an `ErrorKind` named after the status codes of the C library (its
  `status_name()` gives the C name, e.g. `WA_STATUS_INVALID_PROFILE`), and, for a rejected profile or metadata, the
  location of the fault (`cryptoconf.payload_cipher_layers[0].key_cipher_layers[1].key_cipher_algo`).
- **Lifecycle**: what the C API reports as `WA_STATUS_WRONG_STATE` mostly cannot be written. `finalize()` takes
  the encryptor by value, and an offloaded encryptor cannot exist without its sink. The one remaining case is an
  encryptor used again after one of its calls failed: it returns `ErrorKind::WrongState`, and nothing more is
  written.
- **Metadata** is a `Value` tree: built with `Map::from_entries()` and `Value`'s conversions, or decoded from
  WA-CBOR with `decode_document_from_cbor()`. It must be a map without Extended JSON keyword maps (`{"$uuid":
  ...}`), within the nesting limit.
- **Secrets** (keys, shards, cipher states, plaintext buffers) are wiped when dropped, on success and on every
  error path. Buffers holding secrets never grow in place: a growth allocates, copies, wipes the old block and
  releases it, so no stale copy stays in the allocator.

## Platform hooks

The library makes no operating system call and has no global state. It reaches randomness and time only through
the `PlatformHooks` given to each encryptor, and writes only to the `OutputSink`s it is given. Memory comes from
the global allocator of the firmware (`alloc`). `wa_flightbox_host_tools` holds the host implementation
(`getrandom`, the system clock).

- **`fill_random`**: MUST be a cryptographically secure generator. Every secret comes from it: symmetric keys, IVs
  and nonces, Shamir coefficients, HPKE ephemeral keys, ML-KEM encapsulation randomness, OAEP seeds and the random
  bits of UUIDs; neither backend uses a generator of its own, and the library depends on no generator crate.
  An error aborts the operation (`ErrorKind::RandomnessFailure`); there is no fallback. The library can't check the
  entropy of its input, so wire it carefully (§5 of the
  [embedded crypto libraries audit](../../docs/audits/embedded_crypto_libraries_for_flightbox.md)):
  - **STM32U3 / STM32U5**: read the RNG peripheral through the HAL of the chip, check its seed and clock error
    flags, and return an error when they are set; preferably feed a DRBG from it.
  - **ESP32 / ESP32-S3**: `esp_fill_random()` is truly random only while Wi-Fi or Bluetooth is on, or while the
    SAR ADC entropy source is enabled; otherwise it is pseudo-random.
  - **RP2040**: no TRNG; add a secure element or avoid this chip. **RP2350**: read the TRNG into a DRBG.
  - In every case, a DRBG must be seeded from a hardware TRNG, never from a seedable PRNG (§3.1 of the
    specification).
- **`unix_time_in_ten_thousandths_of_second`**: optional, used for the time prefix of UUID0s. Without a clock
  (`None`, the default), those prefixes are zero, which only loses their ordering.
- **`OutputSink::write`**: receives the serialized bytes in order, in pieces of any size. An error stops the
  operation (`ErrorKind::SinkWriteFailure`).

## Features and limits

Cargo features of `wa_flightbox`, both enabled by default: `extended-json` and `wa-cbor`. The writer of a
disabled format, and the base64 encoder in CBOR-only builds, are not compiled; requesting a disabled format gives
`ErrorKind::UnsupportedFeature`. Device profiles are WA-CBOR in every build. The core crate builds without any
format (crypto backend crates depend on it that way, leaving the choice to the firmware), every format being then
refused at run time; the host tools refuse to build without one.

```toml
[dependencies]
wa_flightbox = { path = "...", default-features = false, features = ["wa-cbor"] }
wa_flightbox_backend_rustcrypto = { path = "..." }
```

- **Big chips**: Extended JSON, readable everywhere; keeping both formats costs little.
- **Small chips**: WA-CBOR only, which is more compact on disk and in RAM (no base64 expansion of the key
  ciphertexts nested inside each other).

Limits are run-time values, in `EncryptorLimits` (given when a profile is loaded) and `EncryptorOptions`:

| Value | Default | Meaning |
|---|---|---|
| `max_key_cipher_nesting_depth` | 8 (1 to 64) | Nesting levels of key cipher layers; bounds the core recursion |
| `max_cbor_nesting_depth` | 64 (8 to 64) | Nesting of CBOR arrays and maps in profiles and metadata (metadata gets one level less); lower it to save stack |
| `max_rsa_modulus_bits` | 4096 (2048 to 8192) | Largest RSA trustee key |
| `payload_processing_slice_size` | 4096 (multiple of 16) | Slice size of payload processing, which bounds memory use whatever the chunk size |

### Allocation failures and panics

- Buffers whose size comes from the caller or from an input (inline payload ciphertexts, decoded profiles and
  metadata) are reserved with `try_reserve`: running out of memory there gives `ErrorKind::OutOfMemory`.
- The small internal allocations (tree nodes, keys, cipher states) go through the global allocator, whose failure
  aborts, as everywhere in Rust's `alloc`. Size the heap from the peaks below. The C library reports every
  allocation failure instead.
- Faults of inputs are errors, never panics: the parsing and algorithm modules are compiled with the clippy lints
  denying `unwrap`, `expect`, `panic!`, indexing and unchecked arithmetic. Build device firmware with
  `panic = "abort"` (as the release profile of this workspace does) for what dependencies could still raise.

### Measured footprint

Code size of `wa_flightbox_footprint_probe`: a function loading a profile, decoding metadata and creating an
offloaded then an inline cryptainer with the RustCrypto backend, linked alone with `--gc-sections` (rustc 1.96.1,
release profile of the workspace: `opt-level = "s"`, LTO, one codegen unit, `panic = "abort"`). It is what a
firmware using the whole API adds, allocator support and compiler builtins included:

| Build | Cortex-M33 (`thumbv8m.main-none-eabihf`) | Cortex-M4 (`thumbv7em-none-eabihf`) |
|---|---|---|
| CBOR-only | 130,340 B | 130,282 B |
| JSON-only | 132,264 B | 132,036 B |

Of the CBOR-only Cortex-M33 figure: SHA-2 34.0 KB (26 KB of which is the SHA-512 compression function, used by
RSA-OAEP), the library itself 33.8 KB, big integers for RSA 24.5 KB, backend glue 7.1 KB, ML-KEM 5.5 KB, X25519
4.7 KB, AES 2.6 KB, `alloc`, `core` and compiler builtins 6.6 KB.

These figures are not comparable with the table of the C README, which gives totals of static archives before
the linker's garbage collection: a Rust static library carries the whole standard `core` and `alloc`, so only a
linked figure means something. For orientation, the C archives sum to about 71 KB (library, mlkem-native and the
minimal Mbed TLS), all algorithms included.

Peak heap use (counting allocator of the tests, offloaded payload, 64-bit host; the peak is the same for a 4 KiB
payload, a 1 MiB payload fed in 4 KiB chunks, and a 1 MiB payload fed in one chunk):

| Device profile | Extended JSON | WA-CBOR |
|---|---|---|
| `minimal_rsa_authenticator` (one RSA-OAEP trustee) | 13.6 KB | 11.8 KB |
| `corpus_2026_cbor_key_ciphertexts_04` | 15.7 KB | 13.1 KB |
| `nested_all_layer_kinds` (5 nested layer kinds, every asymmetric algorithm) | 78.7 KB | 19.5 KB |

Stack use has not been measured. The recursive functions are bounded by the two nesting limits above.

## Crypto backends

The library is generic over a `CryptoBackend`: AES-256 in bulk CBC and CTR calls, streaming ChaCha20-Poly1305,
SHA-256, SHA-512, HMAC-SHA256, X25519, the raw RSA public operation and ML-KEM-768 encapsulation from given
randomness. Everything else is portable code of the core crate, so backends share it, and one source of
randomness. Both backends produce byte-identical cryptainers for identical random inputs, and enforce the RFC
8439 limit of a ChaCha20-Poly1305 message (about 256 GiB): more data under one key gives
`ErrorKind::InvalidArgument` rather than a reused keystream.

### RustCrypto (default)

`wa_flightbox_backend_rustcrypto`, over `aes` 0.9, `chacha20` 0.10, `poly1305` 0.9, `sha2` 0.11, `hmac` 0.13,
`x25519-dalek` 3.0, `crypto-bigint` 0.7 and `ml-kem` 0.3 (exact versions in `Cargo.lock`). The minimum Rust
version is 1.87, the highest one these crates require; the workspace is developed with the toolchain pinned in
`rust-toolchain.toml`.

- No C code, no `unsafe` code of ours; the crates have their own, reviewed upstream.
- The software AES of the `aes` crate is constant-time (fixsliced), not table-based.
- None of these crates has a FIPS validation, and `ml-kem` has had no independent audit that we know of. Its
  output is compared byte for byte with pycryptodome's on every test run. Where a validated library is required,
  use the wolfCrypt backend.
- It does not drive hardware accelerators.

### wolfCrypt 5.8

`wa_flightbox_backend_wolfcrypt` calls the same wolfCrypt functions as the C library's adapter, through bindings
that `bindgen` generates at build time from the headers being compiled. Its build script takes:

| Variable | Meaning |
|---|---|
| `WA_WOLFSSL_SOURCE_DIR` | Required: a wolfSSL 5.8.x source tree (the C tree pins 5.8.4). The build script never downloads anything |
| `WA_WOLFSSL_USER_SETTINGS_DIR` | Optional: a directory holding the `user_settings.h` to use, instead of the C tree's `config/wa_wolfssl_user_settings_for_flightbox.h` |
| `LIBCLANG_PATH`, `BINDGEN_EXTRA_CLANG_ARGS` | For `bindgen`: where libclang is, and, when cross-compiling, the include paths of the target's C library |

The required wolfCrypt options are those of the C README; a missing one stops the build by its name. `SP_INT_BITS`
must also cover the `max_rsa_modulus_bits` in use (4096 in the default settings): a larger key is refused with
`ErrorKind::InvalidArgument`. The crate is
a member of the workspace but not one of its default members: plain `cargo build` and `cargo test` leave it out,
`--workspace` and `-p wa_flightbox_backend_wolfcrypt` need the variables above. The host tools select it with
`--no-default-features --features backend-wolfcrypt,extended-json,wa-cbor`.

### Writing a backend, for a hardware AES

A backend is a type without data implementing `CryptoBackend`, with two associated types for the streaming
primitives. The usual case is a chip with an AES peripheral: write an `Aes256Encryptor` driving it, and delegate
the rest to the RustCrypto backend.

```rust,ignore
struct PeripheralAes { /* the key slot of the peripheral */ }

impl Aes256Encryptor for PeripheralAes {
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Result<Self> { /* load the key */ }
    fn encrypt_cbc_blocks(&mut self, chaining_value: &mut [u8; 16], input: &[u8], output: &mut [u8]) -> Result<()> {
        /* one peripheral transfer for the whole slice; write the last ciphertext block back to chaining_value */
    }
    fn encrypt_ctr_blocks(&mut self, counter_block: &mut [u8; 16], input: &[u8], output: &mut [u8]) -> Result<()> {
        /* the same in CTR mode; write the next counter back to counter_block */
    }
}

struct MyChipBackend;

impl CryptoBackend for MyChipBackend {
    type Aes256 = PeripheralAes;
    type ChaCha20Poly1305 = <RustCryptoBackend as CryptoBackend>::ChaCha20Poly1305;
    fn compute_sha256(parts: &[&[u8]]) -> Result<[u8; 32]> { RustCryptoBackend::compute_sha256(parts) }
    // ... the other functions delegate the same way
}
```

The CBC and CTR functions receive whole processing slices (4096 bytes by default), so the peripheral is taken
once per slice, not once per block; `wa_flightbox/tests/integrator_provided_backend.rs` is a complete example,
which counts the calls. EAX and CMAC are built on these two functions, so they use the peripheral too. Run the
functions of `wa_flightbox_backend_conformance` on the new backend: they are its acceptance test.

### The raw RSA note

Backends are only asked for the raw RSA public operation; the OAEP padding (SHA-512, as wacryptolib uses) is
encoded by the portable code, tested against fixed-seed vectors. wolfSSL lists `WC_RSA_NO_PADDING` among the
options that "weaken security", because raw RSA is insecure when misused: here it is only ever applied to an
OAEP-encoded block, and the library exposes no raw RSA function.

## Licences

The Rust tree is GPL-2.0-or-later, like the rest of wacryptolib.

- The RustCrypto crates, `x25519-dalek`, `zeroize` and their dependencies: MIT, Apache-2.0, BSD-3-Clause or
  similar permissive licences, compatible (`deny.toml` holds the allowed list, checked by `cargo deny`).
- **wolfCrypt is GPL-3.0-or-later** (or commercial): a firmware built with the wolfCrypt backend is, as a whole,
  distributed under GPL-3.0-or-later, with its source-availability and installation-information obligations, unless
  a commercial wolfSSL licence is bought. RustCrypto is the default backend for this reason too.

## Differences from the C library

Same input, same cryptainers, same validation rules and error names. What differs:

- Limits are run-time values, not compile-time macros, and document formats are cargo features.
- Memory comes from the global allocator instead of hooks, and small allocation failures abort (see above).
- Most lifecycle errors are compile errors.
- The test driver does not report allocator statistics (`peak_allocated_bytes`, `leaked_block_count`,
  `unwiped_secret_release_count`): measuring them needs a global allocator written with `unsafe` code, which the
  tools crate forbids. The library's own tests measure them, in a dedicated test binary.
- The host tools take their arguments as Unicode strings: a file name that is not valid Unicode is a usage error.
- One error code differs, on an input that profiles cannot contain: sealing directly to an all-zero X25519 public
  key gives `WA_STATUS_KEY_CONSTRAINT_VIOLATION`, where the C library with Mbed TLS gives
  `WA_STATUS_CRYPTO_BACKEND_FAILURE` (Mbed TLS refuses the key before the portable check runs). Such keys are
  rejected when a profile is loaded, by both.

## Building and testing

Requirements: Rust through `rustup` (the toolchain and the two embedded targets are pinned in
`rust-toolchain.toml`), nothing else for the default configuration. Linux, macOS and Windows (MSVC) hosts.

```sh
cd reimplementations/rust
cargo test                       # RustCrypto backend, both document formats
cargo test --no-default-features --features wa-cbor,backend-rustcrypto        # CBOR-only
cargo build --release -p wa_flightbox_footprint_probe --target thumbv8m.main-none-eabihf \
    --no-default-features --features wa-cbor
```

Host CLI (encrypts a file with the operating system's randomness):

```sh
target/debug/wa_flightbox_encrypt_file_cli -p device_profile.cbor --format cbor recording.bin
# -> recording.bin.crypt.cbor and recording.bin.crypt.cbor.payload
```

The whole matrix, on Linux or WSL: `build_and_test_all_backends.sh` (formatting and lints, both backends,
single-format builds with a symbol check of the disabled format, Cortex-M33 and Cortex-M4 builds with their
sizes, fuzz smoke runs, `cargo deny`), then the interoperability tests against wacryptolib, which live in the C
tree and drive any mix of C and Rust builds:

```sh
tox -e rust_flightbox
# or, by hand:
WA_FLIGHTBOX_C_BUILD_DIR=reimplementations/rust/target/debug pytest reimplementations/c-language/tests/interop
```

The script needs, beyond Rust: libclang and a C compiler (wolfCrypt backend), `arm-none-eabi` binutils (code
sizes), a nightly toolchain with `cargo-fuzz`, and `cargo-deny`. It skips, with a message, the steps whose tool
is missing, unless `WA_REQUIRE_ALL_STEPS=1`. When the C builds of `tox -e c_flightbox` exist, they join the
interoperability run, which then compares Rust and C outputs.

Tests:

- **Backend conformance**: published vectors for each primitive (SP 800-38A, RFC 8439, FIPS 180-4, RFC 4231,
  RFC 7748, a 4096-bit raw RSA value, an ML-KEM-768 known answer), with multi-call streaming and edge cases.
- **Unit tests**: codecs against bytes generated by wacryptolib, the decoder against every vector of the WA-CBOR
  specification, the composites against SP 800-38B, EAX and OAEP references, RFC 5869 and RFC 9180, Shamir against
  pycryptodome, key constraints, validation rules with their error locations, chunking equivalence, the failed
  state, wiping of released memory and peak allocation.
- **Interoperability**: every cryptainer is loaded, checked and decrypted by wacryptolib; rejections are compared
  with wacryptolib's; builds are compared with each other.
- **Fuzzing**: the WA-CBOR decoder and the profile loader, seeded like the C targets.
