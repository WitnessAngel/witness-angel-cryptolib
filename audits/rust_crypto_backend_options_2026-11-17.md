# Crypto backend options for a Rust flightbox encryptor

Date: 2026-11-17. Status: exploration report, nothing built or benchmarked.

Question: for a Rust reimplementation of the flightbox encryptor (`reimplementations/rust/`), should the crypto
backend be the same as for the C one (wolfCrypt or Mbed TLS), or are there better Rust-only options?

Short answer: they should not be the same. In Rust the natural backend is the pure-Rust **RustCrypto** crate
family; wolfCrypt and Mbed TLS are reachable through wrappers but become the "second backend" option, not the
default.

## What the backend actually has to provide

The C library asks very little of its backend, because OAEP, HPKE, EAX, HKDF and Shamir are all portable code in
`reimplementations/c-language/src/primitives/`. A Rust port can keep the same seam:

```
+--------------------------------------------------------------+
|  flightbox encryptor (profile loader, WA-CBOR, key layers)   |
+--------------------------------------------------------------+
|  portable primitives: OAEP-SHA512 padding, HPKE, EAX/CMAC,   |
|  HKDF, Shamir GF(2^128), wiping                              |
+--------------------------------------------------------------+
|  backend seam (a small trait)                                |
|   AES block/CBC/CTR | ChaCha20 + Poly1305 | SHA-256/512      |
|   HMAC | raw RSA public op | X25519 | ML-KEM-768 encaps      |
+------------------+---------------------+---------------------+
|  RustCrypto      |  wolfCrypt (FFI)    |  Mbed TLS (FFI)     |
+------------------+---------------------+---------------------+
```

Two properties of the encryptor matter for the choice:

- **It only does public-key operations.** The best-known weakness of the Rust `rsa` crate (the Marvin attack,
  non-constant-time private exponentiation) concerns decryption and does not apply to a device that only encrypts.
- **It needs injected randomness.** The byte-identical tests need deterministic ML-KEM encapsulation and HPKE
  ephemeral keys fed from the platform hooks.

## The options

| Option | Fit for a `no_std` MCU | Main drawback |
|---|---|---|
| **RustCrypto** (`aes`, `cbc`, `ctr`, `cmac`/`eax`, `chacha20`, `poly1305`, `sha2`, `hmac`, `hkdf`, `x25519-dalek`, `ml-kem`, `rsa` or `crypto-bigint`) | Best: pure Rust, plain `cargo build --target thumbv7em-none-eabihf`, no C toolchain | No FIPS validation, software-only, `rsa` 0.10 still in release candidates |
| **wolfCrypt via wolfSSL's `wolfcrypt` crate** | Good: it implements the RustCrypto traits, so it can sit behind the same seam | C cross-compilation and `user_settings.h` come back, plus licence review |
| **Mbed TLS via `rust-mbedtls`** | Workable: `no_std` but needs an allocator and a C build | No ML-KEM (mlkem-native would be vendored again), heaviest build |
| **libcrux** (formally verified) | Possible for ML-KEM only, using its portable path | All crates below 0.1, and its verification claims were publicly disputed in February 2026 |
| **aws-lc-rs / ring** | Poor: aimed at servers and desktops, no bare-metal support found | ring also lacks EAX, ML-KEM and RSA-OAEP encryption |

## Recommendation

Use RustCrypto as the primary backend, behind a trait that mirrors the C seam. To keep the "two backends,
byte-identical output" property, add wolfCrypt as an optional second one, which is cheap because its wrapper speaks
the same traits.

Wrapping the C backends as the default would give up the two things a Rust port offers: memory safety down to the
primitives, and a build with no C toolchain. It would also make the Rust tree a less independent check of the
specification, since it would share crypto engines with the C one.

## Gotchas to know before committing

- **RustCrypto generation skew.** The family moved to new trait versions together in 2026 (`digest` 0.11, `cipher`
  0.5, `chacha20poly1305` 0.11), but no stable `rsa` release supports them yet. Doing OAEP in portable code, as the
  C library does, means only a modular exponentiation is needed, and `crypto-bigint` could be used directly.
- **Streaming.** The `chacha20poly1305` crate is one-shot over a whole buffer. For offloaded payloads fed in chunks
  with bounded memory, `chacha20` and `poly1305` would be composed by hand; EAX needs the same treatment or the
  `eax` crate's online mode (its current API was not checked).
- **ML-KEM audit status.** The `ml-kem` docs say it has never been independently audited; another source claims
  otherwise. Check the RustCrypto/KEMs README before relying on it.
- **Hardware acceleration.** RustCrypto will not use the AES/SHA/MPI accelerators that the C backends get on ESP32
  or STM32. If throughput on video payloads matters, that needs a HAL-backed implementation of the seam.
- **Allocator.** RSA in Rust needs `alloc` in practice (heap big integers), so a fully heap-free build is unlikely
  with RSA trustees.

## Transpiling Rust to C (added 2026-11-18)

Question: to get Rust's memory safety, can the implementation be written in Rust and transpiled to C, for
portability and hardware AES?

It is possible, but it is not a sound base, and neither goal needs it.

**Hardware AES needs no transpilation.** It comes from the backend seam: the Rust core calls a trait, and one
implementation of that trait forwards to `extern "C"` functions supplied by the firmware (ESP-IDF's Mbed TLS, an
STM32 HAL, wolfCrypt). This is the same idea as the platform hooks of the C library.

**Portability mostly needs none either.** Rust compiles natively to Cortex-M, RISC-V and ESP32 (Xtensa through
Espressif's toolchain). The Rust code is built as a `no_std` static library with a C header generated by
`cbindgen`, and C firmware links it like any other `.a`.

```
+---------------------------+      +---------------------------+
|  C firmware (ESP-IDF,     | ---> |  libwa_flightbox.a        |
|  STM32Cube, Zephyr...)    |  C   |  Rust, no_std, C API      |
+---------------------------+ API  +-------------+-------------+
                                                 | crypto trait
                           +---------------------+--------------------+
                           |                                          |
                  +--------v---------+                  +-------------v------------+
                  | RustCrypto       |                  | extern "C" hooks         |
                  | (pure software)  |                  | hardware AES/SHA/RSA via |
                  +------------------+                  | the firmware's library   |
                                                        +--------------------------+
```

Transpilation only earns its place for targets with a C compiler but no Rust backend (vendor-only GCC forks, IAR or
Keil without LLVM, 8/16-bit chips). The tools:

| Tool | State | Verdict |
|---|---|---|
| **Eurydice** (Inria/Microsoft) | Produces readable C; there is a worked Z80 demo, but LWN (January 2026) puts its practical ceiling at small examples | The only one aimed at shipping C, but it accepts a restricted subset of Rust, so the code must be written for it from day one |
| **rustc_codegen_c / cilly** | Translate compiler output to C; cilly managed to translate rustc itself | Experimental, unreadable output, no embedded track record found |
| **mrustc** | Built for bootstrapping rustc; its README calls its output "very ugly C" | Not meant for shipping code |
| **Rust to WebAssembly to C** (`wasm2c`) | Mature, used in Firefox for sandboxing | Portable and sandboxed, but slow and awkward on an MCU |

On memory safety: the compile-time guarantees do survive transpilation, since the borrow checker has already run
and bounds checks are emitted into the C. But the generated C is nobody's source code: it cannot be reviewed or
debugged comfortably, and Eurydice's author recommends `-fno-strict-aliasing` because the output can trip C's
aliasing rules.

Whichever route is taken, the safety guarantee stops at the crypto hooks: a hardware AES call is C code again, as
is the firmware around it. What Rust protects is the part most exposed to hostile input: the WA-CBOR decoder, the
profile loader and the key-layer logic.

## Target chips: STM32U3, STM32U5 and MSP430 (added 2026-11-18)

| Chip | Rust target | Support level | Hardware crypto from Rust |
|---|---|---|---|
| **STM32U5** (Cortex-M33) | `thumbv8m.main-none-eabihf` | Stable toolchain, prebuilt `core` | Chip metadata covers AES, SAES, PKA and HASH; working `embassy-stm32` drivers on U5 not confirmed |
| **STM32U3** (Cortex-M33) | same | Same compiler support; chip support has landed in `embassy-stm32` | Only HASH is described in the metadata; AES, SAES and PKA are marked unsupported so far |
| **MSP430** | `msp430-none-elf` | Tier 3: nightly only, `core` rebuilt locally with `-Zbuild-std`, not tested by the Rust project | None found |

### STM32U3 and U5

The compiler side is a non-issue. Hardware AES depends on the exact part: on U3, only the U385 line (and
U366/U3C5) has AES, SAES and PKA; the U375 has HASH only.

Where the Rust HAL lacks a driver, the C-hooks backend covers it: the Rust core calls ST's HAL or wolfCrypt's ST
port, which lists hardware HASH, RNG, SAES and PKA for both U3 and U5.

### MSP430

Two things block a Rust port there, and the second would bite a C build too:

- **64 KB address space.** Rust's MSP430 target hard-codes 16-bit pointers, and no support was found for the 20-bit
  MSP430X large memory model. Code, constants and RAM must all fit under 64 KB.
- **The library is bigger than that.** The measured Cortex-M4 build of the C library is about 22 KB for
  `wa_flightbox`, 8 KB for ML-KEM and 40 KB for the minimal Mbed TLS, so roughly 70 KB of code before linker garbage
  collection. Peak heap is 14.7 KB for the simplest profile measured, while many MSP430 parts have 8 KB of RAM or
  less.

So MSP430 is where the existing C library earns its keep: `msp430-elf-gcc` supports the large memory model on
MSP430X parts with enough FRAM. Even there it would likely need a trimmed configuration (for example dropping RSA
trustees), and whether the C code is clean for 16-bit `int` has not been checked.

Transpiling Rust to C for MSP430 would hit the same size and RAM limits, so it buys nothing over the C library.

### Resulting plan

```
STM32U5 / U3  -->  Rust core (no_std staticlib)
                     + RustCrypto software backend
                     + C-hooks backend for AES/SAES/PKA where the part has them

MSP430        -->  existing C library, large memory model, reduced feature set
```

## Limits of this report

Exact current versions were not verified on crates.io, and nothing was built for a Cortex-M or MSP430 target. The
version details come from web search results, some of them vendor-authored (wolfSSL's benchmark and FIPS article).
The state of the `embassy-stm32` crypto drivers on U5 and U3 was read from changelogs and chip metadata, not from
the driver sources.

## Open questions

1. Is the Rust port meant as an independent third implementation, or mainly a way to use the flightbox from Rust
   firmware? In the second case, a thin `-sys` wrapper over the existing C library is far less work than a port.
2. Which exact STM32U3 and U5 parts are targeted? Only some have AES, SAES and PKA.
3. Which MSP430 part, with how much flash and RAM, and what must it encrypt? This decides whether any configuration
   fits.
4. Does anyone downstream need FIPS-validated crypto? That is the one requirement that would push wolfCrypt to the
   primary slot.

## Sources

- [RustCrypto/RSA repository](https://github.com/rustcrypto/rsa)
- [RSA v0.10.0-rc.20 pull request](https://github.com/RustCrypto/RSA/pull/768)
- [rsa on lib.rs](https://lib.rs/crates/rsa)
- [ml-kem on lib.rs](https://lib.rs/crates/ml-kem)
- [ml-kem docs](https://docs.rs/ml-kem/latest/ml_kem/)
- [chacha20poly1305 on lib.rs](https://lib.rs/crates/chacha20poly1305)
- [x25519-dalek on lib.rs](https://lib.rs/crates/x25519-dalek)
- [RustCrypto generation migration PR (satkeep)](https://github.com/brent472/satkeep/pull/25)
- [RustCrypto family migration PR (nife)](https://github.com/nifeos/nife/pull/2733)
- [wolfSSL: Rust path to FIPS-certifiable crypto](https://www.wolfssl.com/rust-finally-has-a-path-to-fips-certifiable-crypto/)
- [wolfSSL vs MbedTLS benchmark](https://www.wolfssl.com/wolfssl-vs-mbedtls-an-apples-to-apples-benchmark-across-intel-arm-cortex-a-and-cortex-m-and-risc-v-targets/)
- [mbedtls crate on lib.rs](https://lib.rs/crates/mbedtls)
- [libcrux repository](https://github.com/cryspen/libcrux)
- [libcrux-ml-kem](https://github.com/cryspen/libcrux/tree/main/libcrux-ml-kem)
- [Symbolic Software: bugs in Cryspen's verified code](https://symbolic.software/blog/2026-02-12-cryspen-response/)
- [FIPS 203/205 C and Rust library maturity](https://quantumsecuritydefence.com/insights/fips-203-205-implementation-c-rust-libraries/)
- [ycrypto organisation](https://github.com/ycrypto)
- [Compiling Rust to readable C with Eurydice (LWN)](https://lwn.net/Articles/1055211/)
- [Three Paths to Rust on Custom Hardware](https://tinycomputers.io/posts/three-paths-to-rust-on-custom-hardware.html)
- [crustc ports rustc to C](https://dev.to/randomchaos/crustc-ports-rustc-to-c-and-builds-it-with-gcc-1lbm)
- [crustc discussion (Hacker News)](https://news.ycombinator.com/item?id=48768464)
- [rustic-compiler organisation](https://github.com/rustic-compiler)
- [mrustc](https://github.com/thepowersgang/mrustc)
- [Embedonomicon: a note on compiler support](https://docs.rust-embedded.org/embedonomicon/compiler-support.html)
- [Rust platform support](https://doc.rust-lang.org/nightly/rustc/platform-support.html)
- [msp430_none_elf target spec](https://codebrowser.dev/rust/rust/compiler/rustc_target/src/spec/targets/msp430_none_elf.rs.html)
- [msp430-quickstart](https://github.com/rust-embedded/msp430-quickstart)
- [msp430-rt docs](https://docs.rs/msp430-rt)
- [embassy-stm32 changelog](https://docs.rs/crate/embassy-stm32/latest/source/CHANGELOG.md)
- [embassy-stm32 Cargo.toml](https://github.com/embassy-rs/embassy/blob/main/embassy-stm32/Cargo.toml)
- [stm32-data issue #678: STM32U3 support](https://github.com/embassy-rs/stm32-data/issues/678)
- [stm32-data-generated](https://github.com/embassy-rs/stm32-data-generated)
- [ST wiki: security features on STM32U3](https://wiki.st.com/stm32mcu/wiki/Security:Security_features_on_STM32U3_MCUs)
- [ST AN6051: migrating from STM32L4 to STM32U3](https://www.st.com/resource/en/application_note/an6051-migrating-from-stm32l4-and-stm32l4-to-stm32u3-mcus-stmicroelectronics.pdf)
- [wolfSSL ST port README](https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/port/st/README.md)
