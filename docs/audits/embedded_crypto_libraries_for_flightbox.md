# Cryptographic libraries for flightbox encryptors on microcontrollers

Date: 2026-11-13 (the MicroPython part, section 6, was first written on
2026-10-30). Status: audit, no code changed.
Scope: which cryptographic library (or combination) best provides
wacryptolib's algorithms, or a subset of them, to a C or Rust
reimplementation of the flightbox *encryptor* on microcontrollers such as
the ESP32 family or the Raspberry Pi Pico (RP2040 / RP2350), and how far the
pure-Python MicroPython port (`reimplementations/micropython/`) can go
without one. Complements
`../flightbox_specifications/flightbox_encryptor_specification.md`
(sections 3 and 4 for the primitives), `archives/post_quantum_algorithms_report.md`
(section 6 for MicroPython timing estimates) and
`flightbox_cryptoconf_storage_format.md` (the input format). Library and
hardware facts were checked online against primary sources (section 9);
performance figures are estimates.

## Summary

- **The embedded subset is small.** An encryptor only encrypts with public
  keys, and devices whose trustees are authenticators never sign. What is
  needed: one payload cipher, `ECIES_X25519` and/or `RSA_OAEP` key wrapping,
  optionally `ML_KEM_768`, a hardware RNG, and code that no library provides
  (Shamir over GF(2^128), Extended JSON writer, UUID0, RSA chunking).
- **C on ESP32 (the current prototype): Mbed TLS**, bundled with ESP-IDF and
  using the chip's AES / SHA / RSA accelerators, plus small glue (HPKE seal,
  AES-EAX) and **mlkem-native** if ML-KEM is wanted. ESP-IDF 5.x ships
  Mbed TLS 3.6, where SHA-3, ChaCha20-Poly1305, HKDF and CMAC must be enabled
  in menuconfig; ESP-IDF 6.x ships Mbed TLS 4.x, where crypto goes through
  the PSA API.
- **Single C library alternative: wolfCrypt**, which natively covers AES-EAX,
  SHA-3, ML-KEM and ML-DSA, and has ESP32 and Raspberry Pi Pico ports, but is
  GPL-3.0-or-later (since 5.8.2) or commercial, and its HPKE only offers
  AES-GCM, not the ChaCha20-Poly1305 AEAD we use.
- **Rust: RustCrypto crates + `hpke` + `ml-kem`**, the most complete
  off-the-shelf coverage: the `hpke` crate has our exact X25519 suite, usable
  without a heap, **and** ML-KEM-768 with the same HPKE KEM id (0x0041) as
  pycryptodome. Costs: toolchain friction on Xtensa ESP32 chips, and
  hardware acceleration drivers that are still unstable in esp-hal.
- **Hardware matters more than the library**: the RP2040 has no true RNG,
  the ESP32 RNG is only truly random under conditions, the Pico SDK's
  `pico_rand` is not a cryptographic generator on either Pico chip, and
  without hardware AES the payload cipher should be `CHACHA20_POLY1305`.
- **MicroPython has no native crypto library to lean on**, so its port uses
  vendored pure-Python code. `ECIES_X25519` is supported, at an estimated
  0.5-1 s per seal on an ESP32-S3. `ML_KEM_768` is feasible as a
  pure-Python, encryption-only port (10-20 KB of RAM, but seconds per
  encapsulation because of Keccak), or in milliseconds by building
  mlkem-native into the firmware as a C user module (section 6).

## 1. What an embedded encryptor needs

```
                         needed on device?         notes
 payload ciphers         1 of: CHACHA20_POLY1305   streaming, the only bulk-throughput cost
                               AES_EAX / AES_CBC   (AES only worth it with hardware AES)
 key wrapping            ECIES_X25519              HPKE seal: X25519 + HKDF-SHA256 + ChaCha20-Poly1305
                         RSA_OAEP                  public op only, SHA-512 + MGF1-SHA-512, 60-byte chunks
                         ML_KEM_768 (optional)     encapsulation only, HPKE KEM id 0x0041 (IETF draft)
 hashes                  only if signature confs   none with authenticator trustees
 signatures              no                        authenticators can't sign; local_keyfactory would put
                                                   private keys on the device
 always custom code      Shamir over GF(2^128) (NOT the bit-reflected GCM convention, so a library's
                         GHASH can't be reused), Extended JSON writer, UUID0, RSA chunking, the core
 RNG                     the real hardware question (section 5)
```

Signatures stay out of scope: per section 4 of the specification, an
`authenticator` trustee can't sign, and a `local_keyfactory` trustee would
require private keys, their generation and storage on the device.

## 2. Candidate libraries

| | **Mbed TLS 3.6 (ESP-IDF 5.x) / 4.x (ESP-IDF 6.x)** | **wolfCrypt** | BearSSL | Monocypher | **RustCrypto + `hpke` + `ml-kem`** |
|---|---|---|---|---|---|
| AES-256-CBC + PKCS#7 | yes | yes | yes | no | `aes` + `cbc` (`block_padding::Pkcs7`) |
| AES-EAX | no: about 80 lines of glue on its CTR + CMAC | **yes, native** | **yes, native** (`br_eax_*`) | no | `eax` crate (nonce fixed at 16 bytes, 16-byte tag: matches pycryptodome) |
| ChaCha20-Poly1305 (RFC 8439) | yes (off by default in ESP-IDF 5.x) | yes | yes | yes (`crypto_aead_init_ietf`) | `chacha20poly1305` |
| SHA-2 / SHA-3 | yes / yes since 3.5 (off by default in ESP-IDF 5.x) | yes / yes | yes / no | SHA-512 only (optional module) / no | `sha2` / `sha3` |
| RSA-OAEP SHA-512, encryption | yes | yes | yes | no | `rsa` 0.10 (needs `alloc`; `Oaep::new::<Sha512>()` also uses SHA-512 for MGF1) |
| X25519 + HKDF-SHA256 | yes (X25519 on by default, HKDF off by default in ESP-IDF 5.x) | yes | yes | X25519, but HKDF-SHA-512 only | `x25519-dalek`, `hkdf` |
| HPKE seal with our exact suite | no: about 150 lines of glue (the Python one is 162 lines) | has HPKE, but **AES-GCM AEADs only, no ChaCha20-Poly1305** | no | no | **`hpke` crate: KEM 0x0020 + ChaCha20-Poly1305, heapless via `single_shot_seal_inout_detached_with_rng`** |
| ML-KEM-768 | no (none in any release; integrating mlkem-native is planned): add **mlkem-native** | **yes, native** | no | no | `ml-kem` (never audited) or `libcrux-ml-kem` (hax/F* verified, 0.0.x); **HPKE KEM 0x0041 in the `hpke` crate** |
| ML-DSA-65 | no (only an internal ML-DSA-87 preview in TF-PSA-Crypto 1.2) | yes | no | no | `ml-dsa` (never audited) |
| Hardware acceleration | **ESP-IDF port**: AES, SHA, RSA/MPI on by default | ESP32 port (AES, SHA, RSA/MPI on ESP32/S2/S3/C3/C6); RP2040/RP2350 port with RP2350 TRNG | no | no | esp-hal AES/SHA/RSA drivers exist but are **unstable** and not wired into RustCrypto |
| License | Apache-2.0 or GPL-2.0-or-later | **GPL-3.0-or-later** (since 5.8.2, July 2025) or commercial | MIT | CC0-1.0 or BSD-2-Clause | MIT / Apache-2.0 |

BearSSL's last release is still 0.6 (2018), though occasional bug-fix
commits continue (latest in 2026), and Monocypher only covers the
`ECIES_X25519` part (with HKDF-SHA-512 instead of HKDF-SHA256): useful
references, not foundations. wolfCrypt also has an official Rust wrapper
(`wolfssl-wolfcrypt` crate, GPL-3.0, `no_std`), which links to a separately
built wolfSSL C library: an option for a Rust port wanting wolfCrypt's
coverage.

`rsa` crate: its Marvin timing advisory (RUSTSEC-2023-0071) concerns leaks of
private-key information, so it does not apply to OAEP encryption with a
public key; RustSec lists it as patched since `rsa` 0.10.0 (2026-11-08).

## 3. Three ways to build it

```
 A) C, least friction on ESP32           B) C, a single library            C) Rust
 +-------------------------------+       +----------------------------+    +------------------------------+
 | core + ExtJSON + Shamir       |       | core + ExtJSON + Shamir    |    | core + ExtJSON + Shamir      |
 | glue: HPKE seal, EAX, chunking|       | glue: HPKE w/ ChaCha,      |    | glue: chunking               |
 +---------------+---------------+       |       chunking             |    +------------------------------+
 | Mbed TLS (in  | mlkem-native  |       +----------------------------+    | RustCrypto, hpke (X25519 and |
 | ESP-IDF, HW)  | (optional PQ) |       | wolfCrypt (EAX, SHA3,      |    | ML-KEM suites), ml-kem,      |
 +---------------+---------------+       | ML-KEM, ML-DSA, HW ports)  |    | no_std, memory-safe          |
                                         +----------------------------+    +------------------------------+
 glue: most                              glue: least in C                   glue: least overall
 license: Apache-2.0                     license: GPL-3.0+ or commercial    license: MIT / Apache-2.0
```

- **A, for the existing C prototype (ESP-IDF on ESP32).** Mbed TLS is already
  there and already uses the chip's crypto hardware. The missing pieces are
  small and fully specified: HPKE seal, EAX, and optionally mlkem-native
  (Apache-2.0 / ISC / MIT, C90, memory safety proven with CBMC). On ESP-IDF
  5.x, SHA-3, ChaCha20-Poly1305, HKDF and CMAC must be enabled in
  menuconfig. ESP-IDF 6.x moved to Mbed TLS 4.x, where the legacy
  `mbedtls_*` crypto API is mostly gone: coding against the PSA Crypto API
  from the start avoids a rewrite, and would also let a later port use
  secure elements or TF-M.
- **B** covers the most in one C package, including EAX and ML-KEM, and has
  ports for both ESP32 and the Raspberry Pi Pico. Its licence is compatible
  with wacryptolib's GPL-2.0-or-later, but makes the firmware GPLv3 unless a
  commercial licence is bought, and HPKE glue is still needed: wolfCrypt's
  HPKE only offers AES-GCM AEADs.
- **C** has the best off-the-shelf coverage, including both HPKE suites we
  need. The ESP32-S3's Xtensa core still needs Espressif's forked compiler
  (installed with `espup`), while the RISC-V ESP32-C3/C6/H2 and the Pico
  chips use stock Rust targets. esp-hal's crypto accelerator drivers are
  unstable (behind its `unstable` feature); embassy-rp has an RP2350 TRNG
  driver, rp235x-hal does not.

Code no library provides, whatever the option: the flightbox core, the
Extended JSON writer, Shamir over GF(2^128) (section 3.7 of the
specification), UUID0 and the 60-byte RSA-OAEP chunking.

## 4. Cost estimates

Order-of-magnitude estimates from published benchmarks, not measurements on
our workload:

- RSA-2048 public operation (e = 65537): milliseconds, a few per cryptainer
  (one per 60-byte chunk of the key struct).
- X25519: 3.6 million cycles on a Cortex-M0 with hand-written assembly
  (Düll et al. 2015), about 27 ms at 133 MHz; portable C (Mbed TLS,
  Monocypher) or code running from flash is slower, up to about 100 ms. An
  HPKE seal needs two scalar multiplications.
- ML-KEM-768 encapsulation in C: on a Cortex-M4 (pqm4 benchmarks), about
  0.66 million cycles and 2.9 to 6.5 KB of stack for optimized code, 1.14
  million cycles and 13 KB of stack for portable C. That is milliseconds at
  150 to 240 MHz, versus seconds in pure MicroPython (section 6.3).
- The real budget is payload throughput. Without hardware AES,
  ChaCha20-Poly1305 is both faster and naturally constant-time, whereas
  table-based software AES risks timing leaks.

## 5. Hardware

| | RNG | Crypto accelerators | Consequence |
|---|---|---|---|
| ESP32 / ESP32-S3 | hardware RNG, **truly random only while Wi-Fi/BT is on, while the SAR ADC entropy source is enabled by `bootloader_random_enable()`, or during the second-stage bootloader**; otherwise pseudo-random | AES, SHA-1/2 (up to SHA-512), RSA big-number unit; **no** ECC, X25519 or SHA-3 accelerator | AES ciphers come almost free; keep the radio or the ADC entropy source on while generating keys |
| RP2040 (Pico, Pico W) | **no TRNG**: only the ring-oscillator `RANDOMBIT`, which the datasheet says "does not meet the requirements of randomness for security systems" | none | weak key generation unless a secure element is added; avoid |
| RP2350 (Pico 2) | TRNG (Arm IP, about 7.5 kb/s at 150 MHz) | SHA-256 only, no AES | read the TRNG into a DRBG; prefer `CHACHA20_POLY1305` for payloads |

Details:

- **ESP32 RNG API**: `esp_random()` and `esp_fill_random()`. The ADC entropy
  source enabled by `bootloader_random_enable()` must be disabled with
  `bootloader_random_disable()` before starting Wi-Fi/BT, the ADC or (on the
  original ESP32) I2S. On the ESP32-P4, which has no radio, the ADC source is
  kept enabled at startup. ESP-IDF recommends seeding an Mbed TLS CTR_DRBG or
  HMAC_DRBG when the entropy source can't stay enabled.
- **ESP32 ECC accelerators** exist only on other variants (C2, C5, C6, H2,
  P4...), for NIST P-192/P-256 (P-384 on a few): no ESP32 accelerates
  Curve25519.
- **Pico SDK `pico_rand` is not a cryptographic generator**: it mixes its
  entropy sources into a xoroshiro128** generator. On RP2040 those sources
  are the ring oscillator, timers and bus counters; on RP2350 it uses the
  TRNG, but still through xoroshiro128**. Key material must come from the
  TRNG (or a secure element) through a DRBG, not from `pico_rand`.
- **Secure elements**: Microchip recommends the ATECC608C for new designs
  (the ATECC608A is "Not Recommended for New Designs" since 2020); its TRNG
  holds a NIST SP 800-90B entropy source certificate, over I2C.
- RP2040 clocks: 133 MHz rated, 200 MHz at a raised 1.15 V core voltage;
  RP2350: 150 MHz.

Whatever the library, its DRBG (CTR_DRBG, HMAC_DRBG, `rand_core` RNG)
must be seeded from the hardware TRNG, never from a seedable PRNG
(section 3.1 of the specification).

## 6. MicroPython: pure-Python crypto, no native library

The MicroPython port can't load pycryptodome's C code, and the firmware
exposes no crypto library beyond `hashlib`/`uhashlib` and `cryptolib`, so
its asymmetric primitives are vendored pure Python
(`reimplementations/micropython/lib/`, regenerated by
`vendor_dependencies.py`):

| Primitive | MicroPython implementation | State |
|---|---|---|
| `AES_CBC` | `pyaes` | supported |
| `RSA_OAEP` (SHA-512, MGF1-SHA-512) | `pkcs1` + `rsa` | supported |
| `ECIES_X25519` | `hpke_x25519_seal.py` + `chacha20_poly1305.py` | supported, not yet run on a device (section 6.2) |
| `ML_KEM_768` | none | feasible as a pure-Python port (section 6.3) |
| SHA-256 | built-in `uhashlib`, tried first by the vendored `hashlib` | native, so HKDF and HMAC are cheap |
| SHA-512 | pure-Python fallback of the vendored `hashlib` | supported, slow |
| SHA-3 / SHAKE | none: `fallback_adapter.py` drops `SHA3_*` when missing | missing, needed by ML-KEM |
| Randomness | `os.urandom` | backed by the hardware RNG, with the conditions of section 5 |

`os.urandom` inherits the hardware limits of section 5: on an ESP32 it is
only truly random under the listed conditions, and a MicroPython port on an
RP2040 has no true RNG behind it.

### 6.1 Only encryption is needed on the device

As in C and Rust, the device encapsulates to a trustee's *public* key and
never decrypts: only key decoding, encapsulation, key derivation and AEAD
encryption are needed, and decapsulation stays on PCs and phones. The
device receives raw keys in the key dict, as it already does for X25519
(`flightbox_utilities_implementation.py`,
`public_key_parameters["x25519"]`), so a raw 1184-byte ML-KEM-768 public
key needs no PEM/ASN.1 parsing either.

pycryptodome 4.2 exposes ML-KEM encapsulation only through
`Crypto.Protocol.HPKE` (`MLKEMKey` has no public `encapsulate()`, only the
private `_encaps()` / `_decaps()`): another reason to keep HPKE as the wire
format on both sides rather than invent a custom KEM + AEAD framing.

### 6.2 `ECIES_X25519` on an ESP32-S3

Based on reading the code, not on a run on a device.

- **Python compatibility.** The two blockers found by the first version of
  this audit are fixed: star-unpacking inside list displays, which
  MicroPython rejects (commit `8321779`), and `bytes.ljust()` in Poly1305
  padding, which it lacks (commit `95ce17e`). Expected to work: big ints,
  3-argument `pow()`, `struct` `"<QQ"` / `"<8I"`, `int.from_bytes()` /
  `to_bytes()` with a positional byte order, `bytes(n)` zero padding, and
  the relative-import fallback of `hpke_x25519_seal.py` (MicroPython raises
  `ImportError`, which is caught).
- **Memory.** The sealed plaintext is a small key struct, so the working
  set is a few dozen 256-512-bit ints and a few 64-byte ChaCha20 blocks: a
  few KB at peak. Garbage is heavy (about 255 ladder steps of about 20
  temporary ints) but short-lived. The larger cost is compiling the two
  modules from source at import, about 10-20 KB of transient RAM;
  precompiling them to `.mpy` with `mpy-cross`, or freezing them into the
  firmware, removes most of it. The import is lazy, so RSA-only deployments
  don't pay it.
- **Speed** on an ESP32-S3 at 240 MHz: one X25519 scalar multiplication
  (255-step ladder, about 18 big-int operations per step, plus a modular
  inverse) takes an estimated 0.2-0.5 s, so a seal (2 scalar
  multiplications, about 10 HMAC-SHA256 with native SHA-256, a few ChaCha20
  blocks) takes **about 0.5-1 s**. ChaCha20's 32-bit words exceed
  MicroPython's 31-bit small ints, so each operation allocates, but only a
  few blocks are processed. The cost is paid once per `ECIES_X25519` key
  layer per cryptainer, in the same range as the pure-Python RSA-OAEP
  encryption already used, against tens of milliseconds in C (section 4).

### 6.3 `ML_KEM_768`

pycryptodome's ML-KEM is C code loaded at runtime (`mlkem_encaps` /
`mlkem_decaps` in `_raw_mlkem_lib`), with no pure-Python fallback, so the
device needs its own *encryption-only* ML-KEM-768 + HPKE seal, vendored like
`hpke_x25519_seal.py`. wacryptolib's `ML_KEM_768` suite already uses
HPKE ML-KEM-768 + HKDF-SHA256 + ChaCha20-Poly1305 (switched from
AES-256-GCM in commit `e1f4461`, because `pyaes` has no GCM), so the
device would reuse the vendored ChaCha20-Poly1305 and HPKE key schedule:
only the KEM is new.

| Need | Desktop (pycryptodome 4.2) | MicroPython today | Gap |
|---|---|---|---|
| ML-KEM-768 encapsulation | C, via HPKE | none | pure-Python port (e.g. from kyber-py), checked against FIPS 203 vectors |
| SHA3-256, SHA3-512, SHAKE128, SHAKE256 | yes | none | pure-Python Keccak-f[1600] |
| HKDF-SHA256, ChaCha20-Poly1305 | yes | vendored, as for `ECIES_X25519` | none |
| Randomness | `get_random_bytes` | `os.urandom` | none, but it must be truly random: predictable encapsulation randomness leaks the shared secret |

**Memory is not the problem.** On an ESP32-S3 (about 512 KB of internal
SRAM, a few hundred KB of MicroPython heap, often plus 2-8 MB of PSRAM):

| Item | Size |
|---|---|
| Public key (input) | 1184 bytes |
| KEM ciphertext (output) | 1088 bytes |
| Shared secret | 32 bytes |
| Matrix A (3x3 polynomials of 256 coefficients < 3329) | about 4.6 KB as `array('H')`, about twice that as lists |
| Vectors r, e1, u, plus e2, v and the message polynomial | a few KB |
| Keccak state | 200 bytes (50 32-bit words if bit-interleaved) |

That is a working set of **10-20 KB** plus temporary objects, which fits
even without PSRAM, in line with the 13 KB of the portable C code
(section 4). The practical risk is heap fragmentation from repeated big-int
and bytes allocations: preallocate `array` buffers and reuse them.

**Speed is the problem, because of Keccak.** Polynomial arithmetic is
modulo 3329 and stays in small ints, but Keccak works on 64-bit lanes, which
become heap-allocated big ints in MicroPython (31-bit small ints), with
heavy garbage collection. Mitigations: a bit-interleaved Keccak on 32-bit
halves (the standard technique for 32-bit CPUs);
`@micropython.viper` / `@micropython.native` on the permutation and the NTT;
and caching matrix A, which is expanded from the public key's seed only
(most of the SHAKE128 work) and can be computed once at boot per trustee
key (about 4.6 KB each). The estimate is **1-5 s per encapsulation**
(`archives/post_quantum_algorithms_report.md` section 6), paid once per cryptainer
and per ML-KEM key layer: probably acceptable, to benchmark on real
hardware.

Options, by effort:

1. **Pure-Python encapsulation and Keccak**, vendored in
   `reimplementations/micropython/lib/`, cross-checked against FIPS 203
   known-answer vectors and against pycryptodome 4.2's HPKE `unseal()`:
   seconds per encapsulation, no firmware change.
2. **Keccak as an `.mpy` native module** (about 100 lines of C): likely well
   under a second per encapsulation.
3. **A C user module wrapping mlkem-native** (which pycryptodome 4.x
   embeds) or PQClean: milliseconds and constant-time code, at the cost of
   maintaining a custom firmware build. This is the same library as
   option A of section 3, so a C port would share the work.

Like all pure-Python crypto on the flightbox, options 1 and 2 are not
guaranteed constant-time. For encapsulation the only secrets are the
ephemeral randomness and the shared secret, both single-use, which limits
the exposure to timing side channels compared with long-term private keys.

### 6.4 Next steps for MicroPython

1. Time one seal on a real ESP32-S3 (copy `reimplementations/micropython/lib/`
   to the board, time `hpke_x25519_seal.seal(bytes(range(32)), b"x" * 200)`)
   and check that pycryptodome decrypts the result on desktop. The
   MicroPython Unix port with `-X heapsize=` can confirm syntax and peak
   memory, but not ESP32-S3 timings.
2. For `ML_KEM_768`, start with option 1, gated by cross-validation tests
   against pycryptodome, and only move to options 2 or 3 if the timings
   measured on the ESP32-S3 are unacceptable.

## 7. Testing against wacryptolib

The in-progress OpenSpec change `add-compatibility-fixtures` provides what
C and Rust ports need: bidirectional symmetric cipherdict vectors and
decrypt-only asymmetric ones. The riskiest glue would be checked against it:
EAX, the HPKE key schedule, ML-KEM's draft KEM identifier, and Shamir's
non-GCM field encoding. Shamir output is random, so it can only be validated
end to end, by having wacryptolib decrypt the device's cryptainers
(section 12 of the specification).

## 8. Open questions

- **Which chip?** An Arduino Nano ESP32 script in the workspace suggests an
  ESP32-S3 (the board's u-blox NORA-W106 module contains one). A Pico 2
  would favour ChaCha20 and Rust; a classic Pico raises the RNG problem
  first.
- **Which ESP-IDF version?** 5.x keeps the classic Mbed TLS 3.6 API; 6.x
  requires PSA code. A new C port should probably target 6.x and PSA.
- **Is `RSA_OAEP` still required?** If every authenticator in the field can
  provide an X25519 key, dropping RSA removes the biggest dependency (big
  number arithmetic) from the device.
- **Is `ML_KEM_768` wanted on the device now, or later?** It is the piece
  that decides between options A, B and C, and whether the MicroPython port
  needs a pure-Python Keccak or a custom firmware build (section 6.3).
- **Does the MicroPython port stay the reference device implementation?**
  If a C or Rust port replaces it, the pure-Python ML-KEM work of section
  6.3 may not be worth doing.
- **Firmware licensing:** would GPLv3 firmware ever be a problem? This
  decides whether wolfCrypt is an option at all.
- **C or Rust?** The C prototype is still a skeleton, so this is the moment
  to choose.

## 9. Sources and verification

Checked online on 2026-11-13 against primary sources (project changelogs,
headers and Kconfig files, docs.rs, RustSec, ESP-IDF documentation, Raspberry
Pi datasheets, Microchip datasheets):

- **Mbed TLS**: SHA-3 added in 3.5.0 (`MBEDTLS_SHA3_C`, PSA
  `PSA_WANT_ALG_SHA3_*`; only the PSA option remains in 4.x). No EAX, no
  HPKE and no ML-KEM in any release (latest: 4.2.0, 3.6.7 and
  TF-PSA-Crypto 1.2.0, 2026-07-07). Licence Apache-2.0 OR GPL-2.0-or-later.
- **ESP-IDF**: the 5.x branches now track Mbed TLS 3.6.x LTS (5.2.2 and
  later), 6.0 (March 2026) ships Mbed TLS 4.x. In the 5.5 Kconfig, hardware
  AES / SHA / MPI and X25519 are enabled by default; SHA-3, CMAC,
  ChaCha20-Poly1305 and HKDF are disabled by default and can be enabled.
- **wolfCrypt**: `hpke.h` defines DHKEM P-256/384/521 and X25519 (X448
  declared but not implemented), HKDF-SHA256/384/512, and AEADs AES-128-GCM
  and AES-256-GCM only; `hpke.c` lists ChaCha20 as a to-do. Native AES-EAX,
  SHA-3, ML-KEM-512/768/1024 and ML-DSA-44/65/87. ESP32 and RP2040/RP2350
  ports (the RP2350 SHA-256 accelerator is not used, because of a hardware
  issue). Licence GPLv3-or-later since 5.8.2 (2025-07-17), with GPLv2
  exceptions for some named projects, or commercial.
- **BearSSL**: last release 0.6 (2018), bug-fix commits until 2026; has
  EAX, GCM, CCM and ChaCha20-Poly1305; no SHA-3, no ML-KEM.
- **Monocypher**: CC0-1.0 or BSD-2-Clause; X25519, ChaCha20 (IETF variant),
  Poly1305, RFC 8439-compatible AEAD; optional SHA-512 and HKDF-SHA-512;
  no SHA-256 and no AES.
- **mlkem-native**: C90, Apache-2.0 / ISC / MIT, CBMC proofs of memory safety
  for all C code, HOL-Light proofs for AArch64/x86-64 assembly; tested on
  Cortex-M3 to M55. It publishes no Cortex-M figures; the cycle and stack
  figures of section 4 come from pqm4's own implementations.
- **`hpke` crate** (rozbb/rust-hpke) 0.15.1: `#![no_std]`; X25519 KEM 0x0020,
  ML-KEM-768 0x0041, ML-KEM-1024 0x0042, X-Wing 0x647a (draft
  specifications); ChaCha20-Poly1305 and HKDF-SHA256. Default features
  include `getrandom` and `alloc`, to disable on microcontrollers.
  pycryptodome 4.2 (`Crypto.Protocol.HPKE`, checked locally) uses the same
  ids: 0x0020 for X25519 and 0x0041 with HKDF-SHA256 for ML-KEM-768.
- **Other Rust crates**: `eax` 0.6.1 (`Eax<Cipher, M = U16>`, nonce size =
  block size); `cbc` 0.2.1, `chacha20poly1305` 0.11.0, `x25519-dalek` 3.0.0,
  `rsa` 0.10.0, `ml-kem` 0.3.4, `libcrux-ml-kem` 0.0.11 (portable code proven
  with hax/F*, NEON largely unverified), `ml-dsa` 0.1.2; RUSTSEC-2023-0071
  marked patched in `rsa` 0.10.0 (the GitHub advisory copy still says
  unpatched). esp-hal 1.2.2 (unstable crypto drivers), embassy-rp 0.10.0
  (RP2350 `trng` module), rp235x-hal 0.4.0 (no TRNG module).
- **Hardware**: ESP-IDF "Random Number Generation" pages (ESP32-S3, C6, P4);
  ESP-IDF SoC capability macros (ECC, SHA); RP2040 datasheet section 2.17.5;
  RP2350 datasheet sections 12.12 (TRNG) and 12.13 (SHA-256 accelerator);
  pico-sdk `pico_rand` sources; Arduino Nano ESP32 documentation; Microchip
  ATECC608C summary datasheet and PCN RMES-20NCGX846.
- **MicroPython port** (section 6): checked in the repository, not online
  and not on a device: the vendored modules of
  `reimplementations/micropython/lib/`, the supported algorithms of
  `flightbox_utilities_implementation.py`, the SHA-3 filtering of
  `fallback_adapter.py`, and commits `8321779`, `95ce17e` and `e1f4461`.

Not verified:

- That RUSTSEC-2023-0071 does not concern OAEP encryption: inferred from the
  advisory's wording (leaks of private-key information), which names no
  operation.
- Whether the ATECC608B is formally "Not Recommended for New Designs"
  (Microchip's site was unreachable).
- ESP-IDF 6.x Kconfig defaults for SHA-3, ChaCha20-Poly1305 and HKDF.
- All performance and memory figures on our actual workload and chips,
  including the MicroPython estimates of section 6: the vendored
  `ECIES_X25519` code has never been run on an ESP32-S3, nor on the
  MicroPython Unix port.
- That the vendored `hashlib` gets hardware-accelerated SHA-256 from
  `uhashlib` on the ESP32-S3 (depends on the firmware's Mbed TLS
  configuration).
