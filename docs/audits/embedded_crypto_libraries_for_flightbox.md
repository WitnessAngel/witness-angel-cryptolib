# Cryptographic libraries for C or Rust flightbox encryptors on microcontrollers

Date: 2026-11-13. Status: audit, no code changed.
Scope: which cryptographic library (or combination) best provides
wacryptolib's algorithms, or a subset of them, to a C or Rust
reimplementation of the flightbox *encryptor* on microcontrollers such as
the ESP32 family or the Raspberry Pi Pico (RP2040 / RP2350). Complements
`../flightbox_specifications/flightbox_encryptor_specification.md`
(sections 3 and 4 for the primitives), `micropython_cryptography_support.md`
(the MicroPython side) and `flightbox_cryptoconf_storage_format.md` (the
input format). Library facts come from their documentation where marked
"confirmed", otherwise from memory and are listed in section 8.

## Summary

- **The embedded subset is small.** An encryptor only encrypts with public
  keys, and devices whose trustees are authenticators never sign. What is
  needed: one payload cipher, `ECIES_X25519` and/or `RSA_OAEP` key wrapping,
  optionally `ML_KEM_768`, a hardware RNG, and code that no library provides
  (Shamir over GF(2^128), Extended JSON writer, UUID0, RSA chunking).
- **C on ESP32 (the current prototype): mbedTLS**, already bundled with
  ESP-IDF and using the chip's AES / SHA / RSA accelerators, plus small glue
  (HPKE seal, AES-EAX) and **mlkem-native** if ML-KEM is wanted.
- **Single C library alternative: wolfCrypt**, which natively covers AES-EAX,
  SHA-3, ML-KEM and ML-DSA, but is GPLv3 or commercial, and its HPKE seems
  to lack the ChaCha20-Poly1305 AEAD we use.
- **Rust: RustCrypto crates + `hpke` + `ml-kem`**, the most complete
  off-the-shelf coverage (including the exact HPKE suite), at the cost of
  toolchain friction on Xtensa ESP32 chips and no hardware acceleration by
  default.
- **Hardware matters more than the library**: the RP2040 has no true RNG,
  the ESP32 TRNG has conditions, and without hardware AES the payload cipher
  should be `CHACHA20_POLY1305`.

## 1. What an embedded encryptor needs

```
                         needed on device?         notes
 payload ciphers         1 of: CHACHA20_POLY1305   streaming, the only bulk-throughput cost
                               AES_EAX / AES_CBC   (AES only worth it with hardware AES)
 key wrapping            ECIES_X25519              HPKE seal: X25519 + HKDF-SHA256 + ChaCha20-Poly1305
                         RSA_OAEP                  public op only, SHA-512 + MGF1-SHA-512, 60-byte chunks
                         ML_KEM_768 (optional)     encapsulation only, HPKE KEM id from an IETF draft
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

| | **mbedTLS 3.6 / TF-PSA-Crypto** | **wolfCrypt** | BearSSL | Monocypher | **RustCrypto + `hpke` + `ml-kem`** |
|---|---|---|---|---|---|
| AES-256-CBC + PKCS#7 | yes | yes | yes | no | `aes` + `cbc` |
| AES-EAX | no: about 80 lines of glue on its CTR + CMAC | **yes, native** (confirmed) | glue | no | `eax` crate |
| ChaCha20-Poly1305 (RFC 8439) | yes | yes (confirmed) | yes | yes | `chacha20poly1305` |
| SHA-2 / SHA-3 | yes / yes since 3.5 | yes / yes (confirmed) | yes / no | SHA-512 / no | `sha2` / `sha3` |
| RSA-OAEP SHA-512, encryption | yes | yes (confirmed) | yes | no | `rsa` crate (its Marvin timing advisory concerns private-key decryption, irrelevant here) |
| X25519 + HKDF | yes | yes (confirmed) | yes | X25519 only | `x25519-dalek`, `hkdf` |
| HPKE seal with our exact suite | no: about 150 lines of glue (the Python one is 162 lines) | has HPKE, but its 24 tested combinations suggest AES-GCM AEADs only, **no ChaCha20** (inferred) | no | no | **`hpke` crate: X25519-HKDF-SHA256 + ChaCha20-Poly1305** |
| ML-KEM-768 | no: add **mlkem-native** (PQ Code Package, C90, portable) | **yes, native** (confirmed) | no | no | `ml-kem` or `libcrux-ml-kem` (formally verified) |
| ML-DSA-65 | no | yes (confirmed) | no | no | `ml-dsa` |
| ESP32 hardware acceleration | **bundled with ESP-IDF**, uses the AES / SHA / RSA accelerators | ESP-IDF port with acceleration | no | no | esp-hal has drivers, not wired into RustCrypto |
| License | Apache-2.0 or GPL-2.0-or-later | **GPLv3 or commercial** | MIT | CC0 / BSD-2 | MIT / Apache-2.0 |

BearSSL has had no release since 2018, and Monocypher only covers the
`ECIES_X25519` part: useful references, not foundations. wolfCrypt also has
an official Rust wrapper (`wolfssl-wolfcrypt` crate, confirmed), an option
for a Rust port wanting wolfCrypt's coverage.

## 3. Three ways to build it

```
 A) C, least friction on ESP32           B) C, a single library            C) Rust
 +-------------------------------+       +----------------------------+    +------------------------------+
 | core + ExtJSON + Shamir       |       | core + ExtJSON + Shamir    |    | core + ExtJSON + Shamir      |
 | glue: HPKE seal, EAX, chunking|       | glue: HPKE w/ ChaCha,      |    | glue: chunking, ML-KEM HPKE  |
 +---------------+---------------+       |       chunking             |    |       KEM id (draft)         |
 | mbedTLS (in   | mlkem-native  |       +----------------------------+    +------------------------------+
 | ESP-IDF, HW)  | (optional PQ) |       | wolfCrypt (EAX, SHA3,      |    | RustCrypto, hpke, ml-kem,    |
 +---------------+---------------+       | ML-KEM, ML-DSA, HW ports)  |    | no_std, memory-safe          |
                                         +----------------------------+    +------------------------------+
 glue: most                              glue: least in C                   glue: least overall
 license: Apache-2.0                     license: GPLv3 or commercial       license: MIT / Apache-2.0
```

- **A, for the existing C prototype (ESP-IDF on ESP32).** mbedTLS is already
  there and already uses the chip's crypto hardware. The missing pieces are
  small and fully specified: HPKE seal, EAX, and optionally mlkem-native.
  Coding against the PSA Crypto API rather than raw mbedTLS calls would also
  let a later port use secure elements or TF-M.
- **B** covers the most in one C package, including EAX and ML-KEM. Its
  licence is compatible with wacryptolib's GPL-2.0-or-later, but makes the
  firmware GPLv3 unless a commercial licence is bought, and HPKE glue for
  ChaCha20-Poly1305 is probably still needed.
- **C** has the best off-the-shelf coverage. The ESP32-S3's Xtensa core needs
  Espressif's `espup` compiler fork, while the RISC-V ESP32-C3/C6 and the
  Pico chips work with stock Rust; hardware acceleration needs manual work.

Code no library provides, whatever the option: the flightbox core, the
Extended JSON writer, Shamir over GF(2^128) (section 3.7 of the
specification), UUID0 and the 60-byte RSA-OAEP chunking.

## 4. Cost estimates

Order-of-magnitude estimates, not measurements:

- RSA-2048 public operation (e = 65537): milliseconds, a few per cryptainer
  (one per 60-byte chunk of the key struct).
- X25519: tens of milliseconds even on a Cortex-M0+; an HPKE seal needs two
  scalar multiplications.
- ML-KEM-768 encapsulation in C: milliseconds, with 10 to 20 KB of stack,
  versus seconds in pure MicroPython (`micropython_cryptography_support.md`).
- The real budget is payload throughput. Without hardware AES,
  ChaCha20-Poly1305 is both faster and naturally constant-time, whereas
  table-based software AES risks timing leaks.

## 5. Hardware

| | RNG | Crypto accelerators | Consequence |
|---|---|---|---|
| ESP32 / ESP32-S3 | hardware TRNG, **but only truly random while Wi-Fi/BT is on or `bootloader_random_enable()` is used** | AES, SHA-2, RSA big-number unit | AES ciphers come almost free; keep the radio or entropy source on while generating keys |
| RP2040 (Pico, Pico W) | **no TRNG** (only a ring-oscillator bit) | none | weak key generation unless a secure element (e.g. ATECC608) is added; avoid |
| RP2350 (Pico 2) | TRNG | SHA-256 only, no AES | prefer `CHACHA20_POLY1305` for payloads |

Whatever the library, its DRBG (CTR_DRBG, HMAC_DRBG, `rand_core` RNG)
must be seeded from the hardware TRNG, never from a seedable PRNG
(section 3.1 of the specification).

## 6. Testing against wacryptolib

The in-progress OpenSpec change `add-compatibility-fixtures` provides what
C and Rust ports need: bidirectional symmetric cipherdict vectors and
decrypt-only asymmetric ones. The riskiest glue would be checked against it:
EAX, the HPKE key schedule, ML-KEM's draft KEM identifier, and Shamir's
non-GCM field encoding. Shamir output is random, so it can only be validated
end to end, by having wacryptolib decrypt the device's cryptainers
(section 12 of the specification).

## 7. Open questions

- **Which chip?** An Arduino Nano ESP32 script in the workspace suggests an
  ESP32-S3. A Pico 2 would favour ChaCha20 and Rust; a classic Pico raises
  the RNG problem first.
- **Is `RSA_OAEP` still required?** If every authenticator in the field can
  provide an X25519 key, dropping RSA removes the biggest dependency (big
  number arithmetic) from the device.
- **Is `ML_KEM_768` wanted on the device now, or later?** It is the piece
  that decides between options A, B and C.
- **Firmware licensing:** would GPLv3 firmware ever be a problem? This
  decides whether wolfCrypt is an option at all.
- **C or Rust?** The C prototype is still a skeleton, so this is the moment
  to choose.

## 8. Verified and not verified

Confirmed from wolfSSL's documentation: wolfCrypt's AES-CBC and AES-EAX,
ChaCha20-Poly1305, SHA-2 and SHA-3, RSA, Curve25519, HKDF, ML-KEM-512/768/1024
and ML-DSA, the existence of its HPKE implementation (with "24 algorithm
combination variants" tested), and its Rust wrapper crate.

Checked online (November 2026):

- mbedTLS: SHA-3 was added in 3.5.0, and `MBEDTLS_SHA3_C` is enabled in the
  default 3.6.0 `mbedtls_config.h`. ESP-IDF 5.2 to 5.5 ship 3.6.x
  (3.6.5 to 3.6.7), but ESP-IDF 6.0 and 6.1 ship Mbed TLS 4.x (PSA Crypto
  as the primary interface), so the glue code must target the ESP-IDF
  version chosen. ESP-IDF's own Kconfig options for SHA-3 were not checked.
- wolfCrypt HPKE: wolfSSL's blog post lists KEMs P-256/384/521 and X25519,
  KDFs HKDF-SHA2-256/384/512, and AES-GCM only as AEAD (no ChaCha20-Poly1305).
  That post is about two years old: check `hpke.h` of the current release.
- wolfSSL licence: GPLv3 or commercial for the main library (some older
  pages and sub-projects still say GPLv2, plus GPLv2 exceptions for a list of
  named projects).
- `hpke` crate 0.15.1: features `x25519`, `nistp` and `mlkem` (ML-KEM and
  X-Wing KEMs), KDFs HKDF-SHA2 and SHAKE/TurboSHAKE, AEADs ChaCha20-Poly1305
  and AES-GCM, plus `alloc` and `getrandom` features. Contrary to the
  earlier assumption, it does offer ML-KEM. The KEM/KDF/AEAD lists are
  inferred from the feature list; `no_std` is still not confirmed.
- `eax` crate: default nonce is 128 bits (16 bytes), matching pycryptodome;
  the `alloc` feature can be disabled for heapless targets.
- ESP32 RNG: truly random only while Wi-Fi or Bluetooth is running, or the
  SAR ADC entropy source is enabled via `bootloader_random_enable()`, or
  during the second-stage bootloader; otherwise only pseudo-random. A
  flightbox without radio must enable that source explicitly.
- RP2040 RNG: no hardware TRNG. Only the ring oscillator `RANDOMBIT`
  register exists, and the datasheet (section 2.17.5) says it does not meet
  the randomness requirements of security systems. pico_rand seeds from it
  by default, so an external entropy source is needed for key generation.
  RP2350 was not checked (it is believed to have a TRNG).

Not verified:

- Whether ESP-IDF enables `MBEDTLS_SHA3_C` through its own Kconfig.
- Whether the `hpke` crate is `no_std`.
- Whether the RP2350 has a usable TRNG.
- All performance and memory figures of section 4.
