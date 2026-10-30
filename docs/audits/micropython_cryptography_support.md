# MicroPython cryptography support: ML-KEM-768 on ESP32-S3

Date: 2026-10-30. Status: audit, no code changed.
Scope: can the post-quantum `ML_KEM_768` key wrapping of the
`add-post-quantum-algorithms` branch run on the MicroPython flightbox
(`micropython/`), on an ESP32-S3, regarding Python compatibility and memory?
Complements section 6 of `post_quantum_algorithms_report.md`, which holds the
timing estimates.

## Summary

- **Yes, feasible, but not with the desktop code.** The branch relies on
  pycryptodome 4.2, whose ML-KEM is C code it loads at runtime
  (`mlkem_encaps` / `mlkem_decaps` in `_raw_mlkem_lib`). MicroPython can't
  load it, and wacryptolib's fallback backend can't replace it: pycryptodome
  has no pure-Python ML-KEM to fall back on.
- **Approach:** a pure-Python, *encryption-only* ML-KEM-768 + HPKE seal,
  vendored like `micropython/lib/hpke_x25519_seal.py` is for `ECIES_X25519`.
- **Memory is not the problem**, **speed is**: about 10-20 KB of working
  data, but seconds per encapsulation because of Keccak in pure Python.
- **Missing building block:** SHA3 / SHAKE, which the vendored `hashlib`
  lacks.

## 1. Only encryption is needed on the device

The flightbox encapsulates to a trustee's *public* key and never decrypts,
the same split as `ECIES_X25519`. So the port needs only key decoding,
encapsulation, key derivation and AEAD encryption. Decapsulation stays on
PCs and phones.

The device can receive the raw 1184-byte ML-KEM-768 public key in the key
dict, as it already gets raw X25519 keys
(`flightbox_utilities_implementation.py`, `public_key_parameters["x25519"]`),
so no PEM/ASN.1 parsing is needed on the device.

pycryptodome 4.2 exposes encapsulation only through `Crypto.Protocol.HPKE`;
`MLKEMKey` has no public `encapsulate()` method (only the private
`_encaps()` / `_decaps()`). This is another reason to keep HPKE as the wire
format on both sides rather than invent a custom KEM+AEAD framing.

## 2. Python compatibility gaps

| Need | Desktop (pycryptodome 4.2) | MicroPython today | Gap |
|---|---|---|---|
| ML-KEM-768 encapsulate | C, via HPKE | none | pure-Python port (e.g. from kyber-py), FIPS 203 vectors |
| SHA3-256, SHA3-512, SHAKE128, SHAKE256 | yes | vendored micropython-lib `hashlib` has SHA-2 only; `fallback_adapter.py` already drops SHA3 when missing | pure-Python Keccak-f[1600] |
| HKDF-SHA256 (HPKE key schedule) | yes | vendored `hmac` + `hashlib.sha256` | reuse what `hpke_x25519_seal.py` does |
| AEAD | AES-256-GCM | ChaCha20-Poly1305 pure Python; `pyaes` has no GCM | see below |
| Randomness | `get_random_bytes` | `os.urandom` (hardware RNG) | none |

**AEAD choice.** The branch's `encrypt_via_ml_kem_768` uses HPKE with
AES-256-GCM. For `ECIES_X25519`, ChaCha20-Poly1305 was chosen precisely
because a pure-Python implementation already exists for constrained devices
(see `docs/selected_protocols.rst`). A device-compatible ML-KEM option
should use the HPKE suite **ML-KEM-768 + HKDF-SHA256 + ChaCha20-Poly1305**,
otherwise the device would need a GCM implementation too. Decide this
*before* the branch is merged: once cryptainers exist with the AES-GCM
suite, changing it means keeping both forever.

**RNG.** ML-KEM encapsulation randomness must be unpredictable, otherwise it
leaks the shared secret. The flightbox already uses `os.urandom`
(`_get_random_bytes()`, and in `hpke_x25519_seal.py`), so the RNG concern raised
in `post_quantum_algorithms_report.md` about a pseudo-random
`random.SystemRandom` monkey-patch no longer applies to `micropython/`.

## 3. Memory on ESP32-S3

ESP32-S3: about 512 KB internal SRAM (a few hundred KB of usable MicroPython
heap), often plus 2-8 MB PSRAM.

| Item | Size |
|---|---|
| Public key (input) | 1184 bytes |
| KEM ciphertext (output) | 1088 bytes |
| Shared secret | 32 bytes |
| Matrix A (3x3 polynomials, 256 coefficients < 3329) | ~4.6 KB as `array('H')`, ~2x as lists |
| Vectors r, e1, u, plus e2, v, message polynomial | a few KB |
| Keccak state | 200 bytes (as 50 32-bit words if bit-interleaved) |

Estimated total working set: **10-20 KB**, plus temporary objects. It fits
even without PSRAM. The practical risk is **heap fragmentation** from
repeated big-int / bytes allocations: preallocate `array` buffers and reuse
them. For comparison, the C reference needs about 13 KB of RAM on Cortex-M4
(pqm4).

## 4. Speed: Keccak is the bottleneck

- Polynomial arithmetic is modulo 3329, so coefficients stay small ints,
  which is cheap in MicroPython.
- Keccak works on 64-bit lanes, but MicroPython small ints are 31-bit. A
  naive port makes every lane a heap-allocated big int: slow, with heavy
  garbage collection. Mitigations:
  - **bit-interleaved Keccak** on 32-bit halves (standard technique for
    32-bit CPUs);
  - `@micropython.viper` / `@micropython.native` on the permutation and NTT;
  - **cache matrix A**: it is expanded from the public key's seed only (most
    of the SHAKE128 work), so it can be computed once at boot per trustee key
    (~4.6 KB each).
- Estimate (see `post_quantum_algorithms_report.md` section 6): **1-5 s per
  encapsulation** in pure MicroPython. One encapsulation is needed per
  cryptainer and per ML-KEM key layer, so this is likely acceptable;
  benchmark on real hardware before committing to it.

## 5. Options, by effort

1. **Pure-Python encaps + Keccak** (vendored in `micropython/lib/`,
   regenerated by `vendor_dependencies.py`), cross-checked against FIPS 203
   known-answer vectors and against pycryptodome 4.2 HPKE `unseal()`. Seconds
   per encapsulation, no firmware change.
2. **Native Keccak as an `.mpy` native module** (~100 lines of C): likely
   brings encapsulation well under a second.
3. **C user module** wrapping mlkem-native or PQClean (both portable C
   implementations; pycryptodome 4.x embeds mlkem-native): milliseconds and
   constant-time code, at the cost of maintaining a custom firmware build.

Like all pure-Python crypto on the flightbox, options 1 and 2 are not
guaranteed constant-time. For encapsulation the only secrets are the
ephemeral randomness and the shared secret, both single-use, which limits
exposure to timing side channels compared with long-term private keys.

## Recommendations

1. Switch (or add) the branch's ML-KEM suite to **HPKE ML-KEM-768 +
   ChaCha20-Poly1305** before release, so desktop and flightbox share one
   wire format.
2. Start with option 1, gated by cross-validation tests against pycryptodome,
   and only move to options 2/3 if measured timings on the ESP32-S3 are
   unacceptable.
