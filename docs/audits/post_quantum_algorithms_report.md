# Post-quantum algorithms for wacryptolib: selection report

Date: 2026-10-25. Status: uncommitted audit, no code changed.
Scope: which post-quantum (PQ) key-encapsulation, signature and hash
algorithms are worth adding to `wacryptolib`, with a strong preference for
what can also run on the MicroPython flightbox (`src/micropythonpoc/`).

## TL;DR

| Role in the cryptainer | Today | Recommended PQ addition | MicroPython path |
|---|---|---|---|
| Key wrapping (`key_cipher_algo`) | `RSA_OAEP` | `ML_KEM_768` (FIPS 203) used as KEM + AEAD wrap, via pycryptodome 4.2 HPKE | pure-Python encaps (1-5 s, needs Keccak in Python) or a tiny C user module (mlkem-native / PQClean) |
| Hybrid (classical + PQ) | n/a | nothing new: nest `ML_KEM_768` and `RSA_OAEP` as two `key_cipher_layers` | same as above |
| Payload signature (`payload_signature_algo`) | `RSA_PSS`, `DSA_DSS`, `ECC_DSS` | `ML_DSA_65` (FIPS 204) via pycryptodome 4.1; optionally `SLH_DSA_SHA2_128F` (FIPS 205) later | ML-DSA signing is too heavy in pure MicroPython; SLH-DSA-SHA2-128f is the only pure-MicroPython-feasible signer (native SHA-256), but with 17 KB signatures |
| Hashes | SHA-256/512, SHA3-256/512 | nothing needed for PQ; keep SHA-512 for signatures | SHA-256 native in MicroPython, SHA3 is not |
| Symmetric | AES-256 CBC/EAX, ChaCha20-Poly1305 | nothing needed: 256-bit keys already resist Grover | AES via native `cryptolib`; ChaCha20 is pure Python only |

Decision drivers:

1. **pycryptodome, the lib's only crypto dependency, now ships ML-KEM and
   ML-DSA** (4.1.0 on 2026-10-19, 4.2.0 on 2026-10-24), with PKCS#8 / SPKI
   PEM import-export. No new dependency on the desktop side. Bump
   `pycryptodome = "^3.9.9"` to `^4.2` (requires Python >= 3.9, we are at >= 3.10).
2. The cryptainer already composes `key_cipher_layers`, so a classical+PQ
   hybrid is a cryptoconf change, not a new primitive.
3. On the flightbox only the *public* operations are needed (encapsulate,
   sign, hash, symmetric encrypt). Decapsulation and verification stay on PCs
   and phones. That halves the MicroPython porting surface.

## 1. What the cryptainer actually needs from each primitive

```
  payload ──AES_EAX/CBC/ChaCha──▶ ciphertext            (symmetric, streamed)
     │
  symkey struct ──key_cipher_layers──▶ wrapped key       (asymmetric or Shamir)
     │               ├─ RSA_OAEP(trustee pubkey)  ← REPLACE / HYBRIDISE
     │               ├─ [SHARED_SECRET] shards
     │               └─ AES_EAX sub-key (nested)
     │
  SHA512(ciphertext || timestamp) ──sign──▶ signature    (RSA_PSS / *_DSS)  ← REPLACE
```

Relevant constraints found in the code:

- `cipher.py:24`: `RSA_OAEP_CHUNKS_SIZE = 60`. RSA-OAEP wraps the key struct by
  chunking it into 60-byte blocks. A KEM cannot do that: it produces a
  random shared secret, so the PQ layer must be **KEM + DEM** (encapsulate,
  then AEAD-encrypt the key struct with the shared secret). pycryptodome's
  HPKE object does exactly this (`enc` + `seal()`), with AES-256-GCM or
  ChaCha20-Poly1305 as DEM.
- `keygen.py:_check_asymmetric_key_length_bits`: refuses keys < 2048 bits.
  ML-KEM keys have no "length in bits" in this sense; the registry entry
  needs a `generation_extra_parameters` of `[]` (parameter set is fixed by
  the algo name, e.g. `ML_KEM_768`), and the check must be skipped.
- `keystore.py:404`: keys are stored as `<keychain_uid>_<key_algo>_{public,private}_key.pem`.
  pycryptodome exports ML-KEM/ML-DSA as RFC 7468 PEM, so the keystore and
  the trustee API (`fetch_public_key`) work unchanged.
- `signature.py:95`: signatures are over a SHA-512 hasher object
  (message || timestamp). ML-DSA "pure" mode signs raw bytes; pycryptodome's
  `mldsa.new(key).sign()` also accepts a hash object (HashML-DSA) or a
  `MLDSAMuHash`. Simplest is to sign `hasher.digest()` (64 bytes) in pure
  mode with a context string such as `b"wacryptolib-payload-signature"`.
  That keeps the existing hashing pipeline and adds domain separation.
- Serialization is Pymongo Extended JSON (bytes as base64), so a 1088-byte
  KEM ciphertext or a 3309-byte signature in a cryptainer is a non-issue.

## 2. Key encapsulation: ML-KEM-768

**Recommendation: add `ML_KEM_768` as an asymmetric `key_cipher_algo`.**

- Standard: FIPS 203 (Aug 2024). X.509/PKCS#8 encoding: RFC 9935 (Mar 2026).
- Sizes: public key 1184 B, ciphertext 1088 B, private seed 64 B.
- pycryptodome 4.2: `Crypto.PublicKey.MLKEM.generate(param_set=ML_KEM_768)`,
  `export_key(format="PEM")`, `import_key()`. Encapsulation only through
  `Crypto.Protocol.HPKE.new(receiver_key=pub, aead_id=AES256_GCM)` then
  `enc = ctx.enc; wrapped = ctx.seal(key_struct)`. Based on mlkem-native,
  which is a constant-time C implementation.
- Why 768 and not 512/1024: 768 is the level-3 set that every deployment
  (TLS X25519MLKEM768, OpenSSL defaults, X-Wing) converged on; 512 buys
  little space, 1024 is overkill for key wrapping.

Proposed cipherdict for the layer:

```
{"kem_ciphertext": <1088 B>, "wrapped_key_ciphertext": <bytes>, "hpke_aead": "AES256_GCM"}
```

Both fields are opaque bytes, so the existing `ciphertext_chunks` /
`digest_list` dual naming of RSA does not need to be reproduced.

### Hybrid, for free

Do not implement X-Wing or a composite KEM inside the lib. The cryptoconf
already expresses hybrid wrapping:

```
key_cipher_layers=[
    dict(key_cipher_algo="ML_KEM_768", key_cipher_trustee=...),
    dict(key_cipher_algo="RSA_OAEP",   key_cipher_trustee=...),
]
```

An attacker must break both to recover the key. This matches the
"security resides in the cryptosystem, not in individual algorithms"
stance in `docs/selected_protocols.rst`. pycryptodome's X-Wing keys cannot
be exported to PEM anyway, so they do not fit the keystore model.

### Rejected KEM candidates

| Candidate | Why not now |
|---|---|
| HQC (NIST backup KEM, selected Mar 2025) | Draft standard not out; 4.5 KB ciphertexts; no pycryptodome support. Revisit when FIPS is final (~2027). |
| Classic McEliece | 261 KB+ public keys; unusable on devices and in JSON cryptainers. |
| FrodoKEM | Conservative but ~10 KB public keys, slow; no mainstream Python support. |
| X-Wing / composite KEMs in-lib | Redundant with layered `key_cipher_layers`; not PEM-exportable in pycryptodome. |

## 3. Signatures: ML-DSA-65 first, SLH-DSA as a conservative option

**Recommendation: add `ML_DSA_65` as `payload_signature_algo` and key algo.**

- Standard: FIPS 204. X.509/PKCS#8: RFC 9881 (Oct 2025).
- Sizes: public key 1952 B, signature 3309 B.
- pycryptodome 4.1: `Crypto.PublicKey.MLDSA`, `Crypto.Signature.mldsa`.
  Hedged (randomised) signing by default, which is the right choice for a
  device without a trustworthy clock or RNG monitor. Verification raises
  `ValueError`, same contract as the current PSS/DSS wrappers.
- 65 over 44: the lib already pairs signatures with SHA-512; level 3 is the
  common default (OpenSSL, LAMPS examples). ML-DSA-44 is acceptable if
  signature size on the flightbox matters (2420 B).

**Optional later: `SLH_DSA_SHA2_128F` (FIPS 205, RFC 9909).**

- Hash-based, so its security rests only on SHA-256. The most conservative
  PQ signer, and the only one whose *entire* computation maps onto a
  primitive MicroPython has natively (`hashlib.sha256`).
- Costs: 17 KB signatures, slow signing (pqm4 clean on Cortex-M4:
  ~369 Mcycles sign for 128f, i.e. ~1.5 s at 240 MHz in C; the "s" variant
  is 20x slower to sign). Not in pycryptodome; pyca `cryptography` 48 does
  not have it yet either, so the desktop side would need `pqc-py`,
  `liboqs-python` or a pure-Python port.
- Verdict: do not add until a desktop library lands, but design the
  signature registry so a hash-based scheme with large signatures fits.

### Rejected signature candidates

| Candidate | Why not |
|---|---|
| FN-DSA / Falcon (FIPS 206) | Still a draft (expected final late 2026 / 2027). Floating-point Gaussian sampling is hard to get right and hard to port. Smallest signatures (666 B), so worth a second look once final. |
| XMSS / LMS (SP 800-208) | Stateful: a power loss on the flightbox after signing but before persisting the state means key reuse and a total break. Unacceptable on an SD-card device. |
| Pre-hash HashML-DSA | Only needed when the message cannot be held at once; our signed input is already a 64-byte digest. |

## 4. Hashes: nothing to add for PQ reasons

Grover's algorithm halves the effective preimage security: SHA-256 keeps
128 bits, SHA-512 keeps 256. Both are already in `IMPLEMENTED_HASH_ALGOS`,
as are SHA3-256/512. Keep SHA-512 as the fixed signature hasher.

Two side notes:

- **SHAKE128/256 become an internal dependency** of ML-KEM and ML-DSA
  (matrix expansion, PRFs). On desktop pycryptodome provides them (and now
  has AVX2 Keccak). On MicroPython there is no Keccak at all: `hashlib`
  offers only SHA-256, SHA-1, MD5. This, not the lattice arithmetic, is the
  main porting cost of ML-KEM/ML-DSA to MicroPython.
- Do not expose SHAKE or Ascon-Hash as user-facing `hash_algo` values.
  The existing four are enough and keep cryptoconfs simple.

## 5. Symmetric ciphers: already post-quantum

All three key generators in `keygen.py` draw 32-byte keys, so AES-256 and
ChaCha20 both keep 128-bit security against Grover. No action.

For the MicroPython port specifically (not a PQ concern, but it decides
what the flightbox can realistically stream):

- `cryptolib.aes` is native and supports ECB, CBC, CTR. So `AES_CBC` is
  cheap, and `AES_EAX` can be built on native ECB (CTR + OMAC) with modest
  Python glue. `pyaes`, used by the current POC fallback, is pure Python and
  will not sustain audio/video rates.
- `CHACHA20_POLY1305` has no native MicroPython path; leave it desktop-only.
- Ascon-AEAD128 (NIST SP 800-232, Aug 2025) is attractive on paper for
  constrained devices, but in MicroPython a pure-Python permutation is
  slower than native AES, and it adds a desktop dependency. Skip.

## 6. MicroPython feasibility, by primitive

Reference points: pqm4 "clean" C on Cortex-M4; pure-Python timings from
kyber-py / dilithium-py on a desktop i7 (CPython). MicroPython on an ESP32
is roughly 50-100x slower than CPython on a desktop for integer-heavy code.

| Primitive (public op only) | C, Cortex-M4 clean | Pure Python, desktop CPython | Estimated pure MicroPython on ESP32 | Verdict |
|---|---|---|---|---|
| ML-KEM-768 encapsulate | 1.14 Mcycles (~5 ms @ 240 MHz), 13 KB RAM | 4.5 ms | 1-5 s, dominated by Keccak | feasible once per recording; C module makes it instant |
| ML-DSA-65 sign | 12.4 Mcycles (~50 ms), 80 KB RAM | 49 ms median, rejection loops | 30-120 s, highly variable | not feasible in pure MicroPython; needs C module |
| ML-DSA-44 sign | 7.9 Mcycles, 52 KB RAM | 29 ms | 20-60 s | same |
| SLH-DSA-SHA2-128f sign | 369 Mcycles (~1.5 s), 2.5 KB RAM | n/a | ~120k native SHA-256 calls, ~5-20 s | feasible but slow and 17 KB per signature |
| SHA-256 | native | native | native | fine |
| AES-256-CBC/CTR | native | native | native (`cryptolib`) | fine |

Practical porting plan, in order of effort:

1. **Pure-Python ML-KEM-768 encapsulate only.** kyber-py (MIT/Apache-2)
   is ~1000 lines; the encapsulate path needs: byte decoding of the public
   key, NTT multiply, compression, SHA3-256/512 and SHAKE128/256. A
   pure-Python Keccak-f[1600] on MicroPython allocates 64-bit big ints for
   every lane operation, which is why the estimate above is seconds, not
   milliseconds. Memory stays within a few tens of KB. This is enough for a
   first flightbox build that encrypts with a PQ trustee key.
2. **Native Keccak as a MicroPython `.mpy` native module** (the permutation
   is ~100 lines of C). This alone likely brings ML-KEM encaps under 200 ms
   and makes ML-DSA signing borderline (a few seconds).
3. **Full C user module** wrapping mlkem-native / mldsa-native (the same
   code pycryptodome 4.x embeds, Apache-2) or PQClean. This gives
   millisecond encapsulation and sub-second signing, with constant-time
   code. It ties the flightbox to a custom firmware build, which the ESP32
   POC may already require for other reasons.

A note on RNG: ML-KEM encapsulation and hedged ML-DSA need 32 bytes of real
randomness. The POC's monkey-patch of `random.SystemRandom` with the
pseudo-random `random` module (`src/micropythonpoc/main.py`) must be
replaced by `os.urandom` (hardware RNG on ESP32) before any PQ work, since
a predictable encapsulation randomness leaks the shared secret outright.

## 7. Desktop/phone library landscape (Oct 2026)

| Library | ML-KEM | ML-DSA | SLH-DSA | PEM keys | Notes |
|---|---|---|---|---|---|
| pycryptodome 4.2 | yes (via HPKE) | yes | no | yes | already a dependency; mlkem-native / mldsa-native |
| pyca cryptography 48 | yes | yes | in progress | ? | would add a second C crypto dependency; needs OpenSSL 3.5 or AWS-LC |
| kyber-py / dilithium-py | yes | yes | no | optional | pure Python, educational, not constant time; useful as MicroPython porting base only |
| liboqs-python / pqc-py | yes | yes | yes | partial | heavy native builds; hard on Android/iOS (the Authenticator app) |

The Authenticator app generates trustee keypairs on phones with
pycryptodome, so pycryptodome wheels for Android/iOS (python-for-android,
kivy-ios) must build the new C sources. mlkem-native and mldsa-native are
portable C99, so this is expected to work, but it is the one build risk to
verify early.

## 8. Suggested registry changes (for a future change proposal)

No code in this report; this is the shape of the diff.

- `keygen.py`: `ASYMMETRIC_KEY_ALGOS_REGISTRY` gains `ML_KEM_768` and
  `ML_DSA_65` with `generation_extra_parameters=[]` and pycryptodome
  import/export functions. `_check_asymmetric_key_length_bits` is bypassed
  for them.
- `cipher.py`: `CIPHER_ALGOS_REGISTRY` gains `ML_KEM_768` (asymmetric,
  `encryption_node_class=None`, `is_authenticated=True` because the DEM is
  an AEAD). Encrypt = HPKE seal; decrypt = HPKE unseal.
- `signature.py`: `SIGNATURE_ALGOS_REGISTRY` gains `ML_DSA_65`; sign the
  64-byte digest in pure mode with a fixed context.
- `_crypto_backend/pycryptodome.py`: thin wrappers; `fallback_adapter.py`
  (MicroPython) gets `encrypt_via_ml_kem_768` only.
- `pyproject.toml`: `pycryptodome = "^4.2"`.
- Tests: FIPS 203/204 KATs are already covered by pycryptodome; the lib
  needs round-trip tests plus a fixture cryptainer with a `ML_KEM_768` +
  `RSA_OAEP` hybrid layer, decryptable from both desktop and the POC.

Open questions for the proposal stage:

- Name the key algo `ML_KEM_768` (fixes the parameter set, like the current
  `AES_EAX` naming) or `ML_KEM` + `param_set` extra parameter (like
  `RSA_OAEP` + `key_length_bits`)? Fixed names keep cryptoconf validation
  and keystore filenames simple; recommended.
- Which DEM for the key-struct wrap: AES-256-GCM (HPKE default, hardware
  accelerated everywhere) or ChaCha20-Poly1305? GCM is recommended; EAX is
  not an HPKE option.
- Should the Authenticator UI default new trustees to a hybrid keypair set
  (`RSA_OAEP` + `ML_KEM_768`, `RSA_PSS` + `ML_DSA_65`)? That is a product
  decision, but it is the only way existing cryptoconf templates can become
  PQ-safe without a flag day.

## Sources

- pycryptodome changelog (4.1.0, 4.2.0): https://github.com/Legrandin/pycryptodome/blob/master/Changelog.rst
- pycryptodome ML-KEM / ML-DSA / HPKE docs: https://www.pycryptodome.org/src/public_key/mlkem , https://www.pycryptodome.org/src/signature/mldsa , https://www.pycryptodome.org/src/protocol/hpke
- pyca cryptography 48 PQ announcement: https://blog.trailofbits.com/2026/06/30/shipping-post-quantum-cryptography-to-python/
- RFC 9935 (ML-KEM in X.509): https://www.rfc-editor.org/info/rfc9935
- RFC 9881 (ML-DSA in X.509): https://www.rfc-editor.org/rfc/rfc9881.html
- RFC 9909 (SLH-DSA in X.509): https://www.rfc-editor.org/info/rfc9909
- pqm4 benchmarks: https://github.com/mupq/pqm4/blob/master/benchmarks.md
- kyber-py, dilithium-py: https://github.com/GiacomoPope/kyber-py , https://github.com/GiacomoPope/dilithium-py
- NIST HQC selection: https://www.securityweek.com/nist-announces-hqc-as-fifth-standardized-post-quantum-algorithm/
- NIST SP 800-232 (Ascon): https://csrc.nist.gov/news/2025/nist-publishes-sp-800-232
- MicroPython hashlib / cryptolib: https://docs.micropython.org/en/latest/library/hashlib.html , https://docs.micropython.org/en/latest/library/cryptolib.html
