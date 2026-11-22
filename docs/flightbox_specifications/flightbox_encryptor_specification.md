# Flightbox encryptor: specification for reimplementation

Status: reference specification of the existing Python behaviour, written 2026-11-11.

Scope: **only the ENCRYPTOR workflow**, i.e. turning a payload plus a *cryptoconf* into a
*cryptainer*. Cryptainer storage and listing, decryption, revelation requests, trustee
(keystore) management and key generation for trustees are **out of scope**, except where the
encryptor must produce data in the exact format they expect.

The goal is to allow reimplementations in other languages (C, Rust, Kotlin, Swift, JS...), the
way `reimplementations/micropython/` already reimplements the platform layer, and to produce cryptainers that the
existing `wacryptolib` decryptor accepts without changes.

Sources of truth (in this repository):

| Topic | File |
|---|---|
| Portable core algorithm ("flightbox") | `src/wacryptolib/cryptainer/_flightbox.py` (copied verbatim to `reimplementations/micropython/src/cryptainer/_flightbox.py`) |
| CPython platform utilities and payload encryption | `src/wacryptolib/cryptainer/_encryptor.py` |
| Streaming payload encryption | `src/wacryptolib/cipher.py` (`PayloadEncryptionPipeline`, `*EncryptionNode`), `src/wacryptolib/cryptainer/_encryption_pipeline.py` |
| Signatures of digests | `src/wacryptolib/cryptainer/_signing.py`, `src/wacryptolib/signature.py` |
| Cipher primitives | `src/wacryptolib/cipher.py`, `src/wacryptolib/keygen.py`, `src/wacryptolib/_crypto_backend/pycryptodome.py` |
| Shamir shared secret | `src/wacryptolib/utilities/data_utils.py`, `src/wacryptolib/_crypto_backend/pycryptodome_secret_sharing.py` (vendored as `reimplementations/micropython/src/cryptainer/pycryptodome_secret_sharing.py`) |
| Extended JSON | `extjson` package (vendored as `reimplementations/micropython/lib/extjson.py`) |
| WA-CBOR (binary document format of cryptainer files and key ciphertexts) | `docs/specifications/wa_cbor_document_format.md` (normative), `src/wacryptolib/utilities/wacbor.py` |
| Cryptoconf / cryptainer schemas | `src/wacryptolib/cryptainer/_validation.py` |
| MicroPython platform utilities | `reimplementations/micropython/src/cryptainer/flightbox_utilities_implementation.py`, `reimplementations/micropython/src/cryptainer/fallback_adapter.py` |
| Pure-Python HPKE X25519 seal | `src/wacryptolib/_crypto_backend/fallback/hpke_x25519_seal.py` (vendored in `reimplementations/micropython/lib/`) |
| Device profile (input of embedded encryptors) | `docs/flightbox_specifications/flightbox_device_profile_specification.md` |
| C reimplementation (steps 1 to 3, informative) | `reimplementations/c-language/` (`README.md`, unit test vector generators in `tests/unit/generate_*.py`, interop suites in `tests/interop/`) |
| Rust reimplementation (steps 1 to 3, informative) | `reimplementations/rust/` (`README.md`, test vectors as JSON files in `test_vectors/`, checked by the interop suites of the C tree) |
| Compatibility corpus (cryptoconfs, cryptainers, cipherdicts, keystores) | `compatibility/` (`README.md`, section "Using the corpus from another implementation") |

The key words MUST, SHOULD and MAY are used in the RFC 2119 sense.

---

## 1. Overview

### 1.1 Terminology

| Term | Meaning |
|---|---|
| **cryptoconf** | Tree (JSON-like dict) describing *how* to encrypt: payload cipher layers, key cipher layers, trustees, shared secrets, signatures. Input of the encryptor. |
| **cryptainer** | Tree produced by the encryptor: a deep copy of the cryptoconf enriched with encrypted keys, integrity tags, signatures, identifiers, metadata and the payload ciphertext (inline or offloaded). |
| **trustee** | Entity holding asymmetric keypairs, identified by a small dict (see §5.3). The encryptor only needs its **public** keys (and, for signatures, its ability to sign a digest). |
| **keychain_uid** | UUID selecting one keypair set inside a trustee's keystore. A trustee holds at most one keypair per `(keychain_uid, key_algo)`. |
| **symkey** | Dict of random secrets for a symmetric cipher, e.g. `{"key": <32 bytes>, "iv": <16 bytes>}`. |
| **cipherdict** | Dict returned by a cipher, e.g. `{"ciphertext": ...}` or `{"ciphertext_chunks": [...]}`. |
| **key_ciphertext** | Bytes: the serialization, in Extended JSON or WA-CBOR as stated by the sibling `key_ciphertext_format` field (§2), of the *outermost* cipherdict of a chain of key cipher layers. |
| **secrets** | Sensitive, in-memory-only extract (symkeys + hash algo lists) used to encrypt the payload. MUST never be persisted. |

### 1.2 Encryption workflow

```
                    cryptoconf, cryptainer_metadata
                                 │
   ┌─────────────────────────────▼─────────────────────────────┐
   │ STEP 1 — Flightbox core (§6)                               │
   │   generate_cryptainer_base_and_secrets()                   │
   │   - deep-copy cryptoconf into a new cryptainer             │
   │   - for each payload cipher layer: random symkey,          │
   │     encrypted through its key cipher layers (recursive:    │
   │     asymmetric / symmetric sub-key / Shamir shared secret) │
   │   - fill identifiers, state STARTED                        │
   └───────────────┬───────────────────────────┬───────────────┘
                   │ cryptainer (no payload)    │ secrets (symkeys!)
                   │                            ▼
                   │        ┌──────────────────────────────────────┐
                   │        │ STEP 2 — Payload encryption (§7)      │
   payload ───────────────► │  one-shot, or streamed chunk by chunk │
                   │        │  through all payload cipher layers;   │
                   │        │  digests of plaintext & ciphertexts,  │
                   │        │  MAC tags                             │
                   │        └──────────────┬───────────────────────┘
                   │                       │ ciphertext, integrity tags
   ┌───────────────▼───────────────────────▼───────────────────┐
   │ STEP 3 — Authentication data (§8)                          │
   │   payload_macs, payload_digest_value, optional signatures  │
   │   by trustees, state FINISHED                              │
   └─────────────────────────────┬─────────────────────────────┘
                                 ▼
               cryptainer (JSON or CBOR) + ciphertext (inline or offloaded, §9)
```

Step 1 is the portable "flightbox" algorithm proper (`FlightBox` class). It is purposely
written with **dependency injection** only: every platform-specific operation goes through a
`FlightboxUtilities` object (§10). Steps 2 and 3 are currently implemented by
`CryptainerEncryptor` (CPython only); the MicroPython port currently stops after step 1.

---

## 2. Extended JSON serialization (`dump_to_json_bytes`)

Every intermediate structure that gets encrypted (symkeys, key structs, cipherdicts, shards),
as well as the final cryptainer file, is serialized by default with the **Extended JSON** dialect
of the `extjson` package (MongoDB Extended JSON, *relaxed* mode), then UTF-8 encoded. Both may
instead use WA-CBOR, independently of each other (see the end of this section).

Encoding rules (encoder side, `canonical=False`):

| Native value | JSON encoding |
|---|---|
| dict (string keys) | JSON object |
| list **and tuple** | JSON array (tuples become arrays) |
| str | JSON string |
| int | plain JSON number (NOT `$numberInt`) |
| bool, null | `true` / `false` / `null` |
| float | plain JSON number; NaN / ±Infinity as `{"$numberDouble": "NaN"}` / `"Infinity"` / `"-Infinity"` |
| bytes | `{"$binary": {"base64": "<standard base64, padded, no newline>", "subType": "00"}}` |
| UUID | `{"$uuid": "<32 lowercase hex chars, no dashes>"}` |
| timezone-aware datetime | `{"$date": "YYYY-MM-DDTHH:MM:SS[.mmm]<offset or Z>"}` (UTC offset `+00:00` written as `Z`; naive datetimes are rejected) |
| Decimal | `{"$numberDecimal": "<str>"}` |

Formatting:

- CPython: `json.dumps(..., sort_keys=True)` with default separators (`", "` and `": "`),
  `ensure_ascii=True`.
- MicroPython: same but **keys are not sorted** (and non-ASCII characters may be emitted raw).

**Byte-exactness is NOT required for interoperability**: every serialized structure is either
encrypted (then decrypted and parsed back) or stored as-is, and the decoder only needs valid
JSON with the wrappers above. Reimplementations SHOULD nevertheless sort keys and use the
CPython separators, to ease cross-implementation comparisons and test fixtures.

Decoders also accept canonical forms (`$numberInt`, `$numberLong`, `$binary` with subType `"04"`
for UUIDs...), but an encoder MUST stick to the relaxed forms above for maximum compatibility.

Below, `J(x)` denotes `dump_to_json_bytes(x)`.

**WA-CBOR** is the deterministic CBOR dialect specified in
`docs/specifications/wa_cbor_document_format.md`, which carries exactly the same document trees
as relaxed Extended JSON. `C(x)` denotes its serialization `dump_to_cbor_bytes(x)`, whose output
is byte-exact (unlike `J()`).

Two formats are chosen independently:

- the **cryptainer file format**: the final cryptainer file is written with `J()` or `C()` (§9.1);
- the **key ciphertext format** `F`, `"json"` (default) or `"cbor"`: the intermediate structures
  that get encrypted (symkeys, shards, key structs, and the cipherdicts serialized between key
  cipher layers) are serialized with `S_F`, where `S_json = J` and `S_cbor = C`.

`F` is stated by a `key_ciphertext_format` field next to each `key_ciphertext` of the cryptainer,
written only when `F` is `"cbor"` (an absent field means `"json"`, so JSON-mode cryptainers keep the
exact form of earlier releases). `F` governs the whole chain that produces that `key_ciphertext`,
shard chains included, but not the chain of a nested symmetric key layer, whose own
`key_ciphertext` has its own field (§6.4). Readers MUST take `F` from that field, never guess it
from the bytes. An encryptor SHOULD use one `F` for a whole cryptainer, `"cbor"` giving smaller key
ciphertexts (e.g. fewer RSA-OAEP chunks); constrained devices MAY implement only one of
the two serializations.

### 2.1 Byte-exact Extended JSON (recommended)

Byte-exactness of `J` is not needed for decryption, but a writer reproducing CPython's
`dump_to_json_bytes()` byte for byte can be tested against wacryptolib by plain comparison (re-encoding a
loaded cryptainer, fixtures, deterministic-RNG runs). The C writer does so; reimplementations SHOULD do the
same, by these rules, which only concern the types an encryptor writes (no floats, datetimes nor decimals):

- **Whitespace**: exactly `", "` between items and `": "` after keys, nothing else: no indentation, no
  trailing newline. `{}` and `[]` for empty containers.
- **Key order**: object keys sorted by Unicode **code point**, at every level, wrappers included
  (`"base64"` before `"subType"`). Code point order equals the byte order of the UTF-8 encodings, but
  differs from the UTF-16 code unit order used by some languages' default string comparison (JavaScript,
  Java, C#): CPython sorts the key `"\ue000"` before `"\ud83d\ude00"` (U+E000 before U+1F600), UTF-16 the reverse.
- **Strings**: `"` and `\` are written `\"` and `\\`; U+0008, U+000C, U+000A, U+000D and U+0009 are written
  `\b`, `\f`, `\n`, `\r` and `\t`; every other code point below U+0020 or from U+007F up is written `\uXXXX`
  with **four lowercase** hex digits, code points above U+FFFF as a UTF-16 surrogate pair (U+1F600 is `\ud83d\ude00`).
  `/` is **not** escaped. The output is therefore pure ASCII.
- **Integers**: plain decimal, `-` sign only when negative, no exponent; CPython writes any size, but
  values outside the signed 64-bit range are not portable (§5.4).
- **Bytes**: standard base64 alphabet (`+`, `/`) with `=` padding, empty bytes giving `""`:
  `{"$binary": {"base64": "AP8=", "subType": "00"}}`.
- **UUIDs**: `{"$uuid": "<32 lowercase hex digits>"}`.

Example (as Python would write it): `J({"z": "\x7f\xe9\U0001f600/\x01\t", "t": True, "m": None, "b": UUID(int=1),
"a": [1, b"\x00\xff"]})` is

```
{"a": [1, {"$binary": {"base64": "AP8=", "subType": "00"}}], "b": {"$uuid": "00000000000000000000000000000001"}, "m": null, "t": true, "z": "\u007f\u00e9\ud83d\ude00/\u0001\t"}
```

Pitfalls of general-purpose JSON libraries: compact separators by default (`","`, `":"`), raw UTF-8 output
instead of `\u` escapes, uppercase hex digits, escaped `/`, keys kept in insertion order or sorted by UTF-16
code units, and bytes or UUIDs serialized as bare strings or arrays. A writer built on such a library
still produces decryptable cryptainers if it emits the wrappers above, but not byte-identical ones.

### 2.2 WA-CBOR key ciphertexts

`C` is the core deterministic encoding of RFC 8949 section 4.2.1, as normatively specified in the WA-CBOR
specification: shortest heads, definite lengths, and map keys sorted by the **bytewise order of their
encodings**, which puts shorter text keys first. The key order of the same structure therefore usually
differs between `J` and `C`:

| Structure | `J` key order | `C` encoding (example values) |
|---|---|---|
| `AES_CBC` symkey | `iv`, `key` | `a2 62 6976 50 <16 bytes> 63 6b6579 58 20 <32 bytes>` |
| `AES_EAX` / `CHACHA20_POLY1305` symkey | `key`, `nonce` | `a2 63 6b6579 58 20 <32 bytes> 65 6e6f6e6365 50 <16 bytes>` (`4c <12 bytes>` for ChaCha) |
| key struct | `cryptainer_metadata`, `key_bytes` | `a2 69 "key_bytes" 42 0102 73 "cryptainer_metadata" f6` (null metadata) |
| AEAD cipherdict | `ciphertext`, `tag` | `a2 63 "tag" 41 02 6a "ciphertext" 41 01` |
| HPKE cipherdict | `ciphertext`, `kem_ciphertext` | `ciphertext` first too |
| shard `(1, b"\xaa")` | `[1, {"$binary": {"base64": "qg==", "subType": "00"}}]` | `82 01 41 aa` (an array, never a map) |

Every intermediate structure is a map with text keys, except shards (2-item arrays); bytes are byte strings
(major type 2), UUIDs (only inside metadata) tag 37, and `null` metadata is `f6`. Since `C` is byte-exact, a
WA-CBOR key ciphertext chain is fully reproducible under a deterministic RNG.

Serialized sizes, useful to size buffers, with null metadata and RSA-2048 (each RSA-OAEP chunk wraps up to
60 bytes, §3.5):

| Payload algo | `S_F(symkey)`, J / C | `S_F(key struct)` of it, J / C | RSA-OAEP chunks, J / C |
|---|---|---|---|
| `AES_CBC` | 173 / 59 bytes | 320 / 93 bytes | 6 / 2 |
| `AES_EAX` | 176 / 62 bytes | 324 / 96 bytes | 6 / 2 |
| `CHACHA20_POLY1305` | 168 / 58 bytes | 312 / 92 bytes | 6 / 2 |

Each enclosing layer grows the bytes again: `J` expands every wrapped byte string by about 4/3 plus a
44-byte wrapper, `C` by a 1 to 9-byte head.

---

## 3. Primitives

### 3.1 Randomness

All secrets (symmetric keys, IVs, nonces, Shamir coefficients, ephemeral HPKE keys, RSA-OAEP
seeds, UUID random parts) MUST come from a cryptographically secure RNG (`os.urandom()`
equivalent, hardware RNG on microcontrollers). A seedable/pseudo-random generator MUST NOT be
used.

### 3.2 UUID0 (`generate_uuid0`)

Used for `cryptainer_uid` and for the default `keychain_uid`. 16 bytes:

```
tsi      = floor(unix_time_seconds_as_float * 10000)      # 1/10000 s resolution
t_bytes  = last 6 bytes of big-endian uint64(tsi)          # drop 2 most significant bytes
r_bytes  = 10 random bytes
uuid     = UUID(bytes = t_bytes || r_bytes)
```

No RFC 4122 version/variant bits are set. The time prefix only makes UUIDs roughly sortable;
uniqueness comes from the 80 random bits. Any reimplementation MUST keep at least these 80
random bits; the time prefix SHOULD be kept for consistency.

Details: `tsi` is truncated toward zero, then reduced modulo 2^48 by dropping the two high bytes
(irrelevant before year 2861). CPython reads the clock before drawing the random bytes. A device
without a wall clock (or whose clock read fails) MAY write a zero time prefix: nothing reads it back,
and decryption never depends on it. A clock that is wrong but monotonic is harmless too.

### 3.3 Symmetric key generation (`generate_symkey(cipher_algo)`)

| `cipher_algo` | Generated symkey dict |
|---|---|
| `AES_CBC` | `{"key": random(32), "iv": random(16)}` |
| `AES_EAX` | `{"key": random(32), "nonce": random(16)}` |
| `CHACHA20_POLY1305` | `{"key": random(32), "nonce": random(12)}` |

Keys MUST be 32 bytes (the decryptor rejects keys shorter than 32 bytes). Each symkey is used
for exactly one encryption, so the fixed IV/nonce stored next to the key is safe.

CPython draws the key first, then the IV or nonce (`keygen.py`). This order is not observable by the
decryptor, but implementations SHOULD keep it, so that runs under a deterministic RNG can be compared
with wacryptolib's (§6.8).

The symkey is serialized as `S_F(symkey)` (§2), e.g. with `F = json`
`{"iv": {"$binary": {...}}, "key": {"$binary": {...}}}`, and **these bytes** are what gets
encrypted by key cipher layers.

### 3.4 Symmetric ciphers

All of them are usable both as **payload cipher** (`payload_cipher_algo`, streamable) and as
**key cipher** (`key_cipher_algo` of a symmetric key layer, one-shot). No associated data (AAD /
EAX header) is ever used.

| Algo | Primitive | One-shot cipherdict | Payload MACs (`payload_macs`) |
|---|---|---|---|
| `AES_CBC` | AES-256-CBC, **PKCS#7 padding** to 16 bytes (a full padding block is added when the plaintext length is already a multiple of 16) | `{"ciphertext": bytes}` | `{}` (empty dict) |
| `AES_EAX` | AES-256 in EAX mode (Bellare-Rogaway-Wagner, as in pycryptodome `AES.MODE_EAX`), 16-byte nonce, 16-byte tag, no header | `{"ciphertext": bytes, "tag": bytes(16)}` | `{"tag": bytes(16)}` |
| `CHACHA20_POLY1305` | ChaCha20-Poly1305 AEAD of RFC 8439 (12-byte nonce), empty AAD, 16-byte tag | `{"ciphertext": bytes, "tag": bytes(16)}` | `{"tag": bytes(16)}` |

Streaming (§7.2) MUST produce exactly the same ciphertext and tag as the one-shot form.

`AES_EAX` details, for libraries without an EAX mode (it is easily built from AES-ECB and
CMAC): with `OMAC_t(M) = CMAC-AES-256(key, [t]_16 || M)`, where `[t]_16` is the 16-byte block holding
the integer `t` big-endian (15 zero bytes, then `t`):

```
N   = OMAC_0(nonce)
C   = AES-256-CTR(key, initial counter block = N, plaintext)   # 128-bit big-endian counter, + 1 per block, modulo 2^128
H   = OMAC_1(b"")                                              # empty header, still MACed
tag = N xor H xor OMAC_2(C)                                    # 16 bytes, never truncated
```

The whole 16-byte block is the counter (no nonce/counter split), so it wraps from `ff...ff` to `00...00`;
CTR implementations limited to a 32 or 64-bit counter give wrong output when the low bytes of `N` carry
over. `AES_CBC` uses the stored `iv` as is; `CHACHA20_POLY1305` is the RFC 8439 AEAD construction
(block counter 1 for the first plaintext block, block 0 giving the Poly1305 key).

Empty plaintexts are legal everywhere: `AES_CBC` then gives one 16-byte padding block, `AES_EAX` and
`CHACHA20_POLY1305` an empty ciphertext and a 16-byte tag.

### 3.5 Asymmetric ciphers (key wrapping)

They are only used in key cipher layers, to encrypt a **key struct** (§6.5) with a trustee's
public key.

#### RSA_OAEP

- RSA key size MUST be ≥ 2048 bits (the encryptor raises otherwise).
- RSAES-OAEP (PKCS#1 v2.2) with **SHA-512** as hash, **MGF1-SHA-512**, empty label.
- The plaintext is cut into consecutive chunks of **60 bytes** (`RSA_OAEP_CHUNKS_SIZE`), the
  last one possibly shorter, with **no padding** at chunk level; each chunk is encrypted
  separately (fresh OAEP seed each time). An empty plaintext yields zero chunks.
- Cipherdict: `{"ciphertext_chunks": [bytes, bytes, ...]}` (each item is `k` bytes long,
  `k` = modulus size in bytes). The legacy name `digest_list` MUST NOT be produced.
- Per chunk `M` (RFC 8017 section 7.1.1, `hLen` = 64): `lHash = SHA-512(b"")`;
  `DB = lHash || PS || 0x01 || M` with `PS` zero bytes, `len(DB) = k − 65`; `seed` = **64 fresh random
  bytes**; `maskedDB = DB xor MGF1-SHA-512(seed, k − 65)`; `maskedSeed = seed xor MGF1-SHA-512(maskedDB, 64)`;
  `EM = 0x00 || maskedSeed || maskedDB`; the chunk ciphertext is `EM^e mod n` written big-endian on
  exactly `k` bytes, **leading zero bytes kept**. Seeds are drawn in chunk order.

#### ECIES_X25519

HPKE (RFC 9180), **Base mode**, single-shot seal:

- KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF `0x0001` HKDF-SHA256, AEAD `0x0003`
  ChaCha20-Poly1305.
- `info = b""`, `aad = b""`, a single `Seal()` per context (sequence number 0).
- Recipient public key: raw 32-byte X25519 public key (CPython loads it from a PEM
  `SubjectPublicKeyInfo`; MicroPython receives the raw bytes).
- Cipherdict: `{"kem_ciphertext": enc (32 bytes, ephemeral public key), "ciphertext": sealed bytes (plaintext length + 16-byte tag)}`.
- RFC 9180 Appendix A.2 test vectors apply.

The whole computation, for libraries offering X25519, HKDF-SHA256 and ChaCha20-Poly1305 but no HPKE
(RFC 9180 sections 4, 4.1, 5.1 and 5.2; `||` is concatenation, `I2OSP(x, n)` the n-byte big-endian
encoding):

```
LabeledExtract(suite, salt, label, ikm)    = HKDF-Extract(salt, b"HPKE-v1" || suite || label || ikm)
LabeledExpand(suite, prk, label, info, L)  = HKDF-Expand(prk, I2OSP(L, 2) || b"HPKE-v1" || suite || label || info, L)

# Encap, DHKEM(X25519, HKDF-SHA256)
kem_suite     = b"KEM" || I2OSP(0x0020, 2)
skE           = 32 fresh random bytes            # clamped by X25519 itself
enc           = X25519(skE, 9)                   # = kem_ciphertext
dh            = X25519(skE, pkR)                 # all-zero dh: MUST fail
kem_context   = enc || pkR
eae_prk       = LabeledExtract(kem_suite, b"", b"eae_prk", dh)
shared_secret = LabeledExpand(kem_suite, eae_prk, b"shared_secret", kem_context, 32)

# Key schedule, mode_base (0x00), info = b""
suite         = b"HPKE" || I2OSP(kem_id, 2) || I2OSP(0x0001, 2) || I2OSP(0x0003, 2)
context       = 0x00 || LabeledExtract(suite, b"", b"psk_id_hash", b"")
                     || LabeledExtract(suite, b"", b"info_hash", b"")
secret        = LabeledExtract(suite, shared_secret, b"secret", b"")     # salt = shared_secret, empty psk
key           = LabeledExpand(suite, secret, b"key", context, 32)
base_nonce    = LabeledExpand(suite, secret, b"base_nonce", context, 12)

# Single Seal, sequence number 0
ciphertext    = ChaCha20-Poly1305(key, nonce = base_nonce, aad = b"", plaintext)   # includes the 16-byte tag
```

The ephemeral key MAY instead come from RFC 9180's `DeriveKeyPair` over 32 fresh random bytes; both are
indistinguishable to the decryptor. The exporter secret is never needed.

#### ML_KEM_768 (post-quantum, CPython only for now)

HPKE (RFC 9180) Base mode, as implemented by pycryptodome ≥ 4.2 `Crypto.Protocol.HPKE`:
KEM ML-KEM-768 (FIPS 203), KDF HKDF-SHA256, AEAD ChaCha20-Poly1305 (`0x0003`), empty info and
AAD. Cipherdict: `{"kem_ciphertext": bytes, "ciphertext": bytes}` (same shape as
ECIES_X25519). Reimplementations MUST cross-check against pycryptodome (e.g. by decrypting
with wacryptolib, see §12, or with the `compatibility/cipherdicts/2026_post_quantum/ML_KEM_768/`
vectors), since the HPKE KEM
identifier of ML-KEM comes from an IETF draft.

Exact choices of pycryptodome 4.2, which a reimplementation MUST follow even if later revisions of the
draft (`draft-ietf-hpke-pq`) change them:

- KEM identifier **`0x0041`**, so `suite = b"HPKE" || 0x0041 || 0x0001 || 0x0003`; KDF HKDF-SHA256
  (`0x0001`), AEAD ChaCha20-Poly1305 (`0x0003`).
- Encap is FIPS 203 `ML-KEM.Encaps(ek)`, which consumes 32 fresh random bytes (`m`); `enc` is the ML-KEM
  ciphertext (1088 bytes) and `shared_secret` is the 32-byte ML-KEM shared key **as is**, with no
  `LabeledExtract`/`LabeledExpand` step around it (unlike DHKEM).
- The key schedule and the single `Seal` are then exactly those of ECIES_X25519 above.
- The encapsulation key SHOULD pass the FIPS 203 section 7.2 modulus check (every decoded 12-bit
  coefficient below 3329) before use.

### 3.6 Hash algorithms

Allowed values for `payload_digest_algo`: `SHA256`, `SHA512`, `SHA3_256`, `SHA3_512`
(standard FIPS 180-4 / FIPS 202 digests). A platform MAY support only a subset (e.g.
MicroPython's `hashlib` lacks SHA3); it MUST then refuse cryptoconfs requiring others.

### 3.7 Shamir secret sharing (`split_secret_into_shards`)

Input: `secret` (bytes, any length), `shard_count` n with `1 ≤ n ≤ 30`, `threshold_count` k with
`1 ≤ k ≤ n`. Output: a list of n tuples `(index, shard_bytes)`, index from 1 to n.

**Shard count limit.** A shared secret has at most **30 shards** (`MAX_SHARED_SECRET_SHARD_COUNT`).
Encryptors MUST reject, at validation time (§5.2), a cryptoconf or device profile with more shards in any
shared secret layer. Readers MUST reject a shard whose index is not an integer (booleans excluded) in
`1..30`, and duplicate indices within one shared secret, before any Shamir recombination; such a shard can
only come from tampering, since no conforming writer emits it.

```
padded  = PKCS7_pad(secret, block_size=16)        # always adds 1..16 bytes
chunks  = split padded into 16-byte chunks
for each chunk c:
    chunk_shares[c] = shamir_split_128(k, n, c)   # list of (i, 16 bytes), i = 1..n
for i in 1..n:
    shard_bytes_i = concatenation, in chunk order, of the 16-byte share i of every chunk
    shards.append((i, shard_bytes_i))
```

`shamir_split_128(k, n, secret16)` is pycryptodome's `Crypto.Protocol.SecretSharing.Shamir.split`
(with `ssss=False`), over **GF(2^128)**:

- Field element encoding: 16 bytes read as a **big-endian** 128-bit integer; bit *j* of that
  integer is the coefficient of x^j (the LSB is the constant term). This is NOT the
  bit-reflected GCM convention.
- Reduction polynomial: x^128 + x^7 + x^2 + x + 1. Addition is XOR, multiplication is
  carry-less multiplication modulo that polynomial.
- Polynomial: p(x) = c0 + c1·x + ... + c(k-1)·x^(k-1), with **c0 = secret16** and
  c1..c(k-1) fresh random 16-byte elements (independently drawn **for each chunk**).
- Share i = p(i), where the index i is encoded as the field element with integer value i;
  output as 16 big-endian bytes.
- Draw order (pycryptodome `Shamir.split`): for each chunk, in chunk order, the k − 1 random
  coefficients are drawn **highest degree first** (c(k-1), then c(k-2), ..., c1), then p is
  evaluated by Horner's rule. All chunks are split before any shard gets encrypted. Only the order
  of draws is fixed by this rule; it matters for deterministic-RNG comparisons, not for decryption.
- With k = 1, no random value is drawn.

Each shard tuple is then serialized as `S_F((i, shard_bytes))`, i.e. an **array**, e.g. with
`F = json` `[i, {"$binary": {...}}]`, which is what the decryptor expects (a 2-item list: int,
bytes).

Note: with k = 1, every shard equals the padded secret; this is intended (any single trustee
can then reveal the key).

---

## 4. Signatures (performed by trustees)

Signatures are produced by a trustee holding a private key, on a **digest** computed by the
encryptor; the encryptor only forwards the digest and stores the returned struct.

- Supported `payload_signature_algo`: `RSA_PSS`, `DSA_DSS`, `ECC_DSS`, `ML_DSA_65`.
- Signed message: `SHA512(digest || ascii(decimal(timestamp_utc)))`, `timestamp_utc` being an
  integer Unix timestamp chosen by the signer.
  - `RSA_PSS`: RSASSA-PSS, SHA-512, MGF1-SHA-512, salt length 64 (pycryptodome `pss` defaults).
  - `DSA_DSS` / `ECC_DSS`: FIPS 186-3 DSS, signature as raw fixed-length `r || s`
    (pycryptodome `DSS` "binary" encoding).
  - `ML_DSA_65`: FIPS 204 pure mode, over the 64 SHA-512 output bytes, context
    `b"wacryptolib-payload-signature-v1"`.
- Returned struct: `{"signature_value": bytes, "signature_timestamp_utc": int}`.
- A trustee refuses messages bigger than a digest: only the digest MUST be sent.

For a `local_keyfactory` trustee, the device itself is the signer (with a keypair created on
demand in its own keystore). For `authenticator` trustees (read-only imported public keys),
signing is impossible and fails. For `jsonrpc_api` trustees it is a remote call
(`get_message_signature(keychain_uid, message, signature_algo)`).

---

## 5. Input: the cryptoconf

### 5.1 Grammar

```
cryptoconf := {
    "payload_cipher_layers": [ payload_cipher_layer, ... ]     # NON-EMPTY, applied in order
    ?"payload_plaintext_signatures": [ signature_conf, ... ]   # signatures of the PLAINTEXT
    ?"keychain_uid": UUID                                      # default keychain for the whole tree
}

payload_cipher_layer := {
    "payload_cipher_algo": "AES_CBC" | "AES_EAX" | "CHACHA20_POLY1305",
    "key_cipher_layers": [ key_cipher_layer, ... ],            # NON-EMPTY, applied in order
    "payload_ciphertext_signatures": [ signature_conf, ... ]   # may be empty; signatures of THIS layer's ciphertext
       # legacy alias accepted in input: "payload_signatures"
}

key_cipher_layer := asymmetric_layer | symmetric_layer | shared_secret_layer

asymmetric_layer := {
    "key_cipher_algo": "RSA_OAEP" | "ECIES_X25519" | "ML_KEM_768",
    "key_cipher_trustee": trustee,
    ?"keychain_uid": UUID                                      # overrides the default keychain_uid
}

symmetric_layer := {                                           # wrap with a fresh symmetric SUB-key
    "key_cipher_algo": "AES_CBC" | "AES_EAX" | "CHACHA20_POLY1305",
    "key_cipher_layers": [ key_cipher_layer, ... ]             # NON-EMPTY; protects the sub-key
}

shared_secret_layer := {
    "key_cipher_algo": "[SHARED_SECRET]",
    "key_shared_secret_threshold": int,                        # 1 <= threshold <= number of shards
    "key_shared_secret_shards": [ { "key_cipher_layers": [ key_cipher_layer, ... ] }, ... ]  # 1 to 30 shards, each NON-EMPTY
}

signature_conf := {
    "payload_digest_algo": "SHA256" | "SHA512" | "SHA3_256" | "SHA3_512",
    "payload_signature_algo": "RSA_PSS" | "DSA_DSS" | "ECC_DSS" | "ML_DSA_65",
    "payload_signature_trustee": trustee,
    ?"keychain_uid": UUID
}

trustee := {"trustee_type": "local_keyfactory"}
         | {"trustee_type": "authenticator", "keystore_uid": UUID, ?"keystore_owner": str}
         | {"trustee_type": "jsonrpc_api", "jsonrpc_url": str}
```

The structure is recursive: shards and symmetric layers contain their own key cipher layers,
which may again be shared secrets or symmetric layers, without depth limit in wacryptolib.

Algorithm names are case-sensitive uppercase strings in the cryptoconf.

Value types, as checked by wacryptolib's schema (they are not obvious from the grammar):

- Every `keychain_uid` and `keystore_uid` is a **UUID value** (`{"$uuid": ...}` in Extended JSON, tag 37 in
  WA-CBOR); a UUID written as a text string is rejected.
- `key_shared_secret_threshold` is an integer; a boolean is rejected (beware of languages or decoders
  where `true` is the integer 1).
- A payload layer MUST contain **exactly one** of `payload_ciphertext_signatures` and the legacy
  `payload_signatures`; neither, or both, is invalid. Its list MAY be empty.
- `payload_plaintext_signatures` MAY be absent or empty, with the same meaning.
- `keystore_owner` and `jsonrpc_url` are any text strings, empty included.
- `ML_DSA_65` and the other signature algos are not valid `key_cipher_algo` values, and
  `key_ciphertext_format` is not allowed anywhere in a cryptoconf.
- Presence, not value, selects a `keychain_uid`: the nil UUID `00000000-0000-0000-0000-000000000000` is
  a valid, present value (Python's `or` only skips absent keys here, since UUID values are always truthy).

### 5.2 Validation

The CPython encryptor validates the whole cryptoconf against `CRYPTOCONF_SCHEMA_PYTHON`
(`_validation.py`) **before** any key generation, and rejects unknown keys. Reimplementations
SHOULD do the same (a JSON Schema export is available as `CRYPTOCONF_SCHEMA_JSON`).

Independently of that upfront validation, the flightbox core itself MUST raise a validation
error when:

- `payload_cipher_layers` is empty;
- any `key_cipher_layers` list is empty;
- a shared secret threshold is not in `1..len(key_shared_secret_shards)`;
- a shared secret has more than 30 shards (§3.7).

`cryptainer_metadata` MUST be a dict (JSON-serializable with §2 types) or null (§5.4).

All validation, of the cryptoconf, the metadata and the requested formats, MUST complete before the first
random draw and before any output is written: a rejected input leaves no file, not even a temporary one.
Implementations that resolve public keys from a fixed set (e.g. a device profile) SHOULD also resolve and
check every key before encrypting anything.

**Nesting depth.** wacryptolib has no limit on the nesting of key cipher layers. An encryptor MAY
cap it, to bound recursion or stack use, and MUST then reject deeper cryptoconfs at validation time, with a
dedicated error (§5.5), never fail half-way. The depth unit is the **key cipher nesting level**: the
`key_cipher_layers` list of a payload layer is at level 1, and the list inside a symmetric key layer or a
shard is one level deeper than the list holding that layer. A cap MUST be at least 8 (the C
implementation's default); the cryptoconfs of the compatibility corpus reach level 3. Such a cap only
restricts what an encryptor accepts to produce: decryptors and other readers of cryptainers MUST accept
any nesting depth, within the item nesting limit of their document format (§5.4).

### 5.3 Trustee public key resolution

`get_public_key(trustee, key_algo, keychain_uid)` returns the public key of the keypair
`(keychain_uid, key_algo)` of that trustee:

| `trustee_type` | Resolution |
|---|---|
| `local_keyfactory` | The device's own keystore; the keypair is generated on demand if missing. |
| `authenticator` | A *read-only* imported keystore identified by `keystore_uid` (public keys only). Missing key = error. |
| `jsonrpc_api` | Remote call `fetch_public_key(keychain_uid, key_algo)` on `jsonrpc_url`, returning a PEM. |

How keys are stored/transported is platform-specific (PEM in CPython; raw RSA `(n, e)` integers
or raw X25519 bytes in the MicroPython demo; raw keys in a WA-CBOR device profile for embedded
encryptors, `docs/flightbox_specifications/flightbox_device_profile_specification.md`).

Keys are looked up by **trustee identity**, `keychain_uid` and `key_algo`. The trustee identity is
`trustee_type` plus `keystore_uid` for `authenticator` trustees, plus `jsonrpc_url` for `jsonrpc_api`
trustees, and `trustee_type` alone for `local_keyfactory`; `keystore_owner` is informative and ignored
(wacryptolib's `get_trustee_id()`). The `keychain_uid` used is the layer's own one if present, else the
cryptainer's root one (§6.3). Every public key MUST satisfy the constraints of §11.2 before use.

### 5.4 Cryptainer metadata

`cryptainer_metadata` is copied into the cryptainer and into every key struct (§6.5), so it is
serialized with the cryptainer file format and with `F`. wacryptolib accepts any dict of §2 types (and
checks nothing else in Extended JSON mode); for portability, encryptors SHOULD restrict metadata to what
both formats and every reader handle:

- maps with text keys, arrays, text strings, booleans, null, bytes and UUIDs;
- integers within the signed 64-bit range (larger ones become bignums in WA-CBOR);
- floats, datetimes and decimals are valid in wacryptolib but MAY be refused by constrained encryptors
  (the C one rejects them as unsupported types).

Encryptors MUST reject metadata containing a single-key map whose key is an Extended JSON keyword
(`$binary`, `$uuid`, `$date`, `$numberInt`, `$numberLong`, `$numberDouble`, `$numberDecimal`,
`$undefined`), at any depth: it would be read back as a typed value, or fail to load. wacryptolib
rejects them at validation time, in both document formats.

Metadata nesting counts against the WA-CBOR limit of 64 levels, with the metadata map at level 2 both in
the cryptainer and in key structs: metadata itself MAY nest 63 levels, and an encryptor writing WA-CBOR
MUST reject deeper metadata before any random draw. These checks SHOULD be applied in Extended JSON mode
too, so that a cryptainer can always be converted between file formats.

### 5.5 Error categories

wacryptolib raises Python exceptions (mostly `ValueError` and schema errors) without stable codes. New
implementations SHOULD nevertheless report at least the following distinct categories, which the C
implementation uses (status names in parentheses, informative) and which its interop suites check:

| Category | Raised for | C status |
|---|---|---|
| decoding error | input bytes that are not a well-formed document (WA-CBOR rules, Extended JSON keyword maps, excessive item nesting) | `DECODING_ERROR` |
| unsupported format | unknown or missing format marker (e.g. `device_profile_format`) | `UNSUPPORTED_FORMAT` |
| unsupported type | valid document items the implementation doesn't handle (floats, datetimes, bignums...) | `UNSUPPORTED_TYPE` |
| invalid input | any schema violation of §5.1 and §5.2: unknown or missing keys, wrong types, unknown algo names, empty lists, bad threshold, both signature keys, metadata that is not a map or null, duplicate key entries | `INVALID_PROFILE` |
| unsupported feature | valid input outside the implemented subset: signatures, a disabled document format, an algorithm not built in | `UNSUPPORTED_SIGNATURE`, `UNSUPPORTED_FEATURE`, `UNSUPPORTED_ALGORITHM` |
| missing public key | an asymmetric layer resolving to no key (§5.3) | `MISSING_PUBLIC_KEY` |
| key constraint violation | a public key outside §11.2 (or the stricter device profile rules), an all-zero X25519 shared secret | `KEY_CONSTRAINT_VIOLATION` |
| nesting too deep | key cipher layers or metadata beyond the limits above | `NESTING_TOO_DEEP` |
| platform failure | out of memory, randomness source failure, crypto library failure, output write failure | `OUT_OF_MEMORY`, `RANDOMNESS_FAILURE`, `CRYPTO_BACKEND_FAILURE`, `SINK_WRITE_FAILURE` |
| usage error | invalid arguments, calls in the wrong state (e.g. a chunk after finalization) | `INVALID_ARGUMENT`, `WRONG_STATE` |

When an input has several defects, which one is reported first is **implementation-defined**; tests
SHOULD use inputs with a single defect. For reference, the C implementation checks, in order: the
cryptoconf's allowed keys, then signature lists (rejected as unsupported), then each payload layer and its
key cipher layers depth first, then the root `keychain_uid`; device profiles are checked as listed in
section 9 of the device profile specification.

---

## 6. Step 1 — Flightbox core: cryptainer base and secrets

### 6.1 Entry point

```
function generate_cryptainer_base_and_secrets(cryptoconf, cryptainer_metadata = null,
                                              F = "json")
        -> (cryptainer, secrets)
```

```
 0. if F not in ("json", "cbor"): error                            # before any key generation
 1. assert cryptainer_metadata is null or a dict
 2. cryptainer_uid        = generate_uuid0()                       # ALWAYS fresh
 3. default_keychain_uid  = cryptoconf["keychain_uid"] if present and truthy
                            else generate_uuid0()
 4. cryptainer = deep_copy_without_aliasing(cryptoconf)            # §6.6
 5. if cryptainer["payload_cipher_layers"] is empty: validation error
 6. payload_plaintext_hash_algos =
        [s["payload_digest_algo"] for s in cryptainer.get("payload_plaintext_signatures", [])]
 7. payload_cipher_layer_extracts = []
 8. for layer in cryptainer["payload_cipher_layers"]:              # in order
        algo = layer["payload_cipher_algo"]
        if "payload_signatures" in layer:                          # legacy naming
            legacy = layer.pop("payload_signatures")
            if "payload_ciphertext_signatures" not in layer:
                layer["payload_ciphertext_signatures"] = legacy
        layer["payload_macs"] = null                               # filled at step 3
        symkey      = generate_symkey(algo)
        key_bytes   = S_F(symkey)
        layer["key_ciphertext"] = encrypt_key_through_multiple_layers(
                                      default_keychain_uid, key_bytes,
                                      layer["key_cipher_layers"], cryptainer_metadata, F)
        if F != "json":
            layer["key_ciphertext_format"] = F                     # absent means "json"
        payload_cipher_layer_extracts.append({
            "cipher_algo": algo,
            "symkey":      symkey,
            "hash_algos":  [s["payload_digest_algo"] for s in layer["payload_ciphertext_signatures"]],
        })
 9. cryptainer.update({
        "cryptainer_state":          "STARTED",
        "cryptainer_format":         "cryptainer_1.0",
        "cryptainer_uid":            cryptainer_uid,
        "keychain_uid":              default_keychain_uid,
        "payload_ciphertext_struct": null,          # MUST be filled before persisting (§9)
        "cryptainer_metadata":       cryptainer_metadata,
    })
10. secrets = {
        "payload_plaintext_hash_algos":  payload_plaintext_hash_algos,
        "payload_cipher_layer_extracts": payload_cipher_layer_extracts,
    }
11. return (cryptainer, secrets)
```

The input cryptoconf is never mutated. The CPython caller additionally deep-copies
`cryptainer_metadata` beforehand, so that the cryptainer does not alias caller data.

### 6.2 Chain of key cipher layers

```
function encrypt_key_through_multiple_layers(default_keychain_uid, key_bytes,
                                             key_cipher_layers, cryptainer_metadata, F) -> bytes
    if key_cipher_layers is empty: validation error
    initial = key_bytes
    for key_cipher_layer in key_cipher_layers:                     # in order
        key_cipherdict = encrypt_key_through_single_layer(
                             default_keychain_uid, key_bytes, key_cipher_layer,
                             cryptainer_metadata, F)
        key_bytes = S_F(key_cipherdict)                            # stays bytes all along
    assert key_bytes != initial                                    # safety net
    return key_bytes                                               # = key_ciphertext
```

So the *k*-th layer encrypts the serialization of the (*k*-1)-th layer's cipherdict, and
the result is the serialization of the **last** layer's cipherdict, both in format `F`. The
decryptor walks the list in reverse order.

### 6.3 Single key cipher layer

```
function encrypt_key_through_single_layer(default_keychain_uid, key_bytes,
                                          key_cipher_layer, cryptainer_metadata, F) -> dict
    algo = key_cipher_layer["key_cipher_algo"]

    if algo == "[SHARED_SECRET]":                                  # §6.4
        shard_confs = key_cipher_layer["key_shared_secret_shards"]
        n = len(shard_confs)
        k = key_cipher_layer["key_shared_secret_threshold"]
        if not (0 < k <= n): validation error
        shards = split_secret_into_shards(key_bytes, shard_count=n, threshold_count=k)
        shard_ciphertexts = []
        for (shard, shard_conf) in zip(shards, shard_confs):      # shard i -> i-th shard conf
            shard_bytes = S_F(shard)                               # J: "[i, {"$binary": ...}]"
            shard_ciphertexts.append(
                encrypt_key_through_multiple_layers(default_keychain_uid, shard_bytes,
                                                    shard_conf["key_cipher_layers"],
                                                    cryptainer_metadata, F))  # recursion, same F
        return {"shard_ciphertexts": shard_ciphertexts}

    elif algo is a symmetric cipher algo:                          # §6.4
        sub_symkey = generate_symkey(algo)
        key_cipher_layer["key_ciphertext"] = encrypt_key_through_multiple_layers(
                default_keychain_uid, S_F(sub_symkey),
                key_cipher_layer["key_cipher_layers"], cryptainer_metadata, F)  # recursion, STORED IN PLACE
        if F != "json":
            key_cipher_layer["key_ciphertext_format"] = F          # this sub-chain's own field
        return encrypt_bytestring(key_bytes, cipher_algo=algo, key_dict=sub_symkey)   # one-shot cipherdict

    else:                                                          # asymmetric algo
        keychain_uid = key_cipher_layer.get("keychain_uid") or default_keychain_uid
        return encrypt_key_with_asymmetric_cipher(algo, keychain_uid, key_bytes,
                                                  key_cipher_layer["key_cipher_trustee"],
                                                  cryptainer_metadata, F)
```

An unknown `key_cipher_algo` is an error (assertion in the Python code).

### 6.4 Notes on shared secrets and symmetric sub-keys

- **Shared secret**: the *current* key bytes (the serialized symkey, or an already-wrapped
  serialized cipherdict if the shared secret is not the first layer) are split into n shards; each
  shard goes through its own chain of key cipher layers, typically one trustee per shard. The
  resulting cipherdict `{"shard_ciphertexts": [...]}` keeps the order of
  `key_shared_secret_shards`. Shard *i* (index i, 1-based) MUST be encrypted with the *i*-th
  shard conf.
- **Symmetric layer**: a fresh sub-symkey encrypts the current key bytes (one-shot cipherdict,
  integrity tag included for AEAD algos, returned up the chain), while the sub-symkey itself is
  protected by the nested `key_cipher_layers`, and its resulting ciphertext is **written into
  the symmetric layer dict itself** (`key_cipher_layer["key_ciphertext"]`), along with its
  `key_ciphertext_format` field when `F` is `"cbor"`. This is the only place, besides payload
  cipher layers, where the core mutates key cipher layers of the cryptainer. The format of this
  sub-chain is read from the symmetric layer's own field, whereas the one-shot cipherdict
  returned up the chain belongs to the enclosing chain; with a single `F` per cryptainer, both
  are equal, but readers MUST honor each field separately.
- Asymmetric layers do not get any extra field: their output only travels up the chain. In
  particular the resolved `keychain_uid` is NOT written into the layer (the decryptor
  re-resolves it the same way: layer's own value, else the cryptainer's `keychain_uid`).

### 6.5 Asymmetric wrapping and the key struct

```
function encrypt_key_with_asymmetric_cipher(cipher_algo, keychain_uid, key_bytes,
                                            trustee, cryptainer_metadata, F) -> dict
    public_key = get_public_key(trustee, key_algo=cipher_algo, keychain_uid=keychain_uid)
    key_struct = {"key_bytes": key_bytes, "cryptainer_metadata": cryptainer_metadata}
    return encrypt_bytestring(S_F(key_struct), cipher_algo=cipher_algo, key_dict={"key": public_key})
```

With `F = cbor`, metadata that WA-CBOR can't encode (e.g. nested deeper than its limit) makes
encryption fail before anything is written.

The key struct embeds the (unencrypted) cryptainer metadata inside every asymmetric
encryption, so that a trustee can see what it is asked to decrypt. Its exact format is
mandatory (`KEY_STRUCT_SCHEMA`): a dict with `key_bytes` (bytes) and `cryptainer_metadata`
(dict or null), e.g. with `F = json` (sorted keys):

```json
{"cryptainer_metadata": {"SOME_METADATA": 2726562425242}, "key_bytes": {"$binary": {"base64": "eyJpdiI6...", "subType": "00"}}}
```

Since metadata is repeated in each key struct, large metadata increases the number of
RSA-OAEP chunks accordingly.

When a trustee is asked remotely to decrypt the key struct (revelation requests), the request
data is always the **Extended JSON** serialization of the asymmetric cipherdict: `F = json`
key ciphertexts are sent as they are, and `F = cbor` ones are transcoded with `J(parse_C(...))`,
which is lossless. The decrypted key struct returned by the trustee is then parsed in format `F`.

### 6.6 Deep copy without aliasing

The cryptoconf is copied recursively (dicts and lists only; leaves are immutable) **without
preserving aliasing**: if the same sub-tree object is referenced at several places of the
cryptoconf (e.g. one trustee dict, or one shard conf reused twice), each place gets its own
copy in the cryptainer. This matters because the algorithm writes `key_ciphertext` fields into
those sub-trees; with aliasing, one write would overwrite another. Implementations in languages
with value semantics get this for free; others MUST copy explicitly.

### 6.7 Resulting nesting, example

For the cryptoconf:

```
payload_cipher_layers: [
  { payload_cipher_algo: AES_CBC,
    key_cipher_layers: [
      { key_cipher_algo: RSA_OAEP, key_cipher_trustee: T1 },
      { key_cipher_algo: [SHARED_SECRET], key_shared_secret_threshold: 1,
        key_shared_secret_shards: [
          { key_cipher_layers: [ { key_cipher_algo: ECIES_X25519, key_cipher_trustee: T2 } ] },
          { key_cipher_layers: [ { key_cipher_algo: RSA_OAEP,     key_cipher_trustee: T3 } ] } ] } ],
    payload_ciphertext_signatures: [] } ]
```

the payload layer's `key_ciphertext` is, with `F = json` (with `F = cbor`, every `J` below
becomes `C`, and the payload layer gets `key_ciphertext_format: "cbor"`):

```
J({"shard_ciphertexts": [
     J(ECIES_T2( J({"key_bytes": J([1, shard1]), "cryptainer_metadata": M}) )),
     J(RSA_T3(   J({"key_bytes": J([2, shard2]), "cryptainer_metadata": M}) )) ]})
where shard1, shard2 = Shamir split of
     J(RSA_T1( J({"key_bytes": J(symkey), "cryptainer_metadata": M}) ))
```

### 6.8 Order of random draws (informative)

The decryptor can't observe in which order random values were drawn, so this order is not required for
interoperability. Implementations SHOULD nevertheless follow wacryptolib's, which the algorithm of §6.1 to
§6.5 implies, so that a run fed by a deterministic RNG can be compared with another implementation's (the C
implementation's backends are compared that way):

1. the 10 random bytes of `cryptainer_uid` (§3.2);
2. those of the default `keychain_uid`, only when the cryptoconf has none;
3. for each payload layer, in order: its symkey (key, then IV or nonce, §3.3), then its key cipher layers
   in order, each one consuming:
   - asymmetric: `RSA_OAEP`, one 64-byte seed per chunk in chunk order; `ECIES_X25519`, the 32-byte
     ephemeral key; `ML_KEM_768`, the 32 encapsulation bytes (§3.5). wacryptolib draws these inside
     pycryptodome, from its own RNG, so only implementations with an injectable RNG for every draw can
     be compared byte for byte;
   - symmetric: the sub-symkey (key, then IV or nonce), then the draws of its nested key cipher layers;
     the one-shot encryption with the sub-symkey draws nothing;
   - shared secret: the Shamir coefficients of every chunk (§3.7), then the draws of each shard's key
     cipher layers, in shard order.

Steps 2 and 3 draw nothing (signing trustees may, on their side).

---

## 7. Step 2 — Payload encryption

The payload goes through **all** payload cipher layers, in cryptoconf order: layer 1 encrypts
the plaintext, layer 2 encrypts layer 1's raw ciphertext, etc. The final ciphertext is the raw
output of the last layer. MAC tags are **not** appended to the ciphertext: they are stored
separately in `payload_macs` (§8).

Digests are computed along the way:

- `plaintext_digests`: for each algo in `secrets.payload_plaintext_hash_algos`, the hash of the
  whole plaintext → dict `{hash_algo: digest}` (duplicates collapse into a single entry).
- for each payload layer: `payload_digests` = for each algo of its `hash_algos`, the hash of
  that layer's **raw ciphertext output** (including CBC padding, excluding any MAC tag).
- for each payload layer: `payload_macs` = `{}` for `AES_CBC`, `{"tag": tag}` for AEAD algos.

### 7.1 One-shot mode (`encrypt_data`)

```
current = payload_plaintext
ciphertext_integrity_tags = []
for extract in secrets.payload_cipher_layer_extracts:
    cipherdict = encrypt_bytestring(current, extract.cipher_algo, extract.symkey)
    ciphertext = cipherdict.pop("ciphertext")
    ciphertext_integrity_tags.append({
        "payload_macs":    cipherdict,                                   # what remains: {} or {"tag": ...}
        "payload_digests": {a: hash(a, ciphertext) for a in extract.hash_algos},
    })
    current = ciphertext
plaintext_digests = {a: hash(a, payload_plaintext) for a in secrets.payload_plaintext_hash_algos}
cryptainer["payload_ciphertext_struct"] = {"ciphertext_location": "inline", "ciphertext_value": current}
```

### 7.2 Streaming mode (`PayloadEncryptionPipeline`)

For large payloads (video recordings...), payload layers are chained as streaming nodes, and
the final ciphertext is written to an output stream (typically the offloaded payload file).

Each node keeps: its cipher context, hashers for its ciphertext digests, and for block ciphers
(`AES_CBC`, block size 16) a remainder buffer.

```
node.encrypt(data):
    if block cipher:
        buffer = remainder || data
        aligned = largest prefix of buffer whose length is a multiple of 16
        remainder = rest
        data = aligned
    if data is empty: return b""
    ct = cipher.encrypt(data); update ciphertext hashers with ct; return ct

node.finalize():
    if block cipher:
        ct = cipher.encrypt(PKCS7_pad(remainder, 16)); update hashers; remainder = b""
        return ct
    return b""                         # stream ciphers: nothing pending; tag computed now

pipeline.encrypt_chunk(chunk):
    update plaintext hashers with chunk
    for node in nodes: chunk = node.encrypt(chunk)
    output.write(chunk)

pipeline.finalize():
    pending = b""
    for node in nodes:
        ct = (node.encrypt(pending) if pending else b"") + node.finalize()
        pending = ct
    output.write(pending); output.flush()

pipeline.get_payload_integrity_tags():
    return {
      "plaintext_digests": {algo: digest},
      "ciphertext_integrity_tags": [ {"payload_macs": {} or {"tag": ...},
                                      "payload_digests": {algo: digest}} for each node ],
    }
```

Chunk sizes are free (CPython uses 1 MiB). The output MUST be byte-identical to the one-shot
mode for the same symkeys. Asymmetric algos are not streamable and are invalid as
`payload_cipher_algo`.

In streaming mode, the cryptainer's `payload_ciphertext_struct` is set right after step 1 to
the offloaded marker `{"ciphertext_location": "offloaded"}` (§9.2). An implementation MAY also
dump this unfinished cryptainer (state `STARTED`) as a temporary file, as a savegame in case
the stream is interrupted before finalization.

### 7.3 Streaming and output rules

- Chunks of any size are accepted, an **empty chunk being a no-op**; chunk boundaries never change the
  output. A payload of zero bytes (no chunk, or only empty ones) is legal and gives the ciphertext of
  §3.4 for an empty plaintext.
- An inline empty ciphertext is written as an empty byte string (`"base64": ""` in Extended JSON).
- Chunks are refused after finalization, and finalization happens once. After any failure, the
  encryptor MUST NOT produce a finished cryptainer (the C one enters a failed state, rejecting every
  further call).
- **Offloaded output**: the payload file is named after the **final** cryptainer file name (§9.2). The
  final cryptainer file MUST be written only once the payload file is complete, so that a listed
  cryptainer never points to a partial payload. CPython creates the payload file first, writes an
  optional savegame cryptainer under the final name plus `~` (e.g. `x.crypt.json~`, ignored by
  cryptainer listings), then the final cryptainer, and deletes the savegame. If encryption fails
  before streaming starts, it deletes the payload file and savegame it created; implementations SHOULD
  likewise delete the partial files they created on any failure, unless they deliberately keep the
  savegame for recovery.

---

## 8. Step 3 — Authentication data and finalization

```
function add_authentication_data_to_cryptainer(cryptainer, payload_integrity_tags, signature_policy)
    default_keychain_uid = cryptainer["keychain_uid"]

    if payload_integrity_tags.plaintext_digests is not empty:
        inject_digests_and_signatures(cryptainer["payload_plaintext_signatures"],
                                      payload_integrity_tags.plaintext_digests, ...)

    for (layer, tags) in zip(cryptainer["payload_cipher_layers"],
                             payload_integrity_tags.ciphertext_integrity_tags):
        assert layer["payload_macs"] is null
        layer["payload_macs"] = tags.payload_macs
        inject_digests_and_signatures(layer["payload_ciphertext_signatures"],
                                      tags.payload_digests, ...)

    cryptainer["cryptainer_state"] = "FINISHED"


function inject_digests_and_signatures(signature_confs, payload_digests,
                                       default_keychain_uid, signature_policy)
    for conf in signature_confs:
        conf["payload_digest_value"] = payload_digests[conf["payload_digest_algo"]]   # always set
        if signature_policy == SKIP_SIGNING: continue
        try:
            keychain_uid = conf.get("keychain_uid") or default_keychain_uid
            conf["payload_signature_struct"] = trustee(conf["payload_signature_trustee"])
                    .get_message_signature(keychain_uid, message=conf["payload_digest_value"],
                                           signature_algo=conf["payload_signature_algo"])   # §4
        except error:
            if signature_policy == ATTEMPT_SIGNING: log a warning, leave the struct absent
            else: raise                                                    # REQUIRE_SIGNING
    assert the set of digest algos seen == set(payload_digests keys)
```

Signature policies: `SKIP_SIGNING`, `ATTEMPT_SIGNING` (default in CPython), `REQUIRE_SIGNING`.
A constrained device without access to signing trustees SHOULD use `SKIP_SIGNING` (digests are
still stored) or a cryptoconf without signature confs.

An implementation that computes no digests at all (like the C one) MUST reject, at validation time
(§5.2), every cryptoconf with a non-empty `payload_plaintext_signatures`, `payload_ciphertext_signatures`
or `payload_signatures` list: silently dropping signature confs would alter the requested protection, and
leaving them without `payload_digest_value` would give cryptainers whose integrity can't be checked
against the requested digests (`SKIP_SIGNING` still stores them, rule 10 of §11.1). With only empty
signature lists, step 3 reduces to setting `payload_macs` and `cryptainer_state`, and the lists stay empty
in the cryptainer.

---

## 9. Output: the cryptainer

### 9.1 Fields

A finished cryptainer contains everything from the (normalized) cryptoconf plus:

| Location | Field | Value |
|---|---|---|
| root | `cryptainer_format` | `"cryptainer_1.0"` |
| root | `cryptainer_uid` | fresh UUID0 |
| root | `keychain_uid` | cryptoconf's `keychain_uid`, else a fresh UUID0 (always present) |
| root | `cryptainer_state` | `"STARTED"` after step 1, `"FINISHED"` after step 3 |
| root | `cryptainer_metadata` | the metadata dict, or null |
| root | `payload_ciphertext_struct` | inline or offloaded struct (§9.2) |
| payload layer | `key_ciphertext` | bytes (§6.2) |
| payload layer | `key_ciphertext_format` | `"cbor"`, only for WA-CBOR key ciphertexts (absent means `"json"`, §2) |
| payload layer | `payload_macs` | `{}` or `{"tag": bytes}` |
| payload layer | `payload_ciphertext_signatures` | legacy `payload_signatures` renamed |
| symmetric key layer | `key_ciphertext` | bytes: the protected sub-symkey (§6.4) |
| symmetric key layer | `key_ciphertext_format` | `"cbor"`, only for WA-CBOR key ciphertexts (absent means `"json"`, §2) |
| each signature conf | `payload_digest_value` | bytes |
| each signature conf | `payload_signature_struct` | `{"signature_value": bytes, "signature_timestamp_utc": int}`, if signed |

The cryptainer is serialized either with `J()` (§2) into a UTF-8 Extended JSON file, or in
WA-CBOR (`docs/specifications/wa_cbor_document_format.md`). Writers SHOULD name the file
`<something>.crypt.json` (Extended JSON) or `<something>.crypt.cbor` (WA-CBOR), with these
suffixes in lowercase. The legacy `<something>.crypt` suffix of earlier releases (always Extended
JSON) SHOULD NOT be used for new files. Readers MUST recognize all three suffixes, `.crypt.json`,
`.crypt.cbor` and `.crypt`, in any letter case (rule 14 of §11.1), and SHOULD check that the
content matches the format given by the suffix. The file format says nothing about the key
ciphertext format: e.g. a `.crypt.json` file may hold `"cbor"` key ciphertexts, and converting a
cryptainer between file formats leaves its key ciphertexts and their `key_ciphertext_format`
fields unchanged. `key_ciphertext_format` is not allowed in cryptoconfs.

### 9.2 Payload ciphertext location

- **Inline**: `"payload_ciphertext_struct": {"ciphertext_location": "inline", "ciphertext_value": <bytes>}`;
  the ciphertext is base64-embedded in the JSON.
- **Offloaded**: `"payload_ciphertext_struct": {"ciphertext_location": "offloaded"}` exactly
  (no other key), and the raw final ciphertext bytes are stored in a sibling file named
  `<cryptainer filename>.payload` (e.g. `20261111_184000_video.mp4.crypt.json` and
  `20261111_184000_video.mp4.crypt.json.payload`, or `20261111_184000_video.mp4.crypt.cbor` and
  `20261111_184000_video.mp4.crypt.cbor.payload`; legacy cryptainers have a `.crypt.payload` file).

`payload_ciphertext_struct` MUST NOT stay null in a persisted cryptainer.

### 9.3 Abridged example

Output of `reimplementations/micropython/main.py` (single `AES_CBC` layer wrapped with `RSA_OAEP` by an
`authenticator` trustee), before payload encryption, with base64 shortened and the generated
UUIDs replaced by illustrative values:

```json
{
  "cryptainer_format": "cryptainer_1.0",
  "cryptainer_metadata": {"SOME_METADATA": 2726562425242},
  "cryptainer_state": "STARTED",
  "cryptainer_uid": {"$uuid": "0f2b6e5a1c9d4a0b8e7f6a5b4c3d2e1f"},
  "keychain_uid": {"$uuid": "0f2b6e5a1c9e7c1d2e3f4a5b6c7d8e9f"},
  "payload_cipher_layers": [
    {
      "key_cipher_layers": [
        {"key_cipher_algo": "RSA_OAEP",
         "key_cipher_trustee": {"keystore_uid": "5e840838-7532-4b32-ba72-ccd17f7c923a", "trustee_type": "authenticator"},
         "keychain_uid": "acd7f9f7-849b-44af-9765-9d4913b7f8dd"}
      ],
      "key_ciphertext": {"$binary": {"base64": "eyJjaXBoZXJ0ZXh0X2NodW5rcyI6IFt7IiRiaW5hcnkiOi...", "subType": "00"}},
      "payload_cipher_algo": "AES_CBC",
      "payload_ciphertext_signatures": [],
      "payload_macs": null
    }
  ],
  "payload_ciphertext_struct": null
}
```

(The demo passes UUIDs as plain strings; a real cryptoconf MUST use UUID values, serialized
as `{"$uuid": ...}`.) Decoding the base64 of `key_ciphertext` yields
`{"ciphertext_chunks": [{"$binary": ...}, ... 256-byte chunks ...]}`.

After step 2 and 3: `cryptainer_state` becomes `"FINISHED"`, `payload_macs` becomes `{}`, and
`payload_ciphertext_struct` holds the inline or offloaded struct.

---

## 10. Platform utilities interface (dependency injection)

The core (`FlightBox`) only calls these members of its `FlightboxUtilities` object:

| Member | Contract |
|---|---|
| `logger` | Debug logger. |
| `SUPPORTED_SYMMETRIC_CIPHER_ALGOS` | Algo names routed to the "symmetric layer" branch (CPython: `AES_CBC`, `AES_EAX`, `CHACHA20_POLY1305`). |
| `SUPPORTED_ASYMMETRIC_CIPHER_ALGOS` | Algo names allowed in the asymmetric branch (CPython: `ECIES_X25519`, `ML_KEM_768`, `RSA_OAEP`). |
| `raise_validation_error(msg)` | MUST raise (never return). |
| `dump_to_json_bytes(data)` | §2 (`J`). |
| `dump_to_cbor_bytes(data)` | §2 (`C`), needed only for `F = cbor`. |
| `generate_uuid0()` | §3.2. |
| `split_secret_into_shards(secret, shard_count, threshold_count)` | §3.7, returns list of `(index, bytes)`. |
| `generate_symkey(cipher_algo)` | §3.3. |
| `get_public_key(trustee, key_algo, keychain_uid)` | §5.3, returns an opaque public key accepted by `encrypt_bytestring`. |
| `encrypt_bytestring(plaintext, cipher_algo, key_dict)` | One-shot encryption, symmetric (key_dict = symkey) or asymmetric (key_dict = `{"key": public_key}`); MUST return a **cipherdict** (§3.4, §3.5). |

A reimplementation in another language SHOULD keep this split: a small, auditable, portable
core, and a platform layer for crypto, JSON, randomness and key retrieval.

### 10.1 Current MicroPython profile

`reimplementations/micropython/` implements step 1 only, with:

- symmetric: `AES_CBC` (via `pyaes`), as a symmetric key cipher layer, and for payload
  encryption once step 2 is implemented; asymmetric: `RSA_OAEP` (via `pkcs1`, SHA-512) and
  `ECIES_X25519` (pure-Python HPKE seal);
- trustees: `authenticator` only, public keys provided as an in-memory dict
  `{keystore_uid: {keychain_uid: {"n": int, "e": int, "x25519": bytes(32)}}}`;
- validation errors raised as `RuntimeError`; no upfront schema validation;
- key ciphertexts in Extended JSON only (`F = json`, no `dump_to_cbor_bytes`);
- Shamir via a vendored copy of pycryptodome's pure-Python `Shamir`;
- no payload encryption, digests, signatures nor file output yet (steps 2 and 3).

### 10.2 C profile

`reimplementations/c-language/` is a portable C99 library implementing steps 1 to 3 for
microcontrollers (its `README.md` documents its API, platform hooks, build options and measured
footprint), with:

- symmetric: `AES_CBC`, `AES_EAX` and `CHACHA20_POLY1305`, for payload encryption (inline or
  offloaded, fed by chunks of any size) and as symmetric key cipher layers; asymmetric: `RSA_OAEP`
  (SHA-512), `ECIES_X25519` and `ML_KEM_768` (both through HPKE seal, §3.5); Shamir shared secrets;
  key cipher layers nested up to a compile-time depth (8 by default);
- input: a **device profile**, a WA-CBOR document holding the cryptoconf and the raw public keys of
  its trustees, decoded within a sub-profile of WA-CBOR and fully validated before any encryption
  (`docs/flightbox_specifications/flightbox_device_profile_specification.md`); profiles are exported
  from a cryptoconf and a keystore pool by `scripts/flightbox/export_device_profile.py`;
- trustees `local_keyfactory`, `authenticator` and `jsonrpc_api`, all resolved to public keys of the
  profile (the device never fetches keys), which makes the root `keychain_uid` of the cryptoconf
  mandatory;
- no signatures: cryptoconfs with non-empty signature lists are rejected, so §8 has no digest
  to compute nor signature to inject;
- two crypto backends producing identical output, Mbed TLS 3.6 (with the vendored mlkem-native for
  `ML_KEM_768`) and wolfCrypt 5.8, all randomness coming from a platform hook;
- document formats chosen at compile time (Extended JSON, WA-CBOR, or both), with one format per
  cryptainer: the cryptainer file format and the key ciphertext format `F` of every layer are the
  same, so WA-CBOR cryptainers carry `key_ciphertext_format: "cbor"` on every payload layer and
  symmetric key layer (§2). A WA-CBOR-only build is a single-serialization device, as §2 allows.

### 10.3 Rust profile

`reimplementations/rust/` is a cargo workspace implementing steps 1 to 3 in memory-safe Rust, for
microcontrollers and hosts alike (its `README.md` documents its API, platform hooks, cargo features
and measured footprint). It has the feature set of the C profile (§10.2), and the same input, a
device profile, with the same validation rules and error names. What differs:

- a `no_std` core crate, without `unsafe` code nor cryptographic dependency, holding the algorithm,
  both codecs and the composite constructions (padding, CMAC, EAX, OAEP, HKDF, HPKE, Shamir) over a
  public crypto backend trait, which products implement to drive a hardware AES;
- two crypto backends producing identical output: the RustCrypto crates, in pure Rust (default), and
  wolfCrypt 5.8 through FFI bindings; all randomness comes from a platform hook;
- under the same random bytes and clock, cryptainers byte-identical to those of the C library, which
  the interoperability tests check between every pair of builds;
- document formats chosen by cargo features (Extended JSON, WA-CBOR, or both), with one format per
  cryptainer as in the C profile;
- lifecycle errors of the C API (a chunk after finalization, a missing payload sink) made impossible
  at compile time; allocation failures of small internal buffers abort instead of being reported,
  only caller-sized buffers (inline ciphertexts, decoded inputs) returning an out-of-memory error;
- a key cipher nesting cap and an RSA size limit set at run time (8 and 4096 bits by default).

### 10.4 Notes for new reimplementations

A new implementation can be written from this specification, the WA-CBOR specification and, for
embedded inputs, the device profile specification. The table sums up what is fixed by the cryptainer
format, what is left free, and what the C and Rust implementations chose (informative), for the points
where implementations have to decide:

| Topic | Required | Allowed | C choice | Rust choice |
|---|---|---|---|---|
| Input | a cryptoconf valid per §5.1 and §5.2, validated before any random draw | any transport: Extended JSON or WA-CBOR file, device profile, built-in structure | device profile only | device profile only |
| Public keys | §11.2 constraints, lookup of §5.3 | stricter checks (e.g. a maximum RSA size) | device profile rules, RSA ≤ 4096 bits | device profile rules, RSA ≤ 4096 bits (run-time limit) |
| Subset | rejecting unsupported features at validation time (§5.5) | any subset of algos, trustee types, signatures, formats | no signatures, root `keychain_uid` mandatory | same as C |
| Key ciphertext format `F` | §2 serializations; field written only for `"cbor"` | one or both of `J`, `C`; one `F` per cryptainer | `F` = file format | `F` = file format |
| Extended JSON bytes | decodable relaxed Extended JSON (§2) | any key order, any whitespace | byte-exact CPython output (§2.1) | byte-exact CPython output (§2.1) |
| Key cipher nesting | rejecting too deep cryptoconfs at validation | any cap of at least 8 (§5.2) | 8 (compile-time option) | 8 (run-time limit) |
| Metadata | map or null, no keyword maps, WA-CBOR depth limit (§5.4) | refusing floats, datetimes, decimals, bignums | sub-profile types only | sub-profile types only |
| Randomness | a CSPRNG for every draw (§3.1) | any draw order | §6.8 order, through one platform hook | §6.8 order with the draw sizes of C, through one platform hook |
| UUID0 prefix | 80 random bits | zero prefix without a clock (§3.2) | zero prefix when the clock hook is absent or fails | zero prefix when the clock hook returns none |
| Payload | inline or offloaded (§9.2), identical streamed and one-shot output | any chunk size, including 0 | both, chunks of any size | both, chunks of any size |
| Errors | no finished cryptainer, no partial file after a failure (§7.3) | any error representation and precedence | status codes of §5.5, failed state | error kinds named after the C status codes, failed state |
| Secrets | in memory only (rule 12 of §11.1) | — | wiped through a platform hook | wiped when dropped (`zeroize`) |

Reading the C or Rust sources is not needed, but the test vector generators of the C tree (§12) are
written in Python against wacryptolib and give expected bytes for each primitive; the Rust tree
stores their output as JSON files (`reimplementations/rust/test_vectors/`).

---

## 11. Conformance checklist and pitfalls

### 11.1 General rules

1. Payload layers and key layers are applied **in list order**; the decryptor reverses them.
2. What gets encrypted by key layers is always **serialized bytes** in the key ciphertext format
   `F` (`S_F(symkey)`, `S_F(key_struct)`, `S_F(cipherdict)`, `S_F([index, shard])`, §2), never raw
   key material.
3. Every asymmetric encryption wraps the current bytes in
   `{"key_bytes": ..., "cryptainer_metadata": ...}`; symmetric layers and shared secrets do not.
4. RSA-OAEP uses SHA-512 for both OAEP hash and MGF1, empty label, 60-byte plaintext chunks.
5. Shamir works on the PKCS#7-padded secret, chunk by chunk, with independent random
   coefficients per chunk, over GF(2^128) with big-endian, LSB-is-constant encoding; shard
   indices start at 1; shards are serialized as 2-item arrays, in format `F`.
6. A symmetric key layer stores the protected sub-key in **its own** `key_ciphertext` field.
7. `keychain_uid` resolution: layer/signature-conf value if present (the nil UUID included, §5.1),
   else the cryptainer's root `keychain_uid` (which is generated if the cryptoconf has none, and is
   always written into the cryptainer).
8. `payload_macs` is `null` until finalization, then `{}` (AES_CBC) or `{"tag": ...}`.
9. Payload digests are computed on each layer's raw ciphertext (CBC padding included, MAC tag
   excluded); plaintext digests on the raw plaintext.
10. `payload_digest_value` is stored even when signing is skipped or fails under
    `ATTEMPT_SIGNING`.
11. Sub-trees reused in the cryptoconf MUST be duplicated in the cryptainer (§6.6).
12. Symkeys and the `secrets` structure MUST stay in memory only, and SHOULD be wiped after
    use where the language allows it.
13. Every random value MUST come from a CSPRNG (§3.1).
14. The parts of file names chosen by an implementation MUST be lowercase:
    - cryptainer and payload suffixes;
    - extensions, including record extensions taken from a configuration;
    - timestamps;
    - algo names in key file names.

    Parts given by the caller or by a configuration, such as an original media file name or a
    sensor name, MUST be kept as given (e.g. `20261111_184000_FrontCam_cryptainer.mp4.crypt.json`
    for a sensor `FrontCam` recording `.MP4` files, and `IMG_0001.MP4.crypt.json` for a
    user-supplied `IMG_0001.MP4`). Files MUST be opened by their exact names, so that the filesystem
    decides whether letter case matters. Readers MUST recognize the lowercase suffixes, and SHOULD
    compare names like their platform does (ignoring letter case on Windows only). Filesystem
    keystores also accept key files with the legacy uppercase algo names of earlier releases.

    Exception: the extensions that carry the format of a file, i.e. `.crypt`, `.json`, `.cbor`,
    and the suffixes `.crypt.json` and `.crypt.cbor`, MUST be matched in any letter case on every
    platform (e.g. `X.CRYPT.JSON` is an Extended JSON cryptainer, and `conf.CBOR` a WA-CBOR file,
    on Linux too), so that a name means the same file format everywhere. When a tool creates a file
    from a name typed by a user, it SHOULD lowercase such a trailing extension and leave the rest of
    the name untouched (e.g. the output basename `Clip.CRYPT` gives `Clip.crypt.json`, and the
    output file `OTHER.CBOR` is written as `OTHER.cbor`). Library functions given an explicit path
    keep writing to that exact path.
15. `key_ciphertext_format` is written next to a `key_ciphertext` only when `F` is `"cbor"`; with
    `F = json`, the cryptainer has no such field at all. An unknown `F` is rejected before any key
    generation.
16. Readers MUST take the key ciphertext format from the `key_ciphertext_format` field of the
    payload layer or symmetric key layer governing the chain (shards inheriting it), and MUST
    NEVER guess it by sniffing bytes; Extended JSON bytes in a `"cbor"` chain, or the reverse, are
    an error.
17. Revelation request data sent to remote trustees is always Extended JSON (§6.5), whatever `F`.

Pitfalls met by the C reimplementation, each of which yields cryptainers that fail to decrypt or
validate if missed:

18. UUIDs are UUID values everywhere (`{"$uuid": ...}`, tag 37), never text, in the cryptoconf as in the
    cryptainer; booleans are not integers (§5.1).
19. The key order of a structure differs between `J` (code point order) and `C` (encoded-bytes
    order, shorter keys first); a generic CBOR or JSON library with "canonical" options may implement
    another order (§2.1, §2.2).
20. The key struct is a map in both formats, and a shard is a 2-item **array** `[index, bytes]` in
    both, never a map nor a pair of separate fields.
21. RSA-OAEP chunk ciphertexts are exactly `k` bytes, left-padded with zeros when the integer is
    shorter; bignum libraries often drop those zeros.
22. The EAX counter spans the full 128-bit block (§3.4); the HPKE nonce of the single `Seal` is
    `base_nonce` itself; the ML-KEM shared secret is used without any KDF step around it (§3.5).
23. Shamir field elements are big-endian, not GCM bit-reflected; the shard index is the field
    element with integer value i (§3.7).
24. In a symmetric key layer, the fresh sub-symkey encrypts the **current key bytes** (the one-shot
    cipherdict going up the chain), while `S_F(sub-symkey)` goes through the **nested** layers into the
    layer's own `key_ciphertext`; swapping the two roles, or reusing an enclosing symkey, breaks
    decryption (§6.3, §6.4).
25. Validation, including key checks, metadata checks and nesting caps, is complete before the first
    random draw and before any file is created (§5.2); a failure afterwards leaves no finished
    cryptainer and no partial file (§7.3).
26. In offloaded mode, the payload file is complete before the final cryptainer file is written, and
    is named after that final file name, temporary names excluded (§7.3, §9.2).
27. The output fields of a cryptainer (`key_ciphertext`, `key_ciphertext_format`, `payload_macs`,
    `payload_digest_value`, `payload_signature_struct`, root identifiers and state) are not allowed in
    a cryptoconf, which is validated with unknown keys rejected.

### 11.2 Key and parameter constraints per algorithm

Reference: CPython `src/wacryptolib/` (`keygen.py`, `cipher.py`, `signature.py`,
`trustee.py`, and both crypto backends `_crypto_backend/pycryptodome.py` and
`_crypto_backend/fallback/`). "Checked by" says where a cryptainer violating the constraint
gets rejected. A reimplementation MUST stay within these bounds, even where the reference only
enforces them through the underlying library: a value accepted by one backend but not the
other is not portable.

#### Symmetric key dicts (payload layers and symmetric key layers)

| Algo | Key dict | `key` | IV / nonce | Tag | Checked by |
|---|---|---|---|---|---|
| `AES_CBC` | `{"key": bytes, "iv": bytes}` | **exactly 32 bytes** (AES-256) | `iv`: exactly 16 bytes | none | `_check_symmetric_key_length_bytes()` (≥ 32 bytes) + AES itself (16/24/32 bytes only); IV length by the cipher of both backends |
| `AES_EAX` | `{"key": bytes, "nonce": bytes}` | **exactly 32 bytes** (AES-256) | `nonce`: any **non-empty** length is accepted; 16 bytes are generated and SHOULD be used | 16 bytes | same key checks; empty nonce rejected by both backends |
| `CHACHA20_POLY1305` | `{"key": bytes, "nonce": bytes}` | **exactly 32 bytes** | `nonce`: **exactly 12 bytes** (RFC 8439) | 16 bytes | `_check_symmetric_key_length_bytes()`; pycryptodome would also accept 8-byte (original ChaCha20) and 24-byte (XChaCha20) nonces, but the fallback backend only accepts 12, so only 12 is portable |

Notes:

- The ≥ 32-byte rule (`_check_symmetric_key_length_bytes`) applies at both encryption and
  decryption, so AES-128/192 keys are rejected: in practice every symmetric key is 32 bytes.
  (Its error message wrongly says "32 bits"; the check is on bytes.)
- Key dicts are validated at decryption by `check_symkey_dict_sanity()`: the fields above
  MUST be bytes, and extra fields are tolerated but ignored. Encryptors MUST NOT add extra
  fields.
- Each `(key, iv/nonce)` pair MUST be freshly generated and used for exactly one encryption
  (one payload layer, or one key wrap). This is essential for the stream ciphers: reusing a
  ChaCha20 or EAX nonce with the same key breaks confidentiality and authenticity.
- There is no AAD/header for any of them, and the tag is always 16 bytes (never truncated).

#### Asymmetric public keys (key cipher layers)

| Algo | Public key | Constraints | Ciphertext sizes | Checked by |
|---|---|---|---|---|
| `RSA_OAEP` | RSA public key `(n, e)`; PEM `SubjectPublicKeyInfo` in CPython | modulus **≥ 2048 bits**; `n` odd and ≥ 3, `3 ≤ e < n`, `gcd(n, e) = 1` (generated keys use `e = 65537`) | each chunk is exactly `k` bytes, `k` = modulus byte length (256 for RSA-2048); plaintext chunks ≤ 60 bytes, well under the OAEP-SHA-512 limit of `k − 130` bytes (126 for RSA-2048) | `_check_asymmetric_key_length_bits()` at encryption; public numbers on key import (pycryptodome `construct()`, fallback `_check_rsa_public_numbers()`) |
| `ECIES_X25519` | X25519 public key, 32 raw bytes (RFC 7748); PEM `SubjectPublicKeyInfo` with OID 1.3.101.110 and no parameters in CPython | must be on **Curve25519** (an Ed25519 or NIST-curve key is rejected); **low-order points rejected**: u ∈ {0, 1, the two order-8 points, p−1}, including their non-canonical encodings (u + p, u + 2p); non-canonical u is reduced mod p; the sealing also fails if the X25519 shared secret is all zeros | `kem_ciphertext`: 32 bytes; `ciphertext`: plaintext length + 16 | `_check_x25519_key()` at encryption; import functions and HPKE layer of both backends |
| `ML_KEM_768` | ML-KEM public (encapsulation) key, PEM `SubjectPublicKeyInfo` | parameter set **exactly ML-KEM-768** (FIPS 203): ML-KEM-512 and ML-KEM-1024 keys are rejected; if a private key is given, its public part is used | encapsulation key: 1184 bytes; `kem_ciphertext`: 1088 bytes; `ciphertext`: plaintext length + 16 | `check_pq_key_algo()` at import and encryption; pycryptodome only (no fallback) |

The key generation rules of `keygen.py` for trustees match these bounds: RSA keys of 2048
bits by default (`key_length_bits`, minimum 2048), X25519 keys from 32 random bytes, ML-KEM-768
keys with the fixed parameter set.

#### Signature keys (trustee side, for reference)

Signing happens on trustees (§4), but an encryptor relying on a local signer MUST respect:

| Algo | Key | Constraints |
|---|---|---|
| `RSA_PSS` | RSA private key | ≥ 2048 bits at generation (same rules as `RSA_OAEP`); SHA-512, MGF1-SHA-512, 64-byte salt |
| `DSA_DSS` | DSA private key | ≥ 2048 bits at generation; FIPS 186-3; signature = `r ‖ s`, fixed length |
| `ECC_DSS` | ECDSA private key | **NIST prime curves only**: P-192, P-224, P-256, P-384, P-521 (P-521 by default); Curve25519/Ed25519/Ed448 keys are rejected for DSS; signature = `r ‖ s`, fixed length |
| `ML_DSA_65` | ML-DSA private key | parameter set **exactly ML-DSA-65** (FIPS 204), ML-DSA-44/87 rejected; context `b"wacryptolib-payload-signature-v1"` |

Other parameters:

- The message sent to a trustee for signing MUST be a digest: trustees reject messages longer
  than 128 bytes (`MAX_PAYLOAD_LENGTH_FOR_SIGNATURE`).
- `signature_timestamp_utc` is an integer number of seconds.
- Digests (`payload_digest_value`) are 32 bytes (SHA256, SHA3_256) or 64 bytes (SHA512,
  SHA3_512); wacryptolib asserts a length between 32 and 64 bytes.

#### Shared secrets

- `key_shared_secret_shards` MUST hold 1 to 30 shards, and `1 ≤ key_shared_secret_threshold ≤ len(key_shared_secret_shards)`.
- Shamir operates on 16-byte chunks; each shard's byte length equals the PKCS#7-padded
  secret length (a multiple of 16, at least 16).
- Shard indices are the integers 1..n, all distinct; readers reject indices outside 1..30 and duplicates (§3.7).

---

## 12. Interoperability testing

The reference decryptor is wacryptolib's CPython implementation. A reimplementation SHOULD be
validated by:

1. producing cryptainers with known trustee keypairs (e.g. a `local_keyfactory` or imported
   `authenticator` keystore whose private keys are available on the test machine);
2. loading them with `wacryptolib.cryptainer.load_cryptainer_from_filesystem()` and checking
   them with `check_cryptainer_sanity()`;
3. decrypting them with `wacryptolib.cryptainer.decrypt_payload_from_cryptainer(cryptainer, keystore_pool=...)`
   (or the `flightbox` CLI), and checking that the payload matches and that the operation report
   has no integrity error;
4. covering: each payload algo, multiple payload layers, each asymmetric algo, nested
   symmetric layers, shared secrets (including threshold 1 and threshold = shard count,
   nested shared secrets), metadata null/non-null, empty payload, payload lengths around
   multiples of 16, streaming with odd chunk sizes, and signatures under each policy.

Primitive-level vectors: RFC 9180 Appendix A.2 (ECIES_X25519), RFC 8439 (ChaCha20-Poly1305),
the EAX paper vectors (AES_EAX), and `tests/_crypto_test_vectors.py` /
`tests/test_crypto_backend_vectors.py` in this repository.

### 12.1 Vectors and corpus for reimplementations

The C reimplementation derives its expected outputs from wacryptolib with Python generators, which
any implementation can run or read (`reimplementations/c-language/tests/unit/`):

| Generator | Expected outputs |
|---|---|
| `generate_primitive_vectors.py` | AES-256 CMAC and EAX (the EAX paper messages with AES-256 keys), symmetric cipherdicts, RSA-OAEP chunks with a fixed seed, HPKE seals for X25519 (given ephemeral key) and ML-KEM-768 (given encapsulation coins), Shamir shards with given coefficients |
| `generate_backend_conformance_vectors.py` | published vectors of the underlying primitives (SP 800-38A, RFC 8439, RFC 4231, RFC 7748...), an AES-CTR counter wrapping around 2^128 (§3.4), raw RSA values, a deterministic ML-KEM-768 encapsulation |
| `generate_writer_expected_outputs.py` | wacryptolib's `dump_to_json_bytes()` and `dump_to_cbor_bytes()` of symkeys, key structs, shards, cipherdicts and other sample trees (§2.1, §2.2) |
| `generate_device_profile_samples.py` | valid and invalid device profiles, each with its expected error category and error location |
| `generate_wacbor_specification_vectors.py` | the test vectors of section 10 of the WA-CBOR specification |

In `compatibility/` (see its `README.md`): symmetric and asymmetric cipherdict vectors per algo
(`cipherdicts/*/<ALGO>/`, `cipherdicts/2026_post_quantum/ML_KEM_768/`), which an encryptor can re-encrypt
byte for byte from their recorded symkey; cryptoconfs, valid and `invalid/`, in both formats; cryptainers
with WA-CBOR key ciphertexts (`cryptainers/2026_cbor_key_ciphertexts/`); and the keystore pools holding the
private keys needed to decrypt test outputs (e.g. `keystores/2026_cbor_key_ciphertexts/cbor_key_ciphertexts_pool/`,
`keystores/2026_post_quantum/pq_pool/`). The signature-free cryptoconfs having a root `keychain_uid` can
be exported as device profiles with `scripts/flightbox/export_device_profile.py`.

### 12.2 Cryptainer checklist

The C interop suites (`reimplementations/c-language/tests/interop/`, also run against the Rust
implementation) check each produced cryptainer as
follows; a new implementation SHOULD run the same checks, in both file formats it writes:

1. it loads with `load_cryptainer_from_filesystem()` (payload file included when offloaded) and passes
   `check_cryptainer_sanity()` in both Python and JSON-Schema modes (`jsonschema_mode=True`);
2. re-encoding the loaded tree with wacryptolib in the same format gives the same bytes (meaningful for
   `J` only if §2.1 is followed);
3. every `key_ciphertext` parses in the format of its `key_ciphertext_format` field
   (`check_key_ciphertext_formats()` of `tests/_compatibility_corpus.py`), and the cryptainer has the
   same tree shape as one created by wacryptolib from the same cryptoconf and `F`;
4. it decrypts to the original payload with no error in the operation report, also after
   `flightbox convert-format` to the other file format, and with any threshold subset of shard trustees
   (one trustee's keys withheld);
5. rejected inputs (§5.5) give the expected error category and leave no output file;
6. with several crypto libraries or backends, a deterministic RNG gives identical bytes (§6.8).
