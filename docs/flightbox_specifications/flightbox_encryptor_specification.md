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
| Shamir shared secret | `src/wacryptolib/utilities/data_utils.py`, `reimplementations/micropython/src/cryptainer/pycryptodome_secret_sharing.py` |
| Extended JSON | `extjson` package (vendored as `reimplementations/micropython/lib/extjson.py`) |
| Cryptoconf / cryptainer schemas | `src/wacryptolib/cryptainer/_validation.py` |
| MicroPython platform utilities | `reimplementations/micropython/src/cryptainer/flightbox_utilities_implementation.py`, `reimplementations/micropython/src/cryptainer/fallback_adapter.py` |
| Pure-Python HPKE X25519 seal | `src/wacryptolib/_crypto_backend/fallback/hpke_x25519_seal.py` (vendored in `reimplementations/micropython/lib/`) |

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
| **key_ciphertext** | Bytes: the Extended-JSON serialization of the *outermost* cipherdict of a chain of key cipher layers. |
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
               cryptainer (JSON) + ciphertext (inline or offloaded, §9)
```

Step 1 is the portable "flightbox" algorithm proper (`FlightBox` class). It is purposely
written with **dependency injection** only: every platform-specific operation goes through a
`FlightboxUtilities` object (§10). Steps 2 and 3 are currently implemented by
`CryptainerEncryptor` (CPython only); the MicroPython port currently stops after step 1.

---

## 2. Extended JSON serialization (`dump_to_json_bytes`)

Every intermediate structure that gets encrypted (symkeys, key structs, cipherdicts, shards),
as well as the final cryptainer file, is serialized with the **Extended JSON** dialect of the
`extjson` package (MongoDB Extended JSON, *relaxed* mode), then UTF-8 encoded.

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

### 3.3 Symmetric key generation (`generate_symkey(cipher_algo)`)

| `cipher_algo` | Generated symkey dict |
|---|---|
| `AES_CBC` | `{"key": random(32), "iv": random(16)}` |
| `AES_EAX` | `{"key": random(32), "nonce": random(16)}` |
| `CHACHA20_POLY1305` | `{"key": random(32), "nonce": random(12)}` |

Keys MUST be 32 bytes (the decryptor rejects keys shorter than 32 bytes). Each symkey is used
for exactly one encryption, so the fixed IV/nonce stored next to the key is safe.

The symkey is serialized as `J(symkey)`, e.g.
`{"iv": {"$binary": {...}}, "key": {"$binary": {...}}}`, and **these JSON bytes** are what gets
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

#### ECIES_X25519

HPKE (RFC 9180), **Base mode**, single-shot seal:

- KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF `0x0001` HKDF-SHA256, AEAD `0x0003`
  ChaCha20-Poly1305.
- `info = b""`, `aad = b""`, a single `Seal()` per context (sequence number 0).
- Recipient public key: raw 32-byte X25519 public key (CPython loads it from a PEM
  `SubjectPublicKeyInfo`; MicroPython receives the raw bytes).
- Cipherdict: `{"kem_ciphertext": enc (32 bytes, ephemeral public key), "ciphertext": sealed bytes (plaintext length + 16-byte tag)}`.
- RFC 9180 Appendix A.2 test vectors apply.

#### ML_KEM_768 (post-quantum, CPython only for now)

HPKE (RFC 9180) Base mode, as implemented by pycryptodome ≥ 4.2 `Crypto.Protocol.HPKE`:
KEM ML-KEM-768 (FIPS 203), KDF HKDF-SHA256, AEAD ChaCha20-Poly1305 (`0x0003`), empty info and
AAD. Cipherdict: `{"kem_ciphertext": bytes, "ciphertext": bytes}` (same shape as
ECIES_X25519). Reimplementations MUST cross-check against pycryptodome (e.g. by decrypting
with wacryptolib, see §12, or with `tests/fixtures/post_quantum/`), since the HPKE KEM
identifier of ML-KEM comes from an IETF draft.

### 3.6 Hash algorithms

Allowed values for `payload_digest_algo`: `SHA256`, `SHA512`, `SHA3_256`, `SHA3_512`
(standard FIPS 180-4 / FIPS 202 digests). A platform MAY support only a subset (e.g.
MicroPython's `hashlib` lacks SHA3); it MUST then refuse cryptoconfs requiring others.

### 3.7 Shamir secret sharing (`split_secret_into_shards`)

Input: `secret` (bytes, any length), `shard_count` n ≥ 1, `threshold_count` k with
`1 ≤ k ≤ n`. Output: a list of n tuples `(index, shard_bytes)`, index from 1 to n.

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

Each shard tuple is then serialized as `J((i, shard_bytes))`, i.e. a JSON **array**
`[i, {"$binary": {...}}]`, which is what the decryptor expects (a 2-item list: int, bytes).

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
    "key_shared_secret_shards": [ { "key_cipher_layers": [ key_cipher_layer, ... ] }, ... ]  # each NON-EMPTY
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
which may again be shared secrets or symmetric layers, without depth limit.

Algorithm names are case-sensitive uppercase strings in the cryptoconf.

### 5.2 Validation

The CPython encryptor validates the whole cryptoconf against `CRYPTOCONF_SCHEMA_PYTHON`
(`_validation.py`) **before** any key generation, and rejects unknown keys. Reimplementations
SHOULD do the same (a JSON Schema export is available as `CRYPTOCONF_SCHEMA_JSON`).

Independently of that upfront validation, the flightbox core itself MUST raise a validation
error when:

- `payload_cipher_layers` is empty;
- any `key_cipher_layers` list is empty;
- a shared secret threshold is not in `1..len(key_shared_secret_shards)`.

`cryptainer_metadata` MUST be a dict (JSON-serializable with §2 types) or null.

### 5.3 Trustee public key resolution

`get_public_key(trustee, key_algo, keychain_uid)` returns the public key of the keypair
`(keychain_uid, key_algo)` of that trustee:

| `trustee_type` | Resolution |
|---|---|
| `local_keyfactory` | The device's own keystore; the keypair is generated on demand if missing. |
| `authenticator` | A *read-only* imported keystore identified by `keystore_uid` (public keys only). Missing key = error. |
| `jsonrpc_api` | Remote call `fetch_public_key(keychain_uid, key_algo)` on `jsonrpc_url`, returning a PEM. |

How keys are stored/transported is platform-specific (PEM in CPython; raw RSA `(n, e)` integers
or raw X25519 bytes in the MicroPython demo).

---

## 6. Step 1 — Flightbox core: cryptainer base and secrets

### 6.1 Entry point

```
function generate_cryptainer_base_and_secrets(cryptoconf, cryptainer_metadata = null)
        -> (cryptainer, secrets)
```

```
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
        key_bytes   = J(symkey)
        layer["key_ciphertext"] = encrypt_key_through_multiple_layers(
                                      default_keychain_uid, key_bytes,
                                      layer["key_cipher_layers"], cryptainer_metadata)
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
                                             key_cipher_layers, cryptainer_metadata) -> bytes
    if key_cipher_layers is empty: validation error
    initial = key_bytes
    for key_cipher_layer in key_cipher_layers:                     # in order
        key_cipherdict = encrypt_key_through_single_layer(
                             default_keychain_uid, key_bytes, key_cipher_layer, cryptainer_metadata)
        key_bytes = J(key_cipherdict)                              # stays bytes all along
    assert key_bytes != initial                                    # safety net
    return key_bytes                                               # = key_ciphertext
```

So the *k*-th layer encrypts the JSON serialization of the (*k*-1)-th layer's cipherdict, and
the result is the JSON serialization of the **last** layer's cipherdict. The decryptor walks
the list in reverse order.

### 6.3 Single key cipher layer

```
function encrypt_key_through_single_layer(default_keychain_uid, key_bytes,
                                          key_cipher_layer, cryptainer_metadata) -> dict
    algo = key_cipher_layer["key_cipher_algo"]

    if algo == "[SHARED_SECRET]":                                  # §6.4
        shard_confs = key_cipher_layer["key_shared_secret_shards"]
        n = len(shard_confs)
        k = key_cipher_layer["key_shared_secret_threshold"]
        if not (0 < k <= n): validation error
        shards = split_secret_into_shards(key_bytes, shard_count=n, threshold_count=k)
        shard_ciphertexts = []
        for (shard, shard_conf) in zip(shards, shard_confs):      # shard i -> i-th shard conf
            shard_bytes = J(shard)                                 # "[i, {"$binary": ...}]"
            shard_ciphertexts.append(
                encrypt_key_through_multiple_layers(default_keychain_uid, shard_bytes,
                                                    shard_conf["key_cipher_layers"],
                                                    cryptainer_metadata))     # recursion
        return {"shard_ciphertexts": shard_ciphertexts}

    elif algo is a symmetric cipher algo:                          # §6.4
        sub_symkey = generate_symkey(algo)
        key_cipher_layer["key_ciphertext"] = encrypt_key_through_multiple_layers(
                default_keychain_uid, J(sub_symkey),
                key_cipher_layer["key_cipher_layers"], cryptainer_metadata)   # recursion, STORED IN PLACE
        return encrypt_bytestring(key_bytes, cipher_algo=algo, key_dict=sub_symkey)   # one-shot cipherdict

    else:                                                          # asymmetric algo
        keychain_uid = key_cipher_layer.get("keychain_uid") or default_keychain_uid
        return encrypt_key_with_asymmetric_cipher(algo, keychain_uid, key_bytes,
                                                  key_cipher_layer["key_cipher_trustee"],
                                                  cryptainer_metadata)
```

An unknown `key_cipher_algo` is an error (assertion in the Python code).

### 6.4 Notes on shared secrets and symmetric sub-keys

- **Shared secret**: the *current* key bytes (the symkey JSON, or an already-wrapped
  cipherdict JSON if the shared secret is not the first layer) are split into n shards; each
  shard goes through its own chain of key cipher layers, typically one trustee per shard. The
  resulting cipherdict `{"shard_ciphertexts": [...]}` keeps the order of
  `key_shared_secret_shards`. Shard *i* (index i, 1-based) MUST be encrypted with the *i*-th
  shard conf.
- **Symmetric layer**: a fresh sub-symkey encrypts the current key bytes (one-shot cipherdict,
  integrity tag included for AEAD algos, returned up the chain), while the sub-symkey itself is
  protected by the nested `key_cipher_layers`, and its resulting ciphertext is **written into
  the symmetric layer dict itself** (`key_cipher_layer["key_ciphertext"]`). This is the only
  place, besides payload cipher layers, where the core mutates key cipher layers of the
  cryptainer.
- Asymmetric layers do not get any extra field: their output only travels up the chain. In
  particular the resolved `keychain_uid` is NOT written into the layer (the decryptor
  re-resolves it the same way: layer's own value, else the cryptainer's `keychain_uid`).

### 6.5 Asymmetric wrapping and the key struct

```
function encrypt_key_with_asymmetric_cipher(cipher_algo, keychain_uid, key_bytes,
                                            trustee, cryptainer_metadata) -> dict
    public_key = get_public_key(trustee, key_algo=cipher_algo, keychain_uid=keychain_uid)
    key_struct = {"key_bytes": key_bytes, "cryptainer_metadata": cryptainer_metadata}
    return encrypt_bytestring(J(key_struct), cipher_algo=cipher_algo, key_dict={"key": public_key})
```

The key struct embeds the (unencrypted) cryptainer metadata inside every asymmetric
encryption, so that a trustee can see what it is asked to decrypt. Its exact format is
mandatory (`KEY_STRUCT_SCHEMA`): a dict with `key_bytes` (bytes) and `cryptainer_metadata`
(dict or null), e.g. (sorted keys):

```json
{"cryptainer_metadata": {"SOME_METADATA": 2726562425242}, "key_bytes": {"$binary": {"base64": "eyJpdiI6...", "subType": "00"}}}
```

Since metadata is repeated in each key struct, large metadata increases the number of
RSA-OAEP chunks accordingly.

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

the payload layer's `key_ciphertext` is:

```
J({"shard_ciphertexts": [
     J(ECIES_T2( J({"key_bytes": J([1, shard1]), "cryptainer_metadata": M}) )),
     J(RSA_T3(   J({"key_bytes": J([2, shard2]), "cryptainer_metadata": M}) )) ]})
where shard1, shard2 = Shamir split of
     J(RSA_T1( J({"key_bytes": J(symkey), "cryptainer_metadata": M}) ))
```

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
| payload layer | `payload_macs` | `{}` or `{"tag": bytes}` |
| payload layer | `payload_ciphertext_signatures` | legacy `payload_signatures` renamed |
| symmetric key layer | `key_ciphertext` | bytes: the protected sub-symkey (§6.4) |
| each signature conf | `payload_digest_value` | bytes |
| each signature conf | `payload_signature_struct` | `{"signature_value": bytes, "signature_timestamp_utc": int}`, if signed |

The cryptainer is serialized with `J()` (§2) into a UTF-8 JSON file, conventionally named
`<something>.crypt`.

### 9.2 Payload ciphertext location

- **Inline**: `"payload_ciphertext_struct": {"ciphertext_location": "inline", "ciphertext_value": <bytes>}`;
  the ciphertext is base64-embedded in the JSON.
- **Offloaded**: `"payload_ciphertext_struct": {"ciphertext_location": "offloaded"}` exactly
  (no other key), and the raw final ciphertext bytes are stored in a sibling file named
  `<cryptainer filename>.payload` (e.g. `20261111_184000_video.mp4.crypt` and
  `20261111_184000_video.mp4.crypt.payload`).

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
| `dump_to_json_bytes(data)` | §2. |
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
- Shamir via a vendored copy of pycryptodome's pure-Python `Shamir`;
- no payload encryption, digests, signatures nor file output yet (steps 2 and 3).

---

## 11. Conformance checklist and pitfalls

### 11.1 General rules

1. Payload layers and key layers are applied **in list order**; the decryptor reverses them.
2. What gets encrypted by key layers is always **JSON bytes** (`J(symkey)`, `J(key_struct)`,
   `J(cipherdict)`, `J([index, shard])`), never raw key material.
3. Every asymmetric encryption wraps the current bytes in
   `{"key_bytes": ..., "cryptainer_metadata": ...}`; symmetric layers and shared secrets do not.
4. RSA-OAEP uses SHA-512 for both OAEP hash and MGF1, empty label, 60-byte plaintext chunks.
5. Shamir works on the PKCS#7-padded secret, chunk by chunk, with independent random
   coefficients per chunk, over GF(2^128) with big-endian, LSB-is-constant encoding; shard
   indices start at 1; shards are serialized as 2-item JSON arrays.
6. A symmetric key layer stores the protected sub-key in **its own** `key_ciphertext` field.
7. `keychain_uid` resolution: layer/signature-conf value if present and non-empty, else the
   cryptainer's root `keychain_uid` (which is generated if the cryptoconf has none, and is
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

- `key_shared_secret_shards` MUST be non-empty, and `1 ≤ key_shared_secret_threshold ≤ len(key_shared_secret_shards)`.
- Shamir operates on 16-byte chunks; each shard's byte length equals the PKCS#7-padded
  secret length (a multiple of 16, at least 16).
- Shard indices are the integers 1..n, all distinct.

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
