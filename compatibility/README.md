# Wacryptolib compatibility corpus

This directory holds **frozen test vectors** for the Witness Angel cryptolib ecosystem: plaintexts, cipherdicts,
signatures, keystore pools, cryptoconfs and cryptainers, produced by wacryptolib releases from v0.9 onwards.

- wacryptolib's own test suite (`tests/test_compatibility_fixtures.py`) checks on every run that the current library
  still reads, validates, verifies and decrypts all of them.
- Other implementations (e.g. the MicroPython flightbox) can use them to check their compatibility with wacryptolib,
  in both directions where possible.

> **All secrets here are dummy values** (passphrases, symmetric keys, private keys). They protect nothing and
> must never be reused outside of tests.

This directory is not shipped in the published `wacryptolib` package.


## Layout

```
compatibility/
  README.md
  schemas/                          JSON-Schemas (2020-12) of the sidecars, one per fixture kind, plus _defs
  plaintexts/                       p<size>.bin + sidecars, shared by all generations
  keystores/<generation>/           keystore pool directories + "<pool>.json" sidecars
  cipherdicts/<generation>/<ALGO>/  p<size>.cipherdict (+ variants) + sidecars
  signatures/<generation>/<ALGO>/   *.signature + sidecars
  cryptoconfs/<generation>/         NN_<label>.cryptoconf + sidecars; invalid/ holds cryptoconfs that must be rejected
  cryptainers/<generation>/         NN_<label>.crypt (+ .crypt.payload when offloaded) + sidecars
```

A **generation** is a set of fixtures produced together, by one library version and one method. Its name is
`<year>_<label>` (e.g. `2022_v0.9_genuine`, `2026_current`), and it appears as a subdirectory of each fixture kind
directory that it populates. Fixtures of a generation only reference plaintexts, and keystore pools of the same
generation.

| Generation | Produced by | Notable forms |
|---|---|---|
| `2022_v0.9_genuine` | wacryptolib 0.9 (PyPI) | CANONICAL extjson, `payload_signatures`, legacy authenticator metadata, no symmetric key layers |
| `2022_v0.10_genuine` | wacryptolib 0.10 (PyPI) | idem, with recursive symmetric key layers |
| `2023_v0.11_genuine` | wacryptolib 0.11 (PyPI) | idem, `keychain_uid` inside cryptoconfs |
| `2024_pre_signature_rename` | git commit `2328abe`, the last one before the `payload_signatures` → `payload_ciphertext_signatures` rename | idem, with plaintext signatures |
| `2026_current` | current development version | RELAXED extjson, Shamir shared secrets, multi-trustee signatures, ECIES_X25519, `digest_list` vector, invalid cryptoconfs |
| `2026_post_quantum` | current development version | ML_KEM_768 / ML_DSA_65, hybrid with RSA_OAEP and ECIES_X25519; includes the fixture formerly in `tests/fixtures/post_quantum/` |


## Policy: frozen and append-only

- Committed files are **never regenerated, rewritten or deleted**, even when the library changes. If the library
  can no longer read a fixture, the library is fixed, not the fixture.
- New fixtures are only **added**, as a **new generation**. The generation tooling refuses to write into an
  existing generation directory.
- Every sidecar records the SHA-256 of its asset files, so that any modification is detected.
- Files are committed **byte-exact**: the root `.gitattributes` disables all line-ending conversion here
  (`compatibility/** -text`).
- Tests never write into this directory: keystore pools are always used from temporary copies, since wacryptolib may
  write into a pool (e.g. by autogenerating missing keys).


## Assets

Assets use wacryptolib's own wire formats, with no conversion.

- **Plaintexts** (`.bin`): raw bytes. Sizes cover the empty case, AES block edges (15/16/17, 31/32/33), RSA-OAEP chunk
  edges (59/60/61), 255/256/257, and multi-chunk sizes just above 4 KiB, 64 KiB and 1 MiB (4099, 65539, 1048579). The
  file name is `p` + the size on 8 digits.
- **Cipherdicts** (`.cipherdict`): the dict returned by `wacryptolib.cipher.encrypt_bytestring()`, in extended JSON.
  Field names depend on the algorithm: `ciphertext` (+ `tag` for AES_EAX and CHACHA20_POLY1305);
  `ciphertext_chunks` for RSA_OAEP (or the legacy `digest_list` name, in files suffixed `_digest_list`);
  `kem_ciphertext` + `ciphertext` for ECIES_X25519 and ML_KEM_768.
- **Signatures** (`.signature`): the dict returned by `wacryptolib.signature.sign_message()`, in extended JSON
  (`signature_value` bytes + `signature_timestamp_utc` integer; the timestamp is part of the signed data).
- **Keystore pools** (directories): the on-disk layout of `wacryptolib.keystore.FilesystemKeystorePool`:
  - `local_keyfactory/<keychain_uid>_<KEY_ALGO>_{public,private}_key.pem`;
  - `foreign_keystores/keystore_<keystore_uid>/`, one per imported authenticator, with its PEM files (public keys,
    and passphrase-protected private keys) and its `keystore_metadata.json` (extended JSON). Authenticator metadata of
    old generations may carry legacy fields (e.g. `keystore_secret`), which the library still accepts.
- **Cryptoconfs** (`.cryptoconf`): an encryption configuration, as given to `encrypt_payload_into_cryptainer()`, in
  extended JSON.
- **Cryptainers** (`.crypt`): a cryptainer in extended JSON, as written by `dump_cryptainer_to_filesystem()`. When
  the payload is **offloaded**, the cryptainer's `payload_ciphertext_struct` is the marker
  `{"ciphertext_location": "offloaded"}`, and the ciphertext is in the sibling `<name>.crypt.payload` file (raw bytes).

### Extended JSON flavors

Assets are [MongoDB extended JSON](https://www.mongodb.com/docs/manual/reference/mongodb-extended-json/), in one of
two flavors (recorded as `extjson_flavor` in cryptainer sidecars):

- **RELAXED** (current wacryptolib): bytes as `{"$binary": {"base64": ..., "subType": "00"}}`, UUIDs as
  `{"$uuid": "<32 hex digits>"}`, dates as `{"$date": "<ISO 8601>"}`, numbers as plain JSON numbers.
- **CANONICAL** (releases up to 2024): bytes as above, UUIDs as `{"$binary": {"base64": ..., "subType": "04"}}`,
  dates as `{"$date": {"$numberLong": "<milliseconds>"}}`, integers as `{"$numberInt": "..."}` or
  `{"$numberLong": "..."}`.

Readers must accept both flavors.


## Sidecars

Every asset has a **sidecar**: a plain JSON file named after the asset with `.json` appended, in the same directory
(`x.crypt` → `x.crypt.json`, keystore pool directory `pool/` → `pool.json`). Sidecars only use standard JSON:

- byte strings are **lowercase hex** strings;
- UUIDs are **canonical hyphenated** lowercase strings;
- references to other fixtures are **POSIX paths relative to the sidecar's directory** (never absolute);
- dates are `YYYY-MM-DD` strings.

Each sidecar validates against the schema of its kind, in `schemas/<fixture_kind>.schema.json`, which its `$schema`
field references by relative path. All schemas forbid unknown fields.

### Common fields (all kinds)

| Field | Meaning |
|---|---|
| `$schema` | Relative path to the JSON-Schema of the fixture kind. |
| `fixture_kind` | One of `plaintext`, `cipherdict`, `signature`, `keystore_pool`, `cryptoconf`, `cryptainer`. |
| `generation` | Name of the generation (`<year>_<label>`); for plaintexts, which all generations share, the one which first added them. |
| `description` | Human-readable description of the fixture. |
| `provenance` | How the asset was produced, see below. |
| `requirements` | What a crypto backend needs to exercise the fixture, see below. |
| `asset_sha256` | SHA-256 (hex) of every file of the asset, keyed by path relative to the sidecar directory: the asset file, plus its `.payload` file if offloaded, or every file of a keystore pool directory. |

**`provenance`**:

| Field | Meaning |
|---|---|
| `method` | `genuine`: produced as-is by the named library version. `synthesized`: a current output down-converted to legacy forms, for releases that could not be run. `migrated`: moved from a former location of the repository. |
| `library_version` | Version of wacryptolib that produced the asset (e.g. `0.9`, or `0.12+dev` for a development version). |
| `library_commit` | Git commit of wacryptolib, for development versions. |
| `python_version` | Python version used. |
| `crypto_backend` | `pycryptodome` (native) or `fallback` (pure Python) backend of wacryptolib. |
| `produced_on` | Production date. |
| `legacy_forms` | Legacy wire forms present in the asset (mandatory for `synthesized` ones): `canonical_extjson` (CANONICAL extended JSON), `payload_signatures_field` (former name of `payload_ciphertext_signatures`), `rsa_oaep_digest_list_field` (former name of the RSA-OAEP `ciphertext_chunks`). |
| `notes` | Free-form remarks (e.g. dependency versions used for old releases). |

**`requirements`**: `algorithms` lists the cipher, key and signature algorithms involved, and `pem_protections`
lists the private key PEM protections involved (`none` is never listed). A consumer, or a crypto backend, lacking one
of them must skip the fixture, and must check all others. PEM protections are:

| Value | Meaning |
|---|---|
| `none` | Unprotected PKCS#8 / traditional PEM. |
| `pbes2_pbkdf2_hmac_sha1_aes_cbc` | PKCS#8 encrypted, PBES2 with PBKDF2-HMAC-SHA1 and AES-CBC. |
| `pbes2_pbkdf2_hmac_sha256_aes_cbc` | PKCS#8 encrypted, PBES2 with PBKDF2-HMAC-SHA256 and AES-CBC. |
| `pbes2_scrypt_aes_cbc` | PKCS#8 encrypted, PBES2 with scrypt and AES-CBC. |
| `legacy_encapsulated_header` | OpenSSL "traditional" encryption (`Proc-Type` / `DEK-Info` headers). |

### Shared structures

- **Key reference** (`key_ref`): `keystore_pool` (relative path to a keystore pool directory), `keystore`
  (`local_keyfactory`, or the `keystore_uid` of an authenticator of that pool), `keychain_uid`, `key_algo`, and
  `passphrase` (passphrase of the private key, or `null` if unprotected; only for private key references).
- **Keypair identifier** (`keypair_identifier`): `keychain_uid`, `key_algo`, `private_key_present`, and
  `pem_protection` of the private key (when present).
- **Passphrase mapper** (`passphrase_mapper`): passphrases to try per **trustee id**, as built by wacryptolib's
  `get_trustee_id()`: `local_keyfactory`, or `authenticator@<keystore_uid>`. E.g.
  `{"authenticator@a11ce000-0000-4000-8000-000000000001": ["compat-alice-passphrase"]}`.

### Plaintext sidecars

| Field | Meaning |
|---|---|
| `size` | Size in bytes. |
| `generator` | `{"algo": "sha256_counter", "seed": <hex>}`: the plaintext is the concatenation of `SHA256(seed ‖ counter)` for counter = 0, 1, 2… (4-byte big-endian), truncated to `size`. |

### Cipherdict sidecars

| Field | Meaning |
|---|---|
| `cipher_algo` | Cipher algorithm (e.g. `AES_CBC`, `RSA_OAEP`, `ML_KEM_768`). |
| `plaintext` | Relative path to the plaintext. |
| `direction` | `bidirectional` or `decrypt_only`, see below. |
| `symkey` | For `bidirectional` vectors: the symmetric key dict of the algorithm, hex-encoded (`key` + `iv` for AES_CBC, `key` + `nonce` for AES_EAX and CHACHA20_POLY1305). |
| `private_key` | For `decrypt_only` vectors: key reference to the private key that decrypts the cipherdict. |

- **`bidirectional`** (symmetric algorithms, which are deterministic for a given key and IV/nonce): decrypting the
  cipherdict with `symkey` gives the plaintext, **and** encrypting the plaintext with `symkey` gives exactly the
  cipherdict.
- **`decrypt_only`** (asymmetric algorithms, which are randomized): decrypting the cipherdict with the private key gives
  the plaintext; re-encryption gives a different, but equally valid, cipherdict.

### Signature sidecars

| Field | Meaning |
|---|---|
| `signature_algo` | Signature algorithm (`RSA_PSS`, `DSA_DSS`, `ECC_DSS`, `ML_DSA_65`). |
| `message` / `message_hex` | Signed message: relative path to a plaintext, or inline hex. |
| `public_key` | Key reference to the verification public key. |
| `expected_valid` | `true` if the signature must verify; `false` for tampered vectors, which must be rejected. |

### Keystore pool sidecars

| Field | Meaning |
|---|---|
| `local_keyfactory.keypairs` | Keypair identifiers present in the local keyfactory (local keys are not passphrase-protected). |
| `authenticators` | One entry per imported authenticator keystore (may be empty for migrated pools). |
| `authenticators[].keystore_uid` | UID of the authenticator keystore. |
| `authenticators[].keystore_owner` | Owner name stored in its metadata. |
| `authenticators[].keystore_passphrase_hint` | Passphrase hint stored in its metadata, if any. |
| `authenticators[].passphrase` | Dummy passphrase protecting all private keys of this authenticator. |
| `authenticators[].keypairs` | Keypair identifiers present in this authenticator keystore. |

### Cryptoconf sidecars

| Field | Meaning |
|---|---|
| `expected_valid` | `true` if the cryptoconf must pass validation; `false` if it must be rejected (those live in `invalid/`). |
| `sophistication_level` | 1 (single layer) and up (several payload layers, recursive key layers, Shamir shared secrets, signatures, hybrid post-quantum); 0 for invalid cryptoconfs. |
| `keystore_pool` | For valid cryptoconfs: relative path to a pool whose keys let the cryptoconf encrypt and decrypt. |
| `passphrase_mapper` | For valid cryptoconfs: passphrases needed to decrypt with that pool. |
| `min_library_version` | First wacryptolib version able to use this cryptoconf. |

### Cryptainer sidecars

| Field | Meaning |
|---|---|
| `plaintext` / `plaintext_hex` | Original payload: relative path to a plaintext, or inline hex. |
| `keystore_pool` | Relative path to the pool holding the keys needed to decrypt. |
| `cryptoconf` | Relative path to the cryptoconf the cryptainer was produced from, if any. |
| `cryptainer_metadata` | Expected unencrypted metadata of the cryptainer (`null` if none). |
| `extjson_flavor` | `canonical` or `relaxed`, see above. |
| `payload_offloaded` | `true` if the ciphertext is in a sibling `.crypt.payload` file. |
| `decryption_scenarios` | Decryption attempts and their expected outcomes, see below. |

Each **decryption scenario** has:

| Field | Meaning |
|---|---|
| `name`, `description` | Identification of the scenario (e.g. `all_passphrases`, `threshold_exact_first`, `below_threshold`). |
| `passphrase_mapper` | Passphrases given to the decryptor. |
| `expected` | `success`: the decrypted payload equals the plaintext. `failure`: decryption yields no payload. |
| `expected_warnings` | For successes: error types expected in wacryptolib's decryption report anyway (e.g. `SIGNATURE_ERROR` for a corrupted, non-fatal, signature; `ASYMMETRIC_DECRYPTION_ERROR` for a Shamir shard whose passphrase is missing). Absent means none. |


## Using the corpus from another implementation

1. Discover all `*.json` files outside `schemas/` and outside keystore pool directories: these are the sidecars.
2. Validate each one against its schema, and check its `asset_sha256` digests.
3. Skip fixtures whose `requirements` your implementation does not support.
4. Check each fixture according to its kind, as described above: e.g. decrypt each cipherdict vector, or decrypt each
   cryptainer with the passphrases of each scenario and compare with the expected outcome. Encrypt data with
   `symkey` for `bidirectional` vectors.

`tests/_compatibility_corpus.py` is the reference implementation of these checks.


## Adding a generation

Never modify existing generations; add a new one instead (e.g. when the wire format changes, or when new algorithms
or features appear). From the repository root, with the development environment:

```
# Fixtures of the current library version
PYTHONPATH=src python scripts/compatibility/generate_current.py classic 2027_current
PYTHONPATH=src python scripts/compatibility/generate_current.py post_quantum 2027_post_quantum

# Fixtures of old releases, each run in its own throwaway virtualenv (or synthesized when it cannot run)
PYTHONPATH=src python scripts/compatibility/build_legacy_generations.py --only 0.9
```

Both scripts write into hidden staging directories, move them into place, then check every produced fixture with the
current library, and remove the new generation again if any check fails. Missing plaintexts are added to
`plaintexts/`, existing ones are never touched. Then run
`pytest tests/test_compatibility_fixtures.py`, and commit the new generation as-is.

New algorithms must get vectors: the test suite fails when a cipher, signature or asymmetric key algorithm of the
library appears in no fixture.
