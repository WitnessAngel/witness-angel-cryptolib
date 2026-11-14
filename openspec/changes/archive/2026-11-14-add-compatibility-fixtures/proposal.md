## Why

Wacryptolib's wire formats have changed many times: RSA-OAEP `digest_list` → `ciphertext_chunks` (0.9), `.keystore.json` → `keystore_metadata.json` (0.9), `payload_signatures` → `payload_ciphertext_signatures` (2024), CANONICAL → RELAXED extjson, PBKDF2-protected PEMs, and new ECIES_X25519 / ML_KEM_768 / ML_DSA_65 algorithms. The library still reads these legacy forms, but only through scattered code paths and freshly generated test data. Nothing committed proves that a cryptainer, keystore or cryptoconf produced years ago still decrypts or validates today. The only frozen artifact is `tests/fixtures/post_quantum/`, and its script *regenerates* it, which defeats its purpose. Other implementations (the MicroPython flightbox today, others later) also have no shared reference corpus to check their plaintext↔ciphertext compatibility against.

## What Changes

- Add a `compatibility/` root folder of **frozen, append-only** fixtures covering the whole ecosystem. Each fixture keeps wacryptolib's own wire format:
  - plaintexts of sizes chosen around AES block edges, RSA-OAEP chunk edges and multi-chunk/streaming sizes (up to ~1 MiB)
  - cipherdict vectors for every cipher algo: symmetric ones bidirectional (key/iv/nonce given), asymmetric ones (RSA_OAEP, ECIES_X25519, ML_KEM_768) decrypt-only, including the legacy `digest_list` RSA-OAEP form; signature vectors are verify-only
  - keystore pools of several generations (RSA-only v0.9-era authenticators, then ECIES/post-quantum keypairs), with a local keyfactory and imported authenticators
  - cryptoconfs of increasing sophistication, plus invalid ones that must keep being rejected
  - cryptainers of several generations (v0.9 / 0.10 / 0.11 releases, pre-`payload_signatures`-rename, CANONICAL vs RELAXED extjson, inline vs offloaded payload, with metadata, plaintext signatures, post-quantum hybrid), which must stay decryptable with the documented authenticator passphrases
- Add a **JSON sidecar** next to each fixture that carries information or secrets. It has the same name with `.json` appended (`foo.crypt` → `foo.crypt.json`, keystore pool dir `pool/` → `pool.json`) and holds the original plaintext reference, symkeys, dummy passphrases, decryption scenarios, provenance and algorithm requirements.
- Add **JSON-Schemas** in `compatibility/schemas/`, one per sidecar kind plus shared definitions, so every sidecar can be quick-validated.
- Add generation tooling that only **adds** new generation directories and never rewrites existing ones. Legacy generations come from genuine old releases where they install, and are otherwise synthesized by down-converting current outputs. Every fixture is labelled with its provenance.
- Add `tests/test_compatibility_fixtures.py`. It discovers all sidecars, schema-validates them and exercises every fixture against the current wacryptolib on both crypto backends, skipping only cases the sidecar declares unsupported by a backend (e.g. ML-KEM/ML-DSA on the fallback backend).
- Migrate `tests/fixtures/post_quantum/` into `compatibility/` as the first post-quantum generation, adapt `tests/test_wacryptolib_cryptainer.py`, and retire `scripts/generate_post_quantum_fixtures.py`.
- Add `compatibility/README.md`, documenting layout, naming, sidecar semantics and the contract for other implementations.
- Only local-keyfactory and authenticator trustees are used. JSON-RPC (webserver) trustees are out of scope.

## Capabilities

### New Capabilities
- `compatibility-fixtures`: the committed corpus of frozen cross-version fixtures (layout, sidecar metadata and schemas, coverage, immutability rules) and the obligation for the test suite to keep validating, decrypting and verifying all of them.

### Modified Capabilities

(none: `crypto-backends` and `cryptostructure-validation` requirements are unchanged; the fixtures only exercise them)

## Impact

- New `compatibility/` tree: assets, sidecars, schemas, README. About 10–30 MB in git, mostly 1 MiB plaintexts and their symmetric ciphertexts and cryptainers.
- New generation tooling under `scripts/`, plus throwaway virtualenvs for old releases (local Python 3.9/3.10 interpreters). These are only needed when *adding* a generation, never to run tests.
- New `tests/test_compatibility_fixtures.py`. Test time grows by the decryption of the corpus, mostly with no key generation since keys are committed.
- `tests/test_wacryptolib_cryptainer.py` (PQ fixture paths), removal of `tests/fixtures/post_quantum/` and `scripts/generate_post_quantum_fixtures.py`.
- No new runtime dependency: `jsonschema` is already a dependency. No library API or wire-format change. Any future format change that breaks a committed fixture becomes a visible test failure instead of a silent regression.
- Packaging: `compatibility/` must stay out of the published wheel, like `tests/`.
