## Context

See `proposal.md` (Why) and `docs/audits/post_quantum_algorithms_report.md` (algorithm selection). Current state that shapes the approach:

- Algorithms are declared in three registries: `ASYMMETRIC_KEY_ALGOS_REGISTRY` (keygen.py), `CIPHER_ALGOS_REGISTRY` (cipher.py), `SIGNATURE_ALGOS_REGISTRY` (signature.py). Validation, CLI choices, keystore and tests derive from the `SUPPORTED_*` lists, so most of the lib picks up new entries without edits.
- `RSA_OAEP` encrypts the key struct directly in 60-byte chunks (`RSA_OAEP_CHUNKS_SIZE`). A KEM cannot take a plaintext, so the new layer needs a KEM + DEM construction.
- `_check_asymmetric_key_length_bits` rejects keys below 2048 bits and is called from the RSA cipher functions; ML-KEM/ML-DSA keys have no such parameter.
- Signatures are computed over a SHA-512 hasher fed with `message || str(timestamp)`; backend functions receive the hasher object.
- `trustee.py:decrypt_with_private_key` asserts `cipher_algo == "RSA_OAEP"`.
- Keys are stored as `<keychain_uid>_<key_algo>_{public,private}_key.pem`; pycryptodome 4.2 exports ML-KEM/ML-DSA as RFC 7468 PEM (SPKI / PKCS#8, seed form for private keys), so the keystore is format-agnostic.
- pycryptodome 4.2 exposes ML-KEM only through `Crypto.Protocol.HPKE` (no raw encaps/decaps), which already implements KEM + KDF + AEAD per RFC 9180.

## Goals / Non-Goals

**Goals:**
- Two new algorithm names, `ML_KEM_768` and `ML_DSA_65`, usable everywhere `RSA_OAEP` and `RSA_PSS` are today, through the same registry mechanism and the same PEM-based key plumbing.
- Hybrid protection expressed purely in cryptoconfs, by stacking layers.
- Zero new runtime dependencies; one dependency bump.

**Non-Goals:**
- MicroPython / flightbox implementation (pycryptodome is unavailable there; tracked as a separate change built on the fallback adapter).
- Other PQ schemes (SLH-DSA, FN-DSA, HQC) and composite/X-Wing KEMs.
- Cryptainer format version bump or migration tooling for existing cryptainers.
- Authenticator UI changes.

## Decisions

**D1. Fixed-parameter algorithm names (`ML_KEM_768`, `ML_DSA_65`) rather than `ML_KEM` + `param_set`.**
Matches `AES_EAX` / `CHACHA20_POLY1305` naming, keeps keystore filenames and cryptoconf validation enumerable, and avoids threading a new extra parameter through `generate_keypair`. Adding `ML_KEM_1024` later is one more registry entry. Alternative rejected: a `param_set` generation parameter like `key_length_bits`, which would also require storing it in cryptoconfs.

**D2. KEM + DEM via pycryptodome HPKE, Base mode, AES-256-GCM, empty `info`.**
pycryptodome 4.2 offers no standalone encapsulate/decapsulate, and HPKE is the standardized way to turn a KEM into public-key encryption (RFC 9180, draft-ietf-hpke-pq). Encrypt: `ctx = HPKE.new(receiver_key=pub, aead_id=AEAD.AES256_GCM)`, `enc = ctx.enc`, `ct = ctx.seal(plaintext)`. Decrypt: `HPKE.new(receiver_key=priv, enc=enc, aead_id=...).unseal(ct)`. AES-256-GCM over ChaCha20-Poly1305 because it is the HPKE default and hardware-accelerated on every desktop/phone target. `info` left empty: the key struct already carries its own metadata, and a non-empty info would be one more thing to replicate in the MicroPython port. Alternative rejected: hand-rolled KEM + AES-EAX wrap, which would need raw KEM access pycryptodome does not expose and would re-implement HPKE's key schedule.

**D3. Cipherdict shape for `ML_KEM_768`: `{"kem_ciphertext": bytes, "ciphertext": bytes}`.**
`ciphertext` is the HPKE seal output (AES-GCM ciphertext with its 16-byte tag appended, as HPKE defines). Reusing the `ciphertext` key name satisfies the comment in cipher.py that every cipherdict carries a `ciphertext` attribute, and the symmetric-layer code paths that look for it. `is_authenticated=True`, `encryption_node_class=None` (not streamable, like RSA_OAEP). Both values serialize as base64 in Extended JSON. The AEAD choice is not stored in the cipherdict: it is fixed by the algorithm name, so a future change of AEAD must introduce a new algorithm name.

**D4. ML-DSA signs the 64-byte SHA-512 digest in pure mode with context `b"wacryptolib-payload-signature-v1"`.**
Keeps `_compute_timestamped_hash` unchanged, so the signed material is identical across all signature algorithms. Pure mode on the digest is what RSA-PSS already does conceptually (the hasher is consumed by `pss.new().sign(hasher)`). The context string gives domain separation that RSA/DSA signatures lack, at no cost; it is fixed, not configurable, to keep verification parameter-free. Hedged (randomized) signing is pycryptodome's default and is kept. Alternatives rejected: HashML-DSA (pre-hash variant) is meant for messages that cannot be held in memory, and RFC 9881 only specifies pure mode; `MLDSAMuHash` streaming would require changing the backend signing interface for all algorithms.

**D5. Key-length check bypass.**
`_check_asymmetric_key_length_bits` stays where it is (inside the RSA functions), so the new ML-KEM cipher functions simply do not call it. `generation_extra_parameters=[]` for both new algos, so `key_length_bits` and `curve` are ignored as the spec requires. No change to the `generate_keypair` signature.

**D6. Key class fetchers.**
Signature dispatch checks key types via `compatible_key_class_fetcher`; ML-DSA gets a fetcher returning `(MLDSAKey,)`. Cipher dispatch for `ML_KEM_768` checks `isinstance(key, MLKEMKey)` and raises `ValueError` otherwise, mirroring the key-size check that RSA uses as its implicit type check. Because `MLKEM.import_key` and `MLDSA.import_key` each reject the other family's PEM, loading a key with the wrong `key_algo` fails at load time.

**D7. Trustee assertion removed, not extended.**
`decrypt_with_private_key` replaces `assert cipher_algo == "RSA_OAEP"` with `assert cipher_algo in SUPPORTED_ASYMMETRIC_CIPHER_ALGOS`. The remote trustee JSON-RPC path transports the cipherdict opaquely, so it needs no change.

**D8. Hybrid by layering, nothing in the lib.**
Documented as a cryptoconf pattern (`ML_KEM_768` then `RSA_OAEP`) in `selected_protocols.rst` and exercised by a test. pycryptodome's X-Wing keys are not PEM-exportable and would not fit the keystore; a composite would also duplicate what layering already guarantees (both keys needed).

**D9. Fallback adapter (MicroPython) explicitly untouched.**
`_crypto_backend/__init__.py` imports only from `pycryptodome.py`; the fallback adapter has no ML-KEM entry in this change. The algorithm name, cipherdict shape and HPKE parameters chosen here (Base mode, AES-256-GCM, empty info, HKDF-SHA256 as implied by ML-KEM-768) are the contract the future MicroPython encapsulation-only port must honor.

## Risks / Trade-offs

- [pycryptodome 4.x is one week old; API or wheel regressions possible, especially python-for-android / kivy-ios builds of mlkem-native and mldsa-native] → Pin `^4.2`, keep the new algos out of default cryptoconf templates until the Authenticator build is verified; the change itself does not alter any default.
- [Larger cryptainers: +1.1 KB per ML-KEM layer, +3.3 KB per ML-DSA signature] → Negligible against media payloads; noted in docs.
- [HPKE `seal()` with a fresh context each time means nonce reuse is impossible, but the KEM randomness comes from `Crypto.Random`] → Nothing to do on desktop; the MicroPython port must use `os.urandom` (flagged in the audit report).
- [A cryptainer with a hybrid stack is only as available as both trustees] → Expected: users wanting PQ-only or classical-only resilience pick a single layer or shared-secret shards.
- [Signature context string is fixed forever once cryptainers exist] → Version suffix `-v1` in the context allows a future `ML_DSA_65_V2` entry if ever needed.
- [Existing `assert set(SUPPORTED_SIGNATURE_ALGOS) <= set(SUPPORTED_ASYMMETRIC_KEY_ALGOS)` and "no algo is both cipher and signature" test invariants] → Preserved: `ML_KEM_768` is cipher-only, `ML_DSA_65` is signature-only.

## Migration Plan

1. Bump dependency, run full test suite (existing parametrized tests over `SUPPORTED_*` cover most of the new surface).
2. Ship as a minor release; existing cryptainers and cryptoconfs are unaffected since no default changes.
3. Downstream apps opt in by adding `ML_KEM_768` / `ML_DSA_65` trustees and layers to their cryptoconfs.
4. Rollback: revert the registry entries; cryptainers created with the new algos become undecryptable until re-applied, so communicate before any rollback.

## Open Questions

- Whether `selected_protocols.rst` should recommend the hybrid stack as the default template for new deployments (documentation wording only; does not affect specs or tasks).
