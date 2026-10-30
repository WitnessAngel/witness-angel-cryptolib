## 1. Dependency

- [x] 1.1 Raise `pycryptodome` in `pyproject.toml` from `^3.20.0` to `^3.23.0` (and update `pip_requirements_export.txt` if it pins a lower bound); verify `poetry run python -c "from Crypto.Protocol import HPKE"` succeeds

## 2. CPython backend

- [x] 2.1 In `_crypto_backend/pycryptodome.py`, add `encrypt_via_hpke(plaintext, public_key, aead_id) -> (enc, ciphertext)` and `decrypt_via_hpke(enc, ciphertext, private_key, aead_id) -> bytes` wrapping `HPKE.new(...)`, and export them from `_crypto_backend/__init__.py`; verify a quick X25519 round-trip in a Python shell
- [x] 2.2 In `keygen.py`, add `ECIES_X25519` to `ASYMMETRIC_KEY_ALGOS_REGISTRY` (generator calling `generate_ecc_keypair("curve25519")`, `generation_extra_parameters=[]`, ECC PEM import/export functions); verify `tests/test_wacryptolib_keygen.py` passes (parametrized over `SUPPORTED_ASYMMETRIC_KEY_ALGOS`, including passphrase protection)
- [x] 2.3 In `cipher.py`, add `_encrypt_via_ecies_x25519` / `_decrypt_via_ecies_x25519` (X25519 `EccKey` check raising `ValueError`, cipherdict `{"kem_ciphertext", "ciphertext"}`, ignored `verify_integrity_tags`), register `ECIES_X25519` with `is_authenticated=True`, `encryption_node_class=None`, and add a short code comment summarizing design D2 (why ChaCha20-Poly1305 rather than AES-256-GCM); verify the registry assertions at import time
- [x] 2.4 In `trustee.py`, replace the `RSA_OAEP`-only assertion with `in SUPPORTED_ASYMMETRIC_CIPHER_ALGOS`, and in `keystore.py` widen `PUBLIC_KEY_FILENAME_REGEX` `key_algo` group to `[_a-zA-Z0-9]+`; verify `tests/test_wacryptolib_trustee.py` and `tests/test_wacryptolib_keystore.py` pass

## 3. Pure-Python seal (MicroPython)

- [x] 3.1 Create `_crypto_backend/hpke_x25519_seal.py` (RFC 7748 X25519 ladder with all-zero shared secret rejection, HKDF-SHA256, HPKE labeled extract/expand and Base-mode key schedule, `seal(receiver_public_key_bytes, plaintext, ephemeral_private_key=None)` using `chacha20_poly1305.py`), with a header comment repeating the D2 AEAD rationale and a `ponytail:` comment on non-constant-time bigints; verify it imports with only `hashlib`, `hmac`, `os` and the ChaCha module
- [x] 3.2 Add `tests/test_hpke_x25519_seal.py`: RFC 7748 §5.2 X25519 vectors, RFC 9180 A.2.1 known-answer test (`enc`, `shared_secret`, `key`, `base_nonce` with injected ephemeral key), round-trip pure `seal` → pycryptodome `decrypt_via_hpke`, low-order public key rejected; verify the test file passes
- [x] 3.3 Add `hpke_x25519_seal.py` and `chacha20_poly1305.py` to `SHARED_MODULES` in `micropython/vendor_dependencies.py`; verify running it copies both into `micropython/lib/`
- [ ] 3.4 In `micropython/flightbox_utilities_implementation.py`, add `"ECIES_X25519"` to `SUPPORTED_ASYMMETRIC_CIPHER_ALGOS`, load `{"x25519": bytes}` public key parameters in `get_public_key` per `key_algo`, and dispatch `encrypt_bytestring` to `seal()` returning `{"kem_ciphertext", "ciphertext"}`; verify a MicroPython (unix port) flightbox run with an ECIES layer produces a cryptainer

## 4. Library tests

- [x] 4.1 In `tests/test_wacryptolib_cipher.py`, add ECIES_X25519 tests: empty, short and >60-byte round-trips, cipherdict keys and sizes (32 B / len+16 B), randomized output, tampered `kem_ciphertext`/`ciphertext` and wrong private key raise `DecryptionError`, RSA and P-256 keys raise `EncryptionError`/`DecryptionError`; verify they pass
- [x] 4.2 In `tests/test_wacryptolib_cryptainer.py`, add a cryptoconf with an `ECIES_X25519` key layer and one inside a shared-secret shard to the round-trip and validation parametrizations; verify they pass
- [ ] 4.3 Decrypt on CPython the cryptainer produced by the MicroPython flightbox in 3.4 (with the trustee private key) and check the payload; run the full `tox -e py314` suite and verify it is green

## 5. Docs and follow-up

- [x] 5.1 Add an `ECIES_X25519` section to `docs/selected_protocols.rst` (HPKE suite IDs, cipherdict, sizes, side-channel note) and a CHANGELOG entry; verify `make html` in `docs/` builds without new warnings
- [x] 5.2 Amend `openspec/changes/add-post-quantum-algorithms/design.md` D2/D9 to use ChaCha20-Poly1305 for `ML_KEM_768`, referencing this change's D2, and drop from it the trustee/keystore edits once this change is merged; verify `openspec validate add-post-quantum-algorithms` passes
