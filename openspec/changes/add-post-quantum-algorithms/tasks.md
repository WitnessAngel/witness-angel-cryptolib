## 1. Dependency

- [ ] 1.1 Bump `pycryptodome` to `^4.2` in `pyproject.toml`, refresh `poetry.lock`, and verify `python -c "from Crypto.PublicKey import MLKEM, MLDSA; from Crypto.Protocol import HPKE"` succeeds in the project venv and the existing test suite still passes

## 2. Crypto backend wrappers

- [ ] 2.1 In `_crypto_backend/pycryptodome.py`, add `generate_ml_kem_768_keypair`, `generate_ml_dsa_65_keypair`, `import_ml_kem_key_from_pem`, `export_ml_kem_key_to_pem`, `import_ml_dsa_key_from_pem`, `export_ml_dsa_key_to_pem` (passphrase handled like the ECC exporters), plus `ml_kem_key_class_fetcher` and `ml_dsa_key_class_fetcher`; verify with a quick keypair PEM round-trip in a Python shell
- [ ] 2.2 Add `encrypt_via_ml_kem_768(plaintext, public_key) -> (enc, ciphertext)` and `decrypt_via_ml_kem_768(enc, ciphertext, private_key) -> bytes` using HPKE Base mode with AES-256-GCM and empty info; verify a round-trip and that a flipped byte raises `ValueError`
- [ ] 2.3 Add `sign_with_mldsa(hasher, private_key)` and `verify_with_mldsa(hasher, signature, public_key)` signing `hasher.digest()` in pure mode with context `b"wacryptolib-payload-signature-v1"`; verify sign/verify round-trip and that verification raises `ValueError` on a corrupted signature
- [ ] 2.4 Re-export all new functions from `_crypto_backend/__init__.py`; verify `import wacryptolib` still works and the fallback adapter is unchanged

## 3. Registries

- [ ] 3.1 Add `ML_KEM_768` and `ML_DSA_65` to `ASYMMETRIC_KEY_ALGOS_REGISTRY` in `keygen.py` with `generation_extra_parameters=[]`; verify `tests/test_wacryptolib_keygen.py` passes (it is parametrized over `SUPPORTED_ASYMMETRIC_KEY_ALGOS`) including the "ignored key_length_bits/curve" case
- [ ] 3.2 Add `_encrypt_via_ml_kem_768` / `_decrypt_via_ml_kem_768` in `cipher.py` producing and consuming the cipherdict `{"kem_ciphertext", "ciphertext"}`, with an `isinstance(key, MLKEMKey)` check raising `ValueError`, and register `ML_KEM_768` with `is_authenticated=True`, `encryption_node_class=None`; verify the registry assertions at module import and `tests/test_wacryptolib_cipher.py` pass
- [ ] 3.3 Register `ML_DSA_65` in `SIGNATURE_ALGOS_REGISTRY` in `signature.py`; verify `tests/test_wacryptolib_signature.py` passes and the keygen invariant tests (no algo both cipher and signature) still hold
- [ ] 3.4 In `trustee.py`, replace the `RSA_OAEP`-only assertion with a membership check in `SUPPORTED_ASYMMETRIC_CIPHER_ALGOS`; verify `tests/test_wacryptolib_trustee.py` passes

## 4. Tests for new behavior

- [ ] 4.1 Add cipher tests for `ML_KEM_768`: empty, short and >60-byte plaintexts round-trip; tampered `kem_ciphertext` and tampered `ciphertext` each raise `DecryptionError`; wrong private key raises `DecryptionError`; RSA/ECC/ML-DSA keys raise `ValueError`
- [ ] 4.2 Add signature tests for `ML_DSA_65`: round-trip, altered message/timestamp/signature fail with `SignatureVerificationError`, two signatures of the same input differ, RSA/ML-KEM keys raise `ValueError`
- [ ] 4.3 Add keygen tests: passphrase-protected `ML_KEM_768` and `ML_DSA_65` private keys fail to load with a wrong passphrase and load with the right one, matching the error class used for RSA
- [ ] 4.4 Add cryptainer tests in `tests/test_wacryptolib_cryptainer.py`: single `ML_KEM_768` layer round-trip; hybrid `ML_KEM_768` + `RSA_OAEP` stack decrypts with both keys and reports a key decryption error when either private key is removed from the keystore; `ML_KEM_768` inside a shared-secret shard; `ML_DSA_65` payload signature verified in the decryption report and reported as error when corrupted
- [ ] 4.5 Add a committed fixture cryptainer (hybrid layers + ML-DSA signature) with its keys under the existing test fixtures location, and a test that decrypts it, so future pycryptodome upgrades are checked for wire compatibility
- [ ] 4.6 Run the full suite with `pytest -x` and verify it is green

## 5. Documentation

- [ ] 5.1 Update `docs/selected_protocols.rst` with ML-KEM-768 (KEM + DEM, cipherdict fields, sizes) and ML-DSA-65 (context string, randomized signatures, sizes), plus the hybrid layering pattern; verify `make html` in `docs/` builds without new warnings
- [ ] 5.2 Add a CHANGELOG entry listing the two new algorithm names, the pycryptodome 4.2 requirement, and the note that older versions cannot read cryptainers using them; verify the entry renders in the file
