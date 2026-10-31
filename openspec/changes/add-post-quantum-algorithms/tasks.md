## 1. Dependency

- [x] 1.1 Bump `pycryptodome` to `^4.2` in `pyproject.toml`, refresh `poetry.lock` and `pip_requirements_export.txt`, and verify `python -c "from Crypto.PublicKey import MLKEM, MLDSA; from Crypto.Protocol import HPKE; from Crypto.Signature import mldsa"` succeeds in the project venv and the existing test suite still passes

## 2. Crypto backend wrappers

- [x] 2.1 In `_crypto_backend/pycryptodome.py`, add `PQ_KEY_ALGOS` (key algo to pycryptodome module and parameter set), and helpers keyed by key algo: `generate_pq_keypair(key_algo)` (returning `(public_key, private_key)` like the RSA generator), `import_pq_key_from_pem(key_algo, ...)` and `export_pq_key_to_pem` (through the hardened PEM helpers), `check_pq_key_algo(key, key_algo)` (exact parameter set) and `pq_key_class_fetcher(key_algo)`; verify with a quick keypair PEM round-trip in a Python shell, with and without passphrase
- [x] 2.2 Add `encrypt_via_ml_kem_768(plaintext, public_key) -> (enc, ciphertext)` and `decrypt_via_ml_kem_768(enc, ciphertext, private_key) -> bytes` using HPKE Base mode with `AEAD.CHACHA20_POLY1305` and no `info`; verify a round-trip and that a flipped byte in either value raises `ValueError`
- [x] 2.3 Add `sign_with_mldsa(message, private_key)` and `verify_with_mldsa(message, signature, public_key)` (`message` is the hasher object, as for `sign_with_pss`) signing `message.digest()` in pure mode via `mldsa.new(key, context=b"wacryptolib-payload-signature-v1")`; verify sign/verify round-trip and that verification raises `ValueError` on a corrupted or truncated signature
- [x] 2.4 Re-export all new functions from `_crypto_backend/__init__.py`; verify `import wacryptolib` still works and `fallback_adapter.py` is unchanged

## 3. Registries and plumbing

- [x] 3.1 Add `ML_KEM_768` and `ML_DSA_65` to `ASYMMETRIC_KEY_ALGOS_REGISTRY` in `keygen.py` with `generation_extra_parameters=[]`; in `tests/test_wacryptolib_keygen.py::test_generate_and_load_passphrase_protected_asymmetric_key`, expect the uniform `Wrong passphrase or corrupted encrypted private key` message for a wrong passphrase, and pycryptodome 4's `passphrase is required` for a missing one; verify `tests/test_wacryptolib_keygen.py` passes (parametrized over `SUPPORTED_ASYMMETRIC_KEY_ALGOS`)
- [x] 3.2 Add `_encrypt_via_ml_kem_768` / `_decrypt_via_ml_kem_768` in `cipher.py` producing and consuming the cipherdict `{"kem_ciphertext", "ciphertext"}`, with an `isinstance(key, MLKEMKey)` check raising `ValueError` and a `verify_integrity_tags` parameter that is ignored, and register `ML_KEM_768` with `is_authenticated=True`, `encryption_node_class=None`; verify the registry assertions at module import and `tests/test_wacryptolib_cipher.py` pass
- [x] 3.3 Register `ML_DSA_65` in `SIGNATURE_ALGOS_REGISTRY` in `signature.py`; verify `tests/test_wacryptolib_signature.py` passes and `test_key_algos_mapping_and_isolation` (no algo both cipher and signature) still holds
- [x] 3.4 In `trustee.py`, replace the `RSA_OAEP`-only assertion with a `ValidationError` check of the uppercased `cipher_algo` against `SUPPORTED_ASYMMETRIC_CIPHER_ALGOS`; verify `tests/test_wacryptolib_trustee.py` passes
- [x] 3.5 In `keystore.py`, change the `key_algo` group of `PUBLIC_KEY_FILENAME_REGEX` to `[_a-zA-Z0-9]+`; verify `tests/test_wacryptolib_keystore.py` passes repeatedly (it picks random algos) and `flightbox` CLI `--asym-cipher-algo` help lists `ML_KEM_768` (`tests/test_wacryptolib_cli.py` passes)

## 4. Tests for new behavior

- [x] 4.1 Add cipher tests for `ML_KEM_768` in `tests/test_wacryptolib_cipher.py`: empty, short and >60-byte plaintexts round-trip and the cipherdict has exactly the keys `kem_ciphertext` (1088 bytes) and `ciphertext`; tampered `kem_ciphertext`, tampered `ciphertext` and a wrong private key each raise `DecryptionError`; RSA, ECC and ML-DSA keys raise `EncryptionError` on encryption and `DecryptionError` on decryption
- [x] 4.2 Add signature tests for `ML_DSA_65` in `tests/test_wacryptolib_signature.py` reusing `_common_signature_checks` (round-trip, altered message/timestamp/signature raise `SignatureVerificationError`), plus: two signatures of the same message and timestamp differ, signature value is 3309 bytes, RSA and ML-KEM keys raise `ValueError` ("Incompatible key type")
- [x] 4.3 Add keygen tests in `tests/test_wacryptolib_keygen.py`: `generate_keypair(key_algo=..., key_length_bits=1024, curve="unexisting")` succeeds for both new algos (parameters ignored), and loading an `ML_KEM_768` PEM with `key_algo="ML_DSA_65"` (and vice versa) raises `KeyLoadingError`
- [x] 4.4 Add keystore test in `tests/test_wacryptolib_keystore.py`: a `FilesystemKeystore` holding `ML_KEM_768` and `ML_DSA_65` keypairs lists them in `list_keypair_identifiers()` with `private_key_present` correct
- [x] 4.5 Add cryptainer tests in `tests/test_wacryptolib_cryptainer.py`: define a `PQ_HYBRID_CRYPTOCONF` (`RSA_OAEP` then `ML_KEM_768` key layers, `ML_KEM_768` inside a shared-secret shard, `ML_DSA_65` ciphertext signature) with its trustee-dependencies builder and add it to the parametrizations of `test_standard_cryptainer_encryption_and_decryption`, `test_cryptoconf_validation_success` and `test_cryptainer_validation_success`; add a test that decryption reports an `ASYMMETRIC_DECRYPTION_ERROR` entry and yields no payload when either the ML-KEM or the RSA private key is removed from the keystore; add a test that corrupting the `ML_DSA_65` `signature_value` yields a `SIGNATURE_ERROR` entry while the payload is still returned
- [x] 4.6 Add a committed fixture under a new `tests/fixtures/post_quantum/` directory (cryptainer built from `PQ_HYBRID_CRYPTOCONF` with inline payload, plus the unencrypted keystore PEM files it needs) and a test that decrypts it with no error entries, so future pycryptodome upgrades are checked for wire compatibility
- [x] 4.7 Run the full suite with `pytest -x` and verify it is green

## 5. Documentation

- [x] 5.1 Update `docs/selected_protocols.rst` with ML-KEM-768 (KEM + DEM via HPKE, cipherdict fields, sizes) and ML-DSA-65 (context string, randomized signatures, sizes), plus the hybrid layering pattern; add the new private generator/cipher functions to `docs/api/keygen.rst` and `docs/api/cipher.rst`; verify `make html` in `docs/` builds without new warnings
- [x] 5.2 Add an entry to the `Development` section of `CHANGELOG` listing the two new algorithm names, the pycryptodome 4.2 requirement, the keystore filename regex fix, and the note that older versions cannot read cryptainers using the new algos
