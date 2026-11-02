## 1. Tokens and helpers

- [ ] 1.1 In `cryptainer/_validation.py`, add `ValidatedCryptoconf(dict)` and `ValidatedCryptainer(dict)` (with `inline_payload_checked`), both overriding `__deepcopy__` to return a plain deep-copied dict; verify with a small unit test that `copy.deepcopy(token)` is exactly `dict` and `json.dumps(token)` works
- [ ] 1.2 Add `ensure_validated_cryptoconf(x)` and `ensure_validated_cryptainer(x, require_inline_payload=True)` implementing D2/D4 (O(1) on sufficient tokens, validate then snapshot otherwise), reusing `check_cryptoconf_sanity` / `check_cryptainer_sanity`; verify with `mock.patch` that a second call does not reach `_validate_data_tree`, and that a lenient token is re-validated for a strict request
- [ ] 1.3 Re-export the helpers/types from `cryptainer/__init__.py` after `_validation` (internal only, no docs); verify `import wacryptolib.cryptainer` still works

## 2. Encryption path

- [ ] 2.1 In `CryptainerEncryptor._generate_cryptainer_base_and_secrets`, replace the direct `check_cryptoconf_sanity` call by `ensure_validated_cryptoconf` and assert the token downstream; wrap the generated cryptainer as `ValidatedCryptainer` without re-validating; verify the cryptoconf is validated once per `encrypt_data` call (mock count)
- [ ] 2.2 In `CryptainerStorage.__init__`, ensure `default_cryptoconf` once and keep the token; in `enqueue_file_for_encryption` ensure only an explicitly passed cryptoconf; verify with a mock count that enqueuing N files validates the default cryptoconf once
- [ ] 2.3 Tag the cryptainer at the lifecycle boundaries (generation, finalization) in `_encryptor.py` / `_encryption_pipeline.py`, strict only once inline payload is final; verify an encrypt then decrypt round-trip performs no cryptainer validation

## 3. Decryption and analysis path

- [ ] 3.1 In `_decryptor.py`, replace the direct `check_cryptainer_sanity` call by `ensure_validated_cryptainer(..., require_inline_payload=True)`; verify a lenient token (offloaded payload) is refused with `SchemaValidationError`
- [ ] 3.2 In `_analysis.py`, use `ensure_validated_cryptainer(..., require_inline_payload=False)`; verify a strict token passes without re-validation, and the batch error message still names the faulty cryptainer
- [ ] 3.3 Remove decryptor in-flow guards made unreachable by the upfront check (e.g. empty `key_cipher_layers` at the former `_decryptor.py:480`), each only after confirming a test shows the upfront check refuses the same input; verify the full cryptainer test module passes

## 4. Entry points and duplicates

- [ ] 4.1 Remove the redundant `check_cryptoconf_sanity` calls in `cli.py` (encryption paths) and `operations.py`, relying on the pipeline entry; keep the explicit check in the `validate` command; verify CLI tests pass and an invalid cryptoconf is still refused with the same CLI error
- [ ] 4.2 In `_storage.py` (`check_cryptainer_sanity`) and `_shortcuts.py`, ensure raw dicts on entry; verify behavior unchanged for raw dict inputs

## 5. Tests and docs

- [ ] 5.1 Add tests: validated-once per encryption, once per storage with many files, tag dropped by deepcopy and JSON round-trip, forged/lenient token handling per spec scenarios
- [ ] 5.2 Add a CHANGELOG entry (internal refactor, no API change) and docstrings stating that tokens are internal and not tamper-proof; run the full suite (`PYTHONPATH=src pytest tests -n 4`)
