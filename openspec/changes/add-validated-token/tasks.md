## 1. Tokens and helpers

- [x] 1.1 In `cryptainer/_validation.py`, add `ValidatedCryptoconf(dict)` and `ValidatedCryptainer(dict)` (with `inline_payload_checked`, default False, no-arg constructor working), both overriding `__deepcopy__` to return a plain deep-copied dict; test that `type(copy.deepcopy(token)) is dict`, `type(token.copy()) is dict`, and `dump_to_json_bytes(token)` round-trips to a plain dict
- [x] 1.2 Add `ensure_validated_cryptoconf(x)` and `ensure_validated_cryptainer(x, require_inline_payload=True)` implementing D2/D4 on top of `check_cryptoconf_sanity` / `check_cryptainer_sanity`; test (D9 counting) that a second call on the returned token does not validate, that mutating the original dict afterwards does not change the token, that a lenient token is re-validated for a strict request, and that a strict token is not re-validated for a lenient one
- [x] 1.3 Re-export the helpers and token types from `cryptainer/__init__.py` in the existing `_validation` import line; check `import wacryptolib.cryptainer` and `from wacryptolib.cryptainer import ensure_validated_cryptoconf` work

## 2. Encryption path

- [x] 2.1 In `CryptainerEncryptor._generate_cryptainer_base_and_secrets`, replace `check_cryptoconf_sanity(cryptoconf)` by `cryptoconf = ensure_validated_cryptoconf(cryptoconf)`, and raise `SchemaValidationError` if `cryptainer_metadata` is neither dict nor `None` (D7); in `encrypt_data()`, return `ValidatedCryptainer(cryptainer, inline_payload_checked=True)`; test that `encrypt_payload_into_cryptainer` validates the cryptoconf once and returns a strict token that `check_cryptainer_sanity` accepts
- [x] 2.2 In `CryptainerStorage.__init__`, ensure `default_cryptoconf` when not `None`; in `_resolve_cryptoconf()`, ensure the resolved cryptoconf (no-op for the default token); test that `encrypt_file`/`enqueue_file_for_encryption` of N files validate the default cryptoconf once, and that an invalid per-call cryptoconf raises from `enqueue_file_for_encryption()` itself
- [x] 2.3 Replace the dummy `default_cryptoconf` values of `FakeTestCryptainerStorage` instances in `tests/test_wacryptolib_sensor.py` by a valid cryptoconf (e.g. `SIMPLE_CRYPTOCONF`); the sensor test module passes

## 3. Decryption and analysis path

- [x] 3.1 In `CryptainerDecryptor.decrypt_payload`, replace `check_cryptainer_sanity(cryptainer)` by `cryptainer = ensure_validated_cryptainer(cryptainer)`; test that a token from `ensure_validated_cryptainer(..., require_inline_payload=False)` on a cryptainer loaded with `include_payload_ciphertext=False` is refused with `SchemaValidationError`, and that encrypt-then-decrypt in memory performs no cryptainer validation
- [x] 3.2 In `gather_decryptable_symkeys`, replace the lazily imported `check_cryptainer_sanity(..., require_inline_payload=False)` by `ensure_validated_cryptainer(..., require_inline_payload=False)` (still lazily imported, still wrapped to name the faulty cryptainer); test that a strict token passes without validation and the batch error message still names the faulty cryptainer
- [x] 3.3 Remove the "Empty key_cipher_layers list is forbidden in cryptainer" guard of `_decrypt_key_through_multiple_layers`, after checking that an existing test makes `decrypt_payload` refuse an empty nested `key_cipher_layers` upfront with `SchemaValidationError`; the cryptainer test module passes

## 4. Entry points

- [x] 4.1 In `cli.py` `encrypt`, replace `check_cryptoconf_sanity(cryptoconf)` by `cryptoconf = ensure_validated_cryptoconf(cryptoconf)`; in `operations.py` `___encrypt_payload_to_bytes`, drop the check (and the now unused import); keep the checks of `generate-simple`, both `validate` commands and `ReadonlyCryptainerStorage.check_cryptainer_sanity()`; test that CLI `encrypt` validates the cryptoconf once and still refuses an invalid one with `SchemaValidationError`

## 5. Docs and wrap-up

- [x] 5.0 Implement the debug-only digest guard of D10 (env-var switch, `blake2b` tree walk hashing `bytes` directly, check where tokens are consumed); verify that mutating a tagged tree after tagging raises with the switch on, that nothing is computed with it off, and enable the switch in the test suite configuration (`conftest.py` or `tox.ini`)
- [x] 5.1 Docstrings of the helpers and token types (validate once, not tamper-proof, deepcopy/JSON drop the tag), a mention in the docs page listing `check_cryptoconf_sanity` if any, and a CHANGELOG entry (refactor, public helpers, earlier `CryptainerStorage` errors); run the full suite (`PYTHONPATH=src pytest tests -n 4`)
