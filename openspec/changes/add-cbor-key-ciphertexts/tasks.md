## 1. Encryption

- [ ] 1.1 In `cryptainer/_flightbox.py`:
  - add the `key_ciphertext_format` parameter to `generate_cryptainer_base_and_secrets()`, and thread it through `_encrypt_key_through_multiple_layers()` / `_encrypt_key_through_single_layer()` and the asymmetric wrapping (symkey, sub-symkey, cipherdicts, shards, key structs);
  - call `dump_to_json_bytes()` or the new `dump_to_cbor_bytes()` of the utilities;
  - write `key_ciphertext_format: "cbor"` on every payload layer and symmetric key layer in CBOR mode, and nothing in JSON mode.

  Add `dump_to_cbor_bytes()` to `FlightboxUtilitiesBase` and `FlightboxUtilitiesImpl`. Verify unit tests that the JSON mode output is unchanged, by comparing it with a capture made before the change under fixed randomness, and that every inner structure is WA-CBOR in CBOR mode
- [ ] 1.2 Add the `key_ciphertext_format` parameter to `CryptainerEncryptor`, `CryptainerEncryptionPipeline`, `encrypt_payload_into_cryptainer()` and `encrypt_payload_and_stream_cryptainer_to_filesystem()` (default `"json"`), and to `CryptainerStorage` (default: its `cryptainer_file_format`), with a `ValueError` for unknown values before any key generation. Verify tests for each default, the "Storage default follows the file format" scenario, and the unknown-value error
- [ ] 1.3 Copy `_flightbox.py` verbatim into `reimplementations/micropython/src/cryptainer/`, and add a test asserting that both files are byte-identical. Verify that `reimplementations/micropython/main.py` still runs under CPython (which it supports, besides MicroPython), and outputs a cryptainer without `key_ciphertext_format`

## 2. Validation, decryption and analysis

- [ ] 2.1 Add `OptionalKey("key_ciphertext_format"): Or("json", "cbor")` to the cryptainer-only extras of payload layers and symmetric key layers in `_validation.py`, in Python and JSON-schema modes, and make `_load_and_check_key_cipherdict()` parse with the layer's format. Verify the "Unknown value" and "Field in a cryptoconf" scenarios, and strict validation of CBOR-mode cryptainers
- [ ] 2.2 Replace `_load_untrusted_json_bytes()` with `_load_untrusted_document_bytes(data, document_format, ...)` in `_decryptor.py`, and pass the governing format down every decryption path (layers, shards, sub-symkeys, key structs, predecrypted key structs). Verify the "Shared secret with WA-CBOR key ciphertexts", "Mixed formats in one cryptainer" and "Format contradicting the content" scenarios
- [ ] 2.3 Add `get_revelation_request_data(key_ciphertext, key_ciphertext_format)` and use it:
  - in `gather_decryptable_symkeys()`, which also parses shared-secret cipherdicts with the governing format;
  - in the predecrypted symkey lookup, where the remote key struct sanity check moves, the first valid response being used.

  Verify the "Authenticator-compatible request" and "Remote decryption round trip" scenarios with the existing gateway test fixtures, and that JSON-mode request data is unchanged byte for byte

## 3. CLI

- [ ] 3.1 Add `--key-ciphertext-format json|cbor` to `flightbox encrypt` (long-only, defaulting to `--format`), with help texts distinguishing it from `--format`, and mention in the `convert-format` help and the CLI manual that key ciphertexts are kept. Verify the three CLI scenarios of the `key-ciphertext-format` spec

## 4. Specification, corpus and changelog

- [ ] 4.1 Update `docs/flightbox_specifications/flightbox_encryptor_specification.md` (§2 `S_F`, §6 pseudo-code and §6.7 note, §9.1 field table, §10 utilities, §11 checklist), and verify by a manual read that no remaining text mandates `J()` for inner structures without mentioning the format
- [ ] 4.2 Generate the `2026_cbor_key_ciphertexts` corpus generation with the existing tooling (contents of design D7, lowercase names, sidecars recording `key_ciphertext_format`), synthesize the mixed fixture with a `synthesized` provenance, and update `compatibility/README.md`. Verify that the compatibility suite passes on both backends, and that the "Smaller key ciphertexts" scenario holds on one of the fixtures
- [ ] 4.3 Add a CHANGELOG entry (field, parameters, CLI option, compatibility note), and run `openspec validate add-cbor-key-ciphertexts --strict`, `tox -e py` and the fallback env, verifying that everything passes
