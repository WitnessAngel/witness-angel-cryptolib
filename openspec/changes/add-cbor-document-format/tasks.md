## 1. Dialect specification

- [ ] 1.1 Write `docs/specifications/wa_cbor_document_format.md`: data model, type mapping table with Extended JSON equivalents, CDDL generic item grammar, core deterministic encoding rules, strict decoding rules, unsupported values with reasons, file format recognition rules, relation to the C device profile sub-profile. Verify that every requirement of `specs/cbor-document-format/spec.md` is covered by a section
- [ ] 1.2 Add hex test vectors to that document in a machine-readable block (valid vectors for every data model type, including the datetime with offset, `1.0`/`1.00` decimals, a bignum, NaN/±Inf/-0.0 floats, a nested cryptoconf-like map; invalid vectors for every rejection case). Verify the block parses with a throwaway script and that valid vectors decode as expected with `cbor2`

## 2. WA-CBOR codec

- [ ] 2.1 Add `cbor2` to the dev dependency group (if not already added by `add-c-flightbox-encryptor`), regenerate `pip_requirements_export.txt`, and verify `poetry install` then `python -c "import cbor2"` succeed
- [ ] 2.2 Implement the encoder in `src/wacryptolib/utilities/wacbor.py` (data model checks, unsupported value rejection, deterministic encoding, datetime text identical to extjson's, tag 4 decimals from `as_tuple()`). Verify with unit tests in `tests/test_wacryptolib_utilities.py` that each valid test vector of task 1.2 is reproduced byte for byte and each unsupported value raises without output
- [ ] 2.3 Implement the strict decoder (memoryview slicing, tag whitelist with top-level-only 55799, duplicate keys, simple values, UTF-8, tag payload shapes, keyword maps, trailing bytes, nesting depth limit). Verify that each valid vector decodes to the expected tree and each invalid vector is rejected
- [ ] 2.4 Add a seeded random tree generator test comparing our codec with the `cbor2` oracle (our output loads equal in `cbor2`; `cbor2.dumps(canonical=True)` of in-dialect trees loads equal with ours) and checking the JSON ↔ CBOR bijection and the byte-exact round trips of the spec. Verify that the test passes over at least 1,000 generated trees
- [ ] 2.5 Add a test that parses the test vector block of `docs/specifications/wa_cbor_document_format.md` and checks every vector, and verify it fails when one vector's hex is altered locally

## 3. Document file API and format recognition

- [ ] 3.1 Add `DocumentFormat`, `dump_to_cbor_bytes`/`load_from_cbor_bytes` (+ `_file` variants), `detect_document_format`, `load_from_document_bytes`, `load_from_document_file`, `dump_to_document_file` to `wacryptolib.utilities`, keeping the existing extjson exports. Verify with unit tests for extension-based, sniffed (BOM, whitespace, 0xD9D9F7 prefix) and mismatched-file cases, including the "Mislabeled file refused" scenario
- [ ] 3.2 Add the conversion entry point (tree checks shared with the encoder, so that Extended JSON → WA-CBOR and WA-CBOR → Extended JSON both reject unsupported values). Verify with tests for the keyword-collision, decimal NaN and microsecond-truncation scenarios
- [ ] 3.3 Extend the validation-tag tests (`tests/test_wacryptolib_validation_tokens.py`) so that a validated cryptainer dumped to WA-CBOR and loaded back is untagged. Verify that the new test passes

## 4. Cryptainer naming and storage

- [ ] 4.1 Add `CRYPTAINER_JSON_SUFFIX`, `CRYPTAINER_CBOR_SUFFIX`, `CRYPTAINER_SUFFIXES` and the suffix helpers (`get_cryptainer_suffix`, `split_cryptainer_suffix`, `get_cryptainer_format_from_filename`) in `src/wacryptolib/cryptainer/_base.py`, keeping `CRYPTAINER_SUFFIX = ".crypt"`, and export them. Verify with unit tests over the three suffixes, temporary `~` names and unrelated names
- [ ] 4.2 Make `dump_cryptainer_to_filesystem` / `load_cryptainer_from_filesystem` format-aware via the document file API (`_filesystem.py`). Verify that inline and offloaded cryptainers round-trip under `.crypt`, `.crypt.json` and `.crypt.cbor` names, with payloads at `<filename>.payload`
- [ ] 4.3 Make `list_cryptainer_names()` cover all suffixes for finished and unfinished cryptainers (`_storage.py`). Verify with the "Mixed storage", "Same basename in two formats" and "Unfinished CBOR cryptainer listed" scenarios as tests in `tests/test_wacryptolib_cryptainer.py`
- [ ] 4.4 Add the `cryptainer_format` setting to `CryptainerStorage` (JSON default) and use it in `encrypt_file`, the enqueued encryption path and `CryptainerEncryptionPipeline` (temporary name = final name + `~`). Verify that default storages write `.crypt.json`, CBOR storages write `.crypt.cbor`, and both read every format
- [ ] 4.5 Add the same-basename warning when a storage creates a cryptainer whose basename exists in another format. Verify with a `caplog` test that the warning names the sibling and that the sibling and its payload are untouched
- [ ] 4.6 Check legacy `.crypt` support end to end (list, load, validate, decrypt, delete, purge by age/count/quota, size with payload). Verify with tests on a storage seeded with a corpus legacy cryptainer copied to a temporary directory

## 5. CLI

- [ ] 5.1 Add `--format json|cbor` (long form only) to `encrypt`, pass it to the storage, and switch `encrypt`'s early `_ensure_paths_not_existing` check from `<basename>.crypt` to the cryptainer of the requested format and its payload (design D10). Update the existing overwrite tests of `tests/test_wacryptolib_cli.py` that assert `report.crypt` names. Verify with every `encrypt` scenario of `specs/cli-overwrite-protection/spec.md` (including "A cryptainer in another format does not block encryption") and the "Encrypt to CBOR" / "Encrypt default" scenarios as CLI tests
- [ ] 5.2 Make every cryptoconf reader (`encrypt -c`, `cryptoconf validate`, `cryptoconf summarize`) use format recognition, including STDIN. Verify with CLI tests on JSON and CBOR cryptoconf files and on a CBOR cryptoconf piped to STDIN
- [ ] 5.3 Make `encrypt -o` basename stripping and the `decrypt` default output name handle the three suffixes. Verify with the "Premature suffix stripped" and "Decrypt default output name" scenarios as CLI tests, and with the existing "Decrypting next to the original file is refused" test still passing
- [ ] 5.4 Add `--format json|cbor` (long form only) to `cryptoconf generate-simple`: format from the `-o` extension by default, contradiction = usage error, output opened in binary mode (`wb`, or `xb` without `--force`, binary STDOUT for `-`). Verify with the "Cryptoconf format from extension" and "Contradicting format" scenarios, and with the existing `generate-simple` overwrite and STDOUT tests still passing
- [ ] 5.5 Implement `convert-format SOURCE [-o/--output TARGET] [--force]` per design D8/D9, reusing `FORCE_OPTION` and `_ensure_paths_not_existing`: target resolution, source/payload self-target refusal, early overwrite checks, in-memory encoding, payload first then document, exclusive creation without `--force`, temporary file + `os.replace` with `--force`, cleanup on failure. Verify with CLI tests for every scenario of `specs/cli-format-conversion/spec.md` (including "No -f short option") and the `convert-format` scenarios of `specs/cli-overwrite-protection/spec.md`
- [ ] 5.6 Clarify the help texts ("file format" vs "display format") and update `docs/flightbox_cli_manual.rst` and `docs/flightbox_cli_tutorial.rst` (including `convert-format`). Verify that the Sphinx docs build succeeds (`tox -e doc` or `make html`) and that the tutorial commands run

## 6. Compatibility corpus

- [ ] 6.1 Teach the corpus loader (`tests/_compatibility_corpus.py`, `scripts/compatibility/_corpus.py`) the sidecar disambiguation rule and the new cryptainer suffixes. Verify that the existing compatibility suite still passes unchanged and that a unit test covers the "JSON cryptainer asset versus legacy sidecar" scenario
- [ ] 6.2 Extend the generation tooling to produce a new generation of JSON/CBOR pairs (cryptoconfs, inline and offloaded `.crypt.json`/`.crypt.cbor` cryptainers, cipherdicts, signatures) and invalid WA-CBOR documents with their sidecars, then generate and commit it. Verify that the tooling refuses an existing generation directory, and that the pair-equivalence and invalid-document tests pass
- [ ] 6.3 Update `compatibility/README.md` (generation table, naming and sidecar disambiguation, WA-CBOR reference). Verify with a manual read against the modified `compatibility-fixtures` requirements

## 7. Specifications, changelog and coordination

- [ ] 7.1 Update `docs/flightbox_specifications/flightbox_encryptor_specification.md`: §2 pointer to the WA-CBOR specification, and §9.1/§9.2 new naming (writers SHOULD use `.crypt.json`/`.crypt.cbor`, readers MUST accept all three). Add a follow-up note to `docs/audits/flightbox_cryptoconf_storage_format.md`. Verify with a manual read that no remaining text mandates `.crypt` for new outputs
- [ ] 7.2 Add a note to `add-c-flightbox-encryptor` (design D8/D14 and task 8.2) that its device profile is a WA-CBOR sub-profile and that its CLI output naming should follow the new convention. Verify with `openspec validate add-c-flightbox-encryptor --strict`
- [ ] 7.3 Add the CHANGELOG entries (BREAKING cryptainer naming with the manual downgrade path, WA-CBOR format, `convert-format`, `--format json|cbor`), and amend the unreleased overwrite-protection entry so that it names the `encrypt` target files by their new suffixes. Verify with a manual read
- [ ] 7.4 Run the full test suite under both crypto backends (`tox` environments used in CI) and `openspec validate add-cbor-document-format --strict`. Verify that everything passes
