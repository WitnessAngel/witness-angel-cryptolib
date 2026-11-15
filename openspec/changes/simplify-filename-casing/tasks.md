## 1. Foreign keystore directories

- [x] 1.1 In `tests/test_wacryptolib_keystore.py`, replace `test_keystorepool_foreign_keystore_dirs_in_other_letter_cases` and `test_keystorepool_foreign_keystore_dir_under_both_spellings` with tests for each scenario of "Foreign keystore directory names". Branch the expectations on whether the platform compares names case-insensitively (`os.path.normcase("A") == "a"`). Verify that the "other platforms" expectations fail on the current code in WSL (ext4).
- [x] 1.2 Rewrite `list_foreign_keystore_uids()` and `_get_foreign_keystore_dir()` per design D2, and remove `_list_foreign_keystore_dirnames()`. Verify that the new tests and the existing keystore pool tests pass on Windows and on Linux ext4 (WSL).

## 2. Sensors

- [x] 2.1 Update the two sensor name tests in `tests/test_wacryptolib_sensor.py` (`FrontCam` and `GPS` kept, `.mp4` and `.json` lowercased), and rename them after the extensions. Verify that they fail on the current code.
- [x] 2.2 Lowercase only the extension in `_build_record_filename()`, `_build_tarfile_filename()` and `_build_cryptainer_filename_base()` (design D3). Verify that the sensor tests pass.

## 3. Keystore key listings

- [x] 3.1 Add tests for the "Mixed-case algo name", "Uppercase keychain uid" and "Non-canonical keychain uid" scenarios in `tests/test_wacryptolib_keystore.py`:
  - expectations branched on the platform's comparison;
  - on Windows, a second run with `os.path.normcase` patched to `posixpath.normcase`, to check the skips and the generic warning.

  Verify that the Windows expectations fail on the current code.
- [x] 3.2 Normalize listed key file names with `os.path.normcase()` in `_list_unordered_keypair_identifiers()`, and merge the skips into one condition with the existing "abnormally named" warning (design D4). Verify that the keystore and trustee tests pass on Windows and on Linux ext4 (WSL).

## 4. Amend add-cbor-document-format

- [x] 4.1 Rewrite D12 of `openspec/changes/add-cbor-document-format/design.md` around the principle of design D1 and the shared name matcher of D5. Align the Context, Goals, D5, D6 (helpers and listing), D9 and Risks sections:
  - no exact-lowercase recognition;
  - no case-insensitive CLI variant;
  - no usage errors for other-case `.json`/`.cbor`;
  - the "`X.CRYPT` no longer listed on Windows" risk replaced by the per-platform listing.

  Update the proposal's "Lowercase names" bullet and its Impact line on listing. Verify with a manual read that lowercase writing, caller basenames and lowercase corpus names are unchanged.
- [x] 4.2 Update the delta specs of `add-cbor-document-format`, with Windows and other-platform THEN branches where outcomes differ:
  - `cbor-document-format`: "Document file format recognition" and its "Extension in another letter case" scenario;
  - `cli-format-conversion`: "convert-format command", "Derived target name", "Output format option of writing commands" and "CLI reads both formats", with their letter case scenarios;
  - `cryptainer-file-naming`: "Lowercase cryptainer suffixes" and its scenario, and the parenthesis of "Listing covers every cryptainer suffix".

  Verify with `openspec validate add-cbor-document-format --strict`. Grep the change for leftovers ("lowercase only", "exact lowercase", "whatever its letter case", "in another letter case").
- [x] 4.3 Update tasks 3.1, 4.1, 4.3, 5.3, 5.4, 5.5, 7.1 and 7.3 of `add-cbor-document-format` to the shared matcher. They should test the other platform by patching `os.path.normcase`. Verify with a manual read against the updated delta specs.

## 5. Documentation

- [x] 5.1 Rewrite rule 14 of §11.1 of `docs/flightbox_specifications/flightbox_encryptor_specification.md` per design D6, with the `FrontCam` example. Verify with a manual read that it matches the delta specs of both changes.
- [x] 5.2 Update the three CHANGELOG entries listed in design D6. Verify that the text matches the tests.
- [x] 5.3 Edit the Purpose of `openspec/specs/lowercase-file-naming/spec.md` so that it no longer promises the same listing on every filesystem. Verify with `openspec validate --specs --strict`.

## 6. Wrap-up

- [x] 6.1 Run:
  - the full test suite on Windows;
  - the keystore, trustee and sensor tests on Linux ext4 (WSL);
  - `openspec validate simplify-filename-casing --strict`, `openspec validate add-cbor-document-format --strict` and `openspec validate --specs --strict`.

  Verify that nothing fails compared to the baseline: 1228 passed, 4 skipped on Windows, give or take the replaced tests.
