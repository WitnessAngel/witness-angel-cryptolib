## 1. Fixtures and failing tests first

- [ ] 1.1 Add a test helper building a `FilesystemKeystore` directory in the uppercase layout of earlier releases (keypairs and `free_keys/<UPPERCASE ALGO>/` pairs, for an encryption algo and a signature algo); verify the new tests fail on the current code on a case-sensitive filesystem (on Windows/macOS, mock the path layer as case-sensitive)
- [ ] 1.2 Write the tests for each spec scenario in `tests/test_wacryptolib_keystore.py` and `tests/test_wacryptolib_trustee.py`: lowercase naming of new keys and free keys, fetch without `must_exist`, `get_message_signature`, decryption, read-only keystore (no file change), set over an existing uppercase key, free-keypair count and attach, lowercase-wins conflict with logged warning, listing of a mixed keystore, `check_authenticator`, tree export and re-import

## 2. Path layer

- [ ] 2.1 Make `_get_filepath()` build lowercase canonical paths, and add the resolver (canonical path, else uppercase path, else canonical); use it in `_public_key_exists`, `_private_key_exists`, `_get_public_key`, `_get_private_key`; verify the naming, fetch, sign, decrypt, read-only and set-over-existing tests pass
- [ ] 2.2 Log a warning naming the ignored uppercase file when both spellings exist as distinct files, with no warning when `samefile` is true (case-insensitive filesystem); verify the conflict test passes

## 3. Free keys

- [ ] 3.1 Make `_add_free_keypair()` write into the lowercase subdirectory and `_get_free_keypairs_count()` sum both subdirectories; verify the naming and count tests pass
- [ ] 3.2 Make `_attach_free_keypair_to_uuid()` take from the lowercase subdirectory first, then the uppercase one, moving to the lowercase target path; verify the attach test passes and the attached files carry lowercase names

## 4. Listing and export

- [ ] 4.1 Make `_list_unordered_keypair_identifiers()` uppercase the algo, dedupe `(keychain_uid, algo)` found under both spellings, and compute `private_key_present` with the resolver; verify the mixed-keystore listing test passes
- [ ] 4.2 Verify `check_authenticator()` and `export_to_keystore_tree()` succeed on uppercase, lowercase and mixed keystores, that the tree passes `validate_keystore_tree()`, and that it re-imports into a fresh keystore as lowercase-named files

## 5. Documentation and wrap-up

- [ ] 5.1 Reword the #61/#64 `CHANGELOG` entry (existing keys keep working, new keys use lowercase file names, API names are uppercase, older versions can't see new keys, drop "not found anymore") and check that the text matches the behaviour
- [ ] 5.2 Run the full test suite and `openspec validate store-lowercase-algo-names-with-uppercase-fallback --strict`; verify no new failures compared to the baseline
- [ ] 5.3 Comment on issue #70 with the commit reference, and close it once merged
