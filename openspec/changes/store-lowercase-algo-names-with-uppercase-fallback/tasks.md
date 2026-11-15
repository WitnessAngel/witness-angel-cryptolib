## 1. Fixtures and failing tests first

- [x] 1.1 Add a test helper building a `FilesystemKeystore` directory with the legacy uppercase algo names of earlier releases (keypairs and `free_keys/<UPPERCASE ALGO>/` pairs, for an encryption algo and a signature algo); verify the new tests fail on the current code on a case-sensitive filesystem (on Windows/macOS, mock the path layer as case-sensitive)
- [x] 1.2 Write the tests for each spec scenario in `tests/test_wacryptolib_keystore.py` and `tests/test_wacryptolib_trustee.py`: lowercase naming of new keys and free keys, fetch without `must_exist`, `get_message_signature`, decryption, read-only keystore (no file change), set over an existing legacy key, free-keypair count and attach, conflict between spellings, listing of a mixed keystore, `check_authenticator`, tree export and re-import

## 2. Path layer

- [x] 2.1 Build lowercase canonical paths, and add a resolver finding the canonical path, else the legacy uppercase path; use it in `_public_key_exists`, `_private_key_exists`, `_get_public_key`, `_get_private_key`; verify the naming, fetch, sign, decrypt, read-only and set-over-existing tests pass
- [x] 2.2 Handle the case where both spellings exist as distinct files, but not when they are the same file (case-insensitive filesystem); verify the conflict test passes (superseded by 6.2)

## 3. Free keys

- [x] 3.1 Make `_add_free_keypair()` write into the lowercase subdirectory and `_get_free_keypairs_count()` sum both subdirectories; verify the naming and count tests pass
- [x] 3.2 Make `_attach_free_keypair_to_uuid()` take from the lowercase subdirectory first, then the uppercase one, moving to the lowercase target path; verify the attach test passes and the attached files carry lowercase names

## 4. Listing and export

- [x] 4.1 Make `_list_unordered_keypair_identifiers()` uppercase the algo, dedupe `(keychain_uid, algo)` found under both spellings, and compute `private_key_present` with the resolver; verify the mixed-keystore listing test passes
- [x] 4.2 Verify `check_authenticator()` and `export_to_keystore_tree()` succeed on uppercase, lowercase and mixed keystores, that the tree passes `validate_keystore_tree()`, and that it re-imports into a fresh keystore as lowercase-named files

## 5. Documentation and wrap-up

- [x] 5.1 Reword the #61/#64 `CHANGELOG` entry (existing keys keep working, new keys use lowercase file names, API names are uppercase, older versions can't see new keys, drop "not found anymore") and check that the text matches the behaviour
- [x] 5.2 Run the full test suite and `openspec validate store-lowercase-algo-names-with-uppercase-fallback --strict`; verify no new failures compared to the baseline
- [ ] 5.3 Comment on issue #70 with the commit reference, and close it once merged

## 6. Review follow-ups

- [x] 6.1 Resolve the public and private key files of a keypair together with a single spelling (`_resolve_keypair_files()`), and use it for reads, existence checks, the listing, `_set_public_key`, `_set_private_key` and free keypair attachment, so that a private key set for a legacy public key gets the legacy name; verify with a test
- [x] 6.2 Replace the "lowercase wins" policy by a `KeyFilenameConflict` error (not a `KeyDoesNotExist`) naming the keys directory and files, detected with stats and `os.path.samestat`; verify reads, listing, sets, read-only keystores and an autogenerating trustee all raise it, for full, public-only and private-only twins, and that aliases on case-insensitive filesystems don't
- [x] 6.3 Compute the listing's private key presence with the keychain uid as spelled in the file name, and skip mixed-case algo names with a warning; verify with tests
- [x] 6.4 Decide the disk spellings in `_get_disk_algo_names()` only, rename helpers and tests to drop the ambiguous "uppercase layout" wording (`_get_key_filepath()`, `_get_canonical_key_filepath()`, `_get_existing_free_keys_subdirs()`, `write_legacy_uppercase_algo_keystore()`, `emulate_case_sensitive_filesystem()`, documenting that it only emulates lookups), and move test imports to the top of modules
- [x] 6.5 Update the CHANGELOG entry, then run the full test suite and `openspec validate store-lowercase-algo-names-with-uppercase-fallback --strict`
