## 1. Sensors

- [x] 1.1 Add tests for the "Sensor configured with uppercase names" and "Tar member names" scenarios in `tests/test_wacryptolib_sensor.py`, and verify that they fail on the current code
- [x] 1.2 Lowercase sensor names and extensions in `_build_record_filename()`, `_build_tarfile_filename()` and `_build_cryptainer_filename_base()` (design D1). Verify that the new tests and the existing sensor tests pass

## 2. Foreign keystore directories

- [x] 2.1 Add tests for each scenario of the "Case-insensitive foreign keystore directories" and "No migration of existing names" requirements in `tests/test_wacryptolib_keystore.py`:
  - real directories on case-sensitive filesystems;
  - `emulate_case_sensitive_filesystem()` on Windows and macOS.

  Verify that they fail on the current code, including the `ValueError` crash on Windows.
- [x] 2.2 Rewrite `list_foreign_keystore_uids()` and `_get_foreign_keystore_dir()` per design D2. Verify that the new tests and the existing keystore pool tests pass on Windows and on a Linux ext4 filesystem (WSL)

## 3. Documentation

- [x] 3.1 Add the general lowercase naming rule to the encryptor specification (design D3). Verify with a manual read that it doesn't contradict the suffix rules of `add-cbor-document-format`
- [x] 3.2 Add CHANGELOG entries:
  - BREAKING: lowercase sensor names and extensions in record, tarfile and cryptainer names;
  - foreign keystore directories listed case-insensitively, with no crash on unparsable names.

  Verify that the text matches the behaviour of the tests.

## 4. Wrap-up

- [x] 4.1 Run the full test suite on Windows, the sensor and keystore tests on Linux ext4, and `openspec validate lowercase-filenames --strict`. Verify there are no new failures compared to the baseline
