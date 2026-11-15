## Why

Since issue #70, the toolchain handles the letter case of file names with rules of its own:
- foreign keystore directories are matched case-insensitively on every platform, with a "canonical name wins" rule;
- sensor names from configs are lowercased;
- `add-cbor-document-format` (D12) recognizes suffixes in exact lowercase only, through its own directory listing, and adds special errors for `.JSON`/`.CBOR` spellings.

These rules work against the filesystem instead of with it, and add code, tests and spec scenarios that buy little. A simpler principle covers the same needs:
- names the program opens are built exactly and opened as is, so the filesystem decides whether case matters (NTFS or FAT: no; ext4: yes);
- names the program compares (listings, suffix and extension recognition) follow the platform's rule, case-insensitive on Windows only, like `Path.glob()` and `os.path.normcase()`;
- the parts of names the program chooses (extensions, suffixes, algo names) are lowercase, and the parts the user gives (basenames, sensor names) are kept as given.

The keystore's two fixed spellings of algo names (lowercase, then the legacy uppercase written by earlier releases) are not a case-insensitive match, and stay.

## What Changes

- Foreign keystore directories are listed with `glob` again, with the `keystore_` prefix cut by length instead of the case-sensitive `replace()` that crashed on Windows. A name that isn't a UUID, or isn't the canonical spelling of one under the platform's rule, is skipped with a warning. A keystore is opened at its plain canonical path. This removes:
  - the cross-platform case-insensitive matching;
  - the "lowercase directory wins" rule;
  - the lookup of actual directory names.

  So `KEYSTORE_<UUID>` directories are listed on Windows, but not on Linux.
- Sensors and record aggregators keep `sensor_name` as configured in the names they build, and only lowercase record extensions, which narrows the unreleased BREAKING change of `lowercase-filenames` (e.g. `20261111_184000_FrontCam_cryptainer.mp4.crypt`).
- Filesystem keystore listings compare key file names under the platform's rule, so files with a mixed-case algo name or an uppercase keychain uid are listed on Windows, where the getters can open them. On other platforms, these files are skipped with the generic "abnormally named" warning, which replaces the two dedicated warnings.
- The `add-cbor-document-format` change is amended to follow the same principle:
  - cryptainer suffixes and the `.json`/`.cbor`/`.crypt` extensions are recognized under the platform's rule (any letter case on Windows, lowercase elsewhere);
  - the exact-lowercase listing, the case-insensitive stripping of typed suffixes and the refusal of other-case `.json`/`.cbor` outputs are dropped;
  - writers keep producing lowercase suffixes and extensions, keep caller basenames as given, and new corpus generations keep lowercase names.
- The encryptor specification rule on file names, the `lowercase-file-naming` spec's Purpose and the CHANGELOG are updated accordingly.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
- `lowercase-file-naming`:
  - sensor record names lowercase only record extensions, keeping sensor names;
  - foreign keystore directories are matched under the platform's rule instead of case-insensitively everywhere.
- `keystore-algo-name-storage`: listings compare key file names under the platform's rule, and skip unfetchable files with the generic warning.

The capabilities of `add-cbor-document-format` (`cbor-document-format`, `cli-format-conversion`, `cryptainer-file-naming`) are not archived yet. They are amended in that change's own delta specs, not here.

## Impact

- `src/wacryptolib/keystore.py`:
  - `FilesystemKeystorePool`: replace `_list_foreign_keystore_dirnames()` with the `glob`-based listing, and give `_get_foreign_keystore_dir()` back its plain path;
  - `ReadonlyFilesystemKeystore._list_unordered_keypair_identifiers()`: name comparison and warnings.
- `src/wacryptolib/sensor.py`: the three name builders.
- Tests: `tests/test_wacryptolib_keystore.py` and `tests/test_wacryptolib_sensor.py`.
- Docs:
  - `docs/flightbox_specifications/flightbox_encryptor_specification.md` §11.1 rule 14;
  - `CHANGELOG`;
  - `openspec/specs/lowercase-file-naming/spec.md` (Purpose).
- `openspec/changes/add-cbor-document-format/`: proposal, design (context, goals, D5, D6, D8, D12, risks), delta specs and tasks.
- No dependency change. No released behaviour changes, except the Windows crash on `KEYSTORE_`-prefixed directories, which stays fixed.
