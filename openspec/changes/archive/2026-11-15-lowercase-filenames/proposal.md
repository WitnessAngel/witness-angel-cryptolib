## Why

The lowercase naming policy is now set by two changes:
- `store-lowercase-algo-names-with-uppercase-fallback`, for key files: lowercase writes, with a silent uppercase fallback;
- `add-cbor-document-format`, its decision D12, for cryptainers. Name parts chosen by the library are lowercase, suffixes are recognized in exact lowercase only, and caller-provided basenames are kept as typed.

Two places that name files remain outside both changes:
- **Sensors** compose whole record, tarfile and cryptainer names from sensor names and record extensions, which come from code or recorder configs. So `FrontCam` or `.MP4` produce mixed-case names that no caller chose.
- **Foreign keystore directories** (`foreign_keystores/keystore_<uuid>`) are listed with `Path.glob()` and a case-sensitive prefix strip. An uppercase `KEYSTORE_<UID>` directory (hand-copied, or renamed by FAT tools) therefore crashes the listing on Windows and is invisible on Linux.

## What Changes

- **BREAKING**: sensors and record aggregators lowercase sensor names and record extensions in the names they build: record and tar member names, tarfile names, and the basenames of the cryptainers they create. A sensor `FrontCam` recording `.MP4` files now produces `..._frontcam_cryptainer.mp4.crypt`.
- Foreign keystore directories are recognized case-insensitively, by their `keystore_` prefix and UUID, and opened under their actual name on every filesystem. Unparsable directory names are skipped with a warning instead of crashing the listing. New directories stay lowercase.
- The flightbox encryptor specification states the general writer rule for every implementation: name parts chosen by the implementation are lowercase, and caller-provided basenames are kept as given. This complements the suffix rules added there by `add-cbor-document-format`.
- No migration: existing records, cryptainers and foreign keystore directories keep their names.
- Not in scope, as decided by `add-cbor-document-format` D12:
  - lowercasing caller-provided basenames;
  - case-insensitive cryptainer suffix recognition;
  - payload name fallbacks.

## Capabilities

### New Capabilities
- `lowercase-file-naming`: lowercase names built by sensors and record aggregators, case-insensitive recognition of foreign keystore directories, and no migration of existing names.

### Modified Capabilities

(none: `keystore-algo-name-storage` already covers key files, and cryptainer suffixes and basenames are covered by `add-cbor-document-format`)

## Impact

- **Code:**
  - `src/wacryptolib/sensor.py`: the record, tarfile and cryptainer basename builders;
  - `src/wacryptolib/keystore.py`: the `FilesystemKeystorePool` foreign keystore listing and directory lookup;
  - the tests for both;
  - the CHANGELOG.
- **Docs:** `docs/flightbox_specifications/flightbox_encryptor_specification.md`, which `add-cbor-document-format` task 7.1 also edits.
- **Compatibility:**
  - Recorder outputs get lowercase sensor parts. Readers list cryptainers by their lowercase suffix, so older readers are unaffected.
  - Foreign keystore listings return the same UUIDs as before for lowercase directories, and now also include uppercase ones.
  - No dependency or API signature change.
