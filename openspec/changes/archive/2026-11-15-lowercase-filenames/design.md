## Context

See proposal.md - Why. Current state:
- `sensor.py`:
  - `TarfileRecordAggregator._build_record_filename()` builds `{from}_to_{to}_{sensor_name}{extension}` tar member names;
  - `_build_tarfile_filename()` builds `{from}_to_{to}_cryptainer{tarfile_extension}` (`.tar`);
  - `PeriodicSubprocessStreamRecorder._build_cryptainer_filename_base()` builds `{from}_{sensor_name}_cryptainer{record_extension}` stream basenames.

  Sensor names and extensions come from sensor classes or recorder configs. Timestamps are digits, and the fixed parts are lowercase.
- `FilesystemKeystorePool`:
  - `list_foreign_keystore_uids()` globs `keystore_*` (case-insensitive on Windows and macOS only), strips the prefix with `str.replace()` and parses a UUID. An uppercase `KEYSTORE_…` directory therefore raises `ValueError` on Windows, and is invisible on Linux.
  - `_get_foreign_keystore_dir()` rebuilds `keystore_<str(uuid)>`. It is used by `get_foreign_keystore()`, `_ensure_foreign_keystore_dir_exists()` and `import_foreign_keystore_from_keystore_tree()`.
- `add-cbor-document-format` D12 (merged into this branch from `dev`) is unchanged by this change:
  - lowercase library-chosen parts;
  - caller basenames kept as typed;
  - exact-lowercase suffix recognition.

## Goals / Non-Goals

**Goals:**
- No uppercase letter in names composed by sensors.
- Platform-independent foreign keystore listing that never crashes on a stray directory name.

**Non-Goals:**
- Anything about cryptainer suffixes, basenames or payload names (D12 of `add-cbor-document-format`).
- Renaming existing directories or files.
- Changes to the recorder or other repositories. The recorder may still lowercase its config values, as defense in depth.

## Decisions

**D1. Sensors lowercase in their name builders.**
`_build_record_filename()` and `_build_cryptainer_filename_base()` lowercase the sensor name and the extension, and `_build_tarfile_filename()` lowercases its extension. Lowercasing happens there, not in `add_record()` or in the sensor constructors, so that logs and `sensor_name` properties keep the configured spelling.
Sensors count as library-chosen names under D12: the library composes the whole name, and no user typed it. This differs from basenames passed to `CryptainerStorage`, which are kept as typed.
Alternative: lowercase `sensor_name` at construction. Rejected, since it would change a public attribute used by applications for display.

**D2. Foreign keystore directories: one listing, case-insensitive match, actual names.**
`list_foreign_keystore_uids()` reads `foreign_keystores/` once (`os.scandir()`, directories only). It keeps the names whose lowercase form is `keystore_` followed by the canonical form of a parsable UUID, and returns the sorted, deduplicated UUIDs. Names with the prefix that don't satisfy this (e.g. `keystore_backup`, or a UUID without dashes) are skipped with a warning, since lookups couldn't find them.
`_get_foreign_keystore_dir()` returns:
- the canonical lowercase path if it exists, which costs one stat in the common case;
- else the directory of the listing whose lowercase name equals the canonical one;
- else the canonical path, used for creation.

The lowercase directory thus wins when both spellings exist, and an import into an existing uppercase directory doesn't create a lowercase twin.
This deliberately differs from D12's exact-lowercase rule for cryptainer suffixes. Foreign keystores are whole directories copied from key devices, often through FAT tools, and missing one hides keys needed for decryption. A case-insensitive match can't be ambiguous with anything else, because the name must parse as a UUID.
Alternative: exact-lowercase recognition, only fixing the crash. Rejected by the user, in favour of the fallback.

**D3. Encryptor specification.**
It gets a general naming rule: name parts chosen by an implementation (suffixes, timestamps, sensor and record names, algo names in key files) MUST be lowercase, while caller-provided basenames are kept as given. It sits next to the suffix rules that `add-cbor-document-format` task 7.1 adds to §9; whichever lands second merges the wording.

## Risks / Trade-offs

- [Recorder outputs change name (`FrontCam` becomes `frontcam`)] → Only new recordings are affected, and cryptainers are found by their suffix, so no reader breaks. A CHANGELOG entry flags it as BREAKING for anyone matching names.
- [A listing per lookup of an uppercase foreign keystore] → Only when the canonical directory is missing, which is rare. Pools hold a handful of keystores.
- [A non-directory entry named like a keystore] → Ignored, like any other non-directory entry.

## Migration Plan

No data migration. Release with the CHANGELOG entry. Rollback is reverting the code: lowercase sensor names stay readable, and uppercase foreign keystores go back to being invisible on Linux and crashing on Windows.
