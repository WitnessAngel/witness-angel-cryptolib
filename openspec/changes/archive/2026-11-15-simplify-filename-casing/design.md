## Context

**Current letter-case rules**, all unreleased except where noted:
- **Keystore key files:** written with lowercase algo names, and read lowercase first, then with the legacy uppercase name (`keystore-algo-name-storage`). Listings skip files with mixed-case algo names or non-canonical keychain uids, each with a dedicated warning.
- **Foreign keystore directories** (`lowercase-filenames`, archived): `FilesystemKeystorePool._list_foreign_keystore_dirnames()` matches the `keystore_` prefix and the UUID in any letter case, from one `os.scandir()`, on every platform. A canonical lowercase directory wins over other spellings, and `_get_foreign_keystore_dir()` looks up the actual directory name. The released code globbed `keystore_*` and stripped the prefix with a case-sensitive `replace()`. On Windows, `glob` also matches `KEYSTORE_…`, so `uuid.UUID()` crashed.
- **Sensors** (`lowercase-filenames`): `_build_record_filename()`, `_build_tarfile_filename()` and `_build_cryptainer_filename_base()` lowercase the whole name, including `sensor_name`.
- **`add-cbor-document-format` (D12 and related, not implemented yet):**
  - suffixes and `.json`/`.cbor`/`.crypt` are recognized in exact lowercase only, from a listing that replaces `Path.glob()`;
  - typed names get case-insensitive suffix stripping in the CLI;
  - `.JSON`/`.CBOR` spellings in `-o` are usage errors.

**Platform behaviour:**
- Python >= 3.11. `Path.glob()` and `os.path.normcase()` both ignore case on Windows only.
- Exact-path opens follow the filesystem: NTFS, FAT and exFAT ignore case, ext4 doesn't, and APFS ignores it by default.

## Goals / Non-Goals

**Goals:**
- One principle for every file name, written down once (D1) and applied to the foreign keystores, sensors, keystore listings and the CBOR change.
- Less code and fewer special cases than today, with no regression of the Windows crash fix.
- Keep caller and config names (basenames, `sensor_name`) as given.

**Non-Goals:**
- Changing the two fixed algo spellings of key files. They are legacy names written by earlier releases, not a case-insensitive match.
- Renaming or migrating any existing file or directory.
- Identical listings on every platform for hand-renamed names. Names written by the toolchain are lowercase where it chooses them, so they list identically everywhere.

## Decisions

### D1. The principle
1. **Opening:** build the exact name and open it, so the filesystem decides whether case matters.
2. **Comparing:** compare names after `os.path.normcase()` (or with `Path.glob()`, which follows the same rule). Comparisons are case-insensitive on Windows and case-sensitive elsewhere. This covers listings, suffix and extension recognition, and suffix stripping.
3. **Writing:** parts chosen by the toolchain are lowercase:
   - cryptainer and payload suffixes;
   - extensions added or normalized by the toolchain, including record extensions from configs;
   - algo names.

   Parts given by the caller or a config are kept as given: basenames, explicit paths and `sensor_name`.

**Accepted mismatch.** The comparison rule follows the platform, not the filesystem. macOS and Linux reading a FAT card compare case-sensitively although opens ignore case. Only names renamed by hand in another case are affected.

**Rejected alternative:** the case-insensitive comparison everywhere implemented by `lowercase-filenames`, and the exact-lowercase comparison everywhere of D12. Both are rules of the toolchain's own: they need directory listings instead of `glob`, actual-name lookups and "which spelling wins" rules, and they disagree with what users see in their file managers.

### D2. Foreign keystore directories
`list_foreign_keystore_uids()` gets back its released shape, fixed:

```python
for path in foreign_keystores_dir.glob(prefix + "*"):  # This excludes TEMP folders
    uid_str = path.name[len(prefix):]  # The prefix may be in another letter case on Windows
    # parse uid_str: on ValueError, or if os.path.normcase(uid_str) != str(uid), warn naming the directory and skip
```

`_get_foreign_keystore_dir()` returns the plain canonical path again, and `_list_foreign_keystore_dirnames()` is removed.

- **On Windows**, `KEYSTORE_<UUID>` and `keystore_<UUID>` are listed and opened through the canonical path. Two spellings can't coexist there, so no duplicates are possible.
- **On Linux**, only `keystore_<canonical uuid>` is a foreign keystore.
  - `KEYSTORE_…` isn't matched by `glob`, so it is ignored like any foreign file, silently.
  - `keystore_<UUID>` with an uppercase UUID is skipped with a warning, since it can't be opened at its canonical path.
  - Importing a keystore whose only directory is `KEYSTORE_<UUID>` creates `keystore_<uuid>`, as for any unknown keystore.
- The `is_dir()` filter of `lowercase-filenames` is dropped, as in the released code. Nothing writes `keystore_*` files there.

### D3. Sensors
The three builders lowercase only `extension`, and keep `sensor_name` and the timestamps (digits) as they are. The tarfile extension is lowercased with the same code, so subclasses setting `tarfile_extension = ".TAR"` get `.tar`.

### D4. Keystore key listings
`_list_unordered_keypair_identifiers()` applies `os.path.normcase()` to the names of one `os.listdir()`. Those normalized names are used for parsing and for the private key presence check.
- **On Windows:** `<uid>_Rsa_Oaep_public_key.pem` and uppercase keychain uids normalize to canonical lowercase. They are listed, and the getters open them, since the filesystem ignores case. Legacy uppercase files normalize to lowercase and stay listed once.
- **Elsewhere:** names are unchanged. The mixed-case algo, unparsable uid and non-canonical uid checks keep skipping these files, through one condition and the existing "Skipping abnormally named PEM file" warning; their two dedicated messages are removed.

Getters, writers and free keys are untouched: they already open exact names (D1.1).

### D5. Amending `add-cbor-document-format`
Its artifacts are edited in place, since that change is not implemented yet. A single name matcher replaces the lowercase-only recognition and the CLI's case-insensitive variant: `os.path.normcase(name)` compared with the lowercase suffix. It is used by:
- `split_cryptainer_suffix()` and `get_cryptainer_format_from_filename()`;
- document format recognition;
- listing, which keeps filtering one directory listing (three suffixes and their `~` variants in one pass), now with the matcher;
- `encrypt -o` stripping, the `decrypt` default output, and the `convert-format` derived target.

Consequences, per artifact:
- **Recognition:** `CONF.JSON` is JSON by its name on Windows, and by sniffing elsewhere. It loads the same way in both cases.
- **Writing:** an explicit format, or else the extension under the matcher. `generate-simple -o conf.CBOR` writes CBOR on Windows. On Linux `.CBOR` is not the `.cbor` extension, so the name gets the default JSON, like `conf.txt`. The usage errors for other-case `.json`/`.cbor` are removed from `convert-format -o` and `generate-simple -o`.
- **Derived names:** `Report.JSON` gives `Report.cbor` on Windows and `Report.JSON.cbor` elsewhere. `encrypt -o Clip.CRYPT` gives `Clip.crypt.json` on Windows and `Clip.CRYPT.crypt.json` elsewhere.
- **Listing:** `a.CRYPT.JSON` is listed on Windows, and not elsewhere. The "no longer listed on Windows" risk is removed.
- **Unchanged:**
  - lowercase suffixes and extensions on write;
  - caller basenames kept;
  - lowercase corpus names for new generations;
  - payload name = exact cryptainer name (minus `~`) + `.payload`.

Specs state platform-dependent outcomes as two THEN branches: "on Windows…, on other platforms…". Tests emulate the other platform by patching `os.path.normcase` with `ntpath.normcase` or `posixpath.normcase`.

### D6. Documentation
- **Encryptor specification, §11.1 rule 14:**
  - chosen parts (suffixes, extensions, timestamps, algo names) MUST be lowercase;
  - given parts (basenames, configured sensor names) MUST be kept;
  - readers MUST recognize the lowercase suffixes, and compare names like their platform does;
  - keystores also read legacy uppercase algo names.
- **CHANGELOG:**
  - the sensor BREAKING entry now covers record extensions only;
  - the foreign keystore entry: no Windows crash, names that aren't canonical UUIDs under the platform's rule skipped with a warning, `KEYSTORE_…` usable on Windows only;
  - the listing-warnings entry is updated per D4.
- **`openspec/specs/lowercase-file-naming/spec.md` Purpose:** no longer promises the same listing on every filesystem. It is edited directly, since delta specs don't carry Purpose.

## Risks / Trade-offs

- [A storage or keystore pool lists differently on Windows and Linux for names renamed by hand in another letter case] → accepted (D1), the same as what file managers and `glob` show. The toolchain itself never writes such names.
- [On Linux, `generate-simple -o conf.CBOR` writes JSON into `conf.CBOR`. Copied to Windows, reading it fails with the mislabeled-file error] → the error names the file and both formats. Typing `.CBOR` on Linux is no different from typing `.cbr`.
- [On Linux, a pool holding only `KEYSTORE_<UUID>`, copied there from Windows by hand, doesn't see it, and a new import creates `keystore_<uuid>` next to it] → accepted, and the earlier behaviour on Linux anyway. Renaming the directory restores it.
- [On macOS (APFS), listings compare case-sensitively although opens don't] → only hand-renamed names are concerned. Uppercase-UUID foreign keystore directories are skipped with a warning there.
- [Sensor records of a `FrontCam` sensor now carry mixed-case names] → that is the configured name. Users wanting lowercase names configure lowercase sensor names.

## Migration Plan

None. No released behaviour changes, except:
- record extensions, already listed as BREAKING by `lowercase-filenames`;
- the Windows crash, which stays fixed.

The amendments to `add-cbor-document-format` are planning edits, applied before that change is implemented.

## Open Questions

None.
