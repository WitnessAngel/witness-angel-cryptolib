## Why

All wacryptolib documents (cryptoconfs, cryptainers, cipherdicts, metadata...) are stored as Extended JSON: bytes, UUIDs and dates are wrapped in `{"$binary": ...}`, `{"$uuid": ...}`, `{"$date": ...}` dicts, and binary data is inflated by a third by base64. The flightbox storage audit (`docs/audits/flightbox_cryptoconf_storage_format.md`) recommends CBOR, and the in-progress C flightbox change already needs a CBOR decoder for its device profiles. But no shared CBOR dialect exists, and the audit left open whether cryptainers themselves may use one. A documented CBOR dialect, bijective with our Extended JSON, lets every tool and every reimplementation read and write either format without losing information.

## What Changes

- New **WA-CBOR document format**: a CBOR (RFC 8949) dialect that uses standard semantic tags instead of `$`-wrapper dicts. Bytes are native byte strings, UUIDs use tag 37, datetimes tag 0, decimals tag 4, and bignums tags 2/3. Encoding is deterministic and decoding is strict. The dialect is bijective with wacryptolib's Extended JSON over a defined data model. The few values that one of the formats cannot carry faithfully (e.g. decimal NaN, naive datetimes, `$`-keyword maps) are documented and rejected, never silently altered.
- A normative specification, `docs/specifications/wa_cbor_document_format.md`: type mapping, CDDL, encoding and decoding rules, unsupported values, and hex test vectors checked by the test suite. Other implementations can reproduce the dialect from it.
- Library API to dump and load documents as WA-CBOR, and to dump and load any document file in either format. The format comes from the file extension, from the content, or from an explicit argument.
- **BREAKING** (cryptainer naming): `CryptainerStorage` and the CLI name new cryptainers `<basename>.crypt.json` (Extended JSON, the default) or `<basename>.crypt.cbor`, instead of `<basename>.crypt`.
  - Library code that builds or strips cryptainer names with `CRYPTAINER_SUFFIX` must use the new suffix constants and helpers.
  - Tools built on older wacryptolib versions only list `*.crypt` files, and won't see the new cryptainers.
  - Legacy `<basename>.crypt` cryptainers (always Extended JSON) keep being listed, loaded, decrypted, purged and deleted.
  - Low-level functions given an explicit cryptainer path keep writing to that path, in the format its suffix implies.
  - The offloaded payload file stays named after the whole cryptainer filename plus `.payload`, as today.
- **Letter case of names**, per the file naming principle of `simplify-filename-casing`:
  - name parts chosen by the library are lowercase: cryptainer and payload suffixes, extensions added by the CLI, corpus file and directory names;
  - names given by the caller (cryptainer basenames, explicit paths) are kept as given;
  - suffixes and format extensions are compared like the platform compares file names (`os.path.normcase()`, as `Path.glob()` does): in any letter case on Windows, in lowercase elsewhere. This applies to recognition, listing, and the CLI's stripping or swapping of suffixes.
- `CryptainerStorage` gets a cryptainer format setting (JSON by default). Its listings cover the three suffixes. Creating a cryptainer whose basename already exists in another format logs a warning and proceeds.
- CLI:
  - new `convert-format SOURCE [-o TARGET] [--force]` command. It converts any Extended JSON or WA-CBOR document file, without schema validation, to the other format, or to the format given by the `-o` extension. The source is never modified, and an offloaded payload is copied next to the target. Existing targets are refused unless `--force` is given, per `cli-overwrite-protection`;
  - `--format json|cbor` option (long form only, like every CLI option) on `encrypt` and `cryptoconf generate-simple`;
  - `encrypt`'s overwrite check targets the cryptainer of the requested format and its payload, instead of `<basename>.crypt`. A same-basename cryptainer in another format only triggers a warning;
  - every command reading a cryptoconf (including from STDIN) or a cryptainer accepts both formats.
- Compatibility corpus: a new generation of Extended JSON / WA-CBOR pairs of the same trees (cryptoconfs, inline and offloaded `.crypt.json` / `.crypt.cbor` cryptainers, cipherdicts, signatures), plus invalid WA-CBOR documents that must be rejected. A rule tells `x.crypt.json` assets apart from the legacy `x.crypt.json` sidecars. The new generation, and every later one, uses lowercase file and directory names only (e.g. `aes_cbc/` algo subdirectories), which the tooling enforces.
- The flightbox encryptor specification adopts the new naming: writers SHOULD use `.crypt.json` / `.crypt.cbor`, in lowercase, and readers MUST recognize all three suffixes, comparing names like their platform does. It also refers to the dialect specification.
- CHANGELOG: entries for the BREAKING naming (with a manual downgrade path), WA-CBOR, `convert-format` and `--format`. The unreleased overwrite-protection entry is amended to name the new suffixes.

Out of scope:
- the serializations embedded *encrypted* in cryptainers (symkeys, key structs, shards), which stay Extended JSON as part of the cryptographic protocol;
- the JSON-RPC wire format;
- native CBOR keystores;
- COSE signing;
- full WA-CBOR support in the MicroPython and C ports;
- the offloaded payload shared by a temporary `x.crypt.json~` and its finalized `x.crypt.json` (a data-loss risk when the stale temporary cryptainer is deleted, found by the unfinished cryptainer audit of issue #45): the payload naming rule is kept as is, and fixing it is left to the change for #45;
- lowercasing the names of existing files, cryptainers or corpus generations.

## Capabilities

### New Capabilities
- `cbor-document-format`: the WA-CBOR dialect, its data model, its bijection with Extended JSON, the unsupported values, file format recognition, and the library dump/load API.
- `cryptainer-file-naming`: cryptainer, payload and temporary filenames for each format, the letter case of suffixes, legacy `.crypt` support, listing, the storage format setting and the same-basename warning.
- `cli-format-conversion`: the `convert-format` command, the `--format json|cbor` option of the CLI's writing commands, and dual-format reading in the CLI.

### Modified Capabilities
- `compatibility-fixtures`: assets may also be WA-CBOR documents and `.crypt.json` / `.crypt.cbor` cryptainers. Sidecar naming is disambiguated for `.json` assets. The corpus gains equivalent pairs and invalid WA-CBOR documents, new generations use lowercase names, and its README documents the dialect and the letter case of each generation's names.
- `cryptostructure-validation`: the "tags do not survive serialization" requirement also covers WA-CBOR.
- `cli-overwrite-protection`: `convert-format` joins the protected commands and the `--force` ones. `encrypt`'s target files become the cryptainer of the requested format and its payload, and a same-basename cryptainer in another format does not block `encrypt`.

## Impact

- **Code:**
  - `src/wacryptolib/utilities/`: new WA-CBOR codec and format dispatch;
  - `src/wacryptolib/cryptainer/`: suffix constants and helpers, exports, filesystem dump/load, listing (one directory listing filtered in a single pass with the shared, platform-dependent name matcher, instead of six globs), storage format setting, encryption pipeline;
  - `src/wacryptolib/cli.py`: `convert-format`, `--format`, cryptoconf reading, `encrypt` overwrite check and basename stripping, `decrypt` default output name;
  - tests, including the CLI overwrite tests that assert `.crypt` names;
  - the corpus tooling (`scripts/compatibility/`, `tests/_compatibility_corpus.py`), including the lowercase name check for new generations, and `compatibility/README.md`, whose layout currently shows uppercase `<ALGO>` and `<KEY_ALGO>` names.
- **Docs:** the new dialect specification, the encryptor specification (§2, §9), a follow-up note in the storage-format audit, the CLI manual and tutorial, `CHANGELOG`.
- **Dependencies:** no new runtime dependency, since the WA-CBOR codec is written in-house (see design.md D4). `cbor2` joins the dev dependencies as a test oracle, and `pip_requirements_export.txt` is regenerated.
- **Coordination:**
  - builds on the applied and archived `cli-refuse-overwriting-files` change, whose `--force` option and existence-check helper `convert-format` reuses;
  - follows the file naming principle of the `simplify-filename-casing` change, which amends this change and must be applied before it, or together with it. That change also aligns the `keystore-algo-name-storage` and `lowercase-file-naming` main specs: key files with lowercase algo names and a silent fallback to legacy uppercase ones, and sensor names kept as configured. Cryptainers named by sensors (e.g. `20261111_184000_FrontCam_cryptainer.mp4.crypt.json`) keep that basename, and keystore pools created by the new corpus generation get lowercase key file names;
  - the future change for issue #45 (decrypting unfinished cryptainers) will deal with `~` names, whose naming rule this change keeps (final filename + `~`, payload named after the final filename);
  - `add-c-flightbox-encryptor`: its device profile CBOR becomes a strict sub-profile of WA-CBOR, and the output naming of its CLI (task 8.2) should follow the new convention, lowercase suffixes included.
- **Ecosystem:**
  - `witness-angel-recorder` writes through `CryptainerStorage`, so it produces `.crypt.json` files once upgraded. Its fixture generator asserts `.crypt` names and calls `dump_cryptainer_to_filesystem` with a `.crypt` path, which keeps working;
  - Authenticator / Revelation Station and `wacomponents` must upgrade wacryptolib to see new cryptainers;
  - the MicroPython and C ports stay conformant if they output `.crypt` files, since readers accept all three suffixes, until they adopt the new names;
  - the gateway only stores cryptainer names as strings, and is unaffected.
- **Unchanged:** keystore files are still read and written as JSON only (`convert-format` can convert them, but keystores won't read the `.cbor` result). The Python and JSON-Schema validation schemas are also unchanged, since both formats load to the same trees.
