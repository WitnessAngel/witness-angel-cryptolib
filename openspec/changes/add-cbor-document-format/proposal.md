## Why

All wacryptolib documents (cryptoconfs, cryptainers, cipherdicts, metadata...) are stored as Extended JSON, where bytes, UUIDs and dates are wrapped in `{"$binary": ...}`, `{"$uuid": ...}`, `{"$date": ...}` dicts and binary data is base64-inflated by a third. The flightbox storage audit (`docs/audits/flightbox_cryptoconf_storage_format.md`) recommends CBOR, and the C flightbox change already plans a CBOR decoder, but no shared CBOR dialect exists yet, and the audit left open whether the cryptainer itself may use it. A documented CBOR dialect, bijective with our Extended JSON, lets every tool and every reimplementation read and write either format without losing information.

## What Changes

- New **WA-CBOR document format**: a CBOR (RFC 8949) dialect using semantic tags instead of `$`-wrapper dicts (bytes as native byte strings, UUID as tag 37, datetime as tag 0, Decimal as tag 4, bignums as tags 2/3), with deterministic encoding and strict decoding. It is bijective with wacryptolib's Extended JSON over a defined data model, and the few values that neither format can carry faithfully are documented and rejected instead of being altered silently.
- A normative specification `docs/specifications/wa_cbor_document_format.md` (type mapping, CDDL, encoding and decoding rules, unsupported values, hex test vectors), so that other implementations can reproduce the dialect.
- Library API to load and dump documents as CBOR, and to load/dump any document file with its format chosen by extension or detected from its content.
- **BREAKING** (forward compatibility): new cryptainers are written as `<name>.crypt.json` (Extended JSON, the default) or `<name>.crypt.cbor` instead of `<name>.crypt`. Legacy `<name>.crypt` files (always Extended JSON) keep being listed, loaded, decrypted, purged and deleted. The offloaded payload is always the whole cryptainer filename plus `.payload`. Tools built on older wacryptolib versions only see `*.crypt` files and will not list the new ones.
- `CryptainerStorage` gets a cryptainer format setting (JSON by default); listing covers the three suffixes, and creating a cryptainer whose basename already exists in another format logs a warning and proceeds.
- CLI:
  - new `convert-format` command: converts any Extended JSON or CBOR document file to the other format (or to the format given by the `-o/--output` extension). The source is never modified, an offloaded payload is copied next to the target, and existing targets are refused unless `--force` is given (per `cli-overwrite-protection`).
  - `--format json|cbor` option (long form only, like every CLI option) on `encrypt` and `cryptoconf generate-simple`;
  - `encrypt`'s overwrite check targets the cryptainer of the requested format (`<basename>.crypt.json` or `.crypt.cbor`, plus its payload) instead of `<basename>.crypt`; a same-basename cryptainer in another format only triggers a warning;
  - every command reading a cryptoconf or cryptainer accepts both formats.
- Inner serializations embedded *encrypted* inside cryptainers (symkeys, key structs, shards) stay Extended JSON, since they are part of the cryptographic protocol (non-goal).
- Compatibility corpus: a new generation holds CBOR fixtures and `.crypt.json` cryptainers, paired with Extended JSON equivalents of the same trees.
- The flightbox encryptor specification adopts the new cryptainer naming (writers SHOULD use `.crypt.json`/`.crypt.cbor`, readers MUST accept all three) and refers to the new dialect specification.
- CHANGELOG entry (BREAKING naming).

## Capabilities

### New Capabilities
- `cbor-document-format`: the WA-CBOR dialect, its data model, its bijection with Extended JSON, the unsupported values, file format detection, and the library load/dump API.
- `cryptainer-file-naming`: cryptainer and payload filenames for each format, legacy `.crypt` support, listing, temporary files, the storage format setting and the same-basename warning.
- `cli-format-conversion`: the `convert-format` command and the `--format` option of the CLI's writing commands, plus dual-format reading in the CLI.

### Modified Capabilities
- `compatibility-fixtures`: assets may also be CBOR documents and `.crypt.json`/`.crypt.cbor` cryptainers; sidecar naming is disambiguated for `.json` assets; the corpus gains equivalent JSON/CBOR pairs and documents the CBOR dialect.
- `cryptostructure-validation`: the "tags do not survive serialization" requirement also covers CBOR.
- `cli-overwrite-protection`: `convert-format` joins the protected commands and the `--force` ones, and `encrypt`'s target files become the cryptainer of the requested format and its payload. A same-basename cryptainer in another format does not block `encrypt`.

## Impact

- **Code:**
  - `src/wacryptolib/utilities/` (new CBOR codec and format dispatch);
  - `src/wacryptolib/cryptainer/_base.py`, `_filesystem.py`, `_storage.py`, `_encryption_pipeline.py` (suffixes, payload path, listing, format setting);
  - `src/wacryptolib/cli.py` (`convert-format`, `--format`, reading cryptoconfs, decrypt output name, encrypt basename stripping);
  - tests, `docs/` (dialect specification, CLI manual and tutorial), `CHANGELOG`.
- **Dependencies:** no new runtime dependency (WA-CBOR codec written in-house, see design.md D4); `cbor2` joins the dev dependencies as a test oracle, and `pip_requirements_export.txt` is regenerated.
- **Coordination:**
  - Builds on the applied `cli-refuse-overwriting-files` change: `convert-format` reuses its `--force` option and existence-check helper. Its `encrypt` check (today on `<basename>.crypt`), its CLI tests and its fresh CHANGELOG entry are updated for the new suffixes.
  - `add-c-flightbox-encryptor`: its device profile CBOR becomes a strict sub-profile of WA-CBOR, and its CLI task 8.2 output naming should follow the new convention.
- **Ecosystem:**
  - `witness-angel-recorder` fixtures assert `.crypt` names (`specifications/fixtures/generate_fixtures.py`);
  - Authenticator / Revelation Station and `wacomponents` must upgrade wacryptolib to see `.crypt.json`/`.crypt.cbor` cryptainers;
  - the gateway only stores cryptainer names as strings and is unaffected.
- **Unchanged:** the JSON-RPC wire format, keystore files (they can still be converted with `convert-format`), and the Python validation schemas, since CBOR loads to the same trees.
