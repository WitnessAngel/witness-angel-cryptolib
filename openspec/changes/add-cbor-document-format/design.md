## Context

See proposal.md for the motivation. Current state that shapes the approach:

- All document I/O goes through the external `extjson` package, re-exported by `wacryptolib.utilities` (`dump_to_json_*`, `load_from_json_*`). It writes RELAXED Extended JSON with sorted keys, truncates datetimes to milliseconds, and still reads CANONICAL forms (both forms are in the compatibility corpus).
- JSON appears at two levels:
  - **outer documents**: cryptoconf files, cryptainer files (`_filesystem.py`), keystore metadata;
  - **inner blobs**: symkeys, key structs and shards are dumped with `dump_to_json_bytes()` and then *encrypted* into `key_ciphertext` (`_flightbox.py`, `_decryptor.py`). Signatures cover payload digests, never the serialized document (`_signing.py`).
- Cryptainer naming: `CRYPTAINER_SUFFIX = ".crypt"`, temporary suffix `~`, and offloaded payload = cryptainer filename (minus `~`) + `.payload` (`_get_offloaded_file_path`). `CryptainerStorage.list_cryptainer_names()` globs `*.crypt` and `*.crypt~` with `Path.glob()`, which compares names case-insensitively on Windows only (so `X.CRYPT` is listed there, but not on Linux); the CLI strips `.crypt` in `encrypt -o` and in the `decrypt` default output name.
- File naming principle (`simplify-filename-casing`, D1 there, which amends this change):
  - the toolchain opens names exactly as built, and lets the filesystem decide whether letter case matters;
  - it compares names like the platform does (`os.path.normcase()`, `Path.glob()`): case-insensitively on Windows only;
  - it writes the name parts it chooses in lowercase, and keeps the parts given by callers or configs.

  Keystores write lowercase algo names and fall back silently, file by file, to the legacy uppercase names (`keystore-algo-name-storage`). Sensors lowercase only record extensions and keep `sensor_name` (`lowercase-file-naming`, as amended). The compatibility corpus still names its per-algorithm subdirectories and key files in uppercase (`cipherdicts/<generation>/AES_CBC/`, `<uid>_RSA_OAEP_public_key.pem`).
- The unfinished cryptainer audit (`docs/audits/unfinished_cryptainer_decryption.md`, issue #45) found that a temporary `x.crypt~` and its finalized `x.crypt` share `x.crypt.payload`, so deleting a stale temporary cryptainer deletes the payload of the finished one. It also plans a `cryptainer decrypt --allow-unfinished` option.
- CLI overwrite protection is in place (`cli-overwrite-protection` main spec, from the archived `cli-refuse-overwriting-files` change):
  - no option has a `-f` short form anymore; `--format plain|json` is a display option of listing and viewing commands;
  - `FORCE_OPTION` (`--force`) is on `encrypt`, `cryptainer decrypt` and `cryptoconf generate-simple`;
  - `_ensure_paths_not_existing(paths, force)` refuses existing files unless forced, and always refuses directories;
  - `encrypt` checks `<storage>/<basename>.crypt` and its `.payload` before any work;
  - `decrypt` and `generate-simple` open their outputs in exclusive-creation mode (`x`/`xb`) when not forced, so a file appearing after the early check is not clobbered;
  - `generate-simple -o` is now a `click.Path` written through `click.open_file(..., "w"/"x")` in text mode.
- `add-c-flightbox-encryptor` plans a strict C CBOR decoder (tag 37 only, no floats, no indefinite lengths) for device profiles, and `cbor2` as a dev dependency. micropython-lib's `cbor2` cannot decode tags (audit §8).

## Goals / Non-Goals

**Goals:**
- One dialect, specified precisely enough for the C and MicroPython ports and third parties to reproduce byte-exact output.
- A strict reader: anything outside the dialect fails loudly instead of loading as a near-miss tree.
- Every existing file keeps loading, and every existing API keeps its behaviour, except the default cryptainer filename.
- Letter case handled by the shared file naming principle, with no rule of this change's own (D12).

**Non-Goals:**
- Changing the inner encrypted serializations (protocol change; and converting them would need the keys).
- COSE_Sign1 signing of documents (the deterministic encoding keeps it possible later).
- Keystores reading or writing CBOR natively, and the JSON-RPC wire format.
- MicroPython or C support for full WA-CBOR in this change (the C device profile is a sub-profile; see D3).
- Changing what the `extjson` package's JSON writer accepts (for example its silent stringification of non-text keys); the rejection rules apply to WA-CBOR writing and to conversions.

## Decisions

### D1. Bijection is defined over the data model, not over files

```
   Extended JSON files            data model D                 WA-CBOR files
  (relaxed, canonical,  --load-->  maps(str keys), arrays,  <--load--  (any well-formed
   any key order...)              str, int, float, bool,               in-dialect CBOR)
                        <--dump--  None, bytes, UUID,        --dump-->  core deterministic
   library default writer          aware datetime, Decimal              encoding
```

JSON → tree is many-to-one (canonical/relaxed, whitespace, key order, `$numberInt`), so a file-level bijection is impossible in general. The guarantee is tree equality with strict types, plus byte-exact round trips from the two default writers' outputs (spec "Bijection with Extended JSON"). Alternative considered: a byte-level bijection restricted to a single canonical JSON form. That was rejected because it would refuse the existing corpus generations.

### D2. Tag choices
| Type | Choice | Rejected alternatives |
|---|---|---|
| bytes | untagged major type 2 | tag 21-23 encoding hints: meaningless without JSON text |
| UUID | tag 37 over 16 bytes | text UUID: larger, and diverges from the audit and from the C device profile |
| datetime | tag 0, extjson's exact text form (ms, `Z` or `±HH:MM`) | tag 1 (epoch): loses the UTC offset that RELAXED extjson keeps. Tag 1001 (RFC 9581): little support |
| Decimal | tag 4 `[exponent, mantissa]` from `as_tuple()`, never normalized | text in a custom tag: non-standard |
| big int | tags 2/3 | none (RFC 8949 standard) |

Reusing extjson's exact datetime text makes the bijection trivial: both writers emit the same string, and both readers parse it with the same function.

### D3. WA-CBOR is the parent of the C device profile
The C decoder of `add-c-flightbox-encryptor` (D8 there) accepts a strict subset: no floats, no tags other than 37, and definite lengths only. Every valid device profile is therefore a valid WA-CBOR document. The device profile specification should reference `docs/specifications/wa_cbor_document_format.md` for the shared rules and list only its own restrictions. Writers emit no tag 55799, so the C decoder never sees one. Readers accept it around the top-level item only, as a courtesy to generic tools.

### D4. In-house pure-Python WA-CBOR codec; `cbor2` only as a test oracle
New module `src/wacryptolib/utilities/wacbor.py`, MicroPython-friendly in style like `extjson` (no runtime typing needs), so that it can later be vendored or moved into the `extjson` package:
- **Encoder**: a recursive walk that checks the data model, rejects unsupported values (spec list), and emits core deterministic encoding directly. Map keys are sorted by their encoded bytes, and floats use the shortest form (half, then single, then double) that round-trips. `bool` is checked before `int`.
- **Decoder**: an index-based reader over a `bytes`/`memoryview`, so that large byte strings (inline payloads) are sliced and not copied item by item. It enforces every strict decoding rule: tag whitelist, duplicate keys, simple values, UTF-8, tag payload shapes, trailing bytes, and keyword maps (checked after a map is decoded). It also has a nesting-depth limit (default 64, matching the C decoder).

Alternative considered: `cbor2` as a runtime dependency. Its encoder (`canonical=True`) would do, but its decoder applies built-in semantic decoders (tag 1 to datetime, tag 258 to set, tag 28/29 shared values...) before any `tag_hook`. Its pure-Python and C-accelerated decoders differ, and enforcing duplicate-key, keyword-map and tag-whitelist rules would mean post-validating trees from which tag 1 versus tag 0 is no longer visible. The strictness is the dialect's core, so owning about 400 lines is safer, and it avoids a new runtime dependency. `cbor2` joins the dev dependencies (as already planned by the C change). Property-based and vector tests then check that (a) `cbor2.loads(our_output)` equals our tree and (b) our decoder accepts `cbor2.dumps(tree, canonical=True)` for in-dialect trees.

### D5. File-level API and format recognition
In `wacryptolib.utilities`:
- `DocumentFormat` (`JSON`, `CBOR`);
- `dump_to_cbor_bytes()` / `load_from_cbor_bytes()` and their `_file` variants;
- `detect_document_format(data, filename=None)`, `load_from_document_file(path, format=None)`, `dump_to_document_file(path, data, format=None)`, `load_from_document_bytes(data, filename=None, format=None)`.

Recognition follows the spec. The extension decides for `.json`, `.cbor` and `.crypt`, matched with the shared name matcher (D12). The first significant byte decides otherwise, and it is always checked against the extension. JSON's possible first bytes (`{`, `[`, whitespace, BOM 0xEF) never overlap CBOR's 0x80-0xBF and 0xD9, so detection is unambiguous for map- or array-rooted documents. When writing, an explicit `format` wins, but contradicting a `.json`/`.cbor` extension (under the matcher) is an error; with neither, `dump_to_document_file()` raises instead of guessing. The existing `extjson` functions stay re-exported unchanged.

### D6. Cryptainer naming constants and helpers
- `CRYPTAINER_SUFFIX = ".crypt"` keeps its value: external code imports it, and it remains the legacy suffix. New constants `CRYPTAINER_JSON_SUFFIX = ".crypt.json"`, `CRYPTAINER_CBOR_SUFFIX = ".crypt.cbor"` and `CRYPTAINER_SUFFIXES` (all three) are added.
- Helpers `get_cryptainer_suffix(format)`, `split_cryptainer_suffix(name)` (returns basename and format, or None) and `get_cryptainer_format_from_filename(path)` replace the scattered `endswith(CRYPTAINER_SUFFIX)` logic. They match suffixes with the shared name matcher (D12), and handle a temporary `~` by looking at the final filename. The CLI uses them to strip suffixes from typed names, keeping the basename as typed, then appends the lowercase suffix of the requested format.
- `_get_offloaded_file_path` is already "filename minus `~` + `.payload`", so it is unchanged.
- `dump_cryptainer_to_filesystem` writes WA-CBOR when the filename, without a temporary `~`, ends with `.cbor` under the matcher, and Extended JSON otherwise: legacy `.crypt` paths and ad-hoc paths without suffix (tests, the recorder's fixture generator) keep working as today. `load_cryptainer_from_filesystem` reads with D5's recognition (sniffing for `~` and suffix-less names).
- Listing reads the storage directory once (`os.scandir()`) and keeps, in a single pass, the names ending with `.crypt`, `.crypt.json`, `.crypt.cbor` (or the same with `~`) under the matcher, instead of six globs. The result is the same as `Path.glob()` would give. These suffixes cannot overlap, since a name ends with exactly one of them, and `.payload` files match none.

### D7. Storage format setting and same-basename warning
`CryptainerStorage(..., cryptainer_format=DocumentFormat.JSON)`. The read-only storage base lists and reads all formats. The point where a storage computes a target cryptainer path (both `encrypt_file()` and the enqueued encryption path, through the encryption pipeline) checks for same-basename siblings in the other formats, logs a warning and proceeds. The pipeline's temporary filename becomes "final filename + `~`" for every format.

### D8. `convert-format` checks early, writes exclusively, and copies the payload
Order of operations:
1. Resolve the target (D9). Refuse a bad extension, and a target resolving to the source or to its payload.
2. Load the source (format recognition). Decide whether a payload must be copied: the tree's `payload_ciphertext_struct` equals `OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER`, and the source payload exists (else fail).
3. Call `_ensure_paths_not_existing([target, target_payload?], force)` before any conversion or write. Loading comes first only because the payload check depends on the document's content. No costly or interactive step precedes it.
4. Encode the target **fully in memory**, so unsupported values fail before any write.
5. Write the files, payload first and document last, so that a document never points to a missing payload:
   - **without `--force`**: exclusive creation (`xb`), the same pattern as `decrypt` / `generate-simple`. A file appearing after the early check is never clobbered. On any failure, the files created by this run are deleted.
   - **with `--force`**: each file is written to a temporary file in the target directory, then `os.replace`d. A failed forced conversion leaves the previous targets intact instead of truncated.

No schema validation runs, because the command converts any document. The payload is detected structurally (top-level map, exact marker), not by filename, so offloaded cryptainers with arbitrary names work too. Alternative considered: temporary file + `os.replace` in both modes. It was rejected because `os.replace` silently overwrites a file created after the check, and a no-clobber rename needs hard links, which FAT-formatted SD cards lack.

### D9. Derived target names and the `--format` option
Without `-o`, a final `.json` or `.cbor` (under the matcher) is swapped for the lowercase opposite one, and anything else gets the opposite extension appended. So `x.crypt` becomes `x.crypt.cbor` with no special case, and `Report.JSON` becomes `Report.cbor` on Windows and `Report.JSON.cbor` elsewhere. An explicit `-o` must end with `.json` or `.cbor` under the matcher, and is written as given: `-o OTHER.CBOR` writes WA-CBOR to `OTHER.CBOR` on Windows, and is an unknown-extension usage error elsewhere, like `.yaml`. No dedicated error exists for other spellings.
- `encrypt --format json|cbor` and `cryptoconf generate-simple --format json|cbor` are long-only, like every CLI option (no `-f` anywhere).
- `generate-simple -o` keeps accepting any name, written as given. Without `--format`, the format comes from a `.json`/`.cbor` extension under the matcher, else defaults to JSON. So `conf.CBOR` gets CBOR on Windows, and JSON elsewhere, like `conf.txt`.
- `generate-simple` keeps its `click.Path` `-o`, but opens it in binary mode (`wb` / `xb`, and the binary STDOUT stream for `-`). CBOR bytes, or the current indented JSON encoded as UTF-8, are written to it.
- On listing and viewing commands, `--format plain|json` (display) is untouched. The help texts say "file format" versus "display format" explicitly.

### D10. Integration with `cli-overwrite-protection`
`convert-format` reuses `FORCE_OPTION` and `_ensure_paths_not_existing`. `encrypt`'s early check currently computes `<storage>/<basename> + CRYPTAINER_SUFFIX` and its payload. It switches to `<basename> + get_cryptainer_suffix(format)` and its payload. Same-basename cryptainers in other formats are not overwrite conflicts: they only trigger the D7 warning. The existing CLI tests from that change, which assert `report.crypt` names, are updated to the new names. The delta spec `specs/cli-overwrite-protection/spec.md` records these behaviour changes, and the CHANGELOG entry added by that change (unreleased) is amended to name the new suffixes.

### D11. Documentation and corpus
- `docs/specifications/wa_cbor_document_format.md` is normative. It contains:
  - the data model and the type table with Extended JSON equivalents;
  - a CDDL generic item grammar;
  - the encoding and decoding rules, the unsupported values and the recognition rules;
  - hex test vectors in a machine-readable block that the test suite parses.
- The encryptor specification:
  - §2 gains a pointer to it;
  - §9.1 and §9.2 adopt the new names ("writers SHOULD use `.crypt.json`/`.crypt.cbor`, readers MUST accept all three").
- The storage-format audit gets a short follow-up note answering its open question.
- The corpus gains a new generation (e.g. `2026_cbor_pairs`), produced by the existing generation tooling. It holds JSON/CBOR pairs and invalid CBOR documents, its sidecars use the new `x.crypt.json.json` naming, and the fixture loader applies the sidecar disambiguation rule.
- The new generation is the first one with lowercase names only: the writer of the tooling (`scripts/compatibility/_corpus.py`) lowercases algo subdirectory names and asserts that every path it writes below the generation directory is lowercase. The keystore pools it creates are lowercase thanks to the keystore change. A compatibility test checks the names of this generation and of later ones (declared in a constant next to the corpus loader), and the README marks which generations still use uppercase algo names.

### D12. Letter case of names
This change applies the file naming principle of `simplify-filename-casing` (D1 there), and has no letter case rule of its own:
- **Writing:** the name parts chosen by the library are lowercase: cryptainer suffixes, `.payload`, `~`, extensions added by `convert-format`, corpus files and directories. Caller-provided basenames and explicit paths are kept as given. A basename is the user's data (often the media filename, or a sensor name). Lowercasing it would make `cryptainer decrypt` restore a different name, and on case-sensitive filesystems it could merge distinct recordings.
- **Opening:** payload, sibling and target paths are built from the exact names and opened as is, so the filesystem decides whether letter case matters. Overwrite checks and the same-basename warning follow it too.
- **Comparing:** one name matcher, a small helper in `wacryptolib.utilities`, tests whether a file name ends with a lowercase suffix after `os.path.normcase()`. A stripped basename is cut by the suffix length from the original name, so it keeps its spelling. The matcher is used by:
  - `split_cryptainer_suffix()` and `get_cryptainer_format_from_filename()`;
  - document format recognition, and the choice of the written format from an extension;
  - storage listing;
  - `encrypt -o` stripping, the `decrypt` default output name, and the `convert-format` target extension and derived name.

Outcomes therefore differ by platform only for names spelled in another letter case, which the library never writes: `a.CRYPT.JSON` is listed on Windows and not elsewhere, and `encrypt -o Clip.CRYPT` gives `Clip.crypt.json` on Windows and `Clip.CRYPT.crypt.json` elsewhere. The specs state these outcomes as "on Windows" / "on other platforms" branches. Tests cover the other platform by patching `os.path.normcase` with `ntpath.normcase` or `posixpath.normcase`.

**Accepted mismatch:** comparisons follow the platform, not the filesystem. macOS and Linux reading a FAT card compare case-sensitively although opens ignore case. Only names renamed by hand in another letter case are affected.

**Rejected alternatives:**
- exact-lowercase recognition everywhere, from a dedicated directory listing, with case-insensitive stripping of typed names and usage errors for `.JSON`/`.CBOR` outputs (the previous version of this design);
- case-insensitive comparison everywhere.

Both are rules of the toolchain's own: they need special listings, variants and errors, and they disagree with what `Path.glob()` and file managers show.

## Risks / Trade-offs

- [A storage lists differently on Windows and Linux when suffixes were renamed by hand in another letter case (e.g. `X.CRYPT`)] → accepted (D12), as today with `Path.glob()`, and as file managers show. The library never writes such names.
- [On Linux, `generate-simple -o conf.CBOR` writes JSON into `conf.CBOR`. Copied to Windows, reading it fails with the mislabeled-file error] → the error names the file and both formats. Typing `.CBOR` on Linux is no different from typing `.cbr`.
- [Older apps don't list `.crypt.json`/`.crypt.cbor`] → BREAKING entry in the CHANGELOG, coordinated upgrade of the recorder, Authenticator and `wacomponents`. Manual downgrade path: a JSON cryptainer is byte-identical whatever its name, so renaming `x.crypt.json` → `x.crypt` and `x.crypt.json.payload` → `x.crypt.payload` makes it visible to old versions again (documented).
- [In-house codec bugs] → spec test vectors, a `cbor2` oracle in property-based tests over generated trees, and invalid-document fixtures. The decoder's depth limit and length bounds guard against hostile input.
- [Duplicate cryptainers after conversion (same basename, two formats, payload copied)] → accepted by design (copy semantics). Listing shows both, deletion is per file, and a warning is logged when new ones are created next to siblings. Disk usage doubles for converted offloaded cryptainers, as the user explicitly wants a copy.
- [Strict reader refuses CBOR from generic tools (e.g. tag 1 datetimes, integer keys)] → intentional, documented in the dialect specification with the reason (no faithful Extended JSON equivalent).
- [`.crypt.json` assets versus legacy `.crypt.json` sidecars in the corpus] → explicit disambiguation rule, tested by a scenario.
- [Large inline payloads in CBOR] → no base64 overhead (about 25% smaller than JSON). The decoder slices byte strings from a memoryview, and the encoder joins parts once.

## Migration Plan

1. Release with the BREAKING note. Library users who need old naming can't configure it back: legacy names are read-only by design.
2. Upgrade the consumer apps (Authenticator / Revelation Station, `wacomponents`, recorder), then regenerate the recorder's fixture expectations as a new generation.
3. Rollback: older wacryptolib versions ignore the new files. Rename JSON cryptainers as described above to make them visible again. CBOR cryptainers must first be converted to JSON with a new version.

## Open Questions

- Whether to later move `wacbor.py` into the `extjson` package (or vendor it for MicroPython, patching around micropython-lib's missing tag support): this doesn't change the dialect or the API.
- The exact name of the new corpus generation directory (lowercase, like all its contents).
