## Purpose

Defines how the `flightbox` CLI converts document files between Extended JSON and WA-CBOR, how its writing commands choose the format of their output, and how its reading commands accept both formats.

## ADDED Requirements

### Requirement: convert-format command
The CLI SHALL provide a `convert-format SOURCE` command, with an optional `-o/--output TARGET` path and a `--force` flag (long form only), that converts any Extended JSON or WA-CBOR document file (cryptoconf, cryptainer, cipherdict, keystore metadata...) without validating it against a cryptostructure schema. The source format SHALL be recognized as specified by the document file format recognition rules. The target format SHALL be the one given by the extension of `TARGET`, which SHALL be `.json` or `.cbor` in lowercase (any other extension, including `.JSON` or `.Cbor`, is a usage error whose message gives the lowercase extensions), or, without `-o`, the format opposite to the source's. The target SHALL be written by the library's default writer of its format. The source file, and its payload file if any, SHALL never be modified, moved or deleted.

#### Scenario: Cryptoconf to CBOR
- **WHEN** `flightbox convert-format conf.json -o other.cbor` is run on a valid Extended JSON cryptoconf
- **THEN** `other.cbor` holds the WA-CBOR form of the same tree, and `conf.json` is unchanged

#### Scenario: Unknown target extension
- **WHEN** `flightbox convert-format conf.json -o conf.yaml` is run
- **THEN** the command fails with a usage error, and no file is written

#### Scenario: Target extension in another letter case
- **WHEN** `flightbox convert-format conf.json -o OTHER.CBOR` is run
- **THEN** the command fails with a usage error mentioning `.cbor`, and no file is written

#### Scenario: Same-format normalization
- **WHEN** `flightbox convert-format old.crypt -o old.crypt.json` is run on a legacy cryptainer in CANONICAL Extended JSON
- **THEN** `old.crypt.json` holds the same tree in the library's default RELAXED Extended JSON

### Requirement: Derived target name
Without `-o`, the target path SHALL be derived from the source path: a final `.json` extension, whatever its letter case, is replaced by `.cbor`, a final `.cbor` extension, whatever its letter case, is replaced by `.json`, and any other name gets the extension of the opposite format appended. The extension added by the command SHALL be lowercase, and the rest of the source name SHALL be kept as is.

#### Scenario: JSON cryptainer
- **WHEN** `flightbox convert-format video.mp4.crypt.json` is run
- **THEN** the target is `video.mp4.crypt.cbor`

#### Scenario: Legacy cryptainer
- **WHEN** `flightbox convert-format video.mp4.crypt` is run on a legacy Extended JSON cryptainer
- **THEN** the target is `video.mp4.crypt.cbor`

#### Scenario: Source extension in another letter case
- **WHEN** `flightbox convert-format Report.JSON` is run on an Extended JSON document
- **THEN** the target is `Report.cbor`

#### Scenario: Corpus-style name
- **WHEN** `flightbox convert-format 01_simple.cryptoconf` is run on an Extended JSON cryptoconf
- **THEN** the target is `01_simple.cryptoconf.cbor`

### Requirement: Offloaded payload is copied
When the converted document is a map whose `payload_ciphertext_struct` field equals the offloaded payload marker, `convert-format` SHALL copy the source's payload file, named per the offloaded payload filename rule, to the payload filename of the target. If the source payload file is missing, the command SHALL fail without writing anything.

#### Scenario: Offloaded cryptainer converted
- **WHEN** `flightbox convert-format x.crypt.json` is run on a cryptainer whose payload is offloaded in `x.crypt.json.payload`
- **THEN** `x.crypt.cbor` and `x.crypt.cbor.payload` are written, the latter identical to `x.crypt.json.payload`, and both source files are unchanged

#### Scenario: Missing source payload
- **WHEN** the source cryptainer declares an offloaded payload but its payload file does not exist
- **THEN** the command fails with an error naming the missing payload file, and neither target file is written

### Requirement: convert-format overwrite protection
`convert-format` SHALL apply the `cli-overwrite-protection` rules to its target file and, when a payload is to be copied, to its target payload file. These checks SHALL run before the source document is converted and before any file is written. A file appearing at a target path after these checks SHALL NOT be overwritten without `--force`. Independently of `--force`, the command SHALL refuse a target path that resolves to the source file itself, or to the source payload file.

#### Scenario: Existing target refused
- **WHEN** `flightbox convert-format conf.json` is run while `conf.cbor` already exists
- **THEN** the command fails with an error naming `conf.cbor` and mentioning `--force`, and `conf.cbor` is unchanged

#### Scenario: Existing target payload refused
- **WHEN** an offloaded cryptainer `x.crypt.json` is converted while `x.crypt.cbor` is absent but `x.crypt.cbor.payload` exists
- **THEN** the command fails naming `x.crypt.cbor.payload`, and no file is written

#### Scenario: Forced overwrite
- **WHEN** `flightbox convert-format conf.json --force` is run while `conf.cbor` already exists
- **THEN** `conf.cbor` is replaced by the conversion result

#### Scenario: Target is the source
- **WHEN** `flightbox convert-format conf.json -o conf.json --force` is run
- **THEN** the command fails with a usage error, and `conf.json` is unchanged

#### Scenario: No -f short option
- **WHEN** `flightbox convert-format conf.json -f` is run
- **THEN** the command fails with a "No such option" usage error, and no file is written

### Requirement: Failed conversion leaves no output
When a conversion fails (unreadable or mislabeled source, malformed document, unsupported value, missing payload), `convert-format` SHALL exit with a non-zero status and an error message, and SHALL leave no new or partial target file, nor target payload file, behind.

#### Scenario: Unsupported value
- **WHEN** an Extended JSON document containing an unsupported value (such as a decimal NaN) is converted to WA-CBOR
- **THEN** the command fails naming the unsupported value, and no target file exists afterwards

### Requirement: Output format option of writing commands
The `encrypt` and `cryptoconf generate-simple` commands SHALL accept a `--format json|cbor` option, in long form only like every option of the CLI, choosing the format of the document they write. For `encrypt`, the default SHALL be `json`, and the cryptainer SHALL be written with the suffix of its format. For `cryptoconf generate-simple`, the format SHALL default to the one given by the `-o` file extension (`.json` or `.cbor`), and to `json` otherwise; a `--format` contradicting the `-o` extension, and an `-o` extension spelling `.json` or `.cbor` in another letter case (such as `conf.CBOR`), SHALL be usage errors; CBOR output to STDOUT SHALL be written as raw bytes. On listing and viewing commands, `--format plain|json` SHALL keep its meaning of display format, and the `--help` of each command SHALL make clear whether its `--format` is a display format or a file format.

#### Scenario: Encrypt to CBOR
- **WHEN** `flightbox encrypt video.mp4 --format cbor` is run
- **THEN** the storage receives `video.mp4.crypt.cbor` and, unless `--bundle` is given, `video.mp4.crypt.cbor.payload`

#### Scenario: Encrypt default
- **WHEN** `flightbox encrypt video.mp4` is run
- **THEN** the storage receives `video.mp4.crypt.json`

#### Scenario: Cryptoconf format from extension
- **WHEN** `flightbox cryptoconf generate-simple -o conf.cbor add-payload-cipher-layer ...` is run without `--format`
- **THEN** `conf.cbor` holds a WA-CBOR cryptoconf

#### Scenario: Contradicting format
- **WHEN** `flightbox cryptoconf generate-simple --format json -o conf.cbor ...` is run
- **THEN** the command fails with a usage error, and no file is written

#### Scenario: Cryptoconf extension in another letter case
- **WHEN** `flightbox cryptoconf generate-simple -o conf.CBOR add-payload-cipher-layer ...` is run
- **THEN** the command fails with a usage error mentioning `.cbor`, and no file is written

### Requirement: CLI reads both formats
Every CLI command reading a cryptoconf (`encrypt -c`, `cryptoconf validate`, `cryptoconf summarize`) SHALL accept Extended JSON and WA-CBOR files, including from STDIN, per the document file format recognition rules. Every cryptainer command SHALL accept cryptainers named with any of the `.crypt`, `.crypt.json` and `.crypt.cbor` suffixes. When `encrypt -o` is given a basename ending with one of these suffixes, whatever its letter case, the suffix SHALL be stripped, and the lowercase suffix of the requested format appended. When `cryptainer decrypt` derives its default output filename, it SHALL strip whichever of these suffixes the cryptainer name ends with, whatever its letter case; a temporary `~` name ends with none of them, and keeps getting the `.decrypted` extension.

#### Scenario: CBOR cryptoconf validated
- **WHEN** `flightbox cryptoconf validate conf.cbor` is run on a valid WA-CBOR cryptoconf
- **THEN** the cryptoconf is reported valid

#### Scenario: Decrypt default output name
- **WHEN** `flightbox cryptainer decrypt video.mp4.crypt.cbor` is run without `-o`
- **THEN** the decrypted payload is written to `video.mp4`

#### Scenario: Premature suffix stripped
- **WHEN** `flightbox encrypt video.mp4 -o clip.crypt.json --format cbor` is run
- **THEN** the storage receives `clip.crypt.cbor`

#### Scenario: Premature suffix in another letter case
- **WHEN** `flightbox encrypt video.mp4 -o Clip.CRYPT` is run
- **THEN** the storage receives `Clip.crypt.json`
