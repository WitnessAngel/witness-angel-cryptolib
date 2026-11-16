## MODIFIED Requirements

### Requirement: Existing output files are never overwritten by default
A `flightbox` command that writes a file to disk SHALL NOT overwrite an existing file unless `--force` was given to that command. If a target file already exists, the command SHALL exit with a non-zero status and print an error on stderr that names the blocking path and mentions `--force`. The existing file SHALL be left unmodified, and no other output file of the command SHALL be created or modified.

This applies to the `encrypt` cryptainer files (the cryptainer named with the suffix of the requested format, `<basename>.crypt.json` or `<basename>.crypt.cbor`, and its offloaded payload file), the `cryptainer decrypt` output file, the `cryptoconf generate-simple` output file, and the `convert-format` target file and target payload file. A cryptainer with the same basename in another format (legacy `<basename>.crypt`, or the other of `.crypt.json` / `.crypt.cbor`) is not a target file of `encrypt`, and SHALL NOT block it.

#### Scenario: Decrypting next to the original file is refused
- **WHEN** `flightbox cryptainer decrypt video.mp4.crypt` is run without `-o`, in a directory that already contains `video.mp4`
- **THEN** the command fails with an error naming `video.mp4` and mentioning `--force`
- **AND** the content of `video.mp4` is unchanged

#### Scenario: Decrypting to an existing explicit output file is refused
- **WHEN** `flightbox cryptainer decrypt <name>.crypt -o out.bin` is run and `out.bin` already exists
- **THEN** the command fails with an error naming `out.bin`, and `out.bin` is unchanged

#### Scenario: Encrypting over an existing cryptainer is refused
- **WHEN** `flightbox encrypt <file> -o report` is run and `report.crypt.json` already exists in the cryptainer storage
- **THEN** the command fails with an error naming `report.crypt.json`
- **AND** both `report.crypt.json` and `report.crypt.json.payload` are unchanged

#### Scenario: Encrypting over an existing CBOR cryptainer is refused
- **WHEN** `flightbox encrypt <file> -o report --format cbor` is run and `report.crypt.cbor` already exists in the cryptainer storage
- **THEN** the command fails with an error naming `report.crypt.cbor`, and `report.crypt.cbor` is unchanged

#### Scenario: A leftover offloaded payload file blocks encryption
- **WHEN** `flightbox encrypt <file> -o report` is run and only `report.crypt.json.payload` exists in the cryptainer storage, with or without `--bundle`
- **THEN** the command fails with an error naming `report.crypt.json.payload`, and no `report.crypt.json` is created

#### Scenario: A cryptainer in another format does not block encryption
- **WHEN** `flightbox encrypt <file> -o report` is run and the cryptainer storage holds a legacy `report.crypt` and `report.crypt.payload`, but no `report.crypt.json` nor `report.crypt.json.payload`
- **THEN** the command succeeds with a warning naming `report.crypt`, writes `report.crypt.json`, and leaves `report.crypt` and `report.crypt.payload` unchanged

#### Scenario: Generating a cryptoconf into an existing file is refused
- **WHEN** `flightbox cryptoconf generate-simple -o conf.json add-payload-cipher-layer ...` is run and `conf.json` already exists
- **THEN** the command fails with an error naming `conf.json`, and `conf.json` is unchanged

#### Scenario: Converting into an existing file is refused
- **WHEN** `flightbox convert-format conf.json` is run and `conf.cbor` already exists
- **THEN** the command fails with an error naming `conf.cbor` and mentioning `--force`, and `conf.cbor` is unchanged

#### Scenario: New output files are written as before
- **WHEN** one of these commands is run without `--force` and none of its target files exist
- **THEN** it succeeds and writes its output files, with the names and formats given by its options

### Requirement: The --force flag allows overwriting existing files silently
`encrypt`, `cryptainer decrypt`, `cryptoconf generate-simple` and `convert-format` SHALL accept a `--force` flag, in long form only, documented in their `--help`. With this flag, existing target files SHALL be overwritten without any prompt, error or warning about them, and the command SHALL otherwise behave as without the flag.

#### Scenario: Forced decryption overwrites the output file
- **WHEN** `flightbox cryptainer decrypt <name>.crypt -o out.bin --force` is run and `out.bin` already exists
- **THEN** the command succeeds and `out.bin` contains the decrypted payload

#### Scenario: Forced encryption overwrites the cryptainer
- **WHEN** `flightbox encrypt <file> -o report --force` is run and `report.crypt.json` and `report.crypt.json.payload` already exist in the cryptainer storage
- **THEN** the command succeeds, and the stored `report.crypt.json` cryptainer decrypts to the new input file

#### Scenario: Forced cryptoconf generation overwrites the output file
- **WHEN** `flightbox cryptoconf generate-simple --force -o conf.json add-payload-cipher-layer ...` is run and `conf.json` already exists
- **THEN** the command succeeds and `conf.json` contains the new cryptoconf

#### Scenario: Forced conversion overwrites the target files
- **WHEN** `flightbox convert-format x.crypt.json --force` is run on an offloaded cryptainer, and `x.crypt.cbor` and `x.crypt.cbor.payload` already exist
- **THEN** the command succeeds, and both target files are replaced by the conversion result and the copied payload
