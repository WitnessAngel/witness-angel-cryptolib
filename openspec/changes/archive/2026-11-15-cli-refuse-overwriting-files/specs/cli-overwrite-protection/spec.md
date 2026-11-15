## Purpose

Defines how the `flightbox` CLI handles output files and directories that already exist, so that no user data is destroyed by default: existing files are only overwritten on explicit request, and existing directories never are.

## ADDED Requirements

### Requirement: Existing output files are never overwritten by default
A `flightbox` command that writes a file to disk SHALL NOT overwrite an existing file unless `--force` was given to that command. If a target file already exists, the command SHALL exit with a non-zero status and print an error on stderr that names the blocking path and mentions `--force`. The existing file SHALL be left unmodified, and no other output file of the command SHALL be created or modified.

This applies to the `encrypt` cryptainer files, the `cryptainer decrypt` output file and the `cryptoconf generate-simple` output file.

#### Scenario: Decrypting next to the original file is refused
- **WHEN** `flightbox cryptainer decrypt video.mp4.crypt` is run without `-o`, in a directory that already contains `video.mp4`
- **THEN** the command fails with an error naming `video.mp4` and mentioning `--force`
- **AND** the content of `video.mp4` is unchanged

#### Scenario: Decrypting to an existing explicit output file is refused
- **WHEN** `flightbox cryptainer decrypt <name>.crypt -o out.bin` is run and `out.bin` already exists
- **THEN** the command fails with an error naming `out.bin`, and `out.bin` is unchanged

#### Scenario: Encrypting over an existing cryptainer is refused
- **WHEN** `flightbox encrypt <file> -o report` is run and `report.crypt` already exists in the cryptainer storage
- **THEN** the command fails with an error naming `report.crypt`
- **AND** both `report.crypt` and `report.crypt.payload` are unchanged

#### Scenario: A leftover offloaded payload file blocks encryption
- **WHEN** `flightbox encrypt <file> -o report` is run and only `report.crypt.payload` exists in the cryptainer storage, with or without `--bundle`
- **THEN** the command fails with an error naming `report.crypt.payload`, and no `report.crypt` is created

#### Scenario: Generating a cryptoconf into an existing file is refused
- **WHEN** `flightbox cryptoconf generate-simple -o conf.json add-payload-cipher-layer ...` is run and `conf.json` already exists
- **THEN** the command fails with an error naming `conf.json`, and `conf.json` is unchanged

#### Scenario: New output files are written as before
- **WHEN** one of these commands is run without `--force` and none of its target files exist
- **THEN** it succeeds and writes its output files exactly as it did before this change

### Requirement: The existence check happens before any costly or interactive step
A command SHALL detect a blocking existing file before it prompts for a passphrase, encrypts or decrypts any payload, or contacts a remote trustee or gateway.

#### Scenario: No decryption work is done when the output file exists
- **WHEN** `flightbox cryptainer decrypt` is run without `--force` and its output file already exists
- **THEN** the command fails without attempting to decrypt the cryptainer, and without contacting any trustee

#### Scenario: No encryption work is done when the cryptainer exists
- **WHEN** `flightbox encrypt` is run without `--force` and a target cryptainer file already exists
- **THEN** the command fails without reading or encrypting the input payload

### Requirement: The --force flag allows overwriting existing files silently
`encrypt`, `cryptainer decrypt` and `cryptoconf generate-simple` SHALL accept a `--force` flag, in long form only, documented in their `--help`. With this flag, existing target files SHALL be overwritten without any prompt, error or warning, and the command SHALL otherwise behave as without the flag.

#### Scenario: Forced decryption overwrites the output file
- **WHEN** `flightbox cryptainer decrypt <name>.crypt -o out.bin --force` is run and `out.bin` already exists
- **THEN** the command succeeds and `out.bin` contains the decrypted payload

#### Scenario: Forced encryption overwrites the cryptainer
- **WHEN** `flightbox encrypt <file> -o report --force` is run and `report.crypt` and `report.crypt.payload` already exist in the cryptainer storage
- **THEN** the command succeeds, and the stored `report.crypt` cryptainer decrypts to the new input file

#### Scenario: Forced cryptoconf generation overwrites the output file
- **WHEN** `flightbox cryptoconf generate-simple --force -o conf.json add-payload-cipher-layer ...` is run and `conf.json` already exists
- **THEN** the command succeeds and `conf.json` contains the new cryptoconf

### Requirement: Standard output is not subject to overwrite protection
Writing to STDOUT SHALL NOT be blocked, whether by default or through `-`, and SHALL NOT require `--force`.

#### Scenario: Cryptoconf printed to STDOUT
- **WHEN** `flightbox cryptoconf generate-simple add-payload-cipher-layer ...` is run without `-o`
- **THEN** the cryptoconf is printed on STDOUT, as before

#### Scenario: Decryption to STDOUT
- **WHEN** `flightbox cryptainer decrypt <name>.crypt -o -` is run
- **THEN** the decrypted payload is written to STDOUT, and no file named `-` is checked or created

### Requirement: Existing directories are never overwritten
No `flightbox` command SHALL overwrite, merge into or delete an existing directory that the user designates as a target to be created, and no option SHALL exist to allow it. `authenticator create DIR` SHALL fail when anything already exists at `DIR`, file or directory, with a usage error naming the path, printed before the passphrase prompt. The user must remove the existing path manually. Likewise, a file output path that designates an existing directory SHALL be rejected, with or without `--force`.

#### Scenario: Creating an authenticator in an existing directory is refused
- **WHEN** `flightbox authenticator create DIR` is run and `DIR` is an existing directory, even an empty one
- **THEN** the command fails with an error stating that the target directory must not exist yet, without prompting for a passphrase
- **AND** the content of `DIR` is unchanged

#### Scenario: Creating an authenticator over an existing file is refused
- **WHEN** `flightbox authenticator create DIR` is run and `DIR` is an existing regular file
- **THEN** the command fails with a usage error naming `DIR`, without prompting for a passphrase and without a traceback, and the file is unchanged

#### Scenario: No force option for authenticator creation
- **WHEN** `flightbox authenticator create --help` is displayed
- **THEN** it offers no `--force` option, and passing `--force` fails as an unknown option

#### Scenario: Output file path pointing to a directory is refused even with --force
- **WHEN** `flightbox cryptainer decrypt <name>.crypt -o some_dir --force` is run and `some_dir` is an existing directory
- **THEN** the command fails with an error naming `some_dir`, and `some_dir` is unchanged

### Requirement: No ambiguous -f short option
No `flightbox` command SHALL accept `-f` as a short option. `--force` and `--format` SHALL only be available in their long forms, and their `--help` SHALL list no short alias for them.

#### Scenario: -f is rejected on a listing command
- **WHEN** `flightbox cryptainer list -f json` is run
- **THEN** the command fails with a "No such option" usage error, and `flightbox cryptainer list --format json` keeps working

#### Scenario: -f is rejected on a writing command
- **WHEN** `flightbox cryptainer decrypt <name>.crypt -o out.bin -f` is run and `out.bin` already exists
- **THEN** the command fails with a "No such option" usage error, and `out.bin` is unchanged

#### Scenario: Help texts list no -f alias
- **WHEN** the `--help` of any `flightbox` command or subcommand is displayed
- **THEN** no option is listed with a `-f` short form
