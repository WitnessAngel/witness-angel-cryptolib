## Purpose

Defines how cryptainer files and their offloaded payload files are named for each document format, the lowercase spelling of the suffixes, how legacy `.crypt` cryptainers stay supported, and how cryptainer storages choose the format of the cryptainers they write.

## ADDED Requirements

### Requirement: Cryptainer filenames by format
When a cryptainer storage or the CLI chooses the name of a new cryptainer, it SHALL be `<basename>.crypt.json` for an Extended JSON cryptainer and `<basename>.crypt.cbor` for a WA-CBOR cryptainer, never the legacy `<basename>.crypt`. Library functions that write a cryptainer to an explicit path given by the caller SHALL write it to that path, in the format implied by its name once a temporary `~` suffix is removed: WA-CBOR for a name ending with `.cbor`, Extended JSON otherwise (legacy `.crypt` paths, `.json` paths, and paths without any of these suffixes, as accepted today).

#### Scenario: Explicit legacy path
- **WHEN** a cryptainer is dumped to the filesystem at an explicit path `x.crypt`, outside any storage
- **THEN** it is written to `x.crypt` in Extended JSON, and loads back with the filesystem cryptainer loader

#### Scenario: Default storage writes JSON cryptainers
- **WHEN** a file `video.mp4` is encrypted into a cryptainer storage created without a format setting
- **THEN** the cryptainer is written as `video.mp4.crypt.json`, in Extended JSON

#### Scenario: CBOR storage writes CBOR cryptainers
- **WHEN** a file `video.mp4` is encrypted into a cryptainer storage set to the CBOR format
- **THEN** the cryptainer is written as `video.mp4.crypt.cbor`, in WA-CBOR

#### Scenario: Caller's basename kept as is
- **WHEN** a file `Video.MP4` is encrypted into a default cryptainer storage
- **THEN** the cryptainer is written as `Video.MP4.crypt.json`: the suffix is lowercase, and the basename keeps its letter case

### Requirement: Lowercase cryptainer suffixes
The cryptainer suffixes (`.crypt`, `.crypt.json`, `.crypt.cbor`), the offloaded payload suffix `.payload` and the temporary suffix `~` SHALL be written in lowercase, and recognized in lowercase only, with the same results on case-sensitive and case-insensitive filesystems. A file whose suffix is spelled in another letter case (e.g. `x.CRYPT.JSON`) SHALL NOT be listed as a cryptainer, and its format SHALL NOT be inferred from that suffix.

#### Scenario: Other spelling of a suffix not listed
- **WHEN** a storage directory holds `a.CRYPT.JSON` and `b.crypt.json`, on a case-sensitive or a case-insensitive filesystem
- **THEN** listing returns exactly `b.crypt.json`

### Requirement: Legacy cryptainers stay supported
The system SHALL keep listing, loading, validating, analysing, decrypting, deleting, purging and measuring legacy `<basename>.crypt` cryptainers, which are always Extended JSON, exactly as `.crypt.json` cryptainers. Cryptainer files SHALL be read in the format given by their suffix.

#### Scenario: Legacy cryptainer decrypted from storage
- **WHEN** a storage directory holds `old.crypt` and `old.crypt.payload` produced by a previous library version
- **THEN** `old.crypt` is listed, and decrypting it from the storage returns the original payload

#### Scenario: Legacy cryptainer purged
- **WHEN** a storage purge by age selects a legacy `old.crypt` cryptainer
- **THEN** both `old.crypt` and `old.crypt.payload` are deleted

### Requirement: Offloaded payload filename
The offloaded payload of a cryptainer SHALL be stored next to it, in a file named after the whole cryptainer filename followed by `.payload` (`x.crypt.payload`, `x.crypt.json.payload`, `x.crypt.cbor.payload`). For a temporary cryptainer, the payload filename SHALL be derived from the cryptainer filename without its temporary suffix.

#### Scenario: CBOR cryptainer with offloaded payload
- **WHEN** a cryptainer is written as `x.crypt.cbor` with an offloaded payload
- **THEN** its payload ciphertext is written to `x.crypt.cbor.payload`, and loading `x.crypt.cbor` reads it from there

#### Scenario: Temporary cryptainer payload
- **WHEN** an encryption stream writes the temporary cryptainer `x.crypt.json~`
- **THEN** its payload is written to `x.crypt.json.payload`, the name it keeps once the cryptainer is finalized

### Requirement: Temporary cryptainer filenames
A cryptainer being written by an encryption stream SHALL be named after its final filename followed by the temporary suffix `~` (`x.crypt.json~`, `x.crypt.cbor~`), and SHALL be replaced by a cryptainer with its final filename when finalized. A temporary cryptainer SHALL be written and read in the format of its final filename. Listings of unfinished cryptainers SHALL include temporary cryptainers of the three suffixes, including legacy `x.crypt~` files.

#### Scenario: Unfinished CBOR cryptainer listed
- **WHEN** a CBOR encryption stream has started but not been finalized
- **THEN** listing unfinished cryptainers returns `x.crypt.cbor~`, listing finished cryptainers does not return it, and `x.crypt.cbor~` holds WA-CBOR

### Requirement: Listing covers every cryptainer suffix
Listing the finished cryptainers of a storage SHALL return every file whose name ends with `.crypt`, `.crypt.json` or `.crypt.cbor` (in lowercase, per the lowercase suffix requirement), each as a separate entry with its full filename, and SHALL NOT return payload files nor any other file. Cryptainers sharing a basename in several formats SHALL be listed as distinct cryptainers.

#### Scenario: Mixed storage
- **WHEN** a storage directory holds `a.crypt`, `a.crypt.payload`, `b.crypt.json`, `c.crypt.cbor`, `c.crypt.cbor.payload` and `notes.txt`
- **THEN** listing returns exactly `a.crypt`, `b.crypt.json` and `c.crypt.cbor`

#### Scenario: Same basename in two formats
- **WHEN** a storage directory holds both `a.crypt.json` and `a.crypt.cbor`
- **THEN** listing returns both, and each one can be decrypted or deleted without affecting the other or its payload

### Requirement: Storage format setting
A cryptainer storage SHALL have a format setting, Extended JSON or WA-CBOR, Extended JSON by default, which decides the format and suffix of the cryptainers it writes. The setting SHALL NOT restrict which cryptainers the storage lists or reads.

#### Scenario: CBOR storage reads JSON cryptainers
- **WHEN** a storage set to the CBOR format holds a `b.crypt.json` cryptainer
- **THEN** `b.crypt.json` is listed and can be decrypted

### Requirement: Warning on same basename in another format
When a cryptainer is about to be written as `<basename>.crypt.<format>` while a cryptainer with the same basename exists in another format (`<basename>.crypt`, or the other of `.crypt.json` / `.crypt.cbor`), the system SHALL log a warning naming the existing file, and SHALL proceed without modifying the existing cryptainer or its payload.

#### Scenario: Encrypting next to a legacy cryptainer
- **WHEN** `video.mp4` is encrypted into a storage that already holds `video.mp4.crypt`
- **THEN** a warning naming `video.mp4.crypt` is logged, `video.mp4.crypt.json` is written, and `video.mp4.crypt` and its payload are left untouched
