## Purpose

Extends the lowercase naming policy to the extensions of the file names that sensors build, and defines how keystore pools recognize their foreign keystore directories. Configured sensor names are kept as given, and directory names are compared like the platform compares file names, without letting unexpected names make the listing fail.

## Requirements

### Requirement: Lowercase names for sensor records
Sensors and record aggregators SHALL write lowercase names for the records, tar members, tarfiles and cryptainers they produce, whatever the letter case of the configured sensor names and record extensions. The cryptainer suffixes appended by the cryptainer storage SHALL be unaffected.

#### Scenario: Sensor configured with uppercase names
- **WHEN** a sensor named `FrontCam` records with the extension `.MP4` into a cryptainer storage
- **THEN** its cryptainer names contain `frontcam` and `.mp4`, and no uppercase letter

#### Scenario: Tar member names
- **WHEN** a record aggregator adds a record of the sensor `GPS` with the extension `.JSON` to a tarfile
- **THEN** the tar member is named with `gps` and `.json`, and the cryptainer of the tarfile has a lowercase name

### Requirement: Case-insensitive foreign keystore directories
A filesystem keystore pool SHALL list a foreign keystore for every directory whose name starts with the `keystore_` prefix in any letter case and ends with a UUID in any letter case, with the same result on case-sensitive and case-insensitive filesystems. It SHALL open such a keystore under its actual directory name. Directories whose name has the prefix but doesn't parse as a UUID SHALL be skipped with a warning naming them, instead of making the listing fail. New foreign keystore directories SHALL be named with the lowercase prefix and the canonical lowercase UUID.

#### Scenario: Uppercase foreign keystore directory
- **WHEN** a keystore pool holds a foreign keystore directory named `KEYSTORE_0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0`
- **THEN** listing returns the UUID `0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0`, and the metadata and keys of this keystore can be fetched, on case-sensitive and case-insensitive filesystems

#### Scenario: Foreign keystore directory under both spellings
- **WHEN** a case-sensitive keystore pool holds both `keystore_<uuid>` and `KEYSTORE_<UUID>` for the same UUID
- **THEN** listing returns this UUID once, and the keystore is opened from the lowercase directory

#### Scenario: Import into an existing uppercase foreign keystore
- **WHEN** a keystore tree is imported into a keystore pool already holding its keystore as `KEYSTORE_<UUID>`
- **THEN** the keys are imported into `KEYSTORE_<UUID>`, and no lowercase twin directory is created

#### Scenario: Unparsable foreign keystore directory
- **WHEN** a keystore pool holds a directory named `keystore_backup` next to valid foreign keystores
- **THEN** listing skips it with a warning naming it, and returns the valid ones

#### Scenario: New foreign keystore
- **WHEN** an authenticator keystore tree is imported into a keystore pool
- **THEN** its directory is named `keystore_<uuid>`, with the canonical lowercase UUID

### Requirement: No migration of existing names
Listing and reading SHALL NOT create, rename or delete any file or directory because of the letter case of its name. Records, cryptainers and foreign keystore directories with names in other letter cases, as written by earlier releases or copied by hand, SHALL keep their names.

#### Scenario: Legacy uppercase foreign keystore kept
- **WHEN** a keystore pool holding `KEYSTORE_<UID>` is listed and its keys are fetched
- **THEN** the directory keeps its name
