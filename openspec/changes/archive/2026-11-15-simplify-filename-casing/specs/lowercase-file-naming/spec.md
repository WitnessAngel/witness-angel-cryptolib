## RENAMED Requirements

- FROM: `### Requirement: Lowercase names for sensor records`
- TO: `### Requirement: Lowercase extensions in sensor record names`

## MODIFIED Requirements

### Requirement: Lowercase extensions in sensor record names
Sensors and record aggregators SHALL write lowercase extensions in the names of the records, tar members, tarfiles and cryptainers they produce, whatever the letter case of the configured record extensions. They SHALL keep the configured sensor names as given. The cryptainer suffixes appended by the cryptainer storage SHALL be unaffected.

#### Scenario: Sensor configured with uppercase names
- **WHEN** a sensor named `FrontCam` records with the extension `.MP4` into a cryptainer storage
- **THEN** its cryptainer names contain `FrontCam` and `.mp4`, and not `.MP4`

#### Scenario: Tar member names
- **WHEN** a record aggregator adds a record of the sensor `GPS` with the extension `.JSON` to a tarfile
- **THEN** the tar member is named with `GPS` and `.json`, and the cryptainer of the tarfile has a lowercase name

## ADDED Requirements

### Requirement: Foreign keystore directory names
A filesystem keystore pool SHALL list a foreign keystore for every directory whose name is the `keystore_` prefix followed by a UUID in canonical form (lowercase hexadecimal with dashes). These names SHALL be compared like the platform compares file names: ignoring letter case on Windows, exactly on other platforms. It SHALL open a foreign keystore at its canonical directory name, the filesystem resolving letter case. Directories whose name has the prefix under this comparison, but no canonical UUID under it, SHALL be skipped with a warning naming them, instead of making the listing fail. New foreign keystore directories SHALL be named with the lowercase prefix and the canonical UUID.

#### Scenario: Uppercase foreign keystore directory
- **WHEN** a keystore pool holds a foreign keystore directory named `KEYSTORE_0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0`
- **THEN** on Windows, listing returns the UUID `0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0`, and the metadata and keys of this keystore can be fetched
- **AND** on other platforms, listing doesn't return it, and logs no warning

#### Scenario: Uppercase UUID after a lowercase prefix
- **WHEN** a keystore pool holds a foreign keystore directory named `keystore_0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0`
- **THEN** on Windows, listing returns its UUID, and its keys can be fetched
- **AND** on other platforms, listing skips it with a warning naming it

#### Scenario: Import into an existing uppercase foreign keystore on Windows
- **WHEN** on Windows, a keystore tree is imported into a keystore pool already holding its keystore as `KEYSTORE_<UUID>`
- **THEN** the keys are imported into `KEYSTORE_<UUID>`, and no other directory is created

#### Scenario: Unparsable foreign keystore directory
- **WHEN** a keystore pool holds directories named `keystore_backup` and `keystore_<uuid without dashes>` next to valid foreign keystores
- **THEN** listing skips them with a warning naming each of them, and returns the valid ones

#### Scenario: New foreign keystore
- **WHEN** an authenticator keystore tree is imported into a keystore pool
- **THEN** its directory is named `keystore_<uuid>`, with the canonical lowercase UUID

## REMOVED Requirements

### Requirement: Case-insensitive foreign keystore directories
**Reason**: Replaced by "Foreign keystore directory names". Directory names are now compared like the platform compares file names, and keystores are opened at their canonical path, so the case-insensitive matching on every platform, the "lowercase directory wins" rule and the lookup of actual directory names are dropped.
**Migration**: On Linux and macOS, rename a foreign keystore directory spelled in another letter case to `keystore_<uuid>`, with the canonical lowercase UUID, to make it visible again. Nothing changes on Windows.
