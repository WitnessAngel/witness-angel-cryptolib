## MODIFIED Requirements

### Requirement: Listing reports uppercase algo names
Listing keypair identifiers SHALL report each algo name in uppercase, whatever the spelling of its file names, so that every listed identifier can be fetched through the keystore getters. It SHALL report the private key presence from the names of the files, a private key file of either spelling counting as present. A keypair present under both spellings SHALL be listed once.

Key file names SHALL be compared like the platform compares file names: ignoring letter case on Windows, exactly on other platforms. Files which the getters can't fetch under this comparison SHALL be skipped with a warning naming them:
- those whose algo name is neither all lowercase nor all uppercase;
- those whose keychain uid isn't in canonical form (lowercase hexadecimal with dashes, as written by keystores).

#### Scenario: List mixed keystores
- **WHEN** a keystore holds one keypair in files with legacy uppercase algo names and another in lowercase-named files, and its identifiers are listed
- **THEN** both identifiers report uppercase algo names, with the correct private key presence flags, and fetching their keys succeeds

#### Scenario: Check an authenticator
- **WHEN** an authenticator keystore with keypairs having legacy uppercase algo names is checked
- **THEN** the check succeeds instead of raising a missing key error

#### Scenario: Export a keystore tree
- **WHEN** a keystore with files of either spelling is exported to a keystore tree
- **THEN** the export succeeds, the tree reports uppercase algo names that pass tree validation, and importing it into a fresh keystore yields lowercase-named files

#### Scenario: Mixed-case algo name
- **WHEN** a keystore holds a public key file named `<uid>_Rsa_Oaep_public_key.pem` and its identifiers are listed
- **THEN** on Windows, the keypair is listed with the algo name `RSA_OAEP`, and its public key can be fetched
- **AND** on other platforms, this file is skipped with a warning naming it

#### Scenario: Uppercase keychain uid
- **WHEN** a keystore holds key files whose keychain uid is spelled in uppercase hexadecimal with dashes, and its identifiers are listed
- **THEN** on Windows, the keypair is listed with the canonical keychain uid, and its keys can be fetched
- **AND** on other platforms, these files are skipped with a warning naming them

#### Scenario: Non-canonical keychain uid
- **WHEN** a keystore holds key files whose keychain uid is spelled without dashes, and its identifiers are listed
- **THEN** these files are skipped with a warning naming them, on every platform
