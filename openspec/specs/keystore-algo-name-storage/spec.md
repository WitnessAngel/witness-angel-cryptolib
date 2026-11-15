## Purpose

Defines the naming of key files in filesystem keystores: new files use the lowercase algo name, existing files with legacy uppercase algo names are still loaded, conflicting spellings make operations fail, and the API and listings always expose uppercase algo names. Existing keys must never be silently shadowed by newly generated ones, on any platform.

## Requirements

### Requirement: Lowercase algo names on write
A filesystem keystore SHALL name the key files and the free keypair directories it writes with the lowercase form of the algo name, whatever the letter case used by the caller.

#### Scenario: New keypair naming
- **WHEN** a keypair is generated for the algo `RSA_OAEP`
- **THEN** its files are named with `rsa_oaep`

#### Scenario: New free keypair naming
- **WHEN** free keypairs are generated for the algo `RSA_OAEP`
- **THEN** they are stored in a `rsa_oaep` subdirectory of the free keys directory

### Requirement: Legacy uppercase algo files remain usable
A filesystem keystore SHALL find keypairs and free keypairs stored under the legacy uppercase algo name, as written by earlier releases, on case-sensitive and case-insensitive filesystems alike. The public and private key files of a keypair SHALL be looked up and written with a single spelling: the one of its existing files, else the lowercase one. Reading the public key, reading the private key, checking existence, decrypting and signing SHALL use them, and no new keypair SHALL be generated for a key that already exists under either spelling. Lookups SHALL NOT create, rename or delete any file.

#### Scenario: Fetch an existing key with a legacy uppercase algo name
- **WHEN** a keystore directory contains a keypair stored as `<uid>_RSA_OAEP_*_key.pem` and the public key is fetched for `RSA_OAEP` with `must_exist` unset
- **THEN** the existing public key is returned and no new keypair is generated

#### Scenario: Sign with an existing signature key
- **WHEN** a keystore directory contains a signature keypair stored under an uppercase algo name and a message signature is requested for the same keychain uid
- **THEN** the signature is made with the existing private key and no new keypair is created

#### Scenario: Decrypt with an existing private key
- **WHEN** a cryptainer encrypted for a keypair stored under an uppercase algo name is decrypted through a trustee over that keystore
- **THEN** decryption succeeds with the existing private key

#### Scenario: Read-only keystore
- **WHEN** a read-only keystore (e.g. an imported authenticator) contains keypairs with legacy uppercase algo names
- **THEN** they are found and used, and no file is created, renamed or deleted

#### Scenario: Key already existing under the other spelling
- **WHEN** a key is set for a keychain uid and algo that already exist under the uppercase spelling
- **THEN** the keystore reports that the key already exists, and no lowercase-named twin is created

#### Scenario: Private key added to a legacy public key
- **WHEN** a private key is set for a keypair whose public key file has a legacy uppercase algo name
- **THEN** the private key file is written with the same uppercase algo name, and the keypair is then fully readable

### Requirement: Free keypairs under either spelling
Free keypairs stored in an uppercase algo subdirectory SHALL be counted and attached to a keychain uid like those in the lowercase one, so that existing pools are neither ignored nor regenerated. An attached keypair SHALL end up under the lowercase file names.

#### Scenario: Attach an existing free keypair
- **WHEN** a keystore holds free keypairs only in an uppercase algo subdirectory and a keypair is requested for a new keychain uid
- **THEN** one of these free keypairs is attached to the uid under lowercase file names, and no new keypair is generated

#### Scenario: Free keypairs count
- **WHEN** free keypairs exist in both the lowercase and the uppercase subdirectory of an algo
- **THEN** the reported free keypairs count is their total

### Requirement: Conflicting spellings fail outright
When distinct key files of a same keypair (keychain uid and algo) exist under both the lowercase and the uppercase algo name, whatever their key kinds, reading, checking, listing or setting keys of this keypair SHALL raise a `KeyFilenameConflict` error naming the keys directory and the conflicting files, and SHALL NOT create, modify or delete any file. This error SHALL NOT be a missing key error, so that no keypair is generated over the conflicting ones. On a case-insensitive filesystem, where both names designate the same file, there SHALL be no conflict.

#### Scenario: Both spellings of a key file exist
- **WHEN** a case-sensitive keystore holds `<uid>_rsa_oaep_public_key.pem` and `<uid>_RSA_OAEP_public_key.pem`, and the public key is fetched
- **THEN** a `KeyFilenameConflict` naming the keys directory and both files is raised

#### Scenario: Halves of a keypair under different spellings
- **WHEN** a case-sensitive keystore holds `<uid>_rsa_oaep_public_key.pem` and `<uid>_RSA_OAEP_private_key.pem`, and the private key is fetched
- **THEN** a `KeyFilenameConflict` is raised

#### Scenario: Autogenerating trustee over a conflict
- **WHEN** a trustee fetches, without `must_exist`, the public key of a keypair whose files conflict
- **THEN** the `KeyFilenameConflict` is propagated and no keypair is generated

#### Scenario: Same file under both names
- **WHEN** a keystore lives on a case-insensitive filesystem, where `<uid>_rsa_oaep_public_key.pem` and `<uid>_RSA_OAEP_public_key.pem` designate the same file
- **THEN** the key is read normally, with no error

### Requirement: Listing reports uppercase algo names
Listing keypair identifiers SHALL report each algo name in uppercase, whatever the spelling of its file names, so that every listed identifier can be fetched through the keystore getters, and SHALL report the private key presence as found by the getters, even for files named with a non-canonical form of the keychain uid. A keypair present under both spellings SHALL be listed once. Files whose algo name is neither all lowercase nor all uppercase SHALL be skipped with a warning, since the getters can't fetch them.

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
- **THEN** this file is skipped with a warning naming it
