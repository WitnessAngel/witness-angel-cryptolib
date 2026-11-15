## Purpose

Defines the naming of key files in filesystem keystores: new files use the lowercase algo name, existing files with legacy uppercase algo names are still loaded, conflicting spellings make operations fail, and the API and listings always expose uppercase algo names. Existing keys must never be silently shadowed by newly generated ones, on any platform.

## ADDED Requirements

### Requirement: Lowercase algo names on write
A filesystem keystore SHALL name the key files and the free keypair directories it writes with the lowercase form of the algo name, whatever the letter case used by the caller.

#### Scenario: New keypair naming
- **WHEN** a keypair is generated for the algo `RSA_OAEP`
- **THEN** its files are named with `rsa_oaep`

#### Scenario: New free keypair naming
- **WHEN** free keypairs are generated for the algo `RSA_OAEP`
- **THEN** they are stored in a `rsa_oaep` subdirectory of the free keys directory

### Requirement: Algo names usable in file names
A filesystem keystore SHALL only use algo names made of 1 to 64 ASCII letters, digits and underscores in file and directory names. Looking up keys or free keypairs of another algo name SHALL report them as missing, without accessing the filesystem, and writing them SHALL raise a `ValidationError` without creating any file or directory. An algo name without letters SHALL have a single spelling on disk.

#### Scenario: Algo name with forbidden characters
- **WHEN** a keypair is set for the algo name `../RSA_OAEP`, or its public key is fetched
- **THEN** setting it raises a `ValidationError`, fetching it raises a missing key error, and no file is created

#### Scenario: Algo name without letters
- **WHEN** a keystore holds a public key file named `<uid>_123_public_key.pem`
- **THEN** listing reports it with the algo name `123`, and its key can be fetched

### Requirement: Legacy uppercase algo files remain usable
A filesystem keystore SHALL find keypairs and free keypairs stored under the legacy uppercase algo name, as written by earlier releases, on case-sensitive and case-insensitive filesystems alike. The public and private key files of a keypair SHALL be looked up and written with a single spelling: the one under which its existing files are actually named on disk (also on case-insensitive filesystems, where both spellings open the same files), else the lowercase one. Reading the public key, reading the private key, checking existence, decrypting and signing SHALL use them, and no new keypair SHALL be generated for a key that already exists under either spelling. Lookups SHALL NOT create, rename or delete any file.

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

#### Scenario: Private key added to a legacy public key on a case-insensitive filesystem
- **WHEN** on a case-insensitive filesystem, a private key is set, directly or by importing a keystore tree, for a keypair whose public key file is named `<uid>_RSA_OAEP_public_key.pem`
- **THEN** the private key file is named `<uid>_RSA_OAEP_private_key.pem`, so that the keypair stays readable once copied to a case-sensitive filesystem

### Requirement: Free keypairs under either spelling
Free keypairs stored in an uppercase algo subdirectory SHALL be counted and attached to a keychain uid like those in the lowercase one, so that existing pools are neither ignored nor regenerated. An attached keypair SHALL end up under the lowercase file names.

#### Scenario: Attach an existing free keypair
- **WHEN** a keystore holds free keypairs only in an uppercase algo subdirectory and a keypair is requested for a new keychain uid
- **THEN** one of these free keypairs is attached to the uid under lowercase file names, and no new keypair is generated

#### Scenario: Free keypairs count
- **WHEN** free keypairs exist in both the lowercase and the uppercase subdirectory of an algo
- **THEN** the reported free keypairs count is their total

### Requirement: Conflicting spellings fail outright
When distinct key files of a same keypair (keychain uid and algo) exist under both the lowercase and the uppercase algo name, whatever their key kinds, reading, checking or setting keys of this keypair SHALL raise a `KeyFilenameConflict` error naming the keys directory and the conflicting files, and SHALL NOT create, modify or delete any file. This error SHALL NOT be a missing key error, so that no keypair is generated over the conflicting ones. On a case-insensitive filesystem, where both names designate the same file, there SHALL be no conflict.

So that a single broken keypair doesn't make a whole keystore unusable, listing SHALL still report such a keypair once, with a warning naming the conflicting files (exporting or checking the keystore then fails when its keys are fetched). Decryption authorization requests SHALL report it like a missing private key, and decryption SHALL only give up the cryptainer branches that need it.

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

#### Scenario: Listing a conflicting keypair
- **WHEN** a case-sensitive keystore holds `<uid>_rsa_oaep_public_key.pem` and `<uid>_RSA_OAEP_private_key.pem`, and its identifiers are listed
- **THEN** the keypair is listed once, with its private key present, and a warning names both files

#### Scenario: Decryption authorization over a conflict
- **WHEN** a trustee is asked for decryption authorization on several keypairs, one of which has conflicting files
- **THEN** this keypair is reported among the missing private keys, and the other keypairs are processed normally

#### Scenario: Decryption over a conflict
- **WHEN** a cryptainer is decrypted with a keystore where the keypair of one of its branches has conflicting files
- **THEN** the error is reported in the decryption report instead of being raised, and only the branches needing this keypair are lost

### Requirement: Listing reports uppercase algo names
Listing keypair identifiers SHALL report each algo name in uppercase, whatever the spelling of its file names, so that every listed identifier can be fetched through the keystore getters unless its files conflict, and SHALL report the private key presence from the names of the files. A keypair present under both spellings SHALL be listed once. Files which the getters can't fetch SHALL be skipped with a warning: those whose algo name is neither all lowercase nor all uppercase, and those whose keychain uid isn't in canonical form (lowercase hexadecimal with dashes, as written by keystores).

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

#### Scenario: Non-canonical keychain uid
- **WHEN** a keystore holds key files whose keychain uid is spelled without dashes, and its identifiers are listed
- **THEN** these files are skipped with a warning naming them
