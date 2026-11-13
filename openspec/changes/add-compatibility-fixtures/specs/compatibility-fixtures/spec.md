## Purpose

Defines the committed corpus of frozen fixtures under `compatibility/` (plaintexts, cipherdicts, signatures, keystore pools, cryptoconfs and cryptainers of several generations) and its metadata sidecars and schemas. It also defines the guarantee that the current library keeps validating, verifying and decrypting all of them, so that format regressions are detected and other implementations have a shared reference.

## ADDED Requirements

### Requirement: Fixtures use the library's own wire formats
Each fixture asset SHALL be stored exactly in the form wacryptolib reads or writes it: raw bytes for plaintexts, extended-JSON files for cipherdicts, signatures, cryptoconfs and cryptainers (with the offloaded payload file next to its cryptainer when the payload is offloaded), PEM files inside keystore directory trees laid out as a filesystem keystore pool. Assets SHALL NOT be wrapped, re-encoded or normalized for the corpus.

#### Scenario: Cryptainer fixture loads with the standard loader
- **WHEN** a cryptainer fixture is loaded with the library's filesystem cryptainer loader
- **THEN** it loads without any corpus-specific conversion, including its offloaded payload if it has one

#### Scenario: Keystore pool fixture opens as a pool
- **WHEN** a keystore pool fixture directory (copied elsewhere) is opened as a filesystem keystore pool
- **THEN** its local keyfactory and its imported authenticator keystores are listed with their keypairs

### Requirement: Sidecar metadata files
Every fixture that needs accompanying information or secrets (original plaintext, symmetric keys, dummy passphrases, expected outcomes, provenance) SHALL have a sidecar JSON file. Its name SHALL be the asset's name with `.json` appended, in the same directory (`x.crypt` → `x.crypt.json`, keystore pool directory `pool/` → `pool.json`). Sidecars SHALL be plain JSON readable without extended-JSON support: byte strings encoded as lowercase hex, UUIDs as canonical hyphenated strings, and references to other fixtures as paths relative to the sidecar's directory. Each sidecar SHALL declare its fixture kind and the schema it conforms to. Every sidecar SHALL have its asset, and every cipherdict, signature, keystore pool, cryptoconf and cryptainer asset SHALL have a sidecar.

#### Scenario: Orphan detection
- **WHEN** the corpus contains a sidecar without its asset, or a cryptainer/cryptoconf/cipherdict/signature/keystore pool asset without its sidecar
- **THEN** the compatibility test suite fails and names the offending path

#### Scenario: Secrets are readable by a non-wacryptolib consumer
- **WHEN** a consumer that only has a standard JSON parser reads a cipherdict sidecar
- **THEN** it obtains the plaintext reference and any symmetric key material without needing extended-JSON decoding

### Requirement: Sidecars are validated by committed JSON-Schemas
The corpus SHALL include JSON-Schemas, one per sidecar kind plus shared definitions, in a `schemas` directory at the corpus root. Every sidecar SHALL validate against the schema of its declared kind.

#### Scenario: Valid corpus
- **WHEN** the compatibility test suite runs
- **THEN** every sidecar is validated against its kind's schema, and the suite fails on the first sidecar that does not conform

#### Scenario: Unknown kind
- **WHEN** a sidecar declares a fixture kind for which no schema exists
- **THEN** the compatibility test suite fails

### Requirement: Fixtures are frozen and append-only
Committed fixture files SHALL never be regenerated, rewritten or deleted to accommodate a library change. New fixtures SHALL only be added, grouped by generation. The generation tooling SHALL refuse to write into a generation directory that already exists. Running the test suite SHALL NOT create, modify or delete any file in the corpus. Each sidecar SHALL record a SHA-256 digest of its asset file(s), and the corpus SHALL be committed byte-exact, with no line-ending or text normalization.

#### Scenario: Generation tooling does not overwrite
- **WHEN** the generation tooling is asked to produce a generation whose directory already exists
- **THEN** it aborts without modifying any file

#### Scenario: Accidental modification is detected
- **WHEN** an asset file differs from the SHA-256 digest recorded in its sidecar (e.g. after a line-ending conversion or a reformatting)
- **THEN** the compatibility test suite fails for that fixture

#### Scenario: Tests leave the corpus untouched
- **WHEN** the compatibility test suite runs, including decryptions that use keystore pools
- **THEN** keystore pools are used from temporary copies, and the corpus contents are identical before and after the run

### Requirement: Plaintext coverage
The corpus SHALL provide plaintexts whose sizes cover: empty, 1 byte, around the AES block size (15, 16, 17, 31, 32, 33 bytes), around the RSA-OAEP chunk size (59, 60, 61 bytes), around 256 bytes (255, 256, 257), and multi-chunk sizes of about 4 KiB, 64 KiB and 1 MiB, the larger ones being non-multiples of the block and chunk sizes. Plaintext contents SHALL be reproducible from a generator described in their sidecar, which SHALL record their size and SHA-256 digest.

#### Scenario: Plaintext integrity
- **WHEN** a plaintext fixture is read
- **THEN** its size and SHA-256 digest match its sidecar

### Requirement: Cipherdict vectors for every cipher algorithm
For every cipher algorithm supported by the library, the corpus SHALL contain cipherdict vectors over several plaintext sizes. Symmetric vectors SHALL be bidirectional: their sidecar provides the complete symmetric key dict, encrypting the referenced plaintext with it SHALL reproduce the cipherdict exactly, and decrypting the cipherdict SHALL yield the plaintext. Asymmetric vectors (RSA_OAEP, ECIES_X25519, ML_KEM_768) SHALL be decrypt-only: their sidecar references the private key in a keystore pool fixture, and decrypting SHALL yield the plaintext. The corpus SHALL include at least one RSA_OAEP vector in the legacy `digest_list` form. Asymmetric vectors SHALL be limited to a few KiB of plaintext, while symmetric vectors SHALL include the 1 MiB plaintext.

#### Scenario: Symmetric vector reproduces its ciphertext
- **WHEN** the referenced plaintext is encrypted with the sidecar's symmetric key dict and the vector's cipher algorithm
- **THEN** the resulting cipherdict equals the committed one, byte for byte

#### Scenario: Asymmetric vector decrypts
- **WHEN** an asymmetric cipherdict is decrypted with the referenced private key, unlocked with the sidecar's passphrase if any
- **THEN** the result equals the referenced plaintext

#### Scenario: Legacy RSA-OAEP naming
- **WHEN** the RSA_OAEP vector using the `digest_list` field is decrypted
- **THEN** the result equals the referenced plaintext

### Requirement: Signature vectors for every signature algorithm
For every signature algorithm supported by the library, the corpus SHALL contain verify-only signature vectors whose sidecar references the signed message and the public key in a keystore pool fixture. The corpus SHALL also include at least one tampered-message vector that is expected to fail verification.

#### Scenario: Signature verifies
- **WHEN** a signature vector is verified against its message and public key
- **THEN** verification succeeds if the sidecar expects validity, and fails otherwise

### Requirement: Keystore pool generations
The corpus SHALL contain keystore pool fixtures of several generations: at least one with RSA-only keypairs in v0.9-era authenticators, and one with ECIES_X25519, ML_KEM_768 and ML_DSA_65 keypairs. Each pool SHALL contain a local keyfactory and one or more imported authenticator keystores. Authenticator private keys SHALL be passphrase-protected, and the pool's sidecar SHALL provide each authenticator's keystore UID, owner and dummy passphrase, as well as the keychain UIDs and key algorithms present.

#### Scenario: Authenticator private key unlocks with documented passphrase
- **WHEN** an authenticator private key of a pool fixture is loaded with the passphrase from the pool sidecar
- **THEN** loading succeeds, and loading it with a different passphrase fails

#### Scenario: Keystore metadata is valid
- **WHEN** the keystore metadata of each authenticator of a pool fixture is loaded
- **THEN** it passes the library's keystore metadata validation

### Requirement: Only local and authenticator trustees
Fixtures SHALL only use local-keyfactory and authenticator trustees. No fixture SHALL require a network or JSON-RPC trustee.

#### Scenario: No remote trustee in the corpus
- **WHEN** the trustees of all cryptoconf and cryptainer fixtures are enumerated
- **THEN** each one is either the local keyfactory or an authenticator

### Requirement: Cryptoconf fixtures stay valid
The corpus SHALL contain cryptoconfs of increasing sophistication: a single symmetric layer, several payload cipher layers, symmetric and asymmetric key cipher layers nested recursively, a Shamir shared secret over several authenticators with a threshold, plaintext and ciphertext signatures, and a hybrid RSA_OAEP + ML_KEM_768 stack. Each valid cryptoconf SHALL pass the library's cryptoconf validation, and SHALL encrypt and decrypt a payload round-trip using a keystore pool fixture referenced by its sidecar. The corpus SHALL also contain invalid cryptoconfs whose sidecar expects rejection, and the library SHALL keep rejecting them.

#### Scenario: Valid cryptoconf round-trip
- **WHEN** a payload is encrypted with a valid cryptoconf fixture and then decrypted, using a temporary copy of its keystore pool and its sidecar's passphrases
- **THEN** validation passes, and the decrypted payload equals the original

#### Scenario: Invalid cryptoconf rejected
- **WHEN** an invalid cryptoconf fixture is validated
- **THEN** a schema validation error is raised

### Requirement: Cryptainer generations stay decryptable
The corpus SHALL contain cryptainers of several generations, at least: produced by wacryptolib releases 0.9, 0.10 and 0.11; using the legacy `payload_signatures` field name; serialized in CANONICAL and in RELAXED extended JSON; with inline and with offloaded payload; with cryptainer metadata; with plaintext signatures; and protected by the post-quantum hybrid stack. Each cryptainer sidecar SHALL reference its keystore pool and its original plaintext (or carry it inline when small), and SHALL list decryption scenarios. A scenario gives a set of trustee passphrases and an expected outcome: success with the expected plaintext, possibly with expected non-fatal warnings, or failure. Cryptainers using a Shamir shared secret SHALL include both a threshold-satisfying scenario and a below-threshold scenario.

#### Scenario: Cryptainer passes validation
- **WHEN** a cryptainer fixture is loaded and validated
- **THEN** it passes the library's cryptainer validation

#### Scenario: Successful decryption scenario
- **WHEN** a cryptainer is decrypted with the passphrases of a scenario expecting success
- **THEN** the decrypted payload equals the original plaintext, and the decryption report contains exactly the expected warnings and no error

#### Scenario: Below-threshold scenario
- **WHEN** a shared-secret cryptainer is decrypted with fewer authenticator passphrases than its threshold
- **THEN** no payload is returned, and the decryption report contains errors

#### Scenario: Cryptainer metadata preserved
- **WHEN** a cryptainer fixture declares cryptainer metadata in its sidecar
- **THEN** the metadata extracted from the cryptainer equals the declared metadata

### Requirement: Provenance is recorded
Each sidecar SHALL record the fixture's generation and provenance: whether it was produced genuinely by a given wacryptolib release or commit, or synthesized by down-converting a current output to a legacy form, with the producing library version, Python version, crypto backend and production date.

#### Scenario: Synthesized fixture is labelled
- **WHEN** a fixture was obtained by down-converting a current output to a legacy form
- **THEN** its sidecar provenance states it is synthesized and names the legacy form produced

### Requirement: Backend requirements are declared, not hardcoded
Each sidecar SHALL declare the algorithms and private-key protections its fixture requires. The compatibility test suite SHALL exercise every fixture on the active crypto backend, and SHALL be part of the test runs made under each backend (native and pure-Python fallback). It SHALL skip a fixture only when the active backend lacks one of the declared requirements, and SHALL fail otherwise.

#### Scenario: Post-quantum fixture on the fallback backend
- **WHEN** a fixture declaring ML_KEM_768 is run on the pure-Python fallback backend, which lacks ML-KEM
- **THEN** that fixture is skipped on this backend, with the missing requirement as reason

#### Scenario: Classical fixture on the fallback backend
- **WHEN** a fixture declaring only algorithms supported by the fallback backend is run on it
- **THEN** it is fully exercised, and any failure fails the suite

### Requirement: Corpus coverage follows supported algorithms
The compatibility test suite SHALL check that every cipher algorithm and every signature algorithm supported by the library appears in at least one vector of the corpus, and that every asymmetric key algorithm appears in at least one keystore pool fixture.

#### Scenario: New algorithm without fixtures
- **WHEN** a new cipher, signature or key algorithm is added to the library without adding corresponding fixtures
- **THEN** the compatibility test suite fails, naming the uncovered algorithm

### Requirement: Corpus is documented for other implementations
The corpus SHALL include a README describing its layout, the naming and sidecar conventions, the meaning of each sidecar field, the bidirectional versus decrypt-only vector semantics, the extended-JSON flavors used by the assets, and how new generations are added. The corpus SHALL NOT be shipped in the published library package.

#### Scenario: Package contents
- **WHEN** the library's distribution package is built
- **THEN** it contains no file from the compatibility corpus
