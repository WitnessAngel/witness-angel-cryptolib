## MODIFIED Requirements

### Requirement: Fixtures use the library's own wire formats
Each fixture asset SHALL be stored exactly in the form wacryptolib reads or writes it: raw bytes for plaintexts, extended-JSON or WA-CBOR files for cipherdicts, signatures, cryptoconfs and cryptainers (with the offloaded payload file next to its cryptainer when the payload is offloaded), PEM files inside keystore directory trees laid out as a filesystem keystore pool. Cryptainer assets SHALL be named with the suffix the library uses for their format and generation: `.crypt` for generations produced before the WA-CBOR change, `.crypt.json` or `.crypt.cbor` afterwards. Assets SHALL NOT be wrapped, re-encoded or normalized for the corpus.

#### Scenario: Cryptainer fixture loads with the standard loader
- **WHEN** a cryptainer fixture is loaded with the library's filesystem cryptainer loader
- **THEN** it loads without any corpus-specific conversion, including its offloaded payload if it has one

#### Scenario: CBOR cryptainer fixture loads with the standard loader
- **WHEN** a `.crypt.cbor` cryptainer fixture with an offloaded payload is loaded with the library's filesystem cryptainer loader
- **THEN** it loads from WA-CBOR without any corpus-specific conversion, with its payload read from its `.crypt.cbor.payload` file

#### Scenario: Keystore pool fixture opens as a pool
- **WHEN** a keystore pool fixture directory (copied elsewhere) is opened as a filesystem keystore pool
- **THEN** its local keyfactory and its imported authenticator keystores are listed with their keypairs

### Requirement: Sidecar metadata files
Every fixture that needs accompanying information or secrets (original plaintext, symmetric keys, dummy passphrases, expected outcomes, provenance) SHALL have a sidecar JSON file. Its name SHALL be the asset's name with `.json` appended, in the same directory (`x.crypt` → `x.crypt.json`, `x.crypt.json` → `x.crypt.json.json`, `x.crypt.cbor` → `x.crypt.cbor.json`, keystore pool directory `pool/` → `pool.json`). A `.json` file SHALL be treated as a sidecar if and only if its name without the final `.json` is an existing asset of the same directory; otherwise it is an asset. Sidecars SHALL be plain JSON readable without extended-JSON support: byte strings encoded as lowercase hex, UUIDs as canonical hyphenated strings, and references to other fixtures as paths relative to the sidecar's directory. Each sidecar SHALL declare its fixture kind and the schema it conforms to. Every sidecar SHALL have its asset, and every cipherdict, signature, keystore pool, cryptoconf and cryptainer asset SHALL have a sidecar.

#### Scenario: Orphan detection
- **WHEN** the corpus contains a sidecar without its asset, or a cryptainer/cryptoconf/cipherdict/signature/keystore pool asset without its sidecar
- **THEN** the compatibility test suite fails and names the offending path

#### Scenario: Secrets are readable by a non-wacryptolib consumer
- **WHEN** a consumer that only has a standard JSON parser reads a cipherdict sidecar
- **THEN** it obtains the plaintext reference and any symmetric key material without needing extended-JSON decoding

#### Scenario: JSON cryptainer asset versus legacy sidecar
- **WHEN** one generation holds `a.crypt` and `a.crypt.json`, and another holds `b.crypt.json` and `b.crypt.json.json`
- **THEN** `a.crypt.json` is treated as the sidecar of `a.crypt`, `b.crypt.json` as a cryptainer asset, and `b.crypt.json.json` as its sidecar

### Requirement: Cryptainer generations stay decryptable
The corpus SHALL contain cryptainers of several generations, at least: produced by wacryptolib releases 0.9, 0.10 and 0.11; using the legacy `payload_signatures` field name; serialized in CANONICAL and in RELAXED extended JSON; serialized in WA-CBOR; named with the legacy `.crypt` suffix and with the `.crypt.json` and `.crypt.cbor` suffixes; with inline and with offloaded payload; with cryptainer metadata; with plaintext signatures; and protected by the post-quantum hybrid stack. Each cryptainer sidecar SHALL reference its keystore pool and its original plaintext (or carry it inline when small), and SHALL list decryption scenarios. A scenario gives a set of trustee passphrases and an expected outcome: success with the expected plaintext, possibly with expected non-fatal warnings, or failure. Cryptainers using a Shamir shared secret SHALL include both a threshold-satisfying scenario and a below-threshold scenario.

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

### Requirement: Corpus is documented for other implementations
The corpus SHALL include a README describing its layout, the naming and sidecar conventions (including how `.json` assets are told apart from sidecars), the meaning of each sidecar field, the bidirectional versus decrypt-only vector semantics, the extended-JSON flavors and the WA-CBOR dialect used by the assets (with a reference to the WA-CBOR specification), the letter case of file and directory names in each generation, and how new generations are added. The corpus SHALL NOT be shipped in the published library package.

#### Scenario: Package contents
- **WHEN** the library's distribution package is built
- **THEN** it contains no file from the compatibility corpus

## ADDED Requirements

### Requirement: Equivalent Extended JSON and WA-CBOR fixtures
The corpus SHALL contain a generation in which cryptoconfs, cryptainers (inline and offloaded), cipherdicts and signatures are each provided both as an Extended JSON asset and as a WA-CBOR asset of the same tree, the sidecar of each declaring its equivalent. The compatibility test suite SHALL check that both assets of a pair load to equal trees, and that converting each asset with the library yields the other asset byte for byte. The corpus SHALL also contain invalid WA-CBOR documents (unsupported tags, non-text keys, duplicate keys, Extended JSON keyword maps, malformed datetimes), whose sidecar expects rejection, and the library SHALL keep rejecting them.

#### Scenario: Pair equivalence
- **WHEN** the compatibility test suite loads the Extended JSON and WA-CBOR assets of a pair
- **THEN** both trees are equal, and converting either asset reproduces the other byte for byte

#### Scenario: Invalid WA-CBOR document rejected
- **WHEN** an invalid WA-CBOR fixture is loaded
- **THEN** loading fails, as its sidecar expects

### Requirement: New generations use lowercase names
Every file and directory created by a generation added from the WA-CBOR generation on SHALL have a lowercase name, including per-algorithm subdirectories (e.g. `aes_cbc/`), cryptainer and sidecar names, and the key files of the keystore pools it creates. Earlier generations SHALL keep their names, including uppercase algo names, since they are frozen. The generation tooling SHALL refuse to write a file or directory with a non-lowercase name in a new generation, and the compatibility test suite SHALL check that the names of these generations are lowercase.

#### Scenario: Uppercase name refused by the tooling
- **WHEN** the generation tooling is asked to write a cipherdict under an `AES_CBC/` subdirectory of a new generation
- **THEN** it fails before writing anything into the corpus

#### Scenario: Frozen uppercase names accepted
- **WHEN** the compatibility test suite runs over generations produced before the WA-CBOR generation, which hold `AES_CBC/` subdirectories and `<uid>_RSA_OAEP_public_key.pem` files
- **THEN** their names are accepted, and their fixtures are checked as before
