## Purpose

Lets cryptainer payloads be signed and verified with the ML-DSA-65 post-quantum signature scheme, so integrity and non-repudiation of stored recordings survive the arrival of quantum computers.

## ADDED Requirements

### Requirement: ML-DSA-65 keypair lifecycle
The system SHALL accept `ML_DSA_65` as an asymmetric key algorithm for keypair generation, PEM serialization and deserialization (with optional passphrase), keystore storage and trustee public-key retrieval, with the same interfaces as existing signing key algorithms.

#### Scenario: Generate and round-trip a keypair
- **WHEN** a keypair is generated for key algorithm `ML_DSA_65` with serialization enabled
- **THEN** the result contains public and private PEM bytestrings, and loading each back with key algorithm `ML_DSA_65` yields usable key objects

#### Scenario: Passphrase-protected private key
- **WHEN** an `ML_DSA_65` private key is exported with a passphrase and later loaded with a wrong or missing passphrase
- **THEN** loading fails with a key loading error, and loading with the right passphrase succeeds

#### Scenario: Key length parameter is irrelevant
- **WHEN** a keypair is generated for `ML_DSA_65` with any `key_length_bits` or `curve` value supplied
- **THEN** those parameters are ignored and no key-length or curve validation error is raised

#### Scenario: Listed by a filesystem keystore
- **WHEN** an `ML_DSA_65` keypair is stored in a filesystem keystore
- **THEN** listing the keystore's keypair identifiers includes it, with the correct private-key presence flag

### Requirement: Timestamped signature with ML-DSA-65
The system SHALL accept `ML_DSA_65` as a signature algorithm. Signing SHALL produce the same signature structure as existing algorithms (a signature value plus a UTC timestamp), computed over the SHA-512 digest of the message and timestamp, and bound to a fixed application context so that signatures are not valid for other uses of the same key.

#### Scenario: Sign and verify
- **WHEN** a message is signed with `ML_DSA_65` and an ML-DSA-65 private key, and verified with the matching public key, message and timestamp
- **THEN** verification succeeds

#### Scenario: Modified message or timestamp is rejected
- **WHEN** the message, the timestamp or any byte of the signature value is altered (or the signature value is truncated or extended) before verification
- **THEN** verification fails with a signature verification error

#### Scenario: Signature is randomized
- **WHEN** the same message and timestamp are signed twice with the same `ML_DSA_65` private key
- **THEN** both signatures verify, and they are not byte-identical

#### Scenario: Incompatible key type is rejected
- **WHEN** signing or verifying with algorithm `ML_DSA_65` is attempted with an RSA, DSA, ECC or ML-KEM key
- **THEN** the operation fails with a value error, before any signature creation or verification error is raised

### Requirement: ML-DSA-65 as a cryptainer payload signature
Cryptoconfs SHALL accept `ML_DSA_65` as `payload_signature_algo` in `payload_ciphertext_signatures` and `payload_plaintext_signatures`, and cryptainer signature verification during decryption SHALL verify such signatures and report failures like it does for existing algorithms.

#### Scenario: Cryptainer with an ML-DSA-65 signature
- **WHEN** a payload is encrypted with a cryptoconf declaring an `ML_DSA_65` payload signature from a local keyfactory trustee, then decrypted
- **THEN** the payload is recovered and the operation report contains no signature error entry

#### Scenario: Cryptainer with a corrupted ML-DSA-65 signature
- **WHEN** the stored signature value of such a cryptainer is altered before decryption
- **THEN** the operation report records a signature error entry, and the payload is still returned since signature failures never abort decryption
