## Purpose

Lets cryptainers wrap their symmetric keys with the ML-KEM-768 post-quantum key encapsulation mechanism, alone or stacked with classical layers, so stored recordings stay confidential against future quantum attackers.

## ADDED Requirements

### Requirement: ML-KEM-768 keypair lifecycle
The system SHALL accept `ML_KEM_768` as an asymmetric key algorithm for keypair generation, PEM serialization, PEM deserialization (with optional passphrase protection of the private key), keystore storage and trustee public-key retrieval, with the same interfaces as existing asymmetric key algorithms.

#### Scenario: Generate and round-trip a keypair
- **WHEN** a keypair is generated for key algorithm `ML_KEM_768` with serialization enabled
- **THEN** the result contains a public key and a private key as PEM bytestrings, and loading each PEM back with key algorithm `ML_KEM_768` yields usable key objects

#### Scenario: Passphrase-protected private key
- **WHEN** an `ML_KEM_768` private key is exported with a passphrase and later loaded with a wrong or missing passphrase
- **THEN** loading fails with a key loading error, as for other asymmetric key algorithms, and loading with the right passphrase succeeds

#### Scenario: Key length parameter is irrelevant
- **WHEN** a keypair is generated for `ML_KEM_768` with any `key_length_bits` or `curve` value supplied
- **THEN** those parameters are ignored and no key-length or curve validation error is raised

#### Scenario: Wrong key family is rejected at load time
- **WHEN** an ML-DSA PEM is loaded with key algorithm `ML_KEM_768`
- **THEN** loading fails with a key loading error

#### Scenario: Listed by a filesystem keystore
- **WHEN** an `ML_KEM_768` keypair is stored in a filesystem keystore
- **THEN** listing the keystore's keypair identifiers includes it, with the correct private-key presence flag

### Requirement: Wrapping a bytestring with ML-KEM-768
The system SHALL accept `ML_KEM_768` as an asymmetric cipher algorithm for encrypting a bytestring with a public key and decrypting it with the matching private key. The ciphertext structure SHALL contain the KEM encapsulation (`kem_ciphertext`) and an authenticated encryption of the plaintext derived from the encapsulated secret (`ciphertext`), so that the cipher counts as authenticated.

#### Scenario: Round-trip of a symmetric key struct
- **WHEN** a bytestring of arbitrary length (including empty, and larger than 60 bytes) is encrypted with an `ML_KEM_768` public key and decrypted with the matching private key
- **THEN** the original bytestring is recovered

#### Scenario: Tampered ciphertext is rejected
- **WHEN** any byte of the encapsulation or of the wrapped payload is modified before decryption
- **THEN** decryption fails with a decryption error and no plaintext is returned

#### Scenario: Wrong private key is rejected
- **WHEN** the ciphertext is decrypted with an `ML_KEM_768` private key that does not match the public key used for encryption
- **THEN** decryption fails with a decryption error

#### Scenario: Incompatible key type is rejected
- **WHEN** encryption (resp. decryption) with algorithm `ML_KEM_768` is attempted with an RSA, DSA, ECC or ML-DSA key
- **THEN** the operation fails with an encryption error (resp. a decryption error)

### Requirement: ML-KEM-768 as a cryptainer key cipher layer
Cryptoconfs SHALL accept `ML_KEM_768` as `key_cipher_algo` in `key_cipher_layers`, with a trustee and keychain uid like other asymmetric layers. Encryption, decryption, trustee-side key-struct decryption (local and remote), trustee dependency gathering and cryptoconf/cryptainer validation SHALL treat it as a regular asymmetric layer.

#### Scenario: Cryptainer round-trip with a single ML-KEM layer
- **WHEN** a payload is encrypted with a cryptoconf whose only key cipher layer is `ML_KEM_768` with a local keyfactory trustee
- **THEN** the cryptoconf and the cryptainer validate, and decryption with the trustee's private key recovers the payload with no error entry in the operation report

#### Scenario: Hybrid classical plus post-quantum wrapping
- **WHEN** a payload is encrypted with a cryptoconf whose key cipher layers are `RSA_OAEP` followed by `ML_KEM_768`
- **THEN** decryption succeeds only when both private keys are available, and otherwise returns no payload and records an asymmetric decryption error entry in the operation report

#### Scenario: ML-KEM inside a shared-secret shard
- **WHEN** a shared-secret layer has a shard whose key cipher layer is `ML_KEM_768`
- **THEN** that shard is wrapped and unwrapped like an `RSA_OAEP` shard
