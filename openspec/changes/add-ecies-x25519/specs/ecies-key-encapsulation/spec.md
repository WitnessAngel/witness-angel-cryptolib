## Purpose

Lets cryptainers wrap their symmetric keys with an elliptic-curve integrated encryption scheme (HPKE over X25519). This gives a compact, fast and standardized alternative to RSA-OAEP on desktop, mobile and the MicroPython flightbox.

## ADDED Requirements

### Requirement: X25519 keypair lifecycle
The system SHALL accept `ECIES_X25519` as an asymmetric key algorithm for keypair generation, PEM serialization (SubjectPublicKeyInfo / PKCS#8), PEM deserialization (with optional passphrase protection of the private key), keystore storage and trustee public-key retrieval. It SHALL use the same interfaces as existing asymmetric key algorithms.

#### Scenario: Generate and round-trip a keypair
- **WHEN** a keypair is generated for key algorithm `ECIES_X25519` with serialization enabled
- **THEN** the result contains a public key and a private key as PEM bytestrings, and loading each PEM back with key algorithm `ECIES_X25519` yields usable key objects

#### Scenario: Passphrase-protected private key
- **WHEN** an `ECIES_X25519` private key is exported with a passphrase and later loaded with a wrong or missing passphrase
- **THEN** loading fails with a key loading error, and loading with the right passphrase succeeds

#### Scenario: Key length and curve parameters are irrelevant
- **WHEN** a keypair is generated for `ECIES_X25519` with any `key_length_bits` or `curve` value supplied
- **THEN** those parameters are ignored and the key is always an X25519 key

#### Scenario: Listed by a filesystem keystore
- **WHEN** an `ECIES_X25519` keypair is stored in a filesystem keystore
- **THEN** listing the keystore's keypair identifiers includes it, with the correct private-key presence flag

### Requirement: Wrapping a bytestring with ECIES_X25519
The system SHALL accept `ECIES_X25519` as an asymmetric cipher algorithm for encrypting a bytestring with a public key and decrypting it with the matching private key. The ciphertext structure SHALL contain the 32-byte ephemeral public key (`kem_ciphertext`) and the authenticated encryption of the plaintext (`ciphertext`, which is the plaintext length plus a 16-byte tag). The cipher SHALL count as authenticated. The output SHALL be byte-compatible with RFC 9180 HPKE Base mode, suite DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305, with empty info and empty associated data.

#### Scenario: Round-trip of a key struct
- **WHEN** a bytestring of arbitrary length (including empty, and larger than 60 bytes) is encrypted with an `ECIES_X25519` public key and decrypted with the matching private key
- **THEN** the original bytestring is recovered

#### Scenario: Encryption is randomized
- **WHEN** the same bytestring is encrypted twice with the same public key
- **THEN** both `kem_ciphertext` and `ciphertext` differ between the two results

#### Scenario: Tampered ciphertext is rejected
- **WHEN** any byte of `kem_ciphertext` or of `ciphertext` is modified before decryption
- **THEN** decryption fails with a decryption error and no plaintext is returned

#### Scenario: Wrong private key is rejected
- **WHEN** the ciphertext is decrypted with an `ECIES_X25519` private key that does not match the public key used for encryption
- **THEN** decryption fails with a decryption error

#### Scenario: Incompatible key type is rejected
- **WHEN** encryption (resp. decryption) with algorithm `ECIES_X25519` is attempted with an RSA, DSA, or non-X25519 ECC key
- **THEN** the operation fails with an encryption error (resp. a decryption error)

#### Scenario: Interoperability with the RFC 9180 test vector
- **WHEN** the encryption is run with the receiver public key, ephemeral private key and plaintext of RFC 9180 Appendix A.2.1 (base mode, sequence number 0), with empty info and AAD
- **THEN** the resulting `kem_ciphertext` and shared key schedule match the RFC's `enc`, `key` and `base_nonce` values

### Requirement: ECIES_X25519 as a cryptainer key cipher layer
Cryptoconfs SHALL accept `ECIES_X25519` as `key_cipher_algo` in `key_cipher_layers`, with a trustee and keychain uid like other asymmetric layers. Encryption, decryption, trustee-side key-struct decryption (local and remote), trustee dependency gathering and cryptoconf/cryptainer validation SHALL treat it as a regular asymmetric layer.

#### Scenario: Cryptainer round-trip with an ECIES layer
- **WHEN** a payload is encrypted with a cryptoconf whose key cipher layer is `ECIES_X25519` with a local keyfactory trustee
- **THEN** the cryptoconf and the cryptainer validate, and decryption with the trustee's private key recovers the payload with no error entry in the operation report

#### Scenario: ECIES inside a shared-secret shard
- **WHEN** a shared-secret layer has a shard whose key cipher layer is `ECIES_X25519`
- **THEN** that shard is wrapped and unwrapped like an `RSA_OAEP` shard

### Requirement: ECIES_X25519 encryption on the MicroPython flightbox
The flightbox SHALL accept `ECIES_X25519` as an asymmetric key cipher algorithm when building cryptainers, using only the trustee's raw 32-byte X25519 public key. A cryptainer produced this way SHALL be decryptable by the desktop library with the matching private key.

#### Scenario: Flightbox cryptainer decrypted on desktop
- **WHEN** the flightbox encrypts a payload with a cryptoconf using an `ECIES_X25519` key cipher layer
- **THEN** the desktop library decrypts the resulting cryptainer with the trustee's private key and recovers the payload

#### Scenario: Low-order public key is rejected
- **WHEN** the flightbox is given an X25519 public key yielding an all-zero shared secret
- **THEN** encryption fails with an error instead of producing a cryptainer
