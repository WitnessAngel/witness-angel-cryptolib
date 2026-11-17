## MODIFIED Requirements

### Requirement: Cryptainer generations stay decryptable
The corpus SHALL contain cryptainers of several generations, at least: produced by wacryptolib releases 0.9, 0.10 and 0.11; using the legacy `payload_signatures` field name; serialized in CANONICAL and in RELAXED extended JSON; serialized in WA-CBOR; named with the legacy `.crypt` suffix and with the `.crypt.json` and `.crypt.cbor` suffixes; with inline and with offloaded payload; with cryptainer metadata; with plaintext signatures; protected by the post-quantum hybrid stack; with WA-CBOR key ciphertexts (`key_ciphertext_format: "cbor"`) in both file formats, covering every asymmetric cipher algorithm, a shared secret and a nested symmetric key layer; and mixing Extended JSON and WA-CBOR key ciphertexts in one cryptainer. Each cryptainer sidecar SHALL reference its keystore pool and its original plaintext (or carry it inline when small), and SHALL list decryption scenarios. A scenario gives a set of trustee passphrases and an expected outcome: success with the expected plaintext, possibly with expected non-fatal warnings, or failure. Cryptainers using a Shamir shared secret SHALL include both a threshold-satisfying scenario and a below-threshold scenario.

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

#### Scenario: WA-CBOR key ciphertexts decrypted
- **WHEN** a cryptainer fixture of the `2026_cbor_key_ciphertexts` generation is decrypted with the passphrases of a scenario expecting success
- **THEN** the decrypted payload equals the original plaintext, and every `key_ciphertext` governed by `key_ciphertext_format: "cbor"` loads with `load_from_cbor_bytes()`
