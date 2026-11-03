## Purpose

Defines when cryptoconfs and cryptainers are validated, so that each structure is validated once at its point of entry in a process, and the knowledge is remembered afterwards instead of being re-derived by every layer.

## ADDED Requirements

### Requirement: Validate once at ingress, remember in-process
The system SHALL validate a cryptoconf or cryptainer when it enters an encryption, decryption, analysis or storage operation as an untagged dict, and SHALL remember that validation by tagging a snapshot of it as a validated structure. A structure already tagged as validated, with sufficient strictness, SHALL NOT be validated again by any later step of the same operation chain. Public functions SHALL keep accepting plain dicts, and the explicit `check_cryptoconf_sanity()` / `check_cryptainer_sanity()` functions SHALL always validate.

#### Scenario: Raw cryptoconf is validated exactly once per encryption
- **WHEN** a plain cryptoconf is passed to `encrypt_payload_into_cryptainer` or to the CLI `encrypt` command
- **THEN** the cryptoconf schema validation runs one time in total

#### Scenario: Default cryptoconf of a storage is validated once
- **WHEN** a `CryptainerStorage` is created with a `default_cryptoconf` and several files are then encrypted or enqueued without their own cryptoconf
- **THEN** the default cryptoconf is validated once, at construction, and not again for any file

#### Scenario: Invalid input is still refused at the entry point
- **WHEN** an invalid cryptoconf or cryptainer is passed as a plain dict to an encryption, decryption or storage operation
- **THEN** a `SchemaValidationError` is raised to the caller before any key generation, trustee access or cipher operation

### Requirement: Tags do not survive deep-copying or JSON serialization
The system SHALL NOT propagate a validation tag to derived or reloaded data. Deep-copying a tagged structure SHALL yield a plain dict, and data loaded from JSON or from the filesystem SHALL be untagged and therefore validated at ingress.

#### Scenario: Cryptainer derived from a cryptoconf is not a validated cryptoconf
- **WHEN** a validated cryptoconf is deep-copied, as the flightbox does to build a cryptainer base
- **THEN** the copy is a plain dict, and carries neither the cryptoconf nor the cryptainer tag

#### Scenario: Loaded cryptainer is validated
- **WHEN** a cryptainer is dumped to JSON or to the filesystem and loaded back
- **THEN** the loaded object is a plain dict, and is validated when it enters decryption or analysis

### Requirement: Trust of tags inside a process
The system SHALL trust a validation tag without re-validating the structure, since protection against in-process tampering is out of scope. A cryptainer returned by in-memory encryption from a validated cryptoconf SHALL be tagged as strictly validated without being validated again.

#### Scenario: Encrypt then decrypt in the same process
- **WHEN** a cryptainer returned by `encrypt_payload_into_cryptainer` is passed directly to `decrypt_payload_from_cryptainer`
- **THEN** no cryptainer schema validation runs

### Requirement: Strictness is part of the cryptainer tag
A validated cryptainer SHALL record whether its payload ciphertext was required to be inline. A strictly validated cryptainer SHALL satisfy a lenient requirement, but a leniently validated cryptainer SHALL NOT satisfy a strict one, and SHALL be re-validated strictly when a strict check is requested.

#### Scenario: Lenient token used for decryption
- **WHEN** a cryptainer loaded without its payload ciphertext and validated with `ensure_validated_cryptainer(..., require_inline_payload=False)` is passed to payload decryption
- **THEN** it is validated strictly before use, and refused with a `SchemaValidationError` since its payload ciphertext is not inline bytes

#### Scenario: Strict token used for analysis
- **WHEN** a strictly validated cryptainer is passed to `gather_decryptable_symkeys`
- **THEN** it is accepted without any further validation
