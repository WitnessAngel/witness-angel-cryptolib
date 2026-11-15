## RENAMED Requirements

- FROM: `### Requirement: Tags do not survive deep-copying or JSON serialization`
- TO: `### Requirement: Tags do not survive deep-copying or serialization`

## MODIFIED Requirements

### Requirement: Tags do not survive deep-copying or serialization
The system SHALL NOT propagate a validation tag to derived or reloaded data. Deep-copying a tagged structure SHALL yield a plain dict, and data loaded from Extended JSON, from WA-CBOR or from the filesystem SHALL be untagged and therefore validated at ingress.

#### Scenario: Cryptainer derived from a cryptoconf is not a validated cryptoconf
- **WHEN** a validated cryptoconf is deep-copied, as the flightbox does to build a cryptainer base
- **THEN** the copy is a plain dict, and carries neither the cryptoconf nor the cryptainer tag

#### Scenario: Loaded cryptainer is validated
- **WHEN** a cryptainer is dumped to JSON or to the filesystem and loaded back
- **THEN** the loaded object is a plain dict, and is validated when it enters decryption or analysis

#### Scenario: Cryptainer loaded from WA-CBOR is validated
- **WHEN** a validated cryptainer is dumped to WA-CBOR and loaded back
- **THEN** the loaded object is a plain dict, and is validated when it enters decryption or analysis
