## Purpose

Defines the compact binary document that provisions an embedded flightbox encryptor: one WA-CBOR document holding the cryptoconf and the raw public keys of its trustees, restricted to a sub-profile that small decoders can handle. Device implementations can then encrypt without parsing Extended JSON or PEM.

## Requirements

### Requirement: Device profile document structure
A flightbox device profile SHALL be a WA-CBOR document (`docs/specifications/wa_cbor_document_format.md`) within the sub-profile defined below, whose top-level item is a map with exactly the text-string keys `device_profile_format`, `cryptoconf` and `trustee_public_keys`. `device_profile_format` SHALL be the text string `flightbox_device_profile_1.0`. `cryptoconf` SHALL follow the cryptoconf grammar of section 5.1 of the encryptor specification (`docs/flightbox_specifications/flightbox_encryptor_specification.md`), with the same text-string keys and algorithm names. `trustee_public_keys` SHALL be an array of public key entries. The format SHALL be described by a CDDL (RFC 8610) schema published in `docs/flightbox_specifications/`, which refers to the WA-CBOR specification for every rule it doesn't restrict.

#### Scenario: Minimal valid profile
- **WHEN** a device profile contains the format string `flightbox_device_profile_1.0`, a cryptoconf with a root `keychain_uid` and one `AES_CBC` payload layer wrapped by one `RSA_OAEP` layer for an authenticator trustee, and the matching RSA public key entry
- **THEN** a conforming decoder accepts it, and cryptainers can be created from it

#### Scenario: Unknown format version
- **WHEN** `device_profile_format` holds any other value, or is missing
- **THEN** the decoder rejects the profile with an unsupported-format error

#### Scenario: Unknown root key
- **WHEN** the root map contains a key other than the three defined ones
- **THEN** the decoder rejects the profile with a validation error

### Requirement: WA-CBOR sub-profile
A device profile SHALL only use the following items:
- definite-length maps with text-string keys, and definite-length arrays;
- byte strings, and UTF-8 text strings;
- integers of major types 0 and 1 within the signed 64-bit range;
- `false`, `true` and `null`;
- tag 37 over a 16-byte byte string.

Every UUID (`keychain_uid`, `keystore_uid`) SHALL be such a tag 37 item, and every binary value a byte string, never base64 text.

Decoders SHALL reject a profile that WA-CBOR readers reject, for the same reasons: non-text or duplicate map keys, other tags or simple values, invalid UTF-8, malformed or truncated items, a single-key map whose key is an Extended JSON keyword, nesting deeper than 64 levels, and bytes after the top-level item. These SHALL be reported as decoding errors, except items nested deeper than the decoder's limit, which SHALL be reported as nesting too deep. They SHALL also reject, as unsupported, valid WA-CBOR items outside the sub-profile:
- floats;
- tags 0, 2, 3 and 4;
- indefinite lengths;
- tag 55799;
- integers outside the signed 64-bit range.

They MAY accept the non-shortest heads and unsorted map keys that WA-CBOR readers accept. Every profile a conforming decoder accepts SHALL therefore load with wacryptolib's `load_from_cbor_bytes()`.

#### Scenario: UUID as tag 37
- **WHEN** a cryptoconf's `keychain_uid` is encoded as tag 37 over 16 bytes
- **THEN** it is decoded as that UUID, and later written into the cryptainer as an Extended JSON `{"$uuid": "<32 lowercase hex chars>"}` or a WA-CBOR tag 37 item

#### Scenario: UUID as text is rejected
- **WHEN** a `keychain_uid` or `keystore_uid` is encoded as a text string such as `"acd7f9f7-849b-44af-9765-9d4913b7f8dd"`
- **THEN** the decoder rejects the profile with a validation error

#### Scenario: Indefinite-length item is rejected
- **WHEN** any array, map, byte string or text string in the profile uses indefinite-length encoding
- **THEN** the decoder rejects the profile with an unsupported-type error

#### Scenario: Duplicate map key is rejected
- **WHEN** a map of the profile contains the same key twice
- **THEN** the decoder rejects the profile with a decoding error

#### Scenario: Extended JSON keyword map is rejected
- **WHEN** a map of the profile has the single key `$binary`
- **THEN** the decoder rejects the profile with a decoding error

#### Scenario: WA-CBOR test vectors
- **WHEN** the decoder is run on each test vector of section 10 of the WA-CBOR specification
- **THEN** it rejects every invalid vector, rejects as unsupported every valid vector holding a float, a tag other than 37, an indefinite length or an integer outside the signed 64-bit range, and decodes every other valid vector to the tree given by the vector

#### Scenario: Invalid corpus documents
- **WHEN** an invalid WA-CBOR cryptoconf of `compatibility/cryptoconfs/2026_cbor_pairs/invalid/` is placed as the `cryptoconf` value of a profile
- **THEN** the decoder rejects the profile

### Requirement: Trustee public key entries
Each entry of `trustee_public_keys` SHALL be a map with exactly the keys `trustee`, `keychain_uid`, `key_algo` and `public_key`. `trustee` SHALL be a trustee map with the same grammar as in the cryptoconf. `keychain_uid` SHALL be a UUID. `key_algo` SHALL be one of `RSA_OAEP`, `ECIES_X25519` or `ML_KEM_768`. `public_key` SHALL be raw key material:
- `RSA_OAEP`: a map with exactly the keys `modulus` and `public_exponent`, both unsigned big-endian byte strings without leading zero bytes;
- `ECIES_X25519`: a 32-byte byte string (RFC 7748 u-coordinate, little-endian);
- `ML_KEM_768`: a 1184-byte byte string (FIPS 203 encapsulation key).

The tuple (trustee identity, `keychain_uid`, `key_algo`) SHALL be unique within a profile. Trustee identity is defined as follows:
- `authenticator` trustees: `trustee_type` plus `keystore_uid`;
- `jsonrpc_api` trustees: `trustee_type` plus `jsonrpc_url`;
- `local_keyfactory` trustees: `trustee_type` alone.

`keystore_owner` SHALL NOT take part in the identity. For a `local_keyfactory` trustee, the entry SHALL hold a key pre-provisioned from the local keyfactory of the machine that will decrypt: the device never generates keypairs. Entries that no layer of the cryptoconf uses SHALL be accepted and ignored.

#### Scenario: Wrong raw key size
- **WHEN** an `ECIES_X25519` entry holds 33 bytes, or an `ML_KEM_768` entry holds anything but 1184 bytes
- **THEN** the decoder rejects the profile with a validation error

#### Scenario: Duplicate key entry
- **WHEN** two entries share the same trustee identity, keychain uid and key algo, even if their `keystore_owner` differs
- **THEN** the decoder rejects the profile with a validation error

#### Scenario: Key lookup ignores keystore owner
- **WHEN** the cryptoconf references an authenticator trustee with a `keystore_owner` different from the one in the matching public key entry
- **THEN** the entry is still selected for that trustee

#### Scenario: Unused entry
- **WHEN** the profile contains a valid public key entry that no layer of the cryptoconf references
- **THEN** the profile is accepted, and the entry plays no part in encryption

### Requirement: Public key sanity constraints
A device profile SHALL only be accepted if every public key respects the constraints of section 11.2 of the encryptor specification, tightened so that all implementations accept exactly the same keys:
- RSA: modulus at least 2048 bits and at most a configurable maximum, 4096 bits by default; modulus odd; `3 <= e < n` with `e` odd; `gcd(n, e) = 1`.
- X25519: canonical u-coordinate, so the most significant bit of the last byte is clear and u < p = 2^255 - 19. It SHALL NOT be one of the low-order points (0, 1, the two order-8 points, p - 1).
- ML-KEM-768: encapsulation key whose 768 decoded 12-bit coefficients are all below 3329 (the FIPS 203 modulus check).

#### Scenario: RSA modulus too short or too long
- **WHEN** an `RSA_OAEP` entry holds a 1024-bit modulus, or a modulus above the configured maximum
- **THEN** the profile is rejected with a key-constraint error, and the error location identifies the entry

#### Scenario: RSA exponent sharing a factor with the modulus
- **WHEN** an `RSA_OAEP` entry holds an odd modulus divisible by its exponent 3, or sharing a large prime factor with its exponent
- **THEN** the profile is rejected with a key-constraint error

#### Scenario: Low-order X25519 point
- **WHEN** an `ECIES_X25519` entry holds the all-zero u-coordinate, or `p - 1`
- **THEN** the profile is rejected with a key-constraint error

#### Scenario: Non-canonical X25519 key
- **WHEN** an `ECIES_X25519` entry has its most significant bit set, or encodes a value of at least p, such as `p + 1`
- **THEN** the profile is rejected with a key-constraint error

#### Scenario: Non-reduced ML-KEM key
- **WHEN** an `ML_KEM_768` entry has an encoded coefficient equal to or greater than 3329
- **THEN** the profile is rejected with a key-constraint error

### Requirement: Cryptoconf validation inside a profile
The cryptoconf of a device profile SHALL be validated when the profile is loaded, before any key is generated. The rules SHALL match the cryptoconf schema of the reference library (wacryptolib):
- unknown keys are rejected and algorithm names are checked;
- `payload_cipher_layers` and every `key_cipher_layers` list are non-empty;
- `1 <= key_shared_secret_threshold <= len(key_shared_secret_shards)`.

The legacy `payload_signatures` key SHALL be accepted as an alias of `payload_ciphertext_signatures`. A payload layer carrying both keys SHALL be rejected. On top of these rules:
- the cryptoconf SHALL have a root `keychain_uid`, so that every asymmetric layer resolves to a keychain uid that is known when the profile is provisioned;
- every asymmetric key cipher layer SHALL resolve to exactly one public key entry of the profile, through its own `keychain_uid` or else the root one.

#### Scenario: Missing public key
- **WHEN** an `ECIES_X25519` layer references a trustee and keychain uid with no matching entry in `trustee_public_keys`
- **THEN** the profile is rejected with a missing-public-key error, and the error location identifies the layer

#### Scenario: Missing root keychain uid
- **WHEN** the cryptoconf has no root `keychain_uid`, even if every asymmetric layer has its own
- **THEN** the profile is rejected with a validation error

#### Scenario: Invalid threshold
- **WHEN** a shared secret layer has threshold 0, or a threshold above its number of shards
- **THEN** the profile is rejected with a validation error

#### Scenario: Both signature list keys
- **WHEN** a payload layer has both `payload_signatures` and `payload_ciphertext_signatures`
- **THEN** the profile is rejected with a validation error

### Requirement: Export of a device profile from CPython
The repository SHALL provide a command-line export script that takes a cryptoconf file, in Extended JSON or WA-CBOR, and a keystore pool, and writes a device profile. It SHALL:
- recognize the cryptoconf file format like wacryptolib's document loader does;
- validate the cryptoconf with wacryptolib first;
- require a root `keychain_uid`;
- gather the public key of every asymmetric layer from the pool's local keyfactory or imported authenticator keystores, and convert it to its raw form;
- fail on a missing key, and on `jsonrpc_api` trustees (out of scope for the script);
- encode the profile with wacryptolib's deterministic WA-CBOR writer;
- write it to an output name ending with `.cbor`, matched in any letter case and lowercased in the created file name;
- refuse to overwrite an existing file unless forced.

On any error, it SHALL exit with a non-zero status and write no file. The exported profile SHALL pass the validation rules of this capability.

#### Scenario: Export from the compatibility corpus
- **WHEN** the export script runs on a signature-free cryptoconf with a root `keychain_uid`, together with its keystore pool from `compatibility/keystores/`
- **THEN** it writes a device profile containing exactly one public key entry per distinct (trustee identity, keychain uid, key algo) used by the cryptoconf

#### Scenario: Same profile from both cryptoconf formats
- **WHEN** the export script runs once on `compatibility/cryptoconfs/2026_cbor_pairs/01_single_layer.cryptoconf.json` and once on its WA-CBOR twin `01_single_layer.cryptoconf.cbor`, with the same keystore pool
- **THEN** both device profiles are byte-identical

#### Scenario: Profile readable with the flightbox CLI
- **WHEN** an exported profile is converted with `flightbox convert-format`, then converted back
- **THEN** the intermediate file is a readable Extended JSON document, and the final file is byte-identical to the exported profile

#### Scenario: Export with a missing key
- **WHEN** the keystore pool lacks the keypair of one asymmetric layer
- **THEN** the script exits with a non-zero status and an error naming the missing key, and writes no file

#### Scenario: Export without root keychain uid
- **WHEN** the cryptoconf has no root `keychain_uid`
- **THEN** the script exits with a non-zero status explaining that device profiles require one, and writes no file

#### Scenario: Existing output refused
- **WHEN** the output file already exists and the script is run without its force option
- **THEN** it exits with a non-zero status, and the existing file is unchanged
