## Purpose

Lets the structures that a cryptainer serializes and then encrypts (symkeys, key cipherdicts, Shamir shards, asymmetric key structs) be written either in Extended JSON or in WA-CBOR. The format is declared in clear text next to the key ciphertext bytes it governs.

## Requirements

### Requirement: Key ciphertext format field
A cryptainer's payload cipher layers and symmetric key cipher layers MAY hold a `key_ciphertext_format` field next to their `key_ciphertext`, whose value SHALL be `"json"` or `"cbor"`. An absent field SHALL mean `"json"`. Cryptainer validation SHALL reject any other value, and the field SHALL NOT be accepted in cryptoconfs.

#### Scenario: Absent field
- **WHEN** a cryptainer produced before this change, without any `key_ciphertext_format` field, is validated and decrypted
- **THEN** it validates, and its key ciphertexts are parsed as Extended JSON, exactly as before

#### Scenario: Unknown value
- **WHEN** a cryptainer has `key_ciphertext_format: "yaml"` on a payload layer
- **THEN** cryptainer validation fails, naming the field

#### Scenario: Field in a cryptoconf
- **WHEN** a cryptoconf has a `key_ciphertext_format` field on a payload cipher layer
- **THEN** cryptoconf validation fails

### Requirement: Scope of the format over a key ciphertext chain
With format F stated for a `key_ciphertext`, every structure serialized to produce that key ciphertext SHALL be serialized in F, with `dump_to_json_bytes()` for `"json"` and with the deterministic `dump_to_cbor_bytes()` for `"cbor"`. These structures are:
- the initial key bytes: the symkey of a payload layer, or the sub-symkey of a symmetric key layer;
- the cipherdict returned by each key cipher layer of the chain, including the cipherdict returned by a symmetric key layer of the chain, and the last cipherdict, whose bytes are the `key_ciphertext`;
- the key struct encrypted by each asymmetric layer of the chain;
- for each shared secret layer of the chain, its shards, and recursively every structure serialized in each shard's chain.

The `key_ciphertext` of a symmetric key layer met in the chain SHALL follow the format stated next to it, not F. Decryptors SHALL parse each of these structures in the stated format, and SHALL NOT infer the format from the bytes. A structure that does not parse in the stated format SHALL be reported as a decryption error for its layer.

#### Scenario: Shared secret with WA-CBOR key ciphertexts
- **WHEN** a cryptainer is encrypted with `key_ciphertext_format="cbor"`, with a payload layer whose key goes through `RSA_OAEP`, then a 2-of-3 shared secret
- **THEN** the payload layer has `key_ciphertext_format: "cbor"`, its `key_ciphertext` loads with `load_from_cbor_bytes()`, and wacryptolib decrypts the cryptainer with any two of the three shard keys

#### Scenario: Mixed formats in one cryptainer
- **WHEN** a payload layer has no `key_ciphertext_format` and contains a symmetric key layer with `key_ciphertext_format: "cbor"`
- **THEN** the decryptor parses the payload layer's chain as Extended JSON and the symmetric key layer's sub-symkey chain as WA-CBOR, and decrypts the payload

#### Scenario: Format contradicting the content
- **WHEN** the `key_ciphertext_format` of a JSON-mode payload layer is changed to `"cbor"` in a cryptainer
- **THEN** cryptainer validation, which decryption performs first, fails with a validation error about a key cipherdict unparseable in format `"cbor"`
- **AND** decrypting that layer without prior validation fails with a decryption error about an unparseable key ciphertext
- **AND** no attempt is made to parse the key ciphertext as Extended JSON

### Requirement: Encryption with a chosen key ciphertext format
The encryption functions, `CryptainerEncryptor`, `CryptainerEncryptionPipeline` and `CryptainerStorage` SHALL accept a `key_ciphertext_format` parameter, `"json"` or `"cbor"`. One format SHALL be used for a whole cryptainer. With `"cbor"`, every payload cipher layer and every symmetric key cipher layer SHALL get `key_ciphertext_format: "cbor"`. With `"json"`, no `key_ciphertext_format` field SHALL be written, so that the cryptainer has exactly the form produced before this change. The default SHALL be `"json"`, except for `CryptainerStorage`, where it SHALL be the storage's cryptainer file format. An unknown value SHALL raise an error before any key is generated. Metadata that the chosen format can't encode inside a key struct SHALL make encryption fail before anything is written.

#### Scenario: JSON mode unchanged
- **WHEN** a payload is encrypted with the default `key_ciphertext_format`
- **THEN** the cryptainer has no `key_ciphertext_format` field, and its key ciphertexts are Extended JSON, as before this change

#### Scenario: Storage default follows the file format
- **WHEN** a `CryptainerStorage` with `cryptainer_file_format="cbor"` and no `key_ciphertext_format` encrypts a file
- **THEN** the `.crypt.cbor` cryptainer has `key_ciphertext_format: "cbor"` on every payload layer and symmetric key layer

#### Scenario: Smaller key ciphertexts
- **WHEN** the same payload is encrypted with a cryptoconf of one `AES_CBC` payload layer wrapped by one `RSA_OAEP` layer of a 2048-bit key, once per format
- **THEN** the WA-CBOR `key_ciphertext` holds 2 RSA-OAEP chunks, and the Extended JSON one holds 6

### Requirement: CLI key ciphertext format option
`flightbox encrypt` SHALL accept a long-only `--key-ciphertext-format json|cbor` option, defaulting to the value of its `--format` option. Its `--help` text SHALL state that it governs the encrypted key structures, while `--format` governs the cryptainer file. `convert-format` SHALL leave key ciphertexts and their `key_ciphertext_format` fields unchanged.

#### Scenario: CBOR file, default key ciphertext format
- **WHEN** `flightbox encrypt video.mp4 --format cbor` is run
- **THEN** `video.mp4.crypt.cbor` has `key_ciphertext_format: "cbor"` on every payload layer

#### Scenario: JSON file with WA-CBOR key ciphertexts
- **WHEN** `flightbox encrypt video.mp4 --key-ciphertext-format cbor` is run
- **THEN** `video.mp4.crypt.json` is an Extended JSON file whose payload layers have `key_ciphertext_format: "cbor"`, and `flightbox cryptainer decrypt` restores the video

#### Scenario: Conversion keeps key ciphertexts
- **WHEN** a `.crypt.cbor` cryptainer with WA-CBOR key ciphertexts is converted to `.crypt.json`
- **THEN** its `key_ciphertext` bytes and `key_ciphertext_format` fields are unchanged, and it still decrypts

### Requirement: Revelation requests stay Extended JSON
The revelation request data built for a remote trustee by `gather_decryptable_symkeys()` SHALL be the Extended JSON serialization of the asymmetric layer's cipherdict, whatever the key ciphertext format. For `"json"`, it SHALL be byte-identical to the layer's key ciphertext, as before. For `"cbor"`, it SHALL be transcoded from WA-CBOR. The decryptor SHALL match revelation responses to layers through the same request data. It SHALL parse the returned key struct in the format stated for the layer, and use the first response that passes the key struct checks.

#### Scenario: Authenticator-compatible request
- **WHEN** decryptable symkeys are gathered from a cryptainer with WA-CBOR key ciphertexts and an authenticator trustee
- **THEN** each `symkey_decryption_request_data` loads with `load_from_json_bytes()` as a valid cipherdict of its algorithm

#### Scenario: Remote decryption round trip
- **WHEN** a revelation response for such a request carries the key struct bytes, decrypted by the authenticator key and re-encrypted with the response key
- **THEN** the decryptor uses that response for the matching layer, and decrypts the payload without a key ciphertext format error
