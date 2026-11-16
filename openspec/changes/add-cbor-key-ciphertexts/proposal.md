## Why

The flightbox core serializes several intermediate structures with `dump_to_json_bytes()` and then encrypts them: symkeys, the cipherdict of each key cipher layer, Shamir shards and asymmetric key structs (encryptor specification §6). Since `add-cbor-document-format`, cryptainer *files* may be WA-CBOR, but these inner structures are always Extended JSON, a non-goal of that change. Two problems follow:

- Embedded encryptors that write WA-CBOR cryptainers still need a full Extended JSON writer and a base64 encoder for the inner structures alone. On small chips, the C flightbox encryptor (change `add-c-flightbox-encryptor`) should ship only one document codec.
- Every nesting level base64-inflates its content by a third, and adds `{"$binary": {"base64": ..., "subType": "00"}}` wrappers. For example, an `AES_CBC` symkey is 173 bytes in Extended JSON and 59 bytes in WA-CBOR. The key struct that wraps it in an `RSA_OAEP` layer is 320 bytes (6 RSA-OAEP chunks of 60 bytes) versus 93 bytes (2 chunks). In a shared secret, every shard pays the same overhead. Each chunk costs one RSA private operation on the trustee side, which is slow on the Authenticator, so this matters.

The inner format can't be guessed safely from the decrypted bytes, and it must be known before the outermost cipherdict is parsed. So a cryptainer must state the format explicitly, in clear text, next to the ciphertext bytes it governs.

## What Changes

- Add an optional `key_ciphertext_format` field, `"json"` or `"cbor"`, as a sibling of every `key_ciphertext` field of a cryptainer, in payload cipher layers and symmetric key cipher layers. It gives the document format of every structure serialized to produce that key ciphertext: the symkey, the cipherdicts of the chain (the `key_ciphertext` bytes included), the key structs, and the shards with their own chains. A nested symmetric key layer's `key_ciphertext` has its own field. An absent field means `"json"`, so existing cryptainers are untouched.
- Inner WA-CBOR structures use the deterministic encoding of `dump_to_cbor_bytes()`. Readers never sniff: they use the stated format, and an unparseable structure is a decryption error, as today.
- Encryption: a new `key_ciphertext_format` parameter, Extended JSON by default, on the encryption functions, `CryptainerEncryptor`, `CryptainerEncryptionPipeline` and `CryptainerStorage`. The field is written only for `"cbor"`, so JSON-mode cryptainers stay byte-identical to the current ones. `CryptainerStorage` and the CLI default it to the cryptainer file format: WA-CBOR files get WA-CBOR key ciphertexts, and Extended JSON files keep JSON ones. A new long-only CLI option, `encrypt --key-ciphertext-format json|cbor`, overrides that default.
- Decryption, cryptainer validation (strict mode included) and `gather_decryptable_symkeys()` read every inner structure in the format stated by the governing field.
- The gateway revelation protocol is unchanged. Revelation requests always carry the asymmetric cipherdict as Extended JSON, transcoded from WA-CBOR when needed: deployed Authenticator apps parse it with `load_from_json_bytes()`. Key struct responses stay opaque bytes, which the requestor parses in the stated format.
- `convert-format` leaves key ciphertexts untouched: it can't re-encode encrypted content, so it only changes the file format.
- `FlightBox` (`_flightbox.py`, and its verbatim MicroPython copy) gets the format as a parameter. Its platform utilities gain `dump_to_cbor_bytes()`. The MicroPython port keeps producing JSON key ciphertexts.
- The encryptor specification documents the field and the serialization rule. The compatibility corpus gains a generation of cryptainers with WA-CBOR key ciphertexts.

## Capabilities

### New Capabilities
- `key-ciphertext-format`: the `key_ciphertext_format` field, its scope over key ciphertext chains, the encoding and decoding rules, the encryption parameters and CLI option, validation, and the revelation request transcoding.

### Modified Capabilities
- `compatibility-fixtures`: cryptainer generations must also cover WA-CBOR key ciphertexts, including a cryptainer mixing both formats.

## Impact

- Code: `cryptainer/_flightbox.py` (+ `reimplementations/micropython/src/cryptainer/_flightbox.py`, re-copied), `_encryptor.py`, `_encryption_pipeline.py`, `_shortcuts.py`, `_storage.py`, `_decryptor.py`, `_analysis.py`, `_validation.py`, `cli.py`.
- No change to the wire forms of JSON-mode cryptainers, to the gateway / JSON-RPC protocols, to `waserver`, or to the Authenticator app (`wacomponents`).
- Compatibility: wacryptolib versions without this change refuse cryptainers that have a `key_ciphertext_format` field (strict schema), or fail to parse their key ciphertexts. This change ships in the same release as WA-CBOR cryptainer files (0.12), whose readers therefore always support it. Extended JSON cryptainers keep JSON key ciphertexts by default, so they stay readable by older versions.
- Docs: encryptor specification §2, §6, §9.1, §10 and §11; flightbox CLI manual; CHANGELOG.
- Corpus: a new lowercase generation, `2026_cbor_key_ciphertexts`.
- Prerequisite of `add-c-flightbox-encryptor`, whose CBOR-only builds write WA-CBOR key ciphertexts.
