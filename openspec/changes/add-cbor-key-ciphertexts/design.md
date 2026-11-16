## Context

See proposal.md for the motivation. Current state that shapes the approach:

- The flightbox core (`src/wacryptolib/cryptainer/_flightbox.py`, encryptor specification §6) calls `self._fbu.dump_to_json_bytes()` at four places:
  - the symkey of each payload layer, and the sub-symkey of each symmetric key layer;
  - the cipherdict returned by each key cipher layer, which the next layer encrypts; the last one *is* the stored `key_ciphertext`;
  - each Shamir shard `(index, bytes)`;
  - each asymmetric key struct `{"key_bytes": ..., "cryptainer_metadata": ...}`.
- These structures are parsed back in several places:
  - `_decryptor.py`, through `_load_untrusted_json_bytes()`: cipherdicts, shards, symkeys and key structs, including remote and predecrypted key structs;
  - `_validation.py`, where `_load_and_check_key_cipherdict()` parses the outermost cipherdict of each `key_ciphertext`, in strict validation;
  - `_analysis.py`, where `gather_decryptable_symkeys()` parses shared-secret cipherdicts to reach the shard ciphertexts.
- Revelation flow:
  - `gather_decryptable_symkeys()` sends the asymmetric layer's `key_ciphertext`, a serialized cipherdict, as `symkey_decryption_request_data`;
  - the deployed Authenticator app (`wacomponents/screens/authenticator_revelation_request_detail.py`) parses it with `load_from_json_bytes()`, decrypts it, and returns the key struct bytes unparsed, re-encrypted for the requestor;
  - the requestor's decryptor maps request data to key struct bytes (`predecrypted_symkey_mapper`), keyed by the same `key_ciphertext` bytes.
- `_flightbox.py` is copied verbatim into the MicroPython port (`reimplementations/micropython/src/cryptainer/`), whose platform utilities only have `dump_to_json_bytes()`.
- WA-CBOR (`docs/specifications/wa_cbor_document_format.md`) is bijective with relaxed Extended JSON over the data model, with deterministic writers and strict readers. All inner structures are maps or arrays, which is what WA-CBOR requires of top-level items.
- WA-CBOR cryptainer files (`add-cbor-document-format`) are unreleased, like this change: both ship in 0.12.

## Goals / Non-Goals

**Goals:**
- Let an encryptor produce key ciphertexts whose inner structures are all WA-CBOR, so that a device can ship a single document codec.
- Explicit, clear-text format declaration: no sniffing of decrypted bytes.
- JSON-mode cryptainers byte-identical to the current ones, and every existing cryptainer readable unchanged.
- No change to deployed servers or Authenticator apps.

**Non-Goals:**
- Re-encoding the key ciphertexts of existing cryptainers: that needs the keys. `convert-format` only changes the file format.
- Formats other than Extended JSON and WA-CBOR.
- Making signatures or payload ciphertexts format-dependent: they don't serialize documents.
- WA-CBOR support in the MicroPython port.

## Decisions

### D1. One field per `key_ciphertext`, governing its whole chain

```
payload layer {                                   symmetric key layer {
  key_ciphertext: S_F(cipherdict_n)                 key_ciphertext: S_G(...)   <- sub-symkey chain, format G
  key_ciphertext_format: F   (absent = "json")      key_ciphertext_format: G
  key_cipher_layers: [ L1 ... Ln ] }                key_cipher_algo, key_cipher_layers }
```

The field is a sibling of the `key_ciphertext` it describes, in payload cipher layers and symmetric key cipher layers. These are the only places where a cryptainer stores key ciphertext bytes in clear. With format F, every structure serialized while producing that `key_ciphertext` is serialized with `S_F`, which is `dump_to_json_bytes()` or `dump_to_cbor_bytes()`:
- the initial key bytes: the symkey for a payload layer, the sub-symkey for a symmetric key layer;
- the cipherdict returned by each layer of the chain, including the cipherdict of a symmetric key layer, which belongs to the enclosing chain, and the last one, whose bytes are the `key_ciphertext`;
- the key struct of each asymmetric layer of the chain;
- the shards of each shared secret layer of the chain, and everything in each shard's own chain. Shard ciphertexts are stored inside the shared secret's serialized cipherdict, not in clear-text fields, so they inherit F.

A symmetric key layer met in the chain starts a new chain: its own `key_ciphertext` follows its own field G.

Alternatives considered:
- One root field per cryptainer: simpler, but not next to the bytes it governs, and it forbids the mixed cryptainers that conversion tools or future encryptors may produce.
- A format field inside every cipherdict: it changes the cipherdict shapes, which trustees receive over JSON-RPC and which the corpus freezes.
- Sniffing: the first byte of a JSON document (`{`, `[`) and of a WA-CBOR map or array (`0x80`-`0xBF`) never collide, but decrypted bytes are untrusted. Explicit declaration keeps a forged or corrupted cryptainer from being parsed under the wrong rules, and it was requested.

### D2. Values, absence, and what encryptors write

- Values: `"json"` and `"cbor"`, the `DocumentFormat` values, which the corpus sidecars (`document_format`) and the CLI (`--format`) already use.
- Absent means `"json"`. Readers accept an explicit `"json"` too. Any other value fails cryptainer validation, and fails decryption if the cryptainer was not validated.
- The wacryptolib encryptor uses one format for a whole cryptainer. It writes the field only when the format is `"cbor"`, on every payload cipher layer and every symmetric key cipher layer. JSON-mode cryptainers are therefore byte-identical to the current ones, and older readers keep accepting them.
- Readers honor each field independently, so mixed cryptainers are valid, and the corpus pins this with one synthesized fixture.
- Cryptoconfs must not contain the field: it is an output field, like `key_ciphertext`, and the cryptoconf schema keeps rejecting it.

### D3. Encoding and parsing rules

- `S_cbor` is `dump_to_cbor_bytes()`, the core deterministic encoding. Two implementations serializing the same structure therefore produce identical bytes, which is what the C port's tests rely on.
- Parsing uses the strict `load_from_cbor_bytes()`. `_load_untrusted_json_bytes()` becomes `_load_untrusted_document_bytes(data, document_format, description, sanity_check)`: its error handling stays the same, and only the parser changes.
- Metadata embedded in key structs must be encodable in the chosen format. With `"cbor"`, a metadata tree that WA-CBOR rejects fails encryption before anything is written, for example when nested deeper than 63 levels, since the key struct adds one. Such a tree also fails when the cryptainer is written as a WA-CBOR file.

### D4. Encryption API and defaults

- `FlightBox.generate_cryptainer_base_and_secrets(cryptoconf, cryptainer_metadata=None, key_ciphertext_format="json")` threads the format through `_encrypt_key_through_multiple_layers()` and its callees. It calls `self._fbu.dump_to_json_bytes()` or the new `self._fbu.dump_to_cbor_bytes()`, and sets the field on each layer that receives a `key_ciphertext`. The MicroPython copy is updated verbatim. Its utilities don't define `dump_to_cbor_bytes()`, and its `main.py` keeps the default.
- New `key_ciphertext_format` parameter:
  - `"json"` by default on `encrypt_payload_into_cryptainer()`, `encrypt_payload_and_stream_cryptainer_to_filesystem()`, `CryptainerEncryptor` and `CryptainerEncryptionPipeline`;
  - on `CryptainerStorage`, it defaults to the storage's `cryptainer_file_format`. A WA-CBOR cryptainer file already requires a 0.12 reader, which supports WA-CBOR key ciphertexts, while Extended JSON files stay readable by older versions.
- CLI: `flightbox encrypt --key-ciphertext-format json|cbor`, long-only like every option, defaulting to the value of `--format`. The `--help` text says that it governs the encrypted key structures, while `--format` governs the cryptainer file.
- Unknown values raise a `ValueError` at construction, before any key is generated.

### D5. Decryption, validation and analysis

- The decryptor reads F from each payload layer and symmetric key layer, and passes it down `_decrypt_key_through_multiple_layers()` and `_decrypt_key_through_single_layer()`, including into shard chains and key struct parsing.
- Strict validation (`_load_and_check_key_cipherdict()`) parses each outermost cipherdict with its layer's format. The cryptainer schema gains `OptionalKey("key_ciphertext_format"): Or("json", "cbor")` in the cryptainer-only extras of payload layers and of symmetric key layers, in both Python and JSON-schema modes.
- `gather_decryptable_symkeys()` parses shared-secret cipherdicts with the governing format.

### D6. Revelation requests stay Extended JSON

A single helper, `get_revelation_request_data(key_ciphertext, key_ciphertext_format)`, returns the `key_ciphertext` itself for `"json"`. For `"cbor"`, it returns `dump_to_json_bytes(load_from_cbor_bytes(key_ciphertext))`. Asymmetric cipherdicts only contain bytes and integers, so the transcoding is lossless (WA-CBOR bijection). The helper is used in two places:
- `gather_decryptable_symkeys()` sends this as `symkey_decryption_request_data`, so the deployed Authenticator parses Extended JSON as before;
- the decryptor looks up `predecrypted_symkey_mapper` with the same helper, so responses match their requests.

The key struct bytes that come back were produced by the device's encryptor in format F, and travel opaquely. The decryptor parses them with F. In `_unwrap_predecrypted_symkeys()`, the format isn't known yet, so the key struct sanity check moves to the lookup. The mapper keeps every response received for a request, and the lookup uses the first one that parses in F and passes the sanity check. Invalid ones are reported as today ("Malformed remote key struct").

For JSON-mode cryptainers, request data is unchanged byte for byte, so revelation requests already stored on gateways keep matching.

Alternative considered: a format field in revelation requests. Rejected: it needs `waserver` and `wacomponents` updates, and a coordinated deployment, for no gain.

### D7. Documentation and corpus

- Encryptor specification:
  - §2: define `S_F` next to `J()`, and state that the cryptainer file format and the key ciphertext format are independent;
  - §6: the pseudo-code uses `S_F` with the format passed down, and §6.7 notes that the example is written for `F = json`;
  - §9.1: the field table gains `key_ciphertext_format` for payload layers and symmetric key layers;
  - §10: the utilities table gains `dump_to_cbor_bytes(data)`, needed only for `"cbor"`;
  - §11: checklist entries "field written only for cbor", "never sniff", and "revelation request data is Extended JSON".
- Corpus generation `2026_cbor_key_ciphertexts`, lowercase, produced by the existing tooling. It holds cryptainers with WA-CBOR key ciphertexts:
  - in both file formats, inline and offloaded;
  - with `RSA_OAEP`, `ECIES_X25519` and `ML_KEM_768`, a 2-of-3 shared secret with a below-threshold scenario, and a nested symmetric key layer;
  - with metadata holding a datetime and a float;
  - plus one synthesized mixed cryptainer: a JSON payload layer whose symmetric key layer is `"cbor"`, and a second, `"cbor"` payload layer.

  Its sidecars record `key_ciphertext_format`. The README documents the field.
- CHANGELOG: an entry for the field, the parameters and the CLI option, with the compatibility note of the proposal.

## Risks / Trade-offs

- [Older wacryptolib versions reject cryptainers with WA-CBOR key ciphertexts] → They only appear on request, or by default in WA-CBOR files, which older versions can't read anyway. The CHANGELOG states it.
- [Mixed formats inside one cryptainer add test cases] → The rule is per field and recursive, and implemented by passing one parameter down. A synthesized fixture pins it.
- [`convert-format` users may expect key ciphertexts to follow the file format] → Documented in the CLI manual: the conversion is lossless and keeps key ciphertexts as they are.
- [Transcoded revelation requests cost a decode and an encode per asymmetric layer] → Negligible next to the asymmetric operations, and only for `"cbor"`.
- [The MicroPython core copy diverges if not re-copied] → No test checks the copy today, although both files are currently identical. A new test asserts that they are byte-identical.

## Migration Plan

Additive for readers, and opt-in for writers, except that `CryptainerStorage` and the CLI default to WA-CBOR key ciphertexts in WA-CBOR files, which are new in the same release. Rollback: revert. Cryptainers already produced with WA-CBOR key ciphertexts then become unreadable, so this change must not be reverted after a release.

## Open Questions

- Whether `cryptainer summarize` / `view` should display each key ciphertext format. Not needed for interoperability.
