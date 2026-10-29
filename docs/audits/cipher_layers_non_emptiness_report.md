# Audit: guarantee of at least one payload layer and one key layer

- Date: 2026-10-29
- Context: [issue #41](https://github.com/WitnessAngel/witness-angel-cryptolib/issues/41), "Add (disengageable) security checks for cryptoconfs and cryptainers"
- Question: is it guaranteed that a cryptainer has at least one payload encryption layer, and at least one key encryption layer protecting it?

## Summary

**On the encryption side, yes. On the decryption side and in JSON-schema validation, no.**

| Path | ≥1 payload layer | ≥1 key layer at every level (including nested symmetric layers and each shared-secret shard) |
|---|---|---|
| Python schema (`cryptainer/_validation.py:94`, `:142-150`) | ✅ `And([...], len)` | ✅ `ALL_POSSIBLE_CIPHER_LAYERS_LIST_NON_EMPTY`; the shards list is non-empty because 1 ≤ threshold ≤ number of shards |
| **JSON schema** (`jsonschema_mode=True`) | ❌ accepts `[]` | ❌ accepts `[]`, and accepts an empty shards list with threshold 0 |
| Encryptor runtime (`cryptainer/_flightbox.py:104`, `:173`, threshold check) | ✅ raises `SchemaValidationError` | ✅ raises; recursion means every branch ends in an asymmetric trustee layer |
| **Decryptor** (`decrypt_payload_from_cryptainer`) | ❌ no validation | ⚠️ only `assert len(key_cipher_layers)` (`cryptainer/_decryptor.py:477`), which disappears under `python -O` |

## Encryption: safe

Even if you skip `check_cryptoconf_sanity()`, `encrypt_payload_into_cryptainer()` refuses empty payload or key layer lists:

- `_flightbox.py:104`: `"Empty payload_cipher_layers list is forbidden in cryptoconf"`
- `_flightbox.py:173`: `"Empty key_cipher_layers list is forbidden in cryptoconf"`
- Shared secret: `0 < threshold_count <= shard_count` is enforced, so there is at least one shard.

Every symmetric or shared-secret key layer must itself contain a non-empty list of key layers, so every key path ends in at least one asymmetric (trustee) encryption.

## Gap 1: JSON schema drops the non-emptiness constraints

The `schema` library's `.json_schema()` export can't represent callables like `len` or `validate_shared_secret_threshold`. The generated `CRYPTOCONF_SCHEMA_JSON` and `CRYPTAINER_SCHEMA_JSON` contain zero `minItems`.

I tested three degenerate cryptoconfs:

1. `payload_cipher_layers: []`
2. one payload layer with `key_cipher_layers: []`
3. one payload layer with a `[SHARED_SECRET]` key layer that has no shards and threshold 0

| Cryptoconf | `jsonschema_mode=False` | `jsonschema_mode=True` |
|---|---|---|
| 1 | rejected | **accepted** |
| 2 | rejected | **accepted** |
| 3 | rejected | **accepted** |

## Gap 2: decryption does not validate the structure

`_decryptor.py:346` says *"Non-emptiness of this will be checked by validator"*, but `decrypt_payload_from_cryptainer()` never calls a validator. `operations.py` and `cli.py` call `check_cryptainer_sanity()` first, but anyone calling the library API directly doesn't get that check.

Reproduction:

```python
import uuid
from wacryptolib.cryptainer import decrypt_payload_from_cryptainer, CRYPTAINER_FORMAT, CRYPTAINER_STATES

cryptainer = {
    "cryptainer_state": CRYPTAINER_STATES.FINISHED,
    "cryptainer_format": CRYPTAINER_FORMAT,
    "cryptainer_uid": uuid.uuid4(),
    "keychain_uid": uuid.uuid4(),
    "cryptainer_metadata": None,
    "payload_ciphertext_struct": {"ciphertext_location": "inline", "ciphertext_value": b"FORGED PLAINTEXT"},
    "payload_cipher_layers": [],
}
print(decrypt_payload_from_cryptainer(cryptainer))
# (b'FORGED PLAINTEXT', <OperationReport ...>)
```

Impact: integrity tags and ciphertext signatures are stored inside payload layers, so a cryptainer with no layers skips all of them. The forged "ciphertext" comes back as plaintext with no error, so the caller gets unauthenticated data that looks like a successful decryption. Confidentiality isn't affected, because no real secret is involved.

The `assert` on `key_cipher_layers` at `_decryptor.py:477` is the only guard for empty key layers on this path, and it disappears under `python -O`.

## Recommendations (smallest first)

1. **Decryptor (fixes the real hole):** in `_decrypt_payload_from_cryptainer`, replace the comment with `if not cryptainer["payload_cipher_layers"]: raise SchemaValidationError(...)`, and turn the `assert` at `_decryptor.py:477` into a real raise. Add a regression test using the reproduction above.
2. **JSON schema:** add `minItems: 1` to the generated JSON schemas for `payload_cipher_layers`, every `key_cipher_layers` and `key_shared_secret_shards`, either by post-processing the dict or by wrapping the lists with a small `Schema` subclass that emits it. Shard threshold bounds can't be expressed in JSON Schema, so document that limitation.
3. **Issue #41's optional warnings** (for example, fewer than 2 payload layers, or a single trustee) can then sit on top of these as a disengageable "security level" check. That part is policy, not correctness.
