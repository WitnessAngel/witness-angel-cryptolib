## Why

Cryptoconfs and cryptainers are plain dicts, so no function can know whether one was already validated, and every layer re-validates "just in case": the CLI then the encryptor, the encryptor then its own post-generation check, the decryptor then its in-flow guards, and `CryptainerStorage` once per file for the very same `default_cryptoconf`. This costs CPU on sensor-style workflows, and the checks drift apart (different exceptions, different strictness). A small tag type that *remembers* that validation happened lets each structure be validated exactly once, at its point of entry.

## What Changes

- Add two internal `dict` subclasses, `ValidatedCryptoconf` and `ValidatedCryptainer`, in `cryptainer/_validation.py`: a newtype-style tag meaning "validated when this object was built". They are NOT frozen: mutating one afterwards is a caller bug, and malicious in-process code can break the tag, which is accepted.
- Add idempotent helpers `ensure_validated_cryptoconf(x)` and `ensure_validated_cryptainer(x, require_inline_payload=True)`: a no-op (O(1)) on an already-tagged input of sufficient strictness, otherwise validate then return a tagged deep snapshot.
- Public functions keep accepting raw dicts (**no public API change**) and wrap on entry; tokens never need to be handled by library users.
- Tokens never survive serialization or `copy.deepcopy`: `__deepcopy__` returns a plain dict, so a cryptainer derived by the flightbox from a cryptoconf never carries the cryptoconf tag. Data loaded from JSON or the filesystem is untagged, so it is validated at ingress.
- `CryptainerStorage` validates `default_cryptoconf` once at construction, not once per enqueued file.
- `CryptainerEncryptor` wraps the cryptainer it generates as trusted, without re-validating it (valid cryptoconf implies valid cryptainer), and the decryptor trusts a tagged cryptainer without re-validating it.
- Remove duplicate validations (CLI calls in front of the encryptor, the `gather_decryptable_symkeys` then decrypt double check) and the now-dead in-flow guards of the decryptor (e.g. "Empty key_cipher_layers list is forbidden in cryptainer").
- `FlightBox` stays token-agnostic: it is dependency-injection-only because a diverged copy runs on MicroPython without imports. The CPython caller (`CryptainerEncryptor`) is the one that guarantees a tagged cryptoconf. The flightbox's own minimal "empty layers" guards stay.

## Capabilities

### New Capabilities
- `cryptostructure-validation`: when and how often a cryptoconf or cryptainer is validated, and how validation is remembered inside a process.

### Modified Capabilities

(none: no spec exists under `openspec/specs/` yet for validation, and accepted/refused inputs of public functions are unchanged)

## Impact

- Code: `cryptainer/_validation.py` (types, helpers), `_encryptor.py`, `_decryptor.py`, `_analysis.py`, `_storage.py`, `_shortcuts.py`, `_encryption_pipeline.py`, `cli.py`, `operations.py`; `cryptainer/__init__.py` import order (tokens must be importable by `_encryptor` and `_decryptor`).
- Tests: `tests/test_wacryptolib_cryptainer.py` (validation-count assertions, deepcopy/serialization behavior), CLI tests.
- No new dependency, no public API or file-format change; CHANGELOG entry (internal).
- **Precondition**: builds on PR #63 (`fix/cipher-layers-non-emptiness`), which makes `check_cryptainer_sanity()` strict by default and validates the cryptoconf upfront in the encryptor. This change must be rebased onto `dev` after that PR is merged.
