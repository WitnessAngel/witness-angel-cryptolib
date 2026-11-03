## Why

Cryptoconfs and cryptainers are plain dicts, so no function can know whether one was already validated, and layers re-validate "just in case": the CLI `encrypt` command and `operations.py` then the encryptor, the decryptor then its in-flow guards, and `CryptainerStorage` once per file (inside the encryptor) for the very same `default_cryptoconf`. This costs CPU on sensor-style workflows, and the checks drift apart (different exceptions, different strictness). A small tag type that *remembers* that validation happened lets each structure be validated once, at its point of entry.

## What Changes

- Add two `dict` subclasses, `ValidatedCryptoconf` and `ValidatedCryptainer`, in `cryptainer/_validation.py`: a newtype-style tag meaning "validated when this object was built". They are NOT frozen: mutating one afterwards is a caller bug, and malicious in-process code can break the tag, which is accepted.
- Add idempotent **public** helpers `ensure_validated_cryptoconf(x)` and `ensure_validated_cryptainer(x, require_inline_payload=True)` (exported from `wacryptolib.cryptainer`, documented): a no-op (O(1)) on an already-tagged input of sufficient strictness, otherwise validate then return a tagged deep snapshot. `check_*_sanity()` stay unconditional validators (the `validate` commands rely on that).
- Existing public functions keep accepting raw dicts (**no API change**) and wrap on entry; library users never have to handle tokens, though they may use the helpers to validate once and reuse the result.
- Tokens never survive `copy.deepcopy` or JSON serialization: `__deepcopy__` returns a plain dict, so a cryptainer derived by the flightbox from a cryptoconf never carries the cryptoconf tag. Data loaded from JSON or the filesystem is untagged, so it is validated at ingress.
- `CryptainerStorage` validates `default_cryptoconf` once at construction (and a per-call cryptoconf once at the call), not once per file. **Behavior change**: an invalid cryptoconf now raises `SchemaValidationError` from the constructor / `enqueue_file_for_encryption()` itself, instead of failing (logged, swallowed) in the worker thread.
- `CryptainerEncryptor.encrypt_data()` tags the cryptainer it returns as strictly validated, without re-validating it (valid cryptoconf implies valid cryptainer), and the decryptor trusts a tagged cryptainer without re-validating it.
- Remove duplicate validations (`check_cryptoconf_sanity` in CLI `encrypt` and `operations.py`) and the now-dead in-flow guard of the decryptor ("Empty key_cipher_layers list is forbidden in cryptainer").
- `FlightBox` stays token-agnostic: it is dependency-injection-only because a diverged copy runs on MicroPython without imports. The CPython caller (`CryptainerEncryptor`) is the one that guarantees a tagged cryptoconf. The flightbox's own minimal "empty layers" guards stay.

## Capabilities

### New Capabilities
- `cryptostructure-validation`: when and how often a cryptoconf or cryptainer is validated, and how validation is remembered inside a process.

### Modified Capabilities

(none: no spec exists under `openspec/specs/` yet for validation)

## Impact

- Code: `cryptainer/_validation.py` (types, helpers), `cryptainer/__init__.py` (re-exports), `_encryptor.py`, `_decryptor.py`, `_analysis.py` (keeps its lazy import, it is loaded before `_validation`), `_storage.py`, `cli.py`, `operations.py`. No change needed in `_shortcuts.py`, `_encryption_pipeline.py`, `_filesystem.py` (they delegate to the encryptor/decryptor choke points).
- Tests: `tests/test_wacryptolib_cryptainer.py` (validation-count assertions, deepcopy/serialization behavior), CLI tests, and `tests/test_wacryptolib_sensor.py`, whose `FakeTestCryptainerStorage` instances use dummy cryptoconfs (`{"whatever": True}`...) that construction-time validation would refuse.
- No new dependency, no file-format change; CHANGELOG entry (refactor + the storage behavior change above).
- **Precondition**: builds on PR #63 (`fix/cipher-layers-non-emptiness`), which makes `check_cryptainer_sanity()` strict by default, validates the cryptoconf upfront in the encryptor, and already drops the CLI/`operations.py` decrypt-side checks and the encryptor's post-generation check. This change must be rebased onto `dev` after that PR is merged.
