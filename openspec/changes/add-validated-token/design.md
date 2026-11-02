## Context

- `check_cryptoconf_sanity()` / `check_cryptainer_sanity()` (`cryptainer/_validation.py`) are called from: the CLI (three times around encryption, once for `validate`), `operations.py`, `CryptainerEncryptor._generate_cryptainer_base_and_secrets()`, `decrypt_payload()`, `gather_decryptable_symkeys()` and `ReadonlyCryptainerStorage.check_cryptainer_sanity()`. Several flows hit two of them in a row. `CryptainerStorage` re-validates `default_cryptoconf` for each enqueued file.
- The decryptor also carries in-flow guards (e.g. "Empty key_cipher_layers list is forbidden in cryptainer") that duplicate the upfront schema check.
- Structures are plain mutable JSON-shaped dicts, deep-copied by the flightbox (cryptoconf becomes the cryptainer base), mutated during encryption (signatures, MACs, state), and serialized/loaded as JSON.
- `_flightbox.py` is dependency-injection-only: a diverged copy (`micropython/flightbox.py`) runs on MicroPython and must import nothing. Import order inside `cryptainer/__init__.py` matters (`_flightbox` is loaded before `_validation`).
- Precondition: PR #63 (strict `check_cryptainer_sanity()` with `require_inline_payload=True` default, upfront `check_cryptoconf_sanity()` in the encryptor, `SchemaValidationError` on bad formats) is merged into `dev` first.

## Goals / Non-Goals

**Goals:**
- Validate each cryptoconf/cryptainer once per process path, and make forgetting validation hard.
- Keep every public signature and accepted input unchanged.
- Tokens remember validation at construction time.

**Non-Goals:**
- Soundness against mutation after tagging: no frozen/immutable tree, and malicious in-process code may forge or break a tag.
- Public exposure of the token types, or a stable serialized form for them.
- Any change to the MicroPython flightbox.

## Decisions

**D1: dict subclasses as tags.** `class ValidatedCryptoconf(dict)` and `class ValidatedCryptainer(dict)` (with an `inline_payload_checked: bool` attribute). They stay `dict` for `json.dumps`, indexing and `isinstance(x, dict)`. *Alternatives rejected:* a marker key (serialized, forgeable from a JSON file, pollutes the schema); an `id()` registry or `WeakSet` (plain dicts are not weakref-able and ids are reused); a content-fingerprint cache (hashing a large tree costs about as much as validating it).

**D2: Snapshot at validation, tag by construction.** `ensure_validated_cryptoconf(x)` returns `x` itself if it is already a `ValidatedCryptoconf`; else it validates, then returns `ValidatedCryptoconf(copy.deepcopy(x))`. The snapshot protects the token from later mutation of the caller's original dict; it is not a defence against someone mutating the token itself (accepted, see Non-Goals).

**D3: `__deepcopy__` returns a plain dict.** Without it, `copy.deepcopy(validated_cryptoconf)` in the flightbox would produce a cryptainer base typed as a validated cryptoconf. Both classes override `__deepcopy__` to deep-copy into a plain `dict`; `copy.copy` and pickling are left alone (not used in the library).

**D4: Strictness lives on the cryptainer token.** `ensure_validated_cryptainer(x, require_inline_payload=True)`: a token passes if `token.inline_payload_checked or not require_inline_payload`; otherwise it is re-validated (strictly) and a new token returned. This keeps `gather_decryptable_symkeys` lenient and decryption strict while still validating once for the common strict flow.

**D5: Where tokens are created and consumed.**

```
 raw dict --ensure_validated_cryptoconf--> ValidatedCryptoconf
      CLI / shortcuts / Encryptor entry / CryptainerStorage.__init__
                          |
                          v
        CryptainerEncryptor (assert token) --> FlightBox (token-agnostic)
                          |
                          v   deepcopy => plain dict
                    ValidatedCryptainer  (wrapped by encryptor, no re-validation;
                          |               lenient while state=STARTED/finalizing,
                          |               tagged strict once inline payload final)
          dump_to_json / filesystem ==> untagged ==> ensure_validated_cryptainer at load/decrypt/analysis
```

- Public functions call `ensure_*` on entry; internal layers `assert isinstance(...)` (the assert is a developer guard against reaching internals with a raw dict, not a security check).
- `CryptainerStorage.__init__` validates and stores `default_cryptoconf`; a per-call `cryptoconf` passed to `enqueue_file_for_encryption` is ensured at that call.
- CLI drops its own `check_cryptoconf_sanity` calls in front of encryption (the pipeline entry ensures once); the CLI `validate` command keeps its explicit check since validation is its purpose.
- Decryptor removes the guards made unreachable by the upfront check; `FlightBox` keeps its own (it is the only guard on MicroPython).

**D6: FlightBox stays token-agnostic.** The shared design constraint (no imports, dependency injection) means `FlightBox` cannot reference the token classes. The CPython `CryptainerEncryptor` is the only CPython caller and guarantees the token. Direct `FlightBox` use with a raw dict stays unvalidated (documented), which is the accepted residual risk.

**D7: Cryptainer lifecycle.** The encryptor mutates the cryptainer it generated (signatures, MACs, state). It tags the object it returns/stores at the boundaries (generation: lenient; after finalization: strict). Mid-flight mutation by library code is considered part of building the validated structure.

## Risks / Trade-offs

- [Tag lies if someone mutates a token] → Accepted by decision; documented in docstrings. Serialization always drops the tag.
- [Snapshot deepcopy cost at ingress] → One copy per entry instead of repeated schema validations; for big cryptoconfs shared across many files, the storage-level token amortizes it.
- [Strictness bugs: a lenient token leaking into decryption] → Covered by D4 and dedicated tests (lenient token refused for decryption when payload not inline).
- [Import-order fragility in `cryptainer/__init__.py`] → Tokens live in `_validation.py` (loaded after `_flightbox`), used only by `_encryptor`, `_decryptor`, `_analysis`, `_storage`; no import from `_flightbox`.
- [Behavior drift while removing guards] → Remove a guard only if a test proves the upfront check refuses the same input with a `SchemaValidationError`.

## Migration Plan

Internal refactor; no data or API migration. Rebase on `dev` after PR #63. Ship with a CHANGELOG line. Rollback is a plain revert.

## Open Questions

- Should `ensure_validated_*` live in `_validation.py` only, or also be re-exported in `cryptainer/__init__.py` for `operations.py` and the CLI (internal re-export, undocumented)?
- Count validations in tests via a `mock.patch` on `_validate_data_tree`, or via a module-level counter? (Prefer `mock.patch`.)
