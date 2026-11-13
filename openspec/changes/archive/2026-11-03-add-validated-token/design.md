## Context

State after PR #63 (line numbers of `fix/cipher-layers-non-emptiness`):

- `check_cryptoconf_sanity()` is called by `CryptainerEncryptor._generate_cryptainer_base_and_secrets()` (the choke point of `encrypt_data()` and `build_cryptainer_and_encryption_pipeline()`), and before it by CLI `encrypt` (`cli.py:411`) and `operations.___encrypt_payload_to_bytes()` (`operations.py:134`): two validations per encryption on those paths. It is also called by CLI `cryptoconf generate-simple` output (`cli.py:470`) and `cryptoconf validate` (`cli.py:617`), whose purpose is validation.
- `check_cryptainer_sanity()` is called strictly by `CryptainerDecryptor.decrypt_payload()`, leniently (`require_inline_payload=False`) by `gather_decryptable_symkeys()`, and explicitly by CLI `cryptainer validate` (`cli.py:834`) and `ReadonlyCryptainerStorage.check_cryptainer_sanity()`.
- `CryptainerStorage` passes `default_cryptoconf` (unvalidated, may be `None`) through `_resolve_cryptoconf()` to `create_cryptainer_encryption_stream()`, `enqueue_file_for_encryption()` (worker threads, errors logged and swallowed by `@catch_and_log_exception`) and `encrypt_file()`, so it is validated once per file by the encryptor.
- The decryptor keeps an in-flow guard duplicating the schema ("Empty key_cipher_layers list is forbidden in cryptainer", `_decryptor.py:480`).
- `_flightbox.py` is dependency-injection-only: a diverged copy (`reimplementations/micropython/flightbox.py`) runs on MicroPython and must import nothing. In `cryptainer/__init__.py`, `_analysis` is imported **before** `_validation` (hence PR #63's lazy import in `gather_decryptable_symkeys`); `_decryptor`, `_encryptor`, `_storage` come after.

## Goals / Non-Goals

**Goals:**
- Validate each cryptoconf/cryptainer once per process path, and make forgetting validation hard.
- Keep every public signature unchanged and every valid input accepted.
- Tokens remember validation at construction time.

**Non-Goals:**
- Soundness against mutation after tagging: no frozen/immutable tree, and malicious in-process code may forge or break a tag.
- A stable serialized form for tokens (pickle/`copy.copy` keep the subclass but are not used by the library).
- Any change to the MicroPython flightbox.

## Decisions

**D1: dict subclasses as tags.** `class ValidatedCryptoconf(dict)` and `class ValidatedCryptainer(dict)` (with an `inline_payload_checked: bool` attribute, defaulting to False so that the no-arg constructor still works, as python-`schema` calls `type(data)()` when validating a dict subclass). They stay `dict` for `json.dumps`/extjson (which rebuilds plain dicts), indexing and `isinstance(x, dict)` (python-`schema` and `jsonschema` both accept subclasses). *Alternatives rejected:* a marker key (serialized, forgeable from a JSON file, pollutes the schema); an `id()` registry or `WeakSet` (plain dicts are not weakref-able and ids are reused); a content-fingerprint cache (hashing a large tree costs about as much as validating it).

**D2: Snapshot at validation, tag by construction.** `ensure_validated_cryptoconf(x)` returns `x` itself if it is already a `ValidatedCryptoconf`; else it calls `check_cryptoconf_sanity(x)`, then returns `ValidatedCryptoconf(copy.deepcopy(x))`. The snapshot protects the token from later mutation of the caller's original dict (cheap for cryptainers too: `deepcopy` shares immutable `bytes`); it is not a defence against mutating the token itself (accepted). `check_*_sanity()` stay token-unaware and always validate.

**D3: `__deepcopy__` returns a plain dict.** Without it, `copy.deepcopy(validated_cryptoconf)` in the flightbox would produce a cryptainer base typed as a validated cryptoconf. `dict.copy()` (used by `dump_cryptainer_to_filesystem`), `dict(token)` and extjson conversion already return plain dicts; `copy.copy` and pickle keep the subclass and attribute, which is harmless (unused by the library).

**D4: Strictness lives on the cryptainer token.** `ensure_validated_cryptainer(x, require_inline_payload=True)`: a token passes if `token.inline_payload_checked or not require_inline_payload`; otherwise it is re-validated (with the requested strictness) and a new token returned. This keeps `gather_decryptable_symkeys` lenient and decryption strict while still validating once for the common strict flow. Python-schema mode only (`jsonschema_mode` stays a `check_cryptainer_sanity()` feature).

**D5: Where tokens are created and consumed.**

```
 raw dict --ensure_validated_cryptoconf--> ValidatedCryptoconf
      CLI encrypt / CryptainerStorage (__init__, _resolve_cryptoconf) / Encryptor choke point
                          |
                          v
        CryptainerEncryptor._generate_cryptainer_base_and_secrets --> FlightBox (token-agnostic)
                          |   deepcopy => plain dict, mutated (payload, signatures, MACs, state)
                          v
        encrypt_data() returns ValidatedCryptainer(inline_payload_checked=True), no re-validation
        (pipeline / build_cryptainer_and_encryption_pipeline output stays untagged: only dumped to disk)
                          |
          dump_to_json / filesystem ==> untagged ==> ensure_validated_cryptainer in decrypt_payload / gather
```

- Choke points call `ensure_*` and use its return value: `_generate_cryptainer_base_and_secrets()` (cryptoconf), `decrypt_payload()` (strict cryptainer), `gather_decryptable_symkeys()` (lenient, return values discarded since they are not passed on). Everything public reaches one of them, so no extra `assert isinstance` is needed downstream.
- `CryptainerStorage.__init__` ensures `default_cryptoconf` if not `None`; `_resolve_cryptoconf()` ensures the per-call cryptoconf, covering its three callers. The shared token is only read (deep-copied by the flightbox) by worker threads, which is thread-safe.
- CLI `encrypt` replaces its `check_cryptoconf_sanity` by `cryptoconf = ensure_validated_cryptoconf(cryptoconf)` (still fails before storage/keystore setup, and the storage/encryptor then no-op); `operations.py` drops its check. `cryptoconf generate-simple`, both `validate` commands and `ReadonlyCryptainerStorage.check_cryptainer_sanity()` keep their explicit `check_*` calls.
- The decryptor removes the guard made unreachable by the upfront check; `FlightBox` keeps its own (it is the only guard on MicroPython).

**D6: FlightBox stays token-agnostic.** The shared design constraint (no imports, dependency injection) means `FlightBox` cannot reference the token classes. The CPython `CryptainerEncryptor` is the only CPython caller and guarantees the token. Direct `FlightBox` use with a raw dict stays unvalidated (documented), which is the accepted residual risk.

**D7: Cryptainer lifecycle.** Only `encrypt_data()` tags its output, once finished (inline payload, signatures, MACs, `FINISHED` state), as strict: mid-flight mutation by library code is part of building the structure. The invariant "valid cryptoconf => valid cryptainer" also relies on `cryptainer_metadata` being a dict or `None`, which `FlightBox` only `assert`s (vanishes under `python -O`), so the encryptor checks it explicitly before tagging.

**D8: The `ensure_validated_*` helpers are public.** They are defined in `_validation.py`, re-exported from `wacryptolib.cryptainer`, and documented, so that `operations.py`, the CLI and library users can validate once and pass the result to several operations. The token classes are importable too (they are what the helpers return), but using them stays optional: every public function keeps accepting plain dicts.

**D9: Tests count validation calls with `mock.patch`.** Patch `wacryptolib.cryptainer._validation._validate_data_tree` (the module global used by `check_*_sanity`; patching the package-level name would miss it and would count the decryptor's operation-report validations instead) with `wraps=`, and count calls whose `validation_schema` is `CRYPTOCONF_SCHEMA_PYTHON` or `CRYPTAINER_SCHEMA_PYTHON`.

**D10: Debug-only mutation guard.** Tokens may optionally carry a digest of their tree, computed at tagging time and re-checked where a token is consumed, only when a debug switch is on (an env var set by the test suite; zero cost otherwise). The digest is a recursive walk hashing with `hashlib.blake2b`, hashing `bytes` values directly (no `repr` of a large ciphertext) and tagging each node type so values cannot collide. A mismatch raises, flagging an in-process mutation of a validated tree. It is a developer aid, not a security feature. The encryptor's legitimate mutations happen before tagging (D7), so no re-seal step is needed.

**D11: `CryptainerStorage` fails early.** Validating `default_cryptoconf` at construction and an explicit cryptoconf at `enqueue_file_for_encryption()` (both via `_resolve_cryptoconf()`) means an invalid cryptoconf raises to the caller instead of being logged and swallowed by a worker thread. Accepted by the maintainer, together with the snapshot side effect: editing the original `default_cryptoconf` dict after construction no longer affects the storage.

## Risks / Trade-offs

- [Tag lies if someone mutates a token] → Accepted by decision; documented in docstrings. JSON serialization and deepcopy always drop the tag.
- [Snapshot deepcopy cost at ingress] → One copy per entry instead of repeated schema validations; the storage-level token amortizes it across files.
- [Strictness bugs: a lenient token leaking into decryption] → D4 and a dedicated test.
- [Earlier errors in `CryptainerStorage`] → An invalid cryptoconf now raises from the constructor or from `enqueue_file_for_encryption()` (caller thread) instead of being logged in the worker; a caller mutating its `default_cryptoconf` dict after construction no longer affects the storage (snapshot). Documented in CHANGELOG; sensor test fakes must use a valid cryptoconf.
- [Import-order fragility in `cryptainer/__init__.py`] → Tokens live in `_validation.py`; `_encryptor`, `_decryptor`, `_storage` import them from the package (loaded after `_validation`), `_analysis` keeps a lazy import; nothing imported from `_flightbox`.
- [Behavior drift while removing guards] → Remove a guard only if a test proves the upfront check refuses the same input with a `SchemaValidationError`.

## Migration Plan

Internal refactor; no data or API migration. Rebase on `dev` after PR #63. Ship with a CHANGELOG line. Rollback is a plain revert.

## Open Questions

(none: helper visibility and test counting are resolved by D8 and D9)

Not verified here: downstream apps (Authenticator, Revelation Station) may build `CryptainerStorage` with dummy cryptoconfs in their own tests, which D11 would now refuse. Check them when releasing.
