## Why

On platforms where pycryptodome's native code can't load (iOS forbids `dlopen()`, MicroPython has no extensions at all), `_crypto_backend/pycryptodome.py` currently monkey-patches pycryptodome's internals (`__monkey_patch_pycryptodome_compiled_internals`). It fakes the raw libs, swaps hashers, plugs `pyaes` under `AES.new` and replaces `oaep_decode`. That approach breaks whenever pycryptodome's private internals change. It still requires pycryptodome's Python sources to be installed. It also only works if it runs before any other `Crypto.*` import.

The pure-Python packages it relies on (`rsa`, `pkcs1`, `pyaes`) are mandatory dependencies today, even on desktop, where they are never used. A clean separation gives two things. Desktop installs ship only pycryptodome. Constrained platforms get an explicit, self-contained pure-Python backend that never imports `Crypto`, and that backend is checked against pycryptodome and against official test vectors.

## What Changes

- **BREAKING (packaging)**: `rsa`, `pkcs1` and `pyaes` stop being mandatory dependencies. They move to a new `fallbacks` extra (`pip install wacryptolib[fallbacks]`). `pycryptodome` stays a mandatory dependency, so a default install is unchanged for desktop users. Platforms that can't install pycryptodome install wacryptolib with `--no-deps` plus the fallback packages and the other runtime dependencies they need. This procedure is documented.
- **BREAKING (internal)**: remove `__monkey_patch_pycryptodome_compiled_internals`, the `ios` import probe and the `_patch_pycryptodome_internals` flag. `_crypto_backend/pycryptodome.py` becomes a plain pycryptodome wrapper with no import-time side effects.
- `_crypto_backend/__init__.py` selects one backend at import time. It uses pycryptodome when its native code loads. Otherwise it uses a new `_crypto_backend/fallback/` package. `FORCE_WACRYPTOLIB_FALLBACK_BACKEND` still forces the fallback, as a test hook. `get_random_bytes` and Shamir stay in `__init__.py`, shared by both backends (they are already pure Python).
- New package `_crypto_backend/fallback/` (it replaces `fallback_adapter.py`). It exposes exactly the same public names as `pycryptodome.py`. It is built from the `fallbacks` extra packages, the existing vendored modules (`vendor/chacha20_poly1305.py`, `hpke_x25519_seal.py`) and small new vendored modules where no acceptable PyPI package exists (AES-EAX, classic DSA). Coverage: hashes, AES-CBC, AES-EAX, ChaCha20-Poly1305, RSA (keygen, OAEP-SHA512, PSS-SHA512), DSA (keygen, DSS FIPS 186-3), X25519/HPKE, and PEM import/export of RSA, DSA and X25519 keys with or without passphrase. NIST-curve ECC raises `NotImplementedError` with an explicit message.
- New tests, skipped when their backend's packages are missing:
  - **Conformance**: every primitive of every available backend is checked against official known-answer vectors (NIST CSRC hash examples, NIST SP 800-38A, NIST CAVP FIPS 186-4 DSA, RFC 7748, RFC 8439, RFC 9180), plus Wycheproof where NIST/RFC have nothing for the exact parameters the library uses.
  - **Interoperability**: output of each backend is consumed by the other (encrypt↔decrypt, sign↔verify, PEM export↔import).
  - **API parity**: both backends expose the same public names.
- New tox environment that runs the backend-level tests with pycryptodome uninstalled.

## Capabilities

### New Capabilities
- `crypto-backends`: choosing between the native (pycryptodome) and pure-Python cryptographic backends, keeping their public surface the same, making them interoperate, and making them conform to official test vectors. It also covers how each kind of platform installs them.

### Modified Capabilities
- (none: no existing specs under `openspec/specs/`)

## Impact

- `pyproject.toml`, `poetry.lock`, `pip_requirements_export.txt`: optional deps plus the `[tool.poetry.extras] fallbacks` entry.
- `src/wacryptolib/_crypto_backend/__init__.py`, `pycryptodome.py`: backend selection, and the monkey patch removed.
- `src/wacryptolib/_crypto_backend/fallback_adapter.py` → `src/wacryptolib/_crypto_backend/fallback/__init__.py`, plus `vendor/aes_eax.py`, `vendor/dsa.py`, `fallback/pem.py`, and an `open()` in `hpke_x25519_seal.py`.
- Callers (`cipher.py`, `keygen.py`, `signature.py`, `hash.py`, `keystore.py`, `trustee.py`): no change expected; they only use `isinstance` against the key-class fetchers, `key.curve`, `size_in_bits()`/`bit_size`, and hasher `update()`/`digest()` (see design D3).
- `tests/_test_mockups.py`: `is_fallback_backend()` reads the selected backend instead of the removed `_patch_pycryptodome_internals`.
- `tests/`: new conformance, interop and parity test modules. Existing `test_pkcs1_cryptography_interop.py` / `test_chacha20_poly1305_fallback.py` / `test_hpke_x25519_seal.py` are folded in.
- `tox.ini`: fallback test environment.
- `Readme.rst` / `CHANGELOG`: installation on constrained platforms, coverage table.
- `micropython/`: unchanged. It keeps its own `fallback_adapter.py` copy and the `vendor_dependencies.py` lock lookup keeps working.
- Users who install with plain `pip install wacryptolib` see no behaviour change. Anyone who relied on `FORCE_WACRYPTOLIB_FALLBACK_BACKEND` with the old patched-pycryptodome semantics now gets the new fallback package, which no longer supports NIST-curve ECC or legacy PEM protections other than the ones listed in design D3.
