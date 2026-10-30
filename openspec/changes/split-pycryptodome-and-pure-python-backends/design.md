## Context

- `_crypto_backend/__init__.py` re-exports names from `pycryptodome.py`. `get_random_bytes` (`os.urandom`) and Shamir (`vendor/PycryptodomeSecretSharing.py`, pure Python, no `Crypto` import) are defined there and are already backend-independent: they stay there and need no parity or interop tests.
- When `import ios` succeeds or `FORCE_WACRYPTOLIB_FALLBACK_BACKEND` is set, `pycryptodome.py` monkey-patches `Crypto.Util._raw_api`, `strxor`, the `Crypto.Hash.*` classes, `BLAKE2s`, `AES.new` (pyaes adapter), `ChaCha20_Poly1305.new` (vendored) and `PKCS1_OAEP.oaep_decode`. Everything pycryptodome implements in pure Python on top of those patches (EAX, PSS, PEM/ASN.1, DSA via `Integer`) therefore kept working.
- `fallback_adapter.py` holds a partial pure-Python backend (hashlib hashers, pyaes CBC, pkcs1/rsa OAEP, RSA keygen, unencrypted RSA PEM import). Nothing imports it except `tests/test_pkcs1_cryptography_interop.py`. A diverged copy is used by `micropython/flightbox_utilities_implementation.py`, which never touches PEM: it receives raw `n`/`e` and raw X25519 bytes.
- `tests/_test_mockups.py::is_fallback_backend()` imports `_patch_pycryptodome_internals` from `pycryptodome.py`, and is used by keygen/signature/cryptainer tests.

### What callers actually need from backend objects (verified by grep of `src/wacryptolib`)

| Caller | Uses |
|---|---|
| `cipher.py` RSA-OAEP | `key.size_in_bits()` **or** `key.bit_size` (already falls back to pkcs1's attribute) |
| `cipher.py` ECIES_X25519 | `isinstance(key, ecc_key_class_fetcher())` and `key.curve == "Curve25519"` |
| `cipher.py` `EncryptionNodeBase` | cipher `encrypt()` returning `bytes`; `digest()` for EAX/ChaCha; calls `finalize()` **if the attribute exists** and appends its output |
| `cipher.py`, `hash.py`, `signature.py` | hasher `update()` / `digest()` only |
| `signature.py` | `isinstance(key, *_key_class_fetcher())`; passes an already-fed SHA-512 **hasher object** (not bytes) as `message` to `sign_with_*`/`verify_with_*`; catches only `ValueError` |
| `keygen.py`, `keystore.py`, `trustee.py`, `operations.py`, `cryptainer/` | only go through `generate_*_keypair` and `import_/export_*_key_*_pem`; never call `export_key`, `has_private`, `publickey` directly. `keygen.load_asymmetric_key_from_pem_bytestring` converts only `ValueError`/`IndexError`/`TypeError` to `KeyLoadingError`; `trustee` tries `passphrase=None` first on encrypted PEMs and relies on that error |

So no wrapper classes are needed around pkcs1 keys, and no caller changes.

## Goals / Non-Goals

**Goals:**
- Two independent backends with the same public names. The fallback never imports `Crypto`.
- The fallback covers every algorithm the library exposes: hashes, AES-CBC, AES-EAX, ChaCha20-Poly1305, RSA-OAEP-SHA512, RSA-PSS-SHA512, DSA-DSS, ECDSA (ECC_DSS on NIST curves), HPKE-X25519, RSA/DSA/NIST-ECC/X25519 keygen, and PEM import/export of all these keys including the library's own PBES2 passphrase format (needed on iOS, which generates keys and exports them with a passphrase, like authenticators do).
- Tests that pin both backends to official vectors and to each other.

**Non-Goals:**
- Legacy PEM protections other than PBES2/PBKDF2 (HMAC-SHA1 or HMAC-SHA256) with AES-128/256-CBC. In particular DES-EDE3-CBC (written for DSA keys by versions before commit `f4992a1`) and OpenSSL `Proc-Type` headers raise `ValueError` in the fallback (see open question).
- Running the whole existing test suite under the fallback backend.
- Changing `micropython/` (its `fallback_adapter.py` stays a separate copy).
- Constant-time guarantees for the fallback (impossible with Python bigints). Documented, not solved.

## Decisions

### D1. Packaging: optional deps + `fallbacks` extra
```toml
pkcs1 = { version = "^0.9.7", optional = true }
pyaes = { version = "^1.6.1", optional = true }
ecdsa = { version = "^0.19.2", optional = true }

[tool.poetry.extras]
fallbacks = ["pkcs1", "pyaes", "ecdsa"]
```
`[tool.poetry.extras]` is the right syntax here: `pyproject.toml` uses the legacy `[tool.poetry]` layout (no `[project]` table) with an unpinned `poetry-core`, and both poetry-core 1.x and 2.x read it there. `rsa` is removed from `pyproject.toml` (and with it `pyasn1` from `poetry.lock`): its only uses were PKCS#1/SPKI RSA PEM parsing/writing, now done by `fallback/pem.py`'s DER codec (D3). No DSA package is added (see D3); `ecdsa` (MIT, pure Python, maintained, only depends on `six`) covers NIST-curve ECC. Constrained platforms install `wacryptolib --no-deps` plus an explicit list documented in the Readme (the extra's packages and the non-native runtime deps).

`pip_requirements_export.txt` (used by `tox.ini` and `wacryptolib_installer.py`) is regenerated with `poetry export --with dev --all-extras`, so it keeps listing `pkcs1`/`pyaes` and the main tox envs run the interop tests instead of skipping them. `micropython/vendor_dependencies.py` keeps working for optional packages (they stay in `poetry.lock`), but `rsa`/`pyasn1` leave its `PACKAGES` list since they are no longer locked: `micropython/patches/pyasn1.patch` is deleted, and the dead `import_rsa_key_from_pem` of `micropython/fallback_adapter.py` (the flightbox only imports `encrypt_via_rsa_oaep`/`encrypt_via_aes_cbc`, with raw `n`/`e`) is removed.

*Alternatives:* PEP 771 default extras (still Draft, unsupported); splitting the distribution (two packages to publish, deferred).

### D2. Selection in `_crypto_backend/__init__.py`
```python
def _native_backend_usable():
    if os.getenv("FORCE_WACRYPTOLIB_FALLBACK_BACKEND"):
        return False
    try:
        from Crypto.Cipher import AES  # Module body dlopen()s Crypto.Cipher._raw_aes via load_pycryptodome_raw_lib
    except (ImportError, OSError):
        return False
    return True
```
Then `from .pycryptodome import *` or `from .fallback import *`, `BACKEND_NAME = "pycryptodome" | "fallback"`, and one INFO log. Both modules define `__all__`. An `ImportError` from `.fallback` is re-raised with a message naming both install options.

The probe must import a *public* module that loads native code. `import Crypto.Cipher._raw_aes` (previous draft) is wrong: `_raw_aes.abi3.so` is a ctypes/cffi library, not a Python extension, so importing it always raises `ImportError` and the native backend would never be selected. `Crypto.Cipher.AES` calls `load_pycryptodome_raw_lib("Crypto.Cipher._raw_aes", ...)` at import time, which raises `OSError("Cannot load native module ...")` when `dlopen()` fails (iOS). This replaces the `import ios` probe.

*Alternative rejected:* per-function fallback (mixes key object types in one process).

### D3. Fallback package
```
_crypto_backend/fallback/__init__.py   # public API, same __all__ as pycryptodome.py
_crypto_backend/fallback/pem.py        # minimal DER TLV codec + PKCS#8/SPKI/PBES2 wrappers
_crypto_backend/vendor/aes_eax.py      # NEW: OMAC1 + CTR over a single-block encrypt callable
_crypto_backend/vendor/dsa.py          # NEW: classic DSA keygen + FIPS 186-3 sign/verify
_crypto_backend/hpke_x25519_seal.py    # + open()
```
- **Hashes**: plain `hashlib` objects. Callers only use `update()`/`digest()`, so `HasherCompatibilityLayer` (`oid`, `new()`, only needed by patched pycryptodome) is dropped.
- **AES-CBC**: a ~10-line object over `pyaes.AESModeOfOperationCBC`, feeding it 16 bytes at a time, with `encrypt()` and `decrypt()` like pycryptodome's, and **no `finalize` attribute** (otherwise `EncryptionNodeBase` would append its output). One-shot functions pad with `utilities.data_utils.pad_bytes_pkcs7`/`unpad_bytes_pkcs7` (import is safe: `wacryptolib.utilities` imports `_crypto_backend` but only uses it in dead code).
- **AES-EAX**: `vendor/aes_eax.py`, about 60 lines, block cipher = `pyaes.AES(key).encrypt`. Cipher object with `encrypt`, `decrypt`, `digest`, `verify` (raises `ValueError`), `encrypt_and_digest`; 16-byte tag; nonce of any length.
- **ChaCha20-Poly1305**: `vendor/chacha20_poly1305.py` as is (no AAD support, none needed).
- **RSA keys**: pkcs1 objects unchanged: `RsaPublicKey(n, e)` and `MultiPrimeRsaPrivateKey(primes=[p, q], e)` (what `generate_key_pair` returns; CRT + blinding). `rsa_key_class_fetcher()` returns `(RsaPublicKey, MultiPrimeRsaPrivateKey)` (the current adapter returns `RsaPrivateKey`, which would no longer match). PEM import reads `n, e, p, q` with the DER codec and builds them directly; export computes `d = e⁻¹ mod lcm(p-1, q-1)` (pycryptodome uses the same λ-based `d`, so frozen fixtures match byte for byte; verify, else use φ) and the CRT values `dP, dQ, qInv`, then writes the PKCS#1 `RSAPrivateKey` SEQUENCE (version 0, n, e, d, p, q, dP, dQ, qInv) with the DER codec.
- **RSA-OAEP-SHA512**: encrypt via `pkcs1.rsaes_oaep.encrypt(hash_class=sha512)` (it forwards the hash to MGF1). Decrypt is **not** `pkcs1.rsaes_oaep.decrypt`: besides not forwarding `hash_class` to MGF1, it `print()`s padding bytes and raises distinguishable exceptions (`ValueError` vs `DecryptionError`), i.e. a padding oracle. Instead, ~15 lines of EME-OAEP decoding (RFC 8017 §7.1.2) over `key.rsadp()` and `pkcs1.mgf.mgf1(hash_class=sha512)`, raising one `ValueError("Incorrect decryption.")` for every failure.
- **RSA-PSS-SHA512**: `pkcs1.rsassa_pss.sign/verify` with `hash_class=hashlib.sha512`, and `mgf1=functools.partial(pkcs1.mgf.mgf1, hash_class=hashlib.sha512)`, because pkcs1's EMSA-PSS calls `mgf(h, len)` without the hash, i.e. MGF1-SHA1 (verified: such signatures fail pycryptodome's `pss.verify`, the bound version passes both ways). Salt length defaults to the digest length, as in pycryptodome's `pss.new`. pkcs1 hashes `message` itself, but `signature.py` passes an already-fed hasher, so pass that hasher as `message` with `hash_class=lambda data=b"": data if data is hasher else hashlib.sha512(data)` (EMSA-PSS only calls `hash_class(message).digest()` and `hash_class(m_prime).digest()`); a `ponytail:` comment names this coupling, and the Wycheproof/interop tests catch any pkcs1 change. `verify` returns `False` or raises pkcs1 exceptions: both become `ValueError`.
- **DSA**: no acceptable PyPI package exists (checked 2026-10): `pydsa` 0.14 (2018, unmaintained, no keygen, Python 2 idioms, `random` module); `tlslite-ng`'s `Python_DSAKey` (LGPL-2.1, pulls the whole TLS stack plus `ecdsa`, and its `generate_qp` loop is inverted (`if (p-1) % q: break`), so it yields invalid domain parameters); `ecdsa` only does ECDSA/EdDSA. So `vendor/dsa.py`, about 70 lines, no dependency:
  - keygen with pycryptodome's (L, N) table (2048→224, 3072→256): random N-bit prime q, then search p = 2kq+1 of L bits, g = h^((p-1)/q) mod p for h = 2, 3, … until g > 1, x random in [1, q-1]. Primality via Miller-Rabin with `os.urandom` bases. Not the seeded A.1.1.2 procedure: pycryptodome doesn't check seeds on import, and its own import checks (p, q prime, q | p-1, g^q ≡ 1, sizes) pass.
  - sign: digest truncated to the leftmost N bits, k random in [1, q-1] from `os.urandom` (pycryptodome's `fips-186-3` mode is randomized too, so signatures are verify-compatible, not byte-equal), output `r ‖ s` as two N/8-byte big-endian integers (pycryptodome's default `binary` encoding). A `k` keyword exists for known-answer tests only.
  - verify: range checks 0 < r, s < q, raises `ValueError`.
  - import checks the same domain conditions as pycryptodome, raising `ValueError`.
  - key class `DsaKey(p, q, g, y, x=None)`; `dsa_key_class_fetcher()` returns it.
- **X25519 / HPKE**: `hpke_x25519_seal.seal` for encryption; add `open(receiver_private_key, enc, ciphertext)` reusing `_derive_key_schedule` (the DH is symmetric). Key class with `curve = "Curve25519"` and raw 32-byte keys; `ecc_key_class_fetcher()` returns it. `generate_ecc_keypair` accepts `"curve25519"` only. `encrypt_via_hpke`/`decrypt_via_hpke` raise `NotImplementedError` for an `aead_id` other than ChaCha20-Poly1305.
- **PEM** (`fallback/pem.py`): every structure the library writes is fixed, so a ~40-line DER TLV reader/writer (INTEGER, OCTET STRING, BIT STRING, NULL, OID, SEQUENCE) is enough, without `pyasn1`/`rsa`. It handles all formats below, RSA included. Formats:
  - RSA: private PKCS#1 `RSA PRIVATE KEY` (what pycryptodome writes without passphrase), public SPKI `PUBLIC KEY`; unencrypted PKCS#8 `PRIVATE KEY` accepted on import.
  - DSA: PKCS#8 `PRIVATE KEY` and SPKI `PUBLIC KEY` with `Dss-Parms` (what pycryptodome writes).
  - X25519: PKCS#8 `PRIVATE KEY` (fixed 16-byte DER prefix `302e020100300506032b656e04220420`) and SPKI `PUBLIC KEY` (12-byte prefix `302a300506032b656e032100`), as pycryptodome writes them.
  - Passphrase: `ENCRYPTED PRIVATE KEY` PBES2 envelope, written exactly like `pycryptodome.py` (PBKDF2-HMAC-SHA256, 600 000 iterations, AES-256-CBC, same iteration bound and same single error message). On import, PRF HMAC-SHA1 (also when absent) or HMAC-SHA256 and AES-128/256-CBC are accepted, so RSA keys written by earlier versions (`PBKDF2WithHMAC-SHA1AndAES256-CBC`) still load. Any other protection, a wrong passphrase, a missing passphrase on an encrypted PEM, or malformed DER raise `ValueError` (never codec-internal or pkcs1 exception types).
  - `pycryptodome.py` keeps its own `Crypto.Util.asn1` code: the native backend stays a plain pycryptodome wrapper, and the interop tests plus a PEM fixture keep both byte-compatible.
- **NIST ECC / ECDSA** (`ecdsa` package): `generate_ecc_keypair` maps pycryptodome's curve names (`p256`/`P-256`/`secp256r1`/`prime256v1`, same for p192/p224/p384/p521) to `ecdsa` curves, other unknown names raise `ValueError("Unexisting ECC curve ...")` like pycryptodome. Keys are `ecdsa.SigningKey`/`VerifyingKey`; `ecc_key_class_fetcher()` returns `(X25519Key, SigningKey, VerifyingKey)` (an `ecdsa` key's `curve` is never `"Curve25519"`, so ECIES_X25519 still rejects them). PKCS#8/SPKI DER via `ecdsa`'s `to_der(format="pkcs8")`/`from_der()`, inside the shared PEM armor and PBES2 envelope. `sign_with_dss` signs the SHA-512 digest with `sign_digest_deterministic` (RFC 6979, `allow_truncate=True` for leftmost-bits truncation as FIPS 186-4 requires, `sigencode_string`, i.e. pycryptodome's `binary` r ‖ s); verify raises `ValueError`. DSS on an X25519 key raises `ValueError`, like pycryptodome.

### D4. Tests
A `backend` fixture in `tests/conftest.py`, parametrised over `pycryptodome`/`fallback`, imports the backend module directly (bypassing the selector) and calls `pytest.skip` naming the missing package.

- `tests/test_crypto_backend_parity.py`: `__all__` equality; `NotImplementedError` messages; `ValueError` on failures and nothing printed (`capsys`).
- `tests/test_crypto_backend_vectors.py`: known-answer tests through the public backend functions unless stated. Vectors are inlined as hex with a source comment (Wycheproof/CAVP: a handful of valid and invalid cases each, never downloaded at test time).

  | Primitive | Source |
  |---|---|
  | SHA-256, SHA-512, SHA3-256, SHA3-512 | NIST CSRC "Examples with Intermediate Values" (`abc` and the 448-bit message) |
  | AES-256-CBC (raw, via `build_aes_cbc_encrypter`) | NIST SP 800-38A F.2.5 (CBC-AES256.Encrypt) and F.2.6 (CBC-AES256.Decrypt) |
  | AES-256-EAX, 16-byte nonce, no header | Wycheproof `testvectors_v1/aes_eax_test.json`, keySize 256, ivSize 128, empty `aad` (valid and invalid). The EAX paper vectors are AES-128 with a header, so they don't match the library's parameters |
  | ChaCha20 keystream | RFC 8439 §2.4.2 (vendored-module level; `vendor/chacha20_poly1305.py` has no raw ChaCha20 API, so test via the AEAD keystream as the existing test does) |
  | ChaCha20-Poly1305 AEAD, 12-byte nonce, no AAD | Wycheproof `testvectors_v1/chacha20_poly1305_test.json`, empty `aad`, ivSize 96. RFC 8439 §2.8.2 and A.5 both use AAD, which neither the library nor the vendored cipher supports |
  | X25519 | RFC 7748 §5.2 (incl. 1 and 1000 iterations), §6.1 (vendored-module level, since keys are wrapped) |
  | HPKE DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 | RFC 9180 A.2.1 (Base mode) at key-schedule level: `enc`, `key`, `base_nonce` with the vector's `info`. The vector's encryptions use AAD, so the library's empty-info/AAD end-to-end path is covered by interop only |
  | RSA-OAEP-SHA512 (MGF1-SHA512, empty label), decryption | Wycheproof `testvectors_v1/rsa_oaep_2048_sha512_mgf1sha512_test.json` |
  | RSA-PSS-SHA512 (MGF1-SHA512, salt 64), verification | Wycheproof `testvectors_v1/rsa_pss_4096_sha512_mgf1_64_test.json` (no 2048-bit file exists for these parameters; the key size doesn't change the code path) |
  | DSA verification | NIST CAVP FIPS 186-4 DSA (`186-3dsatestvectors.zip`), `SigVer.rsp` sections `[mod = L=2048, N=224, SHA-512]` and `[mod = L=2048, N=256, SHA-512]`. The library always signs SHA-512 digests, so SHA-256 sections are not used |
  | DSA signing | same zip, `SigGen.txt` (includes `K`), same sections: `vendor/dsa.py` with injected `k` must give the published `R`, `S` (fallback only; pycryptodome's randomized mode can't take `k`) |
  | ECDSA verification | NIST CAVP FIPS 186-4 ECDSA (`186-4ecdsatestvectors.zip`), `SigVer.rsp` sections `[P-256,SHA-512]`, `[P-384,SHA-512]`, `[P-521,SHA-512]` |
  | RSA/DSA/X25519 keygen, PEM | no published vector: interop only, plus a PEM fixture produced once by today's pycryptodome code (recorded with a comment) |
- `tests/test_crypto_backend_interop.py`: requires both backends, skipped otherwise. Covers every interop scenario of the spec, both directions.
- Absorb `test_chacha20_poly1305_fallback.py`, `test_hpke_x25519_seal.py` and `test_pkcs1_cryptography_interop.py` (keeping the `cryptography`-based OAEP check as an optional third reference via `importorskip`).
- `tests/_test_mockups.py::is_fallback_backend()` returns `_crypto_backend.BACKEND_NAME == "fallback"`.
- `tox.ini`: env `py311-fallback` running `pip install -r ../pip_requirements_export.txt`, `pip uninstall -y pycryptodome`, then `pytest test_crypto_backend_*.py test_wacryptolib_cipher.py test_wacryptolib_hash.py test_wacryptolib_signature.py test_wacryptolib_keygen.py` (the last two already skip ECC via `skip_if_fallback_backend`).

### D5. `pycryptodome.py` cleanup
Remove the patch function (including its inner `PyaesCipherAdapter`), the `ios` probe and `_patch_pycryptodome_internals`; drop the `os`/`sys` imports; add `__all__`. Nothing else in `src/` references these names.

## Risks / Trade-offs

- [Fallback lacks DES3/legacy-OpenSSL PEMs] → Explicit `ValueError`, Readme coverage table. Desktop unaffected.
- [`ecdsa` is not constant-time either (its README says so)] → same caveat as the rest of the fallback, documented.
- [Users who imported `rsa`/`pyasn1`/`pkcs1`/`pyaes` transitively] → BREAKING entry in CHANGELOG.
- [Hand-written DER parsing of untrusted PEMs] → strict TLV reader (definite lengths only, no trailing bytes, length bounds checked, non-negative minimal INTEGERs), malformed-DER cases from Wycheproof-style mutations in tests, single `ValueError`.
- [Optional deps missing from a default `poetry install`] → tox/CI install via `pip_requirements_export.txt` exported with `--all-extras`; the interop module asserts in the main env that both backends loaded (fails rather than skips when `CI` is set).
- [Two PEM/DER code paths] → byte-level interop tests both ways, plus a frozen pycryptodome-made fixture.
- [pkcs1 call-pattern coupling for PSS prehashing] → Wycheproof + interop tests; pkcs1 is pinned in `poetry.lock`.
- [Pure-Python DSA keygen is slow (2048-bit p search: seconds on desktop, possibly a minute on phones)] → keygen is rare (keystore setup); documented.
- [Fallback timing side channels] → documented; OAEP decrypt at least collapses all errors to one.
- [Probe relies on `Crypto.Cipher.AES` loading native code at import] → the selection test asserts `BACKEND_NAME == "pycryptodome"` in the main env, so a pycryptodome change fails loudly rather than silently selecting the fallback.

## Migration Plan

1. Add the fallback package, vendored modules and tests while the monkey patch still exists (selector not wired).
2. Wire the selector, delete the monkey patch, update `_test_mockups.py`, make dependencies optional.
3. Regenerate `poetry.lock` / `pip_requirements_export.txt`, update tox, Readme and CHANGELOG.
Rollback: revert. No data format change: both backends read and write the same bytes.

## Open Questions

Resolved in this design: probe module (D2), PSS/OAEP pkcs1 pitfalls (D3), Wycheproof file names (D4), DSA approach (D3), PBKDF2 vector dropped (both backends use `hashlib.pbkdf2_hmac`, testing it would test the stdlib).

Decided by the user (2026-10-30): iOS needs keygen and passphrase-protected PEM export; legacy DES3-protected DSA PEMs are not supported; `ecdsa` is added for NIST-curve ECC; `rsa`/`pyasn1` are dropped.
- Later: replace `micropython/fallback_adapter.py` by vendored copies of `_crypto_backend/fallback/` (the DER codec makes it MicroPython-friendly, no `pyasn1` needed). Not part of this change.
