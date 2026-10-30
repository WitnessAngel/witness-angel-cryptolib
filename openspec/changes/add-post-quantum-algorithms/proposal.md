## Why

Cryptainers are meant to be stored for years, so every symmetric key wrapped today with `RSA_OAEP` and every `RSA_PSS` / `ECC_DSS` payload signature is exposed to harvest-now-decrypt-later attacks once a large quantum computer exists. pycryptodome, the lib's only crypto dependency, shipped ML-DSA (4.1.0, 2026-10-19) and ML-KEM + HPKE (4.2.0, 2026-10-24), so post-quantum support is now a dependency bump plus registry entries rather than a new native dependency. See `docs/audits/post_quantum_algorithms_report.md` for the algorithm selection rationale.

## What Changes

- Add `ML_KEM_768` (FIPS 203) as an asymmetric key algorithm and as a `key_cipher_algo` for wrapping symmetric key structs, using a KEM + DEM construction (encapsulation plus AEAD wrap) via pycryptodome's HPKE.
- Add `ML_DSA_65` (FIPS 204) as an asymmetric key algorithm and as a `payload_signature_algo`, signing the existing SHA-512 digest with a fixed context string.
- Keypair generation, PEM import/export, keystore storage and trustee public-key fetching work for the two new algorithms exactly as for RSA/ECC keys (PKCS#8 / SPKI PEM per RFC 9935 and RFC 9881).
- Fix the filesystem keystore filename regex, which currently only accepts letters and underscores in `key_algo` and would silently skip `ML_KEM_768` / `ML_DSA_65` key files when listing keypairs.
- Classical + post-quantum hybrid wrapping is obtained by stacking an `RSA_OAEP` layer then an `ML_KEM_768` layer in `key_cipher_layers` (this order keeps key ciphertexts small); no composite KEM is added.
- Lift the "only RSA_OAEP" assertion in the trustee API so any registered asymmetric cipher can decrypt key structs.
- Bump `pycryptodome` to `^4.2`.
- No change to hash algorithms or symmetric ciphers (already quantum-safe at 256-bit keys).
- Out of scope: the MicroPython flightbox port of ML-KEM encapsulation (separate change), SLH-DSA / FN-DSA / HQC, and Authenticator UI defaults for hybrid keypairs.

## Capabilities

### New Capabilities
- `post-quantum-key-encapsulation`: generating ML-KEM-768 keypairs, wrapping and unwrapping symmetric key structs with them in cryptainers, and composing them with classical layers for hybrid protection.
- `post-quantum-signature`: generating ML-DSA-65 keypairs and producing / verifying timestamped payload signatures with them.

### Modified Capabilities
- (none: no existing specs under `openspec/specs/`)

## Impact

- `src/wacryptolib/keygen.py`, `cipher.py`, `signature.py`: registry entries.
- `src/wacryptolib/_crypto_backend/__init__.py` and `pycryptodome.py`: thin wrappers around `Crypto.PublicKey.MLKEM`, `Crypto.PublicKey.MLDSA`, `Crypto.Signature.mldsa`, `Crypto.Protocol.HPKE`.
- `src/wacryptolib/trustee.py`: remove the RSA_OAEP-only assertion.
- `src/wacryptolib/keystore.py`: allow digits in the `key_algo` part of `PUBLIC_KEY_FILENAME_REGEX`.
- `pyproject.toml`, `poetry.lock`, `pip_requirements_export.txt`: pycryptodome 4.2+.
- `docs/selected_protocols.rst`, `docs/api/keygen.rst`, `docs/api/cipher.rst`, `CHANGELOG`: document the new algorithms. CLI choices, validation schemas and `SUPPORTED_*` autodata entries derive from the registries and need no edit.
- Tests parametrized over `SUPPORTED_*` lists pick the new algos up automatically (one error-message matcher must be widened); new tests cover cipherdict shape, hybrid cryptainer round-trip, keystore listing and a committed fixture cryptainer.
- Downstream: cryptainers using the new algos are unreadable by older wacryptolib versions. No format version bump: older versions reject them with a `SchemaValidationError` when the cryptainer is validated first (as the CLI does), and with an assertion failure in the decryptor otherwise; neither path can produce silently wrong plaintext. The Authenticator and other apps need pycryptodome 4.2 wheels on Android/iOS.
