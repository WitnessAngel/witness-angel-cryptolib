## Why

`RSA_OAEP` is the only asymmetric cipher for wrapping key structs (issue #40). RSA keys are big and slow to generate, and the pure-Python RSA path is a heavy load on the MicroPython flightbox. Pycryptodome has no "ECIES" as such, but the locked version (3.23) ships HPKE (RFC 9180). HPKE is the standardized, IND-CCA2 successor of ad-hoc ECIES constructions, and it has official test vectors. That means a robust elliptic-curve cipher can be added without any new dependency, and it can be ported to MicroPython as encryption-only pure Python, then cross-validated against pycryptodome.

## What Changes

- Add `ECIES_X25519` as an asymmetric key algorithm, with X25519 keypairs. Generation, PEM import/export with passphrase protection, keystore storage and trustee public-key fetching all work like they do for other asymmetric keys.
- Add `ECIES_X25519` as a `key_cipher_algo`. It is HPKE Base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305, with empty `info` and empty AAD. The cipherdict is `{"kem_ciphertext", "ciphertext"}`, the same shape as the pending `ML_KEM_768` layer.
- Add a pure-Python, encryption-only implementation of that HPKE suite for the MicroPython flightbox. It reuses the existing pure-Python ChaCha20-Poly1305. It is verified against the RFC 9180 / RFC 7748 vectors and against pycryptodome's decryption.
- Lift the "only RSA_OAEP" assertion in the trustee API, so any registered asymmetric cipher can decrypt key structs.
- Allow digits in the `key_algo` part of the keystore public key filename regex.
- Raise the `pycryptodome` lower bound to 3.23, the first version with `Crypto.Protocol.HPKE`. The lock file already has it.
- Out of scope: other curves (P-256 etc.), HPKE Auth/PSK modes, and streaming payload encryption with ECIES.

## Capabilities

### New Capabilities
- `ecies-key-encapsulation`: generating X25519 keypairs, wrapping and unwrapping key structs with them in cryptainers on desktop/mobile, and wrapping them on the MicroPython flightbox, in an interoperable format.

### Modified Capabilities
- (none: no existing specs under `openspec/specs/`)

## Impact

- `src/wacryptolib/keygen.py`, `cipher.py`: registry entries.
- `src/wacryptolib/_crypto_backend/pycryptodome.py`, `__init__.py`: generic HPKE seal/open wrappers, reusable by `ML_KEM_768` later.
- New `src/wacryptolib/_crypto_backend/hpke_x25519_seal.py`: a pure-Python seal, shared with MicroPython through `micropython/vendor_dependencies.py`.
- `micropython/flightbox_utilities_implementation.py`: the new cipher algo and the loading of raw X25519 public keys.
- `src/wacryptolib/trustee.py`, `keystore.py`: assertion and regex fixes. These overlap with `add-post-quantum-algorithms`, and whichever change lands first ships them.
- `pyproject.toml`, `pip_requirements_export.txt`: pycryptodome bound.
- `docs/selected_protocols.rst`: protocol description.
- Downstream: older wacryptolib versions can't read cryptainers that use `ECIES_X25519`. They reject them at schema validation or at an assertion, and never produce wrong plaintext.
