## Context

- Asymmetric ciphers live in `CIPHER_ALGOS_REGISTRY` (cipher.py), and their keys live in `ASYMMETRIC_KEY_ALGOS_REGISTRY` (keygen.py). CLI choices, validation schemas and keystore pools derive from the `SUPPORTED_*` lists.
- The locked pycryptodome is 3.23. It provides `Crypto.Protocol.HPKE` (RFC 9180, Base/Auth/PSK modes) and X25519 keys (`ECC.generate(curve="curve25519")`). The existing `generate_ecc_keypair`, `import_ecc_key_from_pem` and `export_ecc_key_to_pem` (with the PBKDF2-SHA256 PKCS#8 protection) already handle X25519 keys. This was checked locally: PEM round-trip, and seal/unseal with both ChaCha20-Poly1305 and AES-256-GCM.
- HPKE accepts any `EccKey`, so key-type and curve checking can't be delegated to it.
- `trustee.py:decrypt_with_private_key` asserts `cipher_algo == "RSA_OAEP"`. `keystore.PUBLIC_KEY_FILENAME_REGEX` rejects digits in `key_algo`.
- The MicroPython flightbox (`micropython/`) has no pycryptodome. It only **encrypts** key structs with trustee public keys, which are stored as raw parameters in `keystore_data` (RSA uses `{"n", "e"}`). It already vendors a pure-Python ChaCha20-Poly1305 (`_crypto_backend/chacha20_poly1305.py`), pyaes, `hmac` and `hashlib`. On that platform `hmac.compare_digest` is a non-constant-time stub.
- The pending `add-post-quantum-algorithms` change wraps keys with HPKE too, using the same cipherdict shape.

## Goals / Non-Goals

**Goals:**
- One elliptic-curve cipher that is robust (standardized, IND-CCA2, with official vectors), needs no new dependency on CPython, and can be ported to MicroPython as pure Python.
- A MicroPython output that is byte-compatible with pycryptodome's HPKE, and proven so by tests.
- CPython HPKE helpers generic enough for `ML_KEM_768` to reuse.

**Non-Goals:**
- Decryption on MicroPython (the flightbox never holds private keys).
- NIST curves, HPKE Auth/PSK modes, non-empty `info`/AAD, multi-message HPKE contexts.
- Streaming payload encryption (`encryption_node_class=None`, like RSA_OAEP).

## Decisions

**D1. "ECIES" = HPKE Base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 (suite 0x0020/0x0001/0x0003), empty info and AAD.**
HPKE is the IETF-standardized form of ECIES (KEM + key schedule + AEAD), with a security proof and test vectors. It is already in the locked pycryptodome. Alternatives rejected:
- eciespy: secp256k1 through the coincurve C extension, an ad-hoc format, and unusable on MicroPython.
- PyNaCl `SealedBox`: adds libsodium, and would need pure-Python XSalsa20 and BLAKE2b on MicroPython.
- Hand-rolled ECDH + KDF + AES-EAX: re-implements HPKE's key schedule without its vectors.

**D2. AEAD: ChaCha20-Poly1305 rather than AES-256-GCM.** This was recommended by an independent review agent, and is kept as the rationale:
1. *No new MicroPython crypto code.* The pure-Python ChaCha20-Poly1305 already exists, is tested (`tests/test_chacha20_poly1305_fallback.py`), and is vendored to the device. AES-256-GCM would need a new pure-Python GHASH (GF(2^128) multiplication) and GCM framing on top of pyaes, plus its own vectors.
2. *Side channels.* ChaCha20 and Poly1305 are add-rotate-xor and bigint arithmetic, while pyaes is table-lookup AES (cache and flash timing leaks). Exposure is low either way: the key is ephemeral per seal and the device only seals, so the `compare_digest` stub doesn't matter. ChaCha is still the safer default on a microcontroller.
3. *An official vector exists.* RFC 9180 Appendix A.2 is exactly DHKEM(X25519) + HKDF-SHA256 + ChaCha20-Poly1305. There is no Appendix A vector for X25519 + AES-256-GCM: A.1 is AES-128-GCM, and AES-256-GCM only appears with P-521. That gives the MicroPython port a known-answer test that doesn't depend on pycryptodome.
4. *Same security margin, and hardware acceleration doesn't matter here.* Both use a 256-bit key and a 128-bit tag. HPKE single-shot seal uses a fresh key and nonce per message, so nonce-misuse and key-commitment differences don't arise. Decrypting 100 to 300 bytes takes microseconds with either C backend.
5. *Mobile builds behave the same.* pycryptodome's HPKE calls `ChaCha20_Poly1305.new` or `AES.MODE_GCM`, and both are plain C extensions in the python-for-android and kivy-ios recipes.

Follow-up for `add-post-quantum-algorithms`: its D2 picked AES-256-GCM because it is "HPKE default, hardware accelerated", which doesn't matter for 300-byte seals. Its D9 requires the MicroPython port to honor that AEAD, which would mean writing GHASH anyway. That change should switch to ChaCha20-Poly1305 while it is still pending, so the device has a single AEAD code path. Switching after release would need a new algorithm name.

**D3. Algorithm name `ECIES_X25519`, with every parameter fixed by the name.** This follows `AES_EAX` / `ML_KEM_768`. The AEAD, KDF and curve aren't stored in the cipherdict, so changing any of them means a new name. `generation_extra_parameters=[]`, so `curve`/`key_length_bits` are never forwarded.

**D4. Cipherdict `{"kem_ciphertext": enc (32 B), "ciphertext": seal output (len + 16 B)}`.** This is the same shape as `ML_KEM_768` (PQ design D3), so corruption-test helpers and future shared code apply unchanged. Registry flags: `is_authenticated=True`, `encryption_node_class=None`. The decryption function accepts and ignores `verify_integrity_tags`, since HPKE always verifies. Any `ValueError` (bad tag, bad key type) surfaces as `EncryptionError`/`DecryptionError` through the existing wrappers.

**D5. CPython backend: generic `encrypt_via_hpke(plaintext, public_key, aead_id)` / `decrypt_via_hpke(enc, ciphertext, private_key, aead_id)` in `pycryptodome.py`.** The cipher.py functions check `isinstance(key, EccKey) and key.curve == "Curve25519"` themselves and raise `ValueError` otherwise, because HPKE would silently accept a P-256 key. The key functions reuse the existing ECC ones.

**D6. MicroPython backend: new pure-Python module `_crypto_backend/hpke_x25519_seal.py`.** It is shared through `SHARED_MODULES` in `micropython/vendor_dependencies.py`, with `chacha20_poly1305.py` added there as well. Its only imports are `hashlib`, `hmac` and `os`. It contains:
- the RFC 7748 X25519 Montgomery ladder, with clamping and a check that rejects an all-zero shared secret;
- HKDF-SHA256 extract/expand over `hmac`, plus HPKE `LabeledExtract`/`LabeledExpand` with `suite_id`;
- `seal(receiver_public_key_bytes, plaintext, ephemeral_private_key=None) -> (enc, ciphertext)`, which uses `os.urandom(32)` when no key is injected. Injection exists only so the known-answer test can run.

It lives in `src/` rather than `micropython/` so CPython tests can import it directly and check it against pycryptodome. The flightbox keystore stores the raw 32-byte public key (`{"x25519": bytes}`), mirroring the raw `{"n", "e"}` used for RSA, so the device needs no PEM/ASN.1 parsing.

**D7. Trustee assertion and keystore regex.** These are the same edits as PQ D7/D10: `assert cipher_algo.upper() in SUPPORTED_ASYMMETRIC_CIPHER_ALGOS`, and `key_algo` group `[_a-zA-Z0-9]+`. Whichever change merges second drops them.

**D8. Dependency bound `pycryptodome >= 3.23`.** The lock already has 3.23. The PQ change will later raise it to `^4.2`.

## Risks / Trade-offs

- [Pure-Python bigint X25519 isn't constant-time] → Only the ephemeral scalar is exposed, and only to local timing or power observers of the device, which the flightbox threat model already concedes for pyaes. This is flagged with a `ponytail:` comment and in the docs.
- [A port mistake in the key schedule would silently produce undecryptable cryptainers] → It is caught by the RFC 9180 A.2 known-answer test, by a round-trip from the pure seal into pycryptodome unseal in CI, and by a flightbox-produced cryptainer decrypted on CPython.
- [The pure ChaCha20-Poly1305 module rejects AAD] → HPKE here never uses AAD (D1). The wrapper never passes it, and seals only once per context (nonce = `base_nonce`, seq 0).
- [Overlap with `add-post-quantum-algorithms` (trustee, keystore, HPKE helpers)] → The edits are identical and the helpers are generic, so whichever change lands second just drops the duplicates.
- [Older wacryptolib versions can't read ECIES cryptainers] → They fail at schema validation or at an assertion, and never produce wrong plaintext. Same situation as for ML-KEM.

## Migration Plan

This is purely additive: no default cryptoconf changes. To roll back, drop the registry entries. Cryptainers already written with `ECIES_X25519` would then become unreadable, so roll back only before any release that includes it.
