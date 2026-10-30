## Purpose

Defines how wacryptolib picks its cryptographic backend: native pycryptodome by default, a pure-Python fallback on platforms that can't load native code. It also defines the guarantees that both backends expose the same operations, produce mutually compatible data, and conform to official test vectors.

## ADDED Requirements

### Requirement: Default installation uses the native backend
A default installation of the library (without extras or special flags) SHALL install pycryptodome. It SHALL NOT install the pure-Python fallback packages. Installing the `fallbacks` extra SHALL install every third-party package the fallback backend imports.

#### Scenario: Plain install
- **WHEN** the library is installed with a standard installer and no extras
- **THEN** pycryptodome is installed, and none of the fallback-only packages is installed

#### Scenario: Fallbacks extra
- **WHEN** the library is installed with the `fallbacks` extra
- **THEN** every third-party package imported by the fallback backend is installed as well

### Requirement: Backend selection at import time
The library SHALL use the native backend when pycryptodome is importable and its native code loads. Otherwise it SHALL use the pure-Python fallback backend. The choice SHALL be made once, at import time, SHALL be exposed as a readable backend name, and SHALL be logged. An environment variable SHALL force the fallback backend even when pycryptodome is available. The fallback backend SHALL NOT import pycryptodome. The native backend SHALL NOT alter pycryptodome's modules or behaviour.

#### Scenario: pycryptodome available
- **WHEN** the library is imported in an environment where pycryptodome and its native code load
- **THEN** the backend name is the native one, and no attribute of any pycryptodome module differs from its value before the import

#### Scenario: pycryptodome absent
- **WHEN** the library is imported in an environment where pycryptodome is not importable
- **THEN** import succeeds, the backend name is the fallback one, and no pycryptodome module is loaded

#### Scenario: pycryptodome installed but its native code can't load
- **WHEN** pycryptodome's Python sources are importable but loading its native code fails
- **THEN** the fallback backend is selected at import time, instead of an error at first use

#### Scenario: Forced fallback
- **WHEN** the force-fallback environment variable is set before import
- **THEN** the fallback backend is selected even though pycryptodome is available

#### Scenario: Fallback packages missing too
- **WHEN** neither pycryptodome nor the fallback packages are importable
- **THEN** import of the library fails with an error that names both installation options

### Requirement: Identical public surface
Both backends SHALL expose the same set of public names. Where the fallback backend has no implementation for an operation or a parameter (NIST-curve ECC), calling it SHALL raise `NotImplementedError` with a message that names the operation and states that it requires pycryptodome. For every failure that the native backend reports as `ValueError` (bad padding, failed decryption, failed tag or signature verification, unparsable or wrongly-protected PEM), the fallback backend SHALL also raise `ValueError`, and SHALL NOT write anything to standard output or standard error.

#### Scenario: Name parity
- **WHEN** the public names of both backends are compared
- **THEN** they are identical

#### Scenario: Unsupported operation in fallback
- **WHEN** NIST-curve ECC key generation, PEM import or DSS signature is requested from the fallback backend
- **THEN** `NotImplementedError` is raised, mentioning the operation and pycryptodome

#### Scenario: Same error type on failure
- **WHEN** a tampered RSA-OAEP ciphertext is decrypted, a tampered signature is verified, or a PEM is imported with a wrong or missing passphrase, on either backend
- **THEN** both backends raise `ValueError`, and the fallback prints nothing

### Requirement: Cross-backend interoperability
For every operation implemented by both backends, data produced by one backend SHALL be accepted by the other and give the same result. This covers symmetric ciphertexts and tags, RSA-OAEP ciphertexts, HPKE encapsulations, RSA-PSS and DSA signatures, and PEM-serialized RSA, DSA and X25519 keys, passphrase-protected or not.

#### Scenario: Symmetric ciphers
- **WHEN** a plaintext of length 0, 1, 15, 16, 17 or 1000 bytes is encrypted by one backend with AES-CBC, AES-EAX or ChaCha20-Poly1305
- **THEN** the other backend decrypts it to the same plaintext and validates its tag, and with the same key and IV/nonce both backends produce identical ciphertexts and tags

#### Scenario: Streaming encryption
- **WHEN** a plaintext is fed in several chunks (block-aligned for AES-CBC) to the cipher objects returned by either backend's AES-CBC, AES-EAX and ChaCha20-Poly1305 builders
- **THEN** the concatenated output and the final tag equal those of a one-shot encryption by the other backend

#### Scenario: RSA-OAEP and HPKE
- **WHEN** a key struct is encrypted with RSA-OAEP (SHA-512) or HPKE X25519 by one backend
- **THEN** the other backend decrypts it with the matching private key

#### Scenario: PEM keys
- **WHEN** an RSA, DSA or X25519 keypair is generated and exported to PEM by one backend, with or without passphrase
- **THEN** the other backend imports both keys, and the imported keys work for that backend's encryption or signature operations

#### Scenario: Legacy passphrase-protected PEM
- **WHEN** an RSA private key PEM protected with PBKDF2-HMAC-SHA1 and AES-256-CBC (the format written by earlier library versions) is imported with its passphrase by the fallback backend
- **THEN** the imported key equals the one the native backend imports from the same PEM

#### Scenario: Signatures
- **WHEN** a message is signed with RSA-PSS or DSA by one backend
- **THEN** the other backend verifies the signature, and rejects it after a single bit flip

#### Scenario: Tamper detection is consistent
- **WHEN** an authenticated ciphertext or tag is altered and decrypted with integrity verification by either backend
- **THEN** both backends raise `ValueError` and neither returns plaintext

### Requirement: Conformance to official test vectors
Every primitive of every available backend SHALL reproduce the official known-answer test vectors for the exact parameters the library uses, wherever such vectors are published (NIST, IETF RFC). Where no official vector matches the library's parameters, the corresponding Wycheproof vectors SHALL be used instead. A primitive with no published vector at all SHALL be covered by the interoperability requirement alone, and the test suite SHALL record that explicitly.

#### Scenario: Known-answer vectors
- **WHEN** the conformance tests run for a backend
- **THEN** each hash, cipher, key agreement, KEM and signature construction yields exactly the published outputs, decryption of published ciphertexts yields the published plaintexts, and every published invalid case is rejected

#### Scenario: DSA vectors
- **WHEN** the NIST CAVP FIPS 186-4 DSA signature verification vectors for L=2048 with SHA-512 are run on a backend
- **THEN** every vector marked as passing verifies and every vector marked as failing is rejected

#### Scenario: Backend unavailable
- **WHEN** a backend's packages are not installed in the test environment
- **THEN** that backend's conformance and interoperability tests are skipped with a reason naming the missing package, and the other backend's tests still run
