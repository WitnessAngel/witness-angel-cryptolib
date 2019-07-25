

Overview of Algorithms
===============================

This document describes he different technologies available in modern cryptography, in particular the selected algorithms and their worthy or obsolete alternatives.


Invariants
----------------

Unless specified otherwise, UTF-8 is assumed as the encoding of all text data.

When a serialization format doesn't natively support binary strings (e.g. Json), binary strings must be encoded with Base-64 by default.


Safety and performance rules
--------------------------------

- Signatures and miscellaneous digests should be computed on ciphertexts (encrypted payloads), not plaintext (initial data). Attempting decryption on crafted payloads is indeed an important attack vector, so integrity checks should occur before decryption, thanks to proper signatures and digests. We shall rely on modern ciphers with AEAD (for Authenticated Encryption with Associated Data) to have both *confidentiality* and *integrity* in the same process.

- Security resides in the cryptosystem as a whole, not in individual algorithms. So it's more important to ensure that each workflow step is immune to main attack vectors, than to relentlessly seek safer algorithms and longer keys.

- Algorithms used should be part of easily accessible headers, not embedded into layers of multi-encrypted data. It is indeed more important to review these selected algorithms and detect broken/obsolete ones, than to hide them from potential attackers to protect ciphertexts through obscurity.

- Compression of content must occur BEFORE encryption, since ciphertexts naturally have much higher entropy than plaintext. In particular, media data can often achieve high compression ratio at the cost of some accuracy loss.


Hashing
-----------


Signature
------------



Asymmetric ciphers
-------------------



Symmetric ciphers
---------------------


