

Overview of Algorithms
===============================

This document describes the different technologies available in modern cryptography, in particular the selected algorithms and their worthy or obsolete alternatives.


Invariants
----------------

Unless specified otherwise, UTF8 is assumed as the encoding of all text data.

When a serialization format doesn't natively support binary strings (e.g. Json), binary strings must be encoded with Base-64 by default.

Preferably use keyword-only arguments in APIs, to ensure a better forward-compatibility of the client.


Safety and performance rules
--------------------------------

- Signatures and miscellaneous digests should be computed on ciphertexts (encrypted payloads), not plaintext (initial data). Attempting decryption on crafted payloads is indeed an important attack vector, so integrity checks should occur before decryption, thanks to proper signatures and digests. We shall rely on modern ciphers with AEAD (for Authenticated Encryption with Associated Data) to have both *confidentiality* and *integrity* in the same process.

- Security resides in the cryptosystem as a whole, not in individual algorithms. So it's more important to ensure that each workflow step is immune to main attack vectors, than to relentlessly seek safer algorithms and longer keys.

- Algorithms used should be part of easily accessible headers, not embedded into layers of multi-encrypted data. It is indeed more important to review these selected algorithms and detect broken/obsolete ones, than to hide them from potential attackers to protect ciphertexts through obscurity.

- Compression of content must occur BEFORE encryption, since ciphertexts naturally have much higher entropy than plaintext. In particular, media data can often achieve high compression ratio at the cost of some accuracy loss.


Hashing
-----------

Cryptographic hash functions take arbitrary binary strings as input, and produce a random-like fixed-length output (called digest or hash value). It is practically infeasible to derive the original input data from the digest. In other words, the cryptographic hash function is one-way (pre-image resistance). Given the digest of one message, it is also practically infeasible to find another message (second pre-image) with the same digest (weak collision resistance).

.. autodata:: wacryptolib.utilities.SUPPORTED_HASH_ALGOS
   :noindex:


Signature
------------

Signature is used to guarantee integrity and non-repudiation. Digital signatures are based on public key cryptography: the party that signs a message holds the private key, the one that verifies the signature holds the public key.

- PSS (Probabilistic Signature Scheme) : The algorithm used to sign a plaintext is almost the same as the one used to cipher a plaintext in RSA; except that the private key is used to sign, and the public key to check if the signature is authentic.

- DSS (Digital Signature Standard): This algorithm works in the framework of DSA public-key cryptosystems and is based on the algebraic properties of modular exponentiation, together with the discrete logarithm problem, which is considered to be computationally intractable. The algorithm uses a key pair consisting of a public key and a private key. The private key is used to generate a digital signature for a message, and such a signature can be verified by using the signer's corresponding public key. The digital signature provides message authentication (the receiver can verify the origin of the message), integrity (the receiver can verify that the message has not been modified since it was signed) and non-repudiation (the sender cannot falsely claim that they have not signed the message). Also works with ECC keys, based on elliptic curves.


Asymmetric ciphers
-------------------

- RSA (Rivest–Shamir–Adleman) is one of the first public-key cryptosystems and is widely used for secure data transmission. In such a cryptosystem, the encryption key is public and it is different from the decryption key which is kept secret (private). In RSA, this asymmetry is based on the practical difficulty of the factorization of the product of two large prime numbers, the "factoring problem".
  A user of RSA creates and then publishes a public key based on two large prime numbers, along with an auxiliary value. The prime numbers must be kept secret. Anyone can use the public key to encrypt a message, but with currently published methods, and if the public key is large enough, only someone with knowledge of the prime numbers can decode the message feasibly. Breaking RSA encryption is known as the RSA problem. Whether it is as difficult as the factoring problem remains an open question. OAEP (Optimal Asymmetric Encryption Padding) is the padding scheme we use together with RSA encryption.


Symmetric ciphers
---------------------

- AES with CBC (cipher block chaining) mode. This mode applies a XOR operation between each block of plaintext and the previous ciphertext block, before encrypting it. As a result, the entire validity of all preceding blocks is contained in the immediately previous ciphertext block. It uses an initialization vector (IV) of a certain length.

- AES with EAX (encrypt-then-authenticate-then-translate) mode : it is an Authenticated Encryption with Associated Data (AEAD) algorithm designed to simultaneously provide both authentication and privacy of the message.
  The reference implementation uses AES in CTR mode for encryption combined with AES OMAC for authentication.
  EAX is a two-pass scheme, which means that encryption and authentication are done in separate operations.
  This algorithm has several desirable attributes, notably:

    - provable security (dependent on the security of the underlying primitive cipher);
    - message expansion is minimal, being limited to the overhead of the tag length;
    - using CTR mode means the cipher need to be implemented only for encryption, in simplifying implementation of some ciphers (especially desirable attribute for hardware implementation);
    - the algorithm is "on-line", that means that can process a stream of data, using constant memory, without knowing total data length in advance;
    - the algorithm can process static Associated Data (AD), useful for encryption/decryption of communication session parameters (where session parameters may represent the Associated Data).

- ChaCha20 with Poly1305: while this algorithm is mainly used for encryption, its core is a pseudo-random number generator. The cipher text is obtained by XOR'ing the plain text with a pseudo-random stream. Provided you never use the same nonce with the same key twice, you can treat that stream as a one time pad. This makes it very simple: unlike block ciphers, you don't have to worry about padding, and decryption is the same XOR operation as encryption. The Poly1305 authenticator prevents the insertion of fake messages into the stream.


