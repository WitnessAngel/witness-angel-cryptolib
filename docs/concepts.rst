
Concepts
=============

*To avoid too long variable name, and to disambiguate words like "key" which have too many different meanings (symmetric key, asymmetric key, usb key, index key...), this library introduces its own set of terms, in addition to those already widely used in cryptography (cipher, signature, hash...).*


Trusted parties
------------------

The data encrypted by our **Flightbox cryptosystem** relies on multiple actors to protect itself from unwanted access.

Each of these actors is commonly designated as a **trustee** in the code. A trustee offers a set of standard services: providing public keys for encryption, delivering messages signatures, and treating requests for data decryption.

A witness angel device is itself a **local keyfactory trustee**, it can encrypt and sign data using its own digital keys.

But real protection is provided by trustees called **keyguardians**, which are trusted third parties. Access to these remote trustees is generally done via Internet, even if other channels (e.g. usb devices temporarily plugged in) can be used too.


Digital keys
-----------------

A **key-algo** is a reference to either an encryption scheme (symmetric or asymmetric), or a signature scheme (always asymmetric).
In some parts of the code, when the purpose is already sure, the names "cipher-algo" or "signature-algo" might be used instead.

A **symkey** is a dict containing all parameters required to configure a symmetric encryption/decryption cipher. Typically, it means a binary "secret key", and additional fields like "initialization vector" or "nonce" depending on the symmetric key_algo concerned. These symkeys are meant to be randomly generated, immediately protected by asymmetric ciphers, and stored along the encrypted data - as usual in a hybrid cryptosystem. Symkeys are anonymous.

A **keypair** is a dict containing both "public" and "private" keys, for use in an asymmetric cipher or signer. Depending on the situation, these keys can be python objects, or serialized as PEM bytestrings (the private key being possibly passphrase-protected. Keypairs are meant to be identified by a pair of [keychain_uid, key_algo] references (since for security, a keypair should indeed only be used for a single purpose).


Data naming and integrity
-------------------------------

We use **payload** to designate the actual content of recorded data (audio, video, gps...), at various stages of its encryption process. We use **cleartext** and **ciphertext** to differentiate data before and after its encryption, although, since we're in a multi-layered encryption scheme, the ciphertext of an encryption layer becomes the cleartext for the next one.

The word **digest** is used, instead of "hash", to name the short bytestring obtained by hashing a payload. This digest can then be used as the "message" on which a timestamped signature is applied by a trustee, offering of proof of payload integrity and anteriority.
The term **mac** (message authentication code) is used, instead of "tag", to designate a short bytestring which might be obtained at the end of a symmetric encryption operation. This bytestring offers of proof of the payload integrity, and also authenticity (i.e. it was well encrypted with the provided secret key).
Those digests and macs can be considered all together as **integrity tags**.

When a bytestring (typically a serialized symkey) is split in a "Shamir shared secret" scheme, we refer to the parts of the secret as **shards** (and not "shares").

Only when dealing with bytestrings that could be anything (serialized key, serialized json, final encrypted payload...), for example in filesystem utilies, we use the all-embracing term **data**.


Key repositories
-----------------

A **keystore** is a generic storage for keypairs: typically a set of public/private PEM files in a directory, with a JSON metadata file describing this repository (type, owner, unique id...). Keys can be "frozen" or on the contrary generated on demand, private keys can be present or not, they can be protected by passphrases or not, depending on the subtype of the keystore.

The **local-factory keystore**, which backs the local-factory trustee, can generate keyairs on demands, and typically doesn't protect them with passphrases.

An **authenticator** is a subtype of keystore used to provide a digital identity keychain to a trusted third party. It is typically a set of keypairs, all protected by the same passphrase, with some additional authentication fields in the metadata file. An **authdevice**, or authentication device, is a physical device on which an authenticator can be stored. For, we use a simple folder at the root of an usb storage.

Authenticators can publish their public keys, and public metadata, to a **gateway** - a simple online registry - so that other people may easily rely on them as keyguardian.

When keystores are **imported** from an authdevice or a web gateway, the imported copies naturally only contain a part (public, or at least without confidential information) of the initial authenticator.


Encrypted containers
-------------------------

The word **cryptainer** refers to encrypted containers built with this library.

The structure of these cryptainers is driven

More information in the :doc:`cryptainer format <cryptainer_format>` document.


