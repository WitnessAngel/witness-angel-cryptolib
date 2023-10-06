
Cryptolib concepts
=======================

*To avoid too long variable name, and to disambiguate words like "key" which have too many different meanings (symmetric key, asymmetric key, usb key, index key...), this library introduces its own set of terms, in addition to those already widely used in cryptography (cipher, signature, hash...).*


Different digital keys
+++++++++++++++++++++++++++++

Lots of different "keys" and related concepts are used cryptolib code, so we use more precise terms when relevant.

A **key-algo** is a reference to either an encryption scheme (symmetric or asymmetric), or to a signature scheme (always asymmetric).
In some parts of the code, when the purpose of the key is already sure, the names "cipher-algo" or "signature-algo" are used instead.

A **keypair** is a dict containing both "public" and "private" keys, for use in an asymmetric cipher or signature. Depending on the situation, these keys can be python objects, or serialized as PEM bytestrings (the private key being then possibly passphrase-protected. Keypairs are meant to be identified by a pair of [keychain_uid, key_algo] references (since for security, a keypair should indeed only be used for a single purpose). A *keychain* is thus of set of keypairs having a common UUID, but each used for a different purpose/algorithm.

A **symkey** is a dict containing all parameters required to configure a symmetric encryption/decryption cipher. Typically, it means a binary "secret key", and additional fields like "initialization vector" or "nonce", depending on the symmetric key-algo concerned. These symkeys are meant to be randomly generated, immediately protected by asymmetric ciphers, and stored along the encrypted data - as usual in a hybrid cryptosystem. Symkeys are anonymous.

When a bytestring (typically a serialized symkey) is split via a "Shamir shared secret" scheme, we refer to the different parts as **shards** (and not "shares", the other possible name). However, symkeys and their shards are often all called "symkeys" in the code, when the difference doesn't matter (e.g. when issuing decryption authorization requests).

Note that inside configurations and containers, we mostly use the term **key**, since the context should make it clear what exactly is at stake (mostly symmetric keys or their shards being encrypted via miscellaneous algorithms)


Data naming and integrity
++++++++++++++++++++++++++++

We use **payload** to designate the actual content of recorded data (audio, video, gps...), at various stages of its encryption process.

We use **cleartext** and **ciphertext** to differentiate *BINARY* (not actual text) data before and after its encryption; although, since we're in a multi-layered encryption scheme, the ciphertext of an encryption layer becomes the cleartext for the next one.

The word **digest** is used, instead of "hash", to name the short bytestring obtained by hashing a payload. This digest can then be used as the "message" on which a timestamped signature is applied by a trustee, offering of proof of payload integrity and anteriority.
The term **mac** (message authentication code) is used, instead of "tag", to designate a short bytestring which might be obtained at the end of a symmetric encryption operation. This bytestring offers of proof of the payload integrity, and also authenticity (i.e. it was well encrypted with the provided secret key).
Those digests and macs can be considered all together as **integrity tags**.

Only when dealing with bytestrings that could be anything (serialized key, serialized json, final encrypted payload...), for example in filesystem utilies, we use the all-embracing term **data**.


Keypair repositories
+++++++++++++++++++++++++

A **keystore** is a generic storage for asymmetric keypairs. Its is typically a set of public/private PEM files in a directory. Keys can be a predetermined and immutable set, or on the contrary generated on demand; private keys can be present or not, protected by passphrases or not; a JSON metadata file describing this repository (type, owner, unique id...) can be present or not; it all depends on the subtype of the keystore.

The **local-keyfactory keystore** is the default keystore available on recording devices, as well as **server trustees** (see below). It can generate keypairs on demands, and typically doesn't protect them with passphrases.

An **authenticator** is a subtype of keystore used to provide a digital identity keychain to a trusted third party (typically an individual). It is a fixed set of keypairs, all protected by the same passphrase, with some additional authentication fields in a metadata file. An **authdevice**, or authentication device, is a physical device on which an authenticator can be stored (for now, we use a simple folder at the root of an usb storage), if it is not simply stored in a local disk.

Authenticators can publish their public keys, and public metadata, to a **web gateway** - a simple online registry - so that other people may easily access them.

When keystores are **imported** from an authdevice or a web gateway, the imported copies naturally only contains a part (public, or at least without confidential information) of the initial authenticator.


Trusted parties
+++++++++++++++++++++

The data encrypted inside a cryptainer relies on multiple actors to protect itself from unwanted access.

Each of these actors is commonly designated as a **trustee** in the code. A trustee offers a set of standard services: providing public keys for encryption, delivering messages signatures, and treating requests for data decryption.

A recorder device has a **local-keyfactory trustee**, backed by the local-keyfactory keystore, which can encrypt and sign data using its own generated-on-demand digital keys.

But real protection is provided by trustees also called **key guardians**, which are *trusted third parties*. Access to these remote trustees is generally done via Internet, even if other channels (e.g. usb devices temporarily plugged in) can be used too. For now, these remote trustees can be **server trustees** (e.g. a database-backed keystore administrated by an association), or **authenticator trustees** (e.g. an individual having an authenticator keystore on his smartphone).


Cryptainers and cryptoconfs
++++++++++++++++++++++++++++++++++++++++++

For more information on these concepts, see the :doc:`dedicated page <cryptainer_explanations>`.


