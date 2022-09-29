
Discover cryptainers
============================

Overview
+++++++++++++++++++++++++++++++++

A **cryptainer** is a flexible, recursive structure dedicated to hybrid encryption: each piece of data is encrypted one or several times in a row, and the "keys" (random symmetric keys, or shards obtained from a shared secret algorithm) used for these encryption operations become themselves pieces of encryptable data, thus repeating the process.

This gives a tree of protected data, in which the leaves are "trustees" relying on asymmetric (public key) encryption algorithms to protect intermediate "keys", and thus secure the encrypted payload.

This structure allows for some nice features:

- Fine-grained permission system: a complex mix of "mandatory" and "optional" trustees can protect the data together
- Auditability: chosen algorithms and other metadata are clearly exposed, allowing anyone to check that security level is sufficient
- Evolutive encryption: if some algorithms become unsafe, or if a storage wants to add an additional level of safety, it is easy to strengthen the cryptainer by adding some layers of encryption/signature in chosen parts of its tree.

The structure of a cryptainer is driven by a configuration tree called a **cryptoconf**.

A cryptoconf actually defines the *skeleton* of a cryptainer. During encryption, this structure will be filled with ciphertexts, integrity tags, signatures, and miscellaneous metadata to become the actual cryptainer.

Here is an example of medium-complexity cryptoconf::

    +---------+
    | payload |
    |cleartext|
    +---------+
         |
         |
  [AES-EAX CIPHER] <-[RSA-OAEP CIPHER]- [KEY-GUARDIAN "witnessangel.com"]
         |
         v
   +------------+
   |  payload   | <-[RSA-PSS SIGNATURE]- [KEY-GUARDIAN: "Paul Dupond"]
   |ciphertext 1| <-[ECC_DSS SIGNATURE]- [KEY-GUARDIAN: Local Device]
   +------------+
         |                                       _
         |                                      /  <-[RSA-OAEP CIPHER- [KEY-GUARDIAN: "John Doe"]
  [AES-CBC CIPHER] <-[SHARED-SECRET (2 on 3))-  -- <-[RSA-OAEP CIPHER- [KEY-GUARDIAN: "Jane Doe"]
         |                                      \_ <-[RSA-OAEP CIPHER- [KEY-GUARDIAN: "Jack Doe"]
         v
   +------------+
   |  payload   |
   |ciphertext 2|
   +------------+

In this custom cryptosystem:

- the sensitive payload is first encrypted by AES-EAX, then by AES-CBC.
- The randomly-generated symmetric keys used for these symmetric encryptions are then protected in different ways.
- The first one is encrypted with the public key of the key guardian server "witnessangel.com".
- The second one is split into 3 "shards", each protected by the public key of a different member of the family Doe.
- Two timestamped signatures are stapled to the cryptainer, both applied on the intermediate ciphertext (so they will only be verifiable after the outer AES-CBC layer has been decrypted)


Encrypting data into a cryptainer
+++++++++++++++++++++++++++++++++++++++++


Encryption/signature of the payload
----------------------------------------

The first "pipeline" of encryption has a special status, because it deals with the protection of the initial data (audio, video, or any other medium/document), called "payload" in our terminology.

This payload can have a very large size, and it is the actual, sensitive information to secure against reading and modification.

So for this first layer of encryption:

- The payload ciphertext can be stored apart from the cryptainer tree (we then call it an "offloaded payloaded")
- Only symmetric ciphers are allowed, since asymmetric ones are slow and often insecure when handling big inputs
- The resulting ciphertext can be signed and timestamped by one or more trustees (the initial payload can't be signed, for now, as this might leak information about its content)


Encryption of the keys
----------------------------------------

At each level of the rest of the recursive cryptainer tree, the currently considered "key" goes through its own pipeline of encryption. Each node of this pipeline receives as cleartext the ciphertext of the previous node, and can be one of one of these type:

- a shared secret: "splits" the data into N shards, with M of them required to reconstitute the data; each shard is then encrypted through its own pipeline
- a symmetric cipher: encrypts the data using a randomly generated key, which is then encrypted through its own pipeline
- an asymmetric cipher: encrypts the data using a public key owned by a "trustee"; this ends the recursion on that branch of the cryptainer


Different modes of encryption processing
-------------------------------------------

If a payload of cleartext data is available, it can be encrypted and dumped to file in a single pass; however this can consume a lot of CPU and RAM on the moment.

As an alternative, the cryptolib supports on-the-fly encryption of data chunks transmitted during a long recording.

For that, we must setup a recording toolchain consisting of:

- sensors which get pushed, or at the contrary go pull, recorded chunks from hardware
- aggregators which combine data chunks into proper cleartext media/documents
- a pipeline which consumes cleartext data chunk by chunk, encrypts it, and streams it to disk (as an offloaded ciphertext)

In this scenario, the JSON cryptainer structure is initialized at the beginning of the recording, and remains in a *pending* state. At the end of the recording, integrity tags and payload signatures get added to this work-in-progress cryptainer, and it becomes complete.


Decrypting data from a cryptainer
+++++++++++++++++++++++++++++++++++++++++

Like in any layered encryption structure, decryption has to be performed from the outer shell to the core of the cryptainer.

This means that each key encryption pipeline is rolled back to recover a cleartext "key", which is in turn used to roll back the pipeline below it.

Along the way, payload integrity is verified thanks to both ciphertext signatures (checked via the public key of the related trustee), and integrity tags/macs (built in each symmetric or asymmetric cipher).

Since the leaves of the cryptainer tree are protected by trustees, they require external operations to be decrypted.

- "Local Key Factory" trustees are the easiest: their generated-on-demand keypairs have no passphrase protection on their private keys, so as long as these private keys are present (typically, on the recording device), decryption will succeed.
- "Server" trustees rely on keypairs generated-on-demand on a remote server (typically without passphrase protection of private keys). These trustees require decryption authorization requests to be submitted in advance to the server. When these permissions are then granted by an administrator, the server will accept to decrypt "key" ciphertexts submitted during the subsequent decryption operation.
- "Authenticator" trustees are individual key guardians having generated their own digital identity, with a set of keypairs protected by their (secret) passphrase. There are two ways to achieve decryption with them : either import their private keys locally and ask for their passphrase (low security), or send a secure key exchange request on a common web registry, which key guardians will then accept/reject from their own Authenticator device (high security).

**Known limitations**: As of today, the wacryptolib decryptor works in a single pass, and doesn't support partial decryption of cryptainers. It means that all "leaves" of the cryptainer tree must be unlocked in advance, by their relevant trustee. In practice, it means that all "Authenticator" trustees should be at the end of their "key" encryption pipeline, else they do not have access to the "key" ciphertext which must be sent as part of a decryption authorization request (so only the direct input of a passphrase would work). So instead of stacking 3 authenticator-backed RSA-OAEP encryptions in a row, for example, it is better to stack 3 symmetric ciphers (like AES-CBC or ChacCha20), and then protect each of their 3 randomly generated symkeys with a single authenticator-backed asymmetric encryption.


Noteworthy fields of a cryptainer
++++++++++++++++++++++++++++++++++++++

The `cryptainer_uid` field, located at the root of a cryptainer, uniquely identifies it.

The `keychain_uid` field, located nearby, can on the contrary be shared by several cryptainers, which thus end up targeting a common keychain of keypairs held by trustees (these keypairs being differentiated by their key-algo value).
However this default `keychain_uid` can also be overridden deeper in the configuration tree, for each trustee.

A `metadata` dict field can be used to store miscellaneous information about the cryptainer (time, location, type of recording...).
