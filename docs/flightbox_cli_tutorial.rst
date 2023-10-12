Flightbox CLI Tutorial
===================================

CLI Overview
-----------------

The flightbox command-line utility provides all subcommands for an end-to-end workflow around cryptainers.

.. command-output:: flightbox -h

.. hint::

    The positioning of CLI options is rather strict: they must be added directly after the command they are related too, and before the following subcommand. So for example `--gateway-url` must be provided after `flightbox`, but before subcommands like `cryptainer`, `encrypt` etc.


Playing with default encryption
--------------------------------

Imagine that we won't to encrypt a readme file. The corresponding command could be as simple as:

.. command-output:: flightbox encrypt readme.rst

But as the output mentions, this is not a satisfying encryption.
Let's check the structure of the resulting "cryptainer", which has been saved into default cryptainer storage.

.. command-output:: flightbox cryptainer list

.. hint::

    For performance reasons, the cryptainer is, by default, "offloaded". This means it is separated in two files: the metadata in "readme.rst.crypt", and the (possibly huge) encrypted data in "readme.rst.crypt.payload".


.. command-output:: flightbox cryptainer summarize readme.rst.crypt

As we see, the cryptainer uses several types of encryption, but only relies on local device keys, which are not protected by a passphrase.

.. hint::

    If you open readme.rst.crypt with a text editor, you'll notice that it's just a JSON file, but in Pymongo's Extended Json format: it uses specific fields like $binary or $date to add better types to the serialized data.


Creating an authenticator trustee
----------------------------------

To encrypt data in a more secure fashion, we'll need some key guardians, called `trustees` in Flightbox.

The simplest form of trustee is an authenticator, a digital identity for a single person. Currentl, it is backed by a keystore folder containing some metadata and a bunch of keypairs - all protected by the same "passphrase" (a very long password).

The standard way of generating this identity would be to use a standalone program like the mobile application Witness Angel Authenticator (for Android and iOS), and then to publish the public part of this identity to a web registry.

But we can also create authenticators via the CLI:

.. command-output:: flightbox authenticator create ~/mysphinxdocauthenticator --owner "John Doe" --passphrase-hint "Some hint"

For the needs of this doc generation, we had to provide the passphrase as an environment variable, but normally the program will just prompt the user for it.

We can then review the just-created authenticator:

.. command-output:: flightbox authenticator view ~/mysphinxdocauthenticator

And we can check, later, that we still remember the right passphrase:

.. command-output:: flightbox authenticator validate ~/mysphinxdocauthenticator



Importing foreign keystores
----------------------------------

Authenticators are supposed to be remote identities, well protected by their owner.
To use them in our encryption system, we need to import their public keys, which are like "padlocks".
That's what we call "foreign keystores" - partial local copies of remote identities.

Let's begin by importing the authenticator we just created.

.. command-output:: flightbox foreign-keystore import --from-path ~/mysphinxdocauthenticator

Let's also import an identity from a web registry, using its UUID that the owner gave us directly.

.. command-output:: flightbox --gateway-url https://api.witnessangel.com/gateway/jsonrpc/ foreign-keystore import --from-gateway 0f0c0988-80c1-9362-11c1-b06909a3a53c

If we have setup authenticators in default locations of connected USB keys, we can automatically import them:

.. command-output:: flightbox foreign-keystore import --from-usb --include-private-keys

.. warning::

    The `--include-private-keys` option requests that the private part of the identity be imported too, if present (which is not the case e.g. for web gateway identities). This is only useful if one intends to decrypt data locally, by entering passphrases during decryption. But much more secure workflows are now available, for example by using the mobile application Authenticator.

We can then review the imported keystores, which will be usable for encryption:

.. command-output:: flightbox foreign-keystore list


Generating a cryptoconf
--------------------------------

Now that we have locally registered some trustees, it's time to specify how they should protect our data, how they should become our "key guardians". This happens with a cryptoconf, a JSON cryptainer template recursively describing the different layers of encryption to be used on data and on keys, as well as the signatures to apply.

For some simple, signatureless cases, we can use the CLI to generate a cryptoconf fo us.

For example, imagien we want to encrypt the data using AES-CBC, and then protect the


.. command-output:: flightbox cryptoconf generate-simple add-payload-cipher-layer --sym-cipher-algo aes_cbc add-key-cipher-layer --asym-cipher-algo RSA_OAEP --trustee-type authenticator --keystore-uid 0f0c0988-80c1-9362-11c1-b06909a3a53c


