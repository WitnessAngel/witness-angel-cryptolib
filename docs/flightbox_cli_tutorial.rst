Flightbox CLI Tutorial
===================================

CLI Overview
-----------------

The flightbox command-line utility provides all subcommands for an end-to-end workflow around cryptainers.

.. command-output:: flightbox -h


Playing with default encryption
--------------------------------

Imagine that we won't to encrypt a readme file. The corresponding command could be as simple as:

.. command-output:: flightbox encrypt readme.rst

But as the output mentions, this is not a satisfying encryption.
Let's check the structure of the resulting "cryptainer", which has been saved into default cryptainer storage.

.. command-output:: flightbox cryptainer list

.. command-output:: flightbox cryptainer summarize readme.rst.crypt

As we see, the cryptainer uses several types of encryption, but only relies on local device keys, which are not protected by a passphrase.


Creating an authenticator
--------------------------------

To encrypt data in a more secure fashion, we'll need trusted third parties, called `trustees` in Flightbox.

The simplest form of trustee is an authenticator, a digital identity for a single person. It is represented by a folder containing some metadata and a bunch of keypairs - all protected by the same passphrase.

.. command-output:: flightbox authenticator create ~/mysphinxdocauthenticator --owner "John Doe" --passphrase-hint "Some hint"

For the needs of this doc, we had to provide the passphrase (a very long password) as an environment variable, but normally the program will just prompt the user for it.



