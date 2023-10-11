Flightbox CLI Tutorial
===================================

CLI Overview
-----------------

The flightbox command-line utility provides all subcommands for an end-to-end workflow around cryptainers.

.. command-output:: flightbox -h


Let's try a default encryption scheme
------------------------------------------

Imagine that we won't to encrypt a readme file. The corresponding command could be as simple as:

.. command-output:: flightbox encrypt readme.rst

As the output mentions it, this is not a satisfying encryption.
Let's check the structure of the resulting "cryptainer", which has been saved into default cryptainer storage.

.. command-output:: flightbox cryptainer list

.. command-output:: flightbox cryptainer summarize readme.rst.crypt

As we see, the cryptainer uses several types of encryption, but only relies of local device keys, which are not protected.,