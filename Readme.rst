Witness Angel Cryptolib
#############################

.. image:: https://ci.appveyor.com/api/projects/status/y7mfa00b6c34khe0?svg=true
    :target: https://travis-ci.com/WitnessAngel/witness-angel-cryptolib

.. image:: https://readthedocs.org/projects/witness-angel-cryptolib/badge/?version=latest&style=flat
    :target: https://witness-angel-cryptolib.readthedocs.io/en/latest/


`Full documentation on readthedocs! <https://witness-angel-cryptolib.readthedocs.io/en/latest/>`_


Summary
----------------

The WACryptolib is a toolkit aimed at handling secure configuration-driven containers, called *cryptainers*.

By leveraging a flexible JSON-based format called *cryptoconf*, users can define their own hybrid cryptosystem, recursively combining symmetric cihers, asymmetric ciphers, shared secrets, and data signatures.

Access to the cyptainers is secured by a variety of actors: local device, remote server, trusted third parties...

The decryption process can involve different steps, like entering passphrases, or submitting authorization requests to third parties.

Overall, the lib gathers lots of utilities to generate and store cryptographic keys, encrypt/check/decrypt cryptainers, access webservices and recorder sensors, and help testing the libraries willing to extend these tools.


CLI interface
----------------

You can play with cryptainers using this command line interface.

By default, CLI-generated cryptainers use a hard-coded and simple cryptographic conf, using only locally-stored keys, so they are insecure. Use a `--cryptoconf` argument during encryption, to specify a config with your own trusted third parties.

::

    $ python -m wacryptolib encrypt -i <data-file> -o <cryptainer-file>

    $ python -m wacryptolib decrypt -i <cryptainer-file> -o <data-file>

    $ python -m wacryptolib summarize -i <cryptoconf-or-cryptainer>
