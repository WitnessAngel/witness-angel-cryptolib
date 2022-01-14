Witness Angel Cryptolib
#############################

.. image:: https://ci.appveyor.com/api/projects/status/y7mfa00b6c34khe0?svg=true
    :target: https://travis-ci.com/WitnessAngel/witness-angel-cryptolib

.. image:: https://readthedocs.org/projects/witness-angel-cryptolib/badge/?version=latest&style=flat
    :target: https://witness-angel-cryptolib.readthedocs.io/en/latest/


`Full documentation on readthedocs! <https://witness-angel-cryptolib.readthedocs.io/en/latest/>`_


Summary
----------------

This lib gathers utilities to generate and store cryptographic keys, and to encrypt/decrypt/sign encrypted containers, for the WitnessAngel project.

It defines a cryptainer format which allows multiple actors (the user's device as well as trusted third parties) to
add layers of encryption and signature to sensitive data.

It also provides utilities for webservices and their error handling, as well as test helpers so that software extending
the library may easily check that their own subclasses respect the invariants of this system.


CLI interface
----------------

You can play with cryptainers using this command line interface.

By default, CLI-generated cryptainers use a hard-coded and simple cryptographic conf, using only locally-stored keys, so they are insecure. Use `--cryptoconf` argument during encryption, to specify a config with your own trusted third parties.

::

    $ python -m wacryptolib encrypt -i <data-file> -o <cryptainer-file>

    $ python -m wacryptolib decrypt -i <cryptainer-file> -o <data-file>
