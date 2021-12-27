Witness Angel Cryptolib
#############################

.. image:: https://travis-ci.com/WitnessAngel/witness-angel-cryptolib.svg?branch=master
    :target: https://travis-ci.com/WitnessAngel/witness-angel-cryptolib

.. image:: https://readthedocs.org/projects/witness-angel-cryptolib/badge/?version=latest&style=flat
    :target: https://witness-angel-cryptolib.readthedocs.io/en/latest/


`Full documentation on readthedocs! <https://witness-angel-cryptolib.readthedocs.io/en/latest/>`_


Summary
----------------

**WARNING, HUGE REFACTORING OF THIS LIB WILL SOON OCCUR**

This lib gathers utilities to generate and store cryptographic keys, and encrypt/decrypt/sign cryptainer, for the
WitnessAngel project.

It defines a cryptainer format which allows multiple agents (the user's device as well as trusted-third-parties) to
add layers of encryption and signature to the sensitive data.

It also provides utilities for webservices and their error handling, as well as test-helpers so that software using
the library may easily check that their own subclasses respect the invariants of this system.


CLI interface
----------------

You can play with cryptainers using this command line interface.

beware, unless you provide your own crypto-config, these CLI-generated cryptainers will use a hard-coded and simple cryptographic conf, using only locally-stored keys, so they will be insecure.

::

    $ python -m wacryptolib encrypt -i <data-file> -o <cryptainer-file>

    $ python -m wacryptolib decrypt -i <cryptainer-file> -o <data-file>
