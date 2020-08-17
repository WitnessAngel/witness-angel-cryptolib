Witness Angel Cryptolib
#############################

.. image:: https://travis-ci.com/WitnessAngel/witness-angel-cryptolib.svg?branch=master
    :target: https://travis-ci.com/WitnessAngel/witness-angel-cryptolib

.. image:: https://readthedocs.org/projects/witness-angel-cryptolib/badge/?version=latest&style=flat
    :target: https://witness-angel-cryptolib.readthedocs.io/en/latest/


`Read full documentation here! <https://witness-angel-cryptolib.readthedocs.io/en/latest/>`_

This lib gathers utilities to generate and store cryptographic keys, and encrypt/decrypt/sign container, for the
Witness Angel system.

It defines a container format which allows multiple agents (the user's device as well as third-party escrow) to
add layers of encryption and signature to the sensitive data.

It also provides utilities for webservices and their error handling, as well as testing helpers so that software using
the library may easily check their their own subclasses respect the invariants of this system.


CLI interface
----------------

You can play with containers using this command line interface.
For now, these CLI-generated containers use a hard-coded and simple cryptographic conf, using only locally-stored keys, so they are insecure.

::

    $ python -m wacryptolib encrypt -i <data-file> -o <container-file>

    $ python -m wacryptolib decrypt -i <container-file> -o <data-file>
