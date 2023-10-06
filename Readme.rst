Witness Angel Cryptolib
#############################

.. image:: https://ci.appveyor.com/api/projects/status/y7mfa00b6c34khe0?svg=true
    :target: https://travis-ci.com/WitnessAngel/witness-angel-cryptolib

.. image:: https://readthedocs.org/projects/witness-angel-cryptolib/badge/?version=latest&style=flat
    :target: https://witness-angel-cryptolib.readthedocs.io/en/latest/

-> `Full documentation on READTHEDOCS! <https://witness-angel-cryptolib.readthedocs.io/en/latest/>`_ <-


Overview
+++++++++++++++++++++

The Witness Angel Cryptolib is a toolkit aimed at handling secure configuration-driven containers, called *cryptainers*.

By leveraging a flexible JSON-based format called *cryptoconf*, users can define their own hybrid cryptosystem, recursively combining symmetric cihers, asymmetric ciphers, shared secrets, and data signatures.

Access to the cryptainers is secured by a variety of actors: local device, remote servers, trusted third parties...

The decryption process can involve different steps, like entering passphrases, or submitting authorization requests to remote "key guardians".

Overall, the lib gathers utilities to generate and store cryptographic keys, encrypt/check/decrypt cryptainers, access webservices and recorder sensors, and help testing other libraries willing to extend these tools.


Installing the lib
+++++++++++++++++++++

Just launch inside your python environment:

    **pip install wacryptolib**


CLI interface
+++++++++++++++++++++

A command-line interface launcher, **flightbox**, is available to play with simple cryptainers.

::

    $ flightbox --help

Look at the Flightbox manual, on readthedocs.org, for more details.
