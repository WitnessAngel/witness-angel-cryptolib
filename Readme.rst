Witness Angel Cryptolib
#############################

.. image:: https://travis-ci.com/WitnessAngel/witness-angel-cryptolib.svg?branch=master
    :target: https://travis-ci.com/WitnessAngel/witness-angel-cryptolib

This lib gathers utilities to generate and store cryptographic keys, and encrypt/decrypt/sign container, for the
Witness Angel system.

It defines a container format which allows multiple agents (the user's device as well as third-party escrow) to
add layers of encryption and signature to the sensitive data.

It also provides utilities for webservices and their error handling, as well as testing helpers so that software using
the library may easily check their their own subclasses respect the invariants of this system.


