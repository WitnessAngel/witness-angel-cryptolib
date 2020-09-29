Key generation
==============

This module is dedicated to key generation, especially asymmetric public/private key pairs.

Note that keys are separated by use, thus keys of type RSA_OAEP (encryption) and RSA_PSS (signature) are different
for the same keychain uid.


Public API
--------------

.. autodata:: wacryptolib.key_generation.SUPPORTED_ASYMMETRIC_KEY_TYPES

.. autofunction:: wacryptolib.key_generation.generate_asymmetric_keypair

.. autofunction:: wacryptolib.key_generation.load_asymmetric_key_from_pem_bytestring

.. autodata:: wacryptolib.key_generation.SUPPORTED_SYMMETRIC_KEY_ALGOS

.. autofunction:: wacryptolib.key_generation.generate_symmetric_key


Private API
---------------

The functions below are only documented for the details they give on specific arguments.

RSA
~~~~~~~~

.. autofunction:: wacryptolib.key_generation._generate_rsa_keypair_as_objects


DSA
~~~~~~~~

.. autofunction:: wacryptolib.key_generation._generate_dsa_keypair_as_objects


ECC
~~~~~~~~

.. autofunction:: wacryptolib.key_generation._generate_ecc_keypair_as_objects

