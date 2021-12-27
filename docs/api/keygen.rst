Key generation
==============

This module is dedicated to key generation, especially asymmetric public/private key pairs.

Note that keys are separated by use, thus keys of type RSA_OAEP (encryption) and RSA_PSS (signature) are different
for the same keychain uid.


Public API
--------------

.. autodata:: wacryptolib.keygen.SUPPORTED_ASYMMETRIC_KEY_ALGOS

.. autofunction:: wacryptolib.keygen.generate_keypair

.. autofunction:: wacryptolib.keygen.load_asymmetric_key_from_pem_bytestring

.. autodata:: wacryptolib.keygen.SUPPORTED_SYMMETRIC_KEY_ALGOS

.. autofunction:: wacryptolib.keygen.generate_symkey


Private API
---------------

The functions below are only documented for the details they give on specific arguments.

RSA
~~~~~~~~

.. autofunction:: wacryptolib.keygen._generate_rsa_keypair_as_objects


DSA
~~~~~~~~

.. autofunction:: wacryptolib.keygen._generate_dsa_keypair_as_objects


ECC
~~~~~~~~

.. autofunction:: wacryptolib.keygen._generate_ecc_keypair_as_objects
