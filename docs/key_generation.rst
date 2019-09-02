Key generation
==============

This module is dedicated to key generation, especially assymetric public/private key pairs.


Public API
--------------

.. autodata:: wacryptolib.key_generation.SUPPORTED_KEY_TYPES


.. autofunction:: wacryptolib.key_generation.generate_asymmetric_keypair




Private API
---------------

The functions below are only documented for the details they give on specific arguments.

RSA
~~~~~~~~

.. autofunction:: wacryptolib.key_generation._generate_rsa_keypair_as_pem_bytestrings


DSA
~~~~~~~~

.. autofunction:: wacryptolib.key_generation._generate_dsa_keypair_as_pem_bytestrings


ECC
~~~~~~~~

.. autofunction:: wacryptolib.key_generation._generate_ecc_keypair_as_pem_bytestrings

