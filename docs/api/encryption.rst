Encryption
=============

This module allows to encrypt bytestring data, then decrypt it.


Public API
--------------

.. autodata:: wacryptolib.encryption.SUPPORTED_ENCRYPTION_ALGOS

.. autodata:: wacryptolib.encryption.AUTHENTICATED_ENCRYPTION_ALGOS

.. autodata:: wacryptolib.encryption.STREAMABLE_ENCRYPTION_ALGOS

.. autofunction:: wacryptolib.encryption.encrypt_bytestring

.. autofunction:: wacryptolib.encryption.decrypt_bytestring

.. autoclass:: wacryptolib.encryption.StreamManager


Private API
---------------

The objects below are only documented for the details they give on specific arguments.


AES with CBC mode
~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: wacryptolib.encryption.AesCbcEncryptionNode

.. autofunction:: wacryptolib.encryption._encrypt_via_aes_cbc

.. autofunction:: wacryptolib.encryption._decrypt_via_aes_cbc


AES with EAX mode
~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: wacryptolib.encryption.AesEaxEncryptionNode

.. autofunction:: wacryptolib.encryption._encrypt_via_aes_eax

.. autofunction:: wacryptolib.encryption._decrypt_via_aes_eax


ChaCha20_Poly1305
~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: wacryptolib.encryption.Chacha20Poly1305EncryptionNode

.. autofunction:: wacryptolib.encryption._encrypt_via_chacha20_poly1305

.. autofunction:: wacryptolib.encryption._decrypt_via_chacha20_poly1305


RSA - PKCS#1 OAEP
~~~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: wacryptolib.encryption._encrypt_via_rsa_oaep

.. autofunction:: wacryptolib.encryption._decrypt_via_rsa_oaep



