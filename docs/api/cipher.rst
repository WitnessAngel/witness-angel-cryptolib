Encryption
=============

This module allows to encrypt bytestring data, then decrypt it.


Public API
--------------

.. autodata:: wacryptolib.cipher.SUPPORTED_CIPHER_ALGOS

.. autodata:: wacryptolib.cipher.AUTHENTICATED_CIPHER_ALGOS

.. autodata:: wacryptolib.cipher.STREAMABLE_CIPHER_ALGOS

.. autofunction:: wacryptolib.cipher.encrypt_bytestring

.. autofunction:: wacryptolib.cipher.decrypt_bytestring

.. autoclass:: wacryptolib.cipher.PayloadEncryptionPipeline


Private API
---------------

The objects below are only documented for the details they give on specific arguments.


AES with CBC mode
~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: wacryptolib.cipher.AesCbcEncryptionNode

.. autofunction:: wacryptolib.cipher._encrypt_via_aes_cbc

.. autofunction:: wacryptolib.cipher._decrypt_via_aes_cbc


AES with EAX mode
~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: wacryptolib.cipher.AesEaxEncryptionNode

.. autofunction:: wacryptolib.cipher._encrypt_via_aes_eax

.. autofunction:: wacryptolib.cipher._decrypt_via_aes_eax


ChaCha20_Poly1305
~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: wacryptolib.cipher.Chacha20Poly1305EncryptionNode

.. autofunction:: wacryptolib.cipher._encrypt_via_chacha20_poly1305

.. autofunction:: wacryptolib.cipher._decrypt_via_chacha20_poly1305


RSA - PKCS#1 OAEP
~~~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: wacryptolib.cipher._encrypt_via_rsa_oaep

.. autofunction:: wacryptolib.cipher._decrypt_via_rsa_oaep



