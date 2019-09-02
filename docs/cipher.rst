Cipher
======

	Documentation about the functions which permit to encrypt a plain text
	then decrypt the cipher text. 
	Available types: AES-CBC, AES-EAX.


AES with CBC mode
-----------------

.. autofunction:: wacryptolib.encryption._encrypt_via_aes_cbc

____

.. autofunction:: wacryptolib.encryption._decrypt_via_aes_cbc


AES with EAX mode
-----------------

.. autofunction:: wacryptolib.encryption._encrypt_via_aes_eax

____

.. autofunction:: wacryptolib.encryption._decrypt_via_aes_eax


RSA - PKCS#1 OAEP
-----------------

.. autofunction:: wacryptolib.encryption._encrypt_via_rsa_oaep

____

.. autofunction:: wacryptolib.encryption._decrypt_via_rsa_oaep


ChaCha20_Poly1305
-----------------

.. autofunction:: wacryptolib.encryption._encrypt_via_chacha20_poly1305

____

.. autofunction:: wacryptolib.encryption._decrypt_via_chacha20_poly1305
