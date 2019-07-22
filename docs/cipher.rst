Cipher
======

	Documentation about the functions which permit to encrypt a plain text
	then decrypt the cipher text. 
	Available types: AES-CBC, AES-EAX.


AES with CBC mode
-----------------

.. autofunction:: wacryptolib.cipher.encrypt_via_aes_cbc

____

.. autofunction:: wacryptolib.cipher.decrypt_via_aes_cbc


AES with EAX mode
-----------------

.. autofunction:: wacryptolib.cipher.encrypt_via_aes_eax

____

.. autofunction:: wacryptolib.cipher.decrypt_via_aes_eax


RSA - PKCS#1 OAEP
-----------------

.. autofunction:: wacryptolib.cipher.encrypt_via_rsa_oaep

____

.. autofunction:: wacryptolib.cipher.decrypt_via_rsa_oaep


ChaCha20_Poly1305
-----------------

.. autofunction:: wacryptolib.cipher.encrypt_via_chacha20_poly1305

____

.. autofunction:: wacryptolib.cipher.decrypt_via_chacha20_poly1305