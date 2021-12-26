Cryptainer
==========

This module provides utilities to write and read encrypted cryptainers, which themselves use
encryption/signing keys of the escrow system.


Cryptainer object processing
----------------------------------

.. autofunction:: wacryptolib.cryptainer.encrypt_data_into_cryptainer

.. autofunction:: wacryptolib.cryptainer.decrypt_data_from_cryptainer

.. autofunction:: wacryptolib.cryptainer.extract_metadata_from_cryptainer

.. autofunction:: wacryptolib.cryptainer.get_cryptoconf_summary

.. autoclass:: wacryptolib.cryptainer.CryptainerEncryptionStream

.. autofunction:: wacryptolib.cryptainer.encrypt_data_and_dump_cryptainer_to_filesystem


Validation utilities
---------------------------

.. autofunction:: wacryptolib.cryptainer.check_cryptainer_sanity

.. autofunction:: wacryptolib.cryptainer.check_conf_sanity


Filesystem operations
-----------------------------

.. autofunction:: wacryptolib.cryptainer.dump_cryptainer_to_filesystem

.. autofunction:: wacryptolib.cryptainer.load_cryptainer_from_filesystem

.. autofunction:: wacryptolib.cryptainer.delete_cryptainer_from_filesystem

.. autofunction:: wacryptolib.cryptainer.get_cryptainer_size_on_filesystem


Cryptainer storage system
---------------------------------

.. autoclass:: wacryptolib.cryptainer.CryptainerStorage


Escrow operations
--------------------------

.. autofunction:: wacryptolib.cryptainer.get_escrow_proxy

.. autofunction:: wacryptolib.cryptainer.gather_escrow_dependencies

.. autofunction:: wacryptolib.cryptainer.request_decryption_authorizations
