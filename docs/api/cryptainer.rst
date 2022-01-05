Cryptainer
==========

This module provides utilities to write and read encrypted cryptainers, which themselves use
encryption/signing keys of the trustee system.


Cryptainer object processing
----------------------------------

.. autofunction:: wacryptolib.cryptainer.encrypt_payload_into_cryptainer

.. autofunction:: wacryptolib.cryptainer.decrypt_payload_from_cryptainer

.. autofunction:: wacryptolib.cryptainer.extract_metadata_from_cryptainer

.. autofunction:: wacryptolib.cryptainer.get_cryptoconf_summary

.. autoclass:: wacryptolib.cryptainer.CryptainerEncryptionPipeline

.. autofunction:: wacryptolib.cryptainer.encrypt_payload_and_stream_cryptainer_to_filesystem


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

.. autoclass:: wacryptolib.cryptainer.ReadonlyCryptainerStorage

.. autoclass:: wacryptolib.cryptainer.CryptainerStorage


Trustee operations
--------------------------

.. autofunction:: wacryptolib.cryptainer.get_trustee_proxy

.. autofunction:: wacryptolib.cryptainer.gather_trustee_dependencies

.. autofunction:: wacryptolib.cryptainer.request_decryption_authorizations
